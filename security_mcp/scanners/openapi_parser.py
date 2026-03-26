"""OpenAPI / Swagger specification parser for automated endpoint discovery.

Parses OpenAPI 2.0 (Swagger), 3.0, and 3.1 specifications from URLs or raw data.
Extracts endpoints, parameters, request bodies, and authentication requirements
in a format compatible with the standard crawl output pipeline.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx
import yaml

logger = logging.getLogger(__name__)

# Common fallback paths when a URL returns HTML (Swagger UI) instead of a spec.
_SPEC_FALLBACK_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.yaml",
    "/swagger.yaml",
    "/api/openapi.json",
    "/api/swagger.json",
]

_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head", "trace"}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class OpenAPIParameter:
    """A single parameter on an API endpoint."""

    name: str
    location: str  # "query", "path", "header", "cookie", "body"
    param_type: str  # "string", "integer", "boolean", "array", "object"
    required: bool = False
    description: str = ""
    example: Any = None
    enum: list[str] = field(default_factory=list)


@dataclass
class OpenAPIEndpoint:
    """A single API endpoint with its metadata."""

    path: str  # /api/users/{id}
    method: str  # GET, POST, PUT, DELETE, PATCH
    parameters: list[OpenAPIParameter] = field(default_factory=list)
    request_body_type: str = ""  # "application/json", "multipart/form-data", etc.
    request_body_schema: dict = field(default_factory=dict)  # JSON schema for request body
    request_body_required: bool = False
    auth_required: bool = False
    auth_schemes: list[str] = field(default_factory=list)  # ["bearer", "api_key", "basic"]
    tags: list[str] = field(default_factory=list)
    summary: str = ""
    deprecated: bool = False


@dataclass
class OpenAPISpec:
    """Parsed specification with all extracted data."""

    title: str = ""
    version: str = ""
    base_url: str = ""
    endpoints: list[OpenAPIEndpoint] = field(default_factory=list)
    security_schemes: dict[str, dict] = field(default_factory=dict)
    total_endpoints: int = 0
    spec_version: str = ""  # "2.0", "3.0", "3.1"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class OpenAPIParser:
    """Parses OpenAPI 2.0 / 3.0 / 3.1 specifications into a normalised model.

    Usage::

        parser = OpenAPIParser()
        spec = await parser.fetch_and_parse("https://petstore.swagger.io/v2/swagger.json")
        crawl_output = parser.to_crawl_format(spec, target_base="https://petstore.swagger.io")
    """

    def __init__(self) -> None:
        self._resolved_refs: set[str] = set()  # Circular-reference guard

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_and_parse(self, url: str, timeout: float = 15.0) -> OpenAPISpec:
        """Fetch a spec from *url* (JSON or YAML), then parse it.

        If the URL returns HTML (e.g. Swagger UI), common fallback paths are
        tried automatically.

        Args:
            url: URL pointing to the specification file.
            timeout: HTTP request timeout in seconds.

        Returns:
            Parsed ``OpenAPISpec``.
        """
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; security-mcp/1.0)"},
        ) as client:
            spec_data = await self._fetch_spec(client, url)
            if spec_data is None:
                logger.warning("Could not retrieve a valid OpenAPI spec from %s", url)
                return OpenAPISpec()

        return self.parse(spec_data, base_url=url)

    def parse(self, spec_data: dict, base_url: str = "") -> OpenAPISpec:
        """Parse a raw spec dict into an ``OpenAPISpec``.

        Detects the spec version and dispatches to the appropriate parser.

        Args:
            spec_data: Parsed JSON/YAML dict of the specification.
            base_url: Optional base URL used when servers/host are relative.

        Returns:
            Populated ``OpenAPISpec``.
        """
        if not isinstance(spec_data, dict):
            logger.error("Expected dict for spec_data, got %s", type(spec_data).__name__)
            return OpenAPISpec()

        # Reset circular-ref guard for each top-level parse call.
        self._resolved_refs = set()
        spec_data = self._resolve_refs(spec_data)

        # Detect version
        if "swagger" in spec_data:
            return self._parse_swagger2(spec_data, base_url)
        if "openapi" in spec_data:
            return self._parse_openapi3(spec_data, base_url)

        logger.warning("Unrecognised spec format (no 'swagger' or 'openapi' key)")
        return OpenAPISpec()

    def to_crawl_format(self, spec: OpenAPISpec, target_base: str = "") -> dict[str, Any]:
        """Convert an ``OpenAPISpec`` to the standard crawl output format.

        The returned dict is directly compatible with the composite crawl
        pipeline so downstream vulnerability tools work unchanged.

        Args:
            spec: Parsed OpenAPI specification.
            target_base: Target base URL to prepend to relative paths.

        Returns:
            Dict matching the crawl tool output schema.
        """
        base = target_base.rstrip("/") or spec.base_url.rstrip("/")

        urls: list[str] = []
        api_endpoints: list[dict[str, Any]] = []

        for ep in spec.endpoints:
            full_url = f"{base}{ep.path}" if base else ep.path
            if full_url not in urls:
                urls.append(full_url)

            params: list[dict[str, Any]] = []
            for p in ep.parameters:
                param_dict: dict[str, Any] = {
                    "name": p.name,
                    "in": p.location,
                    "type": p.param_type,
                    "required": p.required,
                }
                if p.example is not None:
                    param_dict["example"] = p.example
                else:
                    param_dict["example"] = self._generate_example_value(p)
                if p.enum:
                    param_dict["enum"] = p.enum
                params.append(param_dict)

            entry: dict[str, Any] = {
                "url": ep.path,
                "method": ep.method,
                "parameters": params,
                "auth_required": ep.auth_required,
            }
            if ep.request_body_type:
                entry["content_type"] = ep.request_body_type
            if ep.request_body_schema:
                entry["body_schema"] = ep.request_body_schema
            if ep.auth_schemes:
                entry["auth_schemes"] = ep.auth_schemes
            if ep.tags:
                entry["tags"] = ep.tags
            if ep.summary:
                entry["summary"] = ep.summary
            if ep.deprecated:
                entry["deprecated"] = True

            api_endpoints.append(entry)

        return {
            "crawler": "openapi",
            "openapi_source": True,
            "spec_title": spec.title,
            "spec_version": spec.spec_version,
            "urls": urls,
            "api_endpoints": api_endpoints,
            "forms": [],
            "js_files": [],
            "security_schemes": spec.security_schemes,
            "total_endpoints": spec.total_endpoints,
        }

    # ------------------------------------------------------------------
    # Fetching helpers
    # ------------------------------------------------------------------

    async def _fetch_spec(self, client: httpx.AsyncClient, url: str) -> dict | None:
        """Fetch and decode a spec, falling back to common paths if HTML is returned."""
        data = await self._try_fetch(client, url)
        if data is not None:
            return data

        # URL returned HTML or failed — try common fallback paths.
        from urllib.parse import urlparse

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for path in _SPEC_FALLBACK_PATHS:
            fallback_url = f"{origin}{path}"
            if fallback_url == url:
                continue
            data = await self._try_fetch(client, fallback_url)
            if data is not None:
                logger.info("Found spec at fallback path %s", fallback_url)
                return data

        return None

    async def _try_fetch(self, client: httpx.AsyncClient, url: str) -> dict | None:
        """Attempt to GET *url* and parse response as JSON or YAML."""
        try:
            resp = await client.get(url)
            if resp.status_code >= 400:
                return None
        except httpx.HTTPError as exc:
            logger.debug("HTTP error fetching %s: %s", url, exc)
            return None

        body = resp.text

        # Quick reject: if it looks like an HTML page, skip.
        if body.lstrip().startswith("<!") or "<html" in body[:500].lower():
            return None

        # Try JSON first, then YAML.
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, ValueError):
            pass

        try:
            data = yaml.safe_load(body)
            if isinstance(data, dict):
                return data
        except yaml.YAMLError:
            pass

        return None

    # ------------------------------------------------------------------
    # $ref resolution
    # ------------------------------------------------------------------

    def _resolve_refs(self, spec: dict) -> dict:
        """Recursively resolve all ``$ref`` pointers in *spec*.

        Handles local references (``#/definitions/...``, ``#/components/...``),
        nested refs, and circular references (breaks cycles).
        """
        root = spec  # Keep a reference to the top-level dict for pointer resolution.
        return self._walk_and_resolve(spec, root, set())

    def _walk_and_resolve(self, node: Any, root: dict, seen_refs: set[str]) -> Any:
        """Depth-first walk replacing ``$ref`` dicts with their targets."""
        if isinstance(node, dict):
            if "$ref" in node and isinstance(node["$ref"], str):
                ref_path = node["$ref"]
                if ref_path in seen_refs:
                    # Circular — return a stub to avoid infinite recursion.
                    return {"_circular_ref": ref_path}
                resolved = self._lookup_ref(ref_path, root)
                if resolved is not None:
                    seen_copy = seen_refs | {ref_path}
                    return self._walk_and_resolve(resolved, root, seen_copy)
                return node  # Unresolvable ref — keep as-is.
            return {k: self._walk_and_resolve(v, root, seen_refs) for k, v in node.items()}
        if isinstance(node, list):
            return [self._walk_and_resolve(item, root, seen_refs) for item in node]
        return node

    @staticmethod
    def _lookup_ref(ref: str, root: dict) -> Any | None:
        """Resolve a local JSON Pointer (``#/a/b/c``) against *root*."""
        if not ref.startswith("#/"):
            return None  # External refs not supported.
        parts = ref[2:].split("/")
        current: Any = root
        for part in parts:
            # JSON Pointer escapes: ~1 -> /, ~0 -> ~
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
            if current is None:
                return None
        return current

    # ------------------------------------------------------------------
    # Swagger 2.0
    # ------------------------------------------------------------------

    def _parse_swagger2(self, spec: dict, base_url: str) -> OpenAPISpec:
        """Parse a Swagger 2.0 specification."""
        info = spec.get("info", {})
        host = spec.get("host", "")
        base_path = spec.get("basePath", "")
        schemes = spec.get("schemes", ["https"])
        scheme = schemes[0] if schemes else "https"

        if host:
            computed_base = f"{scheme}://{host}{base_path}".rstrip("/")
        elif base_url:
            computed_base = base_url.rstrip("/")
        else:
            computed_base = ""

        # Security definitions
        security_defs = spec.get("securityDefinitions", {})
        security_schemes: dict[str, dict] = {}
        for name, defn in security_defs.items():
            if isinstance(defn, dict):
                security_schemes[name] = dict(defn)

        global_security = spec.get("security", [])

        # Parse paths
        endpoints: list[OpenAPIEndpoint] = []
        paths = spec.get("paths", {})
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters (shared across all operations on this path)
            path_params = path_item.get("parameters", [])

            for method in _HTTP_METHODS:
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue

                # Merge path-level + operation-level params (operation wins on conflict)
                merged_params = self._merge_parameters(path_params, operation.get("parameters", []))
                parameters = self._extract_parameters(merged_params, spec_version="2.0")

                # Body parameter (Swagger 2.0 uses "in: body" with a schema)
                body_type = ""
                body_schema: dict = {}
                body_required = False
                consumes = operation.get("consumes", spec.get("consumes", ["application/json"]))
                for p in merged_params:
                    if isinstance(p, dict) and p.get("in") == "body":
                        body_type = consumes[0] if consumes else "application/json"
                        body_schema = p.get("schema", {})
                        body_required = bool(p.get("required", False))
                        break

                # formData params imply form content type
                if not body_type:
                    for p in merged_params:
                        if isinstance(p, dict) and p.get("in") == "formData":
                            body_type = "application/x-www-form-urlencoded"
                            break

                auth_required, auth_names = self._infer_auth_required(operation, global_security, security_schemes)

                ep = OpenAPIEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=parameters,
                    request_body_type=body_type,
                    request_body_schema=body_schema,
                    request_body_required=body_required,
                    auth_required=auth_required,
                    auth_schemes=auth_names,
                    tags=operation.get("tags", []),
                    summary=str(operation.get("summary", "")),
                    deprecated=bool(operation.get("deprecated", False)),
                )
                endpoints.append(ep)

        result = OpenAPISpec(
            title=str(info.get("title", "")),
            version=str(info.get("version", "")),
            base_url=computed_base,
            endpoints=endpoints,
            security_schemes=security_schemes,
            total_endpoints=len(endpoints),
            spec_version="2.0",
        )
        logger.info("Parsed Swagger 2.0 spec '%s': %d endpoints", result.title, result.total_endpoints)
        return result

    # ------------------------------------------------------------------
    # OpenAPI 3.0 / 3.1
    # ------------------------------------------------------------------

    def _parse_openapi3(self, spec: dict, base_url: str) -> OpenAPISpec:
        """Parse an OpenAPI 3.0 or 3.1 specification."""
        info = spec.get("info", {})
        openapi_version = str(spec.get("openapi", "3.0"))

        # Determine base URL from servers
        servers = spec.get("servers", [])
        computed_base = self._resolve_server_url(servers, base_url)

        # Security schemes from components
        components = spec.get("components", {})
        raw_schemes = components.get("securitySchemes", {})
        security_schemes: dict[str, dict] = {}
        for name, defn in raw_schemes.items():
            if isinstance(defn, dict):
                security_schemes[name] = dict(defn)

        global_security = spec.get("security", [])

        # Parse paths
        endpoints: list[OpenAPIEndpoint] = []
        paths = spec.get("paths", {})
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            path_params = path_item.get("parameters", [])

            for method in _HTTP_METHODS:
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue

                merged_params = self._merge_parameters(path_params, operation.get("parameters", []))
                parameters = self._extract_parameters(merged_params, spec_version="3.x")

                # Request body (OpenAPI 3.x)
                body_type, body_schema, body_required = self._extract_body_schema(operation.get("requestBody", {}))

                auth_required, auth_names = self._infer_auth_required(operation, global_security, security_schemes)

                ep = OpenAPIEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=parameters,
                    request_body_type=body_type,
                    request_body_schema=body_schema,
                    request_body_required=body_required,
                    auth_required=auth_required,
                    auth_schemes=auth_names,
                    tags=operation.get("tags", []),
                    summary=str(operation.get("summary", "")),
                    deprecated=bool(operation.get("deprecated", False)),
                )
                endpoints.append(ep)

        # Normalise version to "3.0" or "3.1"
        short_version = "3.1" if openapi_version.startswith("3.1") else "3.0"

        result = OpenAPISpec(
            title=str(info.get("title", "")),
            version=str(info.get("version", "")),
            base_url=computed_base,
            endpoints=endpoints,
            security_schemes=security_schemes,
            total_endpoints=len(endpoints),
            spec_version=short_version,
        )
        logger.info("Parsed OpenAPI %s spec '%s': %d endpoints", short_version, result.title, result.total_endpoints)
        return result

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_server_url(servers: list[dict], base_url: str) -> str:
        """Pick a base URL from the servers array, resolving templates and relative paths."""
        if not servers:
            return base_url.rstrip("/") if base_url else ""

        server = servers[0]
        if not isinstance(server, dict):
            return base_url.rstrip("/") if base_url else ""

        url = str(server.get("url", ""))

        # Resolve template variables (e.g. {environment})
        variables = server.get("variables", {})
        if isinstance(variables, dict):
            for var_name, var_def in variables.items():
                if not isinstance(var_def, dict):
                    continue
                # Use enum[0] if present, else default, else literal "default"
                enum_vals = var_def.get("enum", [])
                default = var_def.get("default", enum_vals[0] if enum_vals else "default")
                url = url.replace(f"{{{var_name}}}", str(default))

        # Relative URL — resolve against the base
        if url.startswith("/"):
            if base_url:
                from urllib.parse import urlparse

                parsed = urlparse(base_url)
                url = f"{parsed.scheme}://{parsed.netloc}{url}"
        elif not url.startswith("http") and base_url:
            url = urljoin(base_url, url)

        return url.rstrip("/")

    @staticmethod
    def _merge_parameters(path_params: list, operation_params: list) -> list[dict]:
        """Merge path-level and operation-level parameters.

        Operation parameters take precedence when they share the same (name, in) pair.
        """
        merged: dict[tuple[str, str], dict] = {}
        for p in path_params:
            if isinstance(p, dict):
                key = (str(p.get("name", "")), str(p.get("in", "")))
                merged[key] = p
        for p in operation_params:
            if isinstance(p, dict):
                key = (str(p.get("name", "")), str(p.get("in", "")))
                merged[key] = p  # Operation wins
        return list(merged.values())

    def _extract_parameters(self, params_list: list[dict], spec_version: str) -> list[OpenAPIParameter]:
        """Convert raw parameter dicts to ``OpenAPIParameter`` objects.

        Handles both Swagger 2.0 (``type`` at top level) and OpenAPI 3.x
        (``type`` nested under ``schema``).
        """
        result: list[OpenAPIParameter] = []
        for raw in params_list:
            if not isinstance(raw, dict):
                continue
            location = str(raw.get("in", "query"))
            # Skip body params here — they are handled separately.
            if location == "body":
                continue

            # Type inference
            if spec_version == "2.0":
                param_type = str(raw.get("type", "string"))
                enum = raw.get("enum", [])
                example = raw.get("x-example", raw.get("default"))
            else:
                schema = raw.get("schema", {})
                if not isinstance(schema, dict):
                    schema = {}
                param_type = self._flatten_schema_type(schema)
                enum = schema.get("enum", [])
                example = schema.get("example", raw.get("example"))

            # Normalise formData -> body for our model
            if location == "formData":
                location = "body"

            param = OpenAPIParameter(
                name=str(raw.get("name", "")),
                location=location,
                param_type=param_type,
                required=bool(raw.get("required", False)),
                description=str(raw.get("description", "")),
                example=example,
                enum=[str(e) for e in enum] if isinstance(enum, list) else [],
            )
            result.append(param)
        return result

    @staticmethod
    def _extract_body_schema(request_body: dict | None) -> tuple[str, dict, bool]:
        """Extract content type, schema, and required flag from a requestBody.

        Prefers ``application/json``, falls back to the first available content type.
        """
        if not request_body or not isinstance(request_body, dict):
            return "", {}, False

        required = bool(request_body.get("required", False))
        content = request_body.get("content", {})
        if not isinstance(content, dict) or not content:
            return "", {}, required

        # Prefer application/json
        preferred_order = [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
        ]
        selected_type = ""
        for ct in preferred_order:
            if ct in content:
                selected_type = ct
                break
        if not selected_type:
            selected_type = next(iter(content))

        media_obj = content.get(selected_type, {})
        if not isinstance(media_obj, dict):
            return selected_type, {}, required

        schema = media_obj.get("schema", {})
        return selected_type, schema if isinstance(schema, dict) else {}, required

    @staticmethod
    def _infer_auth_required(
        operation: dict, global_security: list, security_schemes: dict[str, dict]
    ) -> tuple[bool, list[str]]:
        """Determine whether an endpoint requires authentication.

        Checks operation-level ``security`` first, then falls back to global.
        Maps scheme names to friendly labels (e.g. ``bearerAuth`` -> ``bearer``).

        Returns:
            (auth_required, list_of_friendly_scheme_names)
        """
        # operation-level security overrides global (including empty list = no auth)
        security = operation.get("security")
        if security is None:
            security = global_security
        if not security:
            return False, []

        # Friendly name mapping based on scheme definition
        friendly_names: list[str] = []
        for entry in security:
            if not isinstance(entry, dict):
                continue
            for scheme_name in entry:
                defn = security_schemes.get(scheme_name, {})
                scheme_type = str(defn.get("type", "")).lower()

                if scheme_type == "http":
                    http_scheme = str(defn.get("scheme", "")).lower()
                    if http_scheme == "bearer":
                        friendly_names.append("bearer")
                    elif http_scheme == "basic":
                        friendly_names.append("basic")
                    else:
                        friendly_names.append(http_scheme or "http")
                elif scheme_type == "apikey":
                    friendly_names.append("api_key")
                elif scheme_type == "oauth2":
                    friendly_names.append("oauth2")
                elif scheme_type == "openidconnect":
                    friendly_names.append("oidc")
                else:
                    # Swagger 2.0 types or unknown — best-effort
                    friendly_names.append(scheme_name.lower())

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for n in friendly_names:
            if n not in seen:
                seen.add(n)
                unique.append(n)

        return bool(unique), unique

    @staticmethod
    def _flatten_schema_type(schema: dict) -> str:
        """Resolve a schema to a simple type string.

        Handles ``oneOf``, ``anyOf``, ``allOf`` by picking the first concrete type.
        """
        if "type" in schema:
            return str(schema["type"])

        for composite in ("oneOf", "anyOf", "allOf"):
            variants = schema.get(composite)
            if isinstance(variants, list):
                for v in variants:
                    if isinstance(v, dict) and "type" in v:
                        return str(v["type"])

        # No determinable type
        return "object"

    @staticmethod
    def _generate_example_value(param: OpenAPIParameter) -> Any:
        """Generate a plausible example value for security testing.

        Priority: explicit example > first enum > type-based default.
        """
        if param.example is not None:
            return param.example
        if param.enum:
            return param.enum[0]

        ptype = param.param_type.lower()
        name_lower = param.name.lower()

        if ptype == "integer" or ptype == "number":
            if "id" in name_lower:
                return 1
            return 1
        if ptype == "boolean":
            return True
        if ptype == "array":
            return ["test"]
        if ptype == "object":
            return {}

        # string (default)
        if "id" in name_lower and param.location == "path":
            return "1"
        if "email" in name_lower:
            return "test@example.com"
        if "url" in name_lower or "uri" in name_lower:
            return "https://example.com"
        if "date" in name_lower:
            return "2025-01-01"
        return "test"


# ---------------------------------------------------------------------------
# Quick-test entry point
# ---------------------------------------------------------------------------


async def _main() -> None:
    """Fetch the Petstore spec and print a summary."""
    parser = OpenAPIParser()
    spec = await parser.fetch_and_parse("https://petstore.swagger.io/v2/swagger.json")

    print(f"Title   : {spec.title}")
    print(f"Version : {spec.version}")
    print(f"Base URL: {spec.base_url}")
    print(f"Spec    : Swagger {spec.spec_version}")
    print(f"Endpoints: {spec.total_endpoints}")
    print()

    for ep in spec.endpoints[:10]:
        auth = f"  [auth: {', '.join(ep.auth_schemes)}]" if ep.auth_required else ""
        params = f"  params={[p.name for p in ep.parameters]}" if ep.parameters else ""
        print(f"  {ep.method:7s} {ep.path}{params}{auth}")

    if spec.total_endpoints > 10:
        print(f"  ... and {spec.total_endpoints - 10} more")

    print()
    crawl_out = parser.to_crawl_format(spec)
    print(f"Crawl format: {len(crawl_out['urls'])} unique URLs, {len(crawl_out['api_endpoints'])} endpoint entries")


if __name__ == "__main__":
    import asyncio

    asyncio.run(_main())
