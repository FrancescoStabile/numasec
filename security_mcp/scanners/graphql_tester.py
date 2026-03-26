"""Python-native GraphQL security tester.

Detects common GraphQL security issues:
1. Introspection enabled (schema disclosure)
2. Field suggestion enumeration (type/field names leak via error messages)
3. Query depth abuse (no depth limiting)
4. Batch query attacks (multiple operations in one request)
5. Mutation authorization bypass (CWE-862)
6. Field-level authorization bypass on sensitive fields (CWE-200)
7. Alias-based resource exhaustion (no alias limit)
8. Persisted query (APQ) enforcement bypass
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger("security_mcp.scanners.graphql_tester")

_INTROSPECTION_QUERY = """{
  __schema {
    types {
      name
      kind
      fields { name }
    }
    queryType { name }
    mutationType { name }
  }
}"""

_DEPTH_QUERY_TEMPLATE = """{{
  {nested}
}}"""

# Common GraphQL endpoint paths to probe
_GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/v1",
    "/api/graphql",
    "/gql",
    "/query",
    "/v1/graphql",
]

# Probe queries for field suggestion enumeration
_SUGGESTION_PROBES = [
    "{ user { id } }",
    "{ users { id email } }",
    "{ me { id } }",
    "{ admin { id } }",
    "{ orders { id } }",
]

# Mutation probes for authorization testing (check 5)
_MUTATION_PROBES: list[tuple[str, str]] = [
    (
        'mutation { createUser(input: {name: "test", email: "test@test.com"}) { id } }',
        "createUser",
    ),
    (
        'mutation { updateUser(id: "1", input: {role: "admin"}) { id role } }',
        "updateUser",
    ),
    (
        'mutation { deleteUser(id: "1") { id } }',
        "deleteUser",
    ),
    (
        "mutation { updateSettings(input: {debug: true}) { debug } }",
        "updateSettings",
    ),
]

# Sensitive field names to look for in introspection results (check 6)
_SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "secret",
        "token",
        "ssn",
        "credit_card",
        "creditCard",
        "api_key",
        "apiKey",
        "private",
        "hash",
        "salt",
        "otp",
        "mfa",
    }
)

# Number of aliases for the resource exhaustion check (check 7)
_ALIAS_COUNT: int = 100


@dataclass
class GraphQLVulnerability:
    """A single GraphQL finding."""

    vuln_type: str
    severity: str
    evidence: str
    endpoint: str = ""


@dataclass
class GraphQLResult:
    """Complete GraphQL test result."""

    target: str
    endpoint_found: bool = False
    endpoint: str = ""
    vulnerable: bool = False
    vulnerabilities: list[GraphQLVulnerability] = field(default_factory=list)
    schema_types: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "endpoint_found": self.endpoint_found,
            "endpoint": self.endpoint,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "evidence": v.evidence,
                    "endpoint": v.endpoint,
                }
                for v in self.vulnerabilities
            ],
            "schema_types": self.schema_types,
            "duration_ms": round(self.duration_ms, 2),
        }


class GraphQLTester:
    """Multi-check GraphQL security tester."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def test(self, url: str, parsed_headers: dict[str, str] | None = None) -> GraphQLResult:
        """Run GraphQL security tests against a target.

        If the URL doesn't end with a known GraphQL path, probes
        common paths to discover the endpoint first.

        Args:
            url: Target URL (base URL or specific GraphQL endpoint).
            parsed_headers: Optional dict of HTTP headers to include in
                            requests (e.g. authorization tokens).

        Returns:
            ``GraphQLResult`` with discovered vulnerabilities.
        """
        start = time.monotonic()
        result = GraphQLResult(target=url)
        hdrs = {**(parsed_headers or {}), "Content-Type": "application/json"}

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            # Step 1: Discover GraphQL endpoint
            endpoint = await self._discover_endpoint(client, url)
            if not endpoint:
                result.duration_ms = (time.monotonic() - start) * 1000
                return result

            result.endpoint_found = True
            result.endpoint = endpoint

            # Step 2: Test introspection (also captures schema types for later checks)
            introspection_types = await self._test_introspection(client, endpoint, result)

            # Step 3: Test field suggestion enumeration
            await self._test_field_suggestions(client, endpoint, result)

            # Step 4: Test query depth limiting
            await self._test_depth_limit(client, endpoint, result)

            # Step 5: Test batch queries
            await self._test_batch_queries(client, endpoint, result)

            # Step 6: Test mutation authorization bypass
            mutation_vulns = await self._check_mutation_auth(endpoint, hdrs, client)
            for mv in mutation_vulns:
                result.vulnerabilities.append(mv)
                result.vulnerable = True

            # Step 7: Test field-level authorization bypass (needs introspection data)
            if introspection_types:
                field_vulns = await self._check_field_auth(endpoint, hdrs, introspection_types, client)
                for fv in field_vulns:
                    result.vulnerabilities.append(fv)
                    result.vulnerable = True

            # Step 8: Test alias-based resource exhaustion
            alias_vulns = await self._check_alias_dos(endpoint, hdrs, client)
            for av in alias_vulns:
                result.vulnerabilities.append(av)
                result.vulnerable = True

            # Step 9: Test persisted query bypass
            pq_vulns = await self._check_persisted_query_bypass(endpoint, hdrs, client)
            for pv in pq_vulns:
                result.vulnerabilities.append(pv)
                result.vulnerable = True

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "GraphQL test complete: %s — endpoint=%s, %d vulns, %.0fms",
            url,
            endpoint or "none",
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    async def _discover_endpoint(self, client: httpx.AsyncClient, url: str) -> str | None:
        """Discover the GraphQL endpoint by probing common paths."""
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(url)

        # Check if the URL itself is a GraphQL endpoint
        paths_to_try = [parsed.path] if parsed.path.rstrip("/") in _GRAPHQL_PATHS else []
        # Add common paths
        paths_to_try.extend(_GRAPHQL_PATHS)

        seen: set[str] = set()
        for path in paths_to_try:
            test_url = urlunparse(parsed._replace(path=path, query=""))
            if test_url in seen:
                continue
            seen.add(test_url)

            try:
                # GraphQL endpoints respond to POST with JSON
                resp = await client.post(
                    test_url,
                    json={"query": "{ __typename }"},
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    body = resp.text
                    if "__typename" in body or '"data"' in body or '"errors"' in body:
                        logger.info("GraphQL endpoint found: %s", test_url)
                        return test_url
            except httpx.HTTPError:
                continue

        return None

    async def _test_introspection(
        self, client: httpx.AsyncClient, endpoint: str, result: GraphQLResult
    ) -> list[dict[str, Any]]:
        """Test if introspection is enabled (schema disclosure).

        Returns:
            List of user-defined type dicts from the schema (empty list if
            introspection is disabled or the request fails).  This list is
            consumed by downstream checks such as field-level auth testing.
        """
        try:
            resp = await client.post(
                endpoint,
                json={"query": _INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError:
            return []

        if resp.status_code != 200:
            return []

        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            return []

        schema = data.get("data", {}).get("__schema")
        if not schema:
            return []

        types = schema.get("types", [])
        result.schema_types = len(types)

        # Filter to user-defined types (exclude __ prefixed internal types)
        user_types = [t for t in types if not t.get("name", "").startswith("__")]
        type_names = [t.get("name", "") for t in user_types[:20]]

        result.vulnerabilities.append(
            GraphQLVulnerability(
                vuln_type="introspection_enabled",
                severity="medium",
                evidence=(
                    f"Full schema introspection enabled. {len(types)} types exposed "
                    f"(user-defined: {len(user_types)}). Types include: {', '.join(type_names[:10])}."
                ),
                endpoint=endpoint,
            )
        )
        result.vulnerable = True
        return user_types

    async def _test_field_suggestions(self, client: httpx.AsyncClient, endpoint: str, result: GraphQLResult) -> None:
        """Test if error messages leak field/type names via suggestions."""
        suggested_fields: list[str] = []

        for probe in _SUGGESTION_PROBES:
            try:
                resp = await client.post(
                    endpoint,
                    json={"query": probe},
                    headers={"Content-Type": "application/json"},
                )
            except httpx.HTTPError:
                continue

            if resp.status_code != 200:
                continue

            text = resp.text.lower()
            if "did you mean" in text or "suggest" in text:
                suggested_fields.append(probe.split("{")[1].split("}")[0].strip().split()[0])

        if suggested_fields:
            result.vulnerabilities.append(
                GraphQLVulnerability(
                    vuln_type="field_suggestion_leak",
                    severity="low",
                    evidence=(
                        f"GraphQL error messages contain field suggestions, "
                        f"enabling schema enumeration. Probed fields: {', '.join(suggested_fields)}."
                    ),
                    endpoint=endpoint,
                )
            )
            result.vulnerable = True

    async def _test_depth_limit(self, client: httpx.AsyncClient, endpoint: str, result: GraphQLResult) -> None:
        """Test if deeply nested queries are accepted (no depth limiting)."""
        # Build a deeply nested query (10 levels)
        inner = "id"
        for _ in range(10):
            inner = f"... on Query {{ __typename {inner} }}"
        deep_query = f"{{ __typename {inner} }}"

        try:
            resp = await client.post(
                endpoint,
                json={"query": deep_query},
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError:
            return

        if resp.status_code == 200:
            text = resp.text
            # If the server processes it without a depth error, it's vulnerable
            if '"errors"' not in text or "depth" not in text.lower():
                result.vulnerabilities.append(
                    GraphQLVulnerability(
                        vuln_type="no_depth_limit",
                        severity="medium",
                        evidence=(
                            "Server accepted a deeply nested query (10 levels) "
                            "without rejecting it for excessive depth. "
                            "Enables denial-of-service via recursive queries."
                        ),
                        endpoint=endpoint,
                    )
                )
                result.vulnerable = True

    async def _test_batch_queries(self, client: httpx.AsyncClient, endpoint: str, result: GraphQLResult) -> None:
        """Test if batch queries (array of operations) are accepted."""
        batch = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]

        try:
            resp = await client.post(
                endpoint,
                json=batch,
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError:
            return

        if resp.status_code == 200:
            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                return

            if isinstance(data, list) and len(data) >= 3:
                result.vulnerabilities.append(
                    GraphQLVulnerability(
                        vuln_type="batch_queries_enabled",
                        severity="low",
                        evidence=(
                            f"Server accepts batch queries ({len(data)} responses returned). "
                            "Enables brute-force attacks and resource exhaustion "
                            "by sending many operations in a single request."
                        ),
                        endpoint=endpoint,
                    )
                )
                result.vulnerable = True

    # ------------------------------------------------------------------
    # Check 5: Mutation authorization testing (CWE-862)
    # ------------------------------------------------------------------

    async def _check_mutation_auth(
        self,
        endpoint: str,
        parsed_headers: dict[str, str],
        client: httpx.AsyncClient,
    ) -> list[GraphQLVulnerability]:
        """Test if mutations are accessible without authentication.

        Sends common mutation operations WITHOUT auth headers to see if the
        server allows them.  If the caller provided auth headers, also tests
        admin-like mutations with those (low-privilege) headers to detect
        privilege escalation.

        Returns:
            List of ``GraphQLVulnerability`` for each accessible mutation.
        """
        findings: list[GraphQLVulnerability] = []

        # Headers stripped of any auth for the unauthenticated probe
        unauth_headers = {"Content-Type": "application/json"}

        for mutation_query, mutation_name in _MUTATION_PROBES:
            # --- Unauthenticated probe ---
            try:
                resp = await client.post(
                    endpoint,
                    json={"query": mutation_query},
                    headers=unauth_headers,
                )
            except httpx.HTTPError:
                continue

            if self._mutation_succeeded(resp):
                findings.append(
                    GraphQLVulnerability(
                        vuln_type="mutation_no_auth",
                        severity="high",
                        evidence=(
                            f"Mutation '{mutation_name}' accessible without authentication. "
                            f"Server returned {resp.status_code} with data payload. "
                            f"Missing authorization on state-changing operations (CWE-862)."
                        ),
                        endpoint=endpoint,
                    )
                )
                continue  # Already confirmed unauthed; skip priv-esc test for this mutation

            # --- Low-privilege escalation probe (only if auth was provided) ---
            has_auth = any(k.lower() in ("authorization", "cookie", "x-api-key") for k in parsed_headers)
            if not has_auth:
                continue

            try:
                resp = await client.post(
                    endpoint,
                    json={"query": mutation_query},
                    headers=parsed_headers,
                )
            except httpx.HTTPError:
                continue

            if self._mutation_succeeded(resp):
                findings.append(
                    GraphQLVulnerability(
                        vuln_type="mutation_priv_escalation",
                        severity="high",
                        evidence=(
                            f"Admin mutation '{mutation_name}' accessible with low-privilege token. "
                            f"Server returned {resp.status_code} with data payload. "
                            f"Broken access control on mutations (CWE-862)."
                        ),
                        endpoint=endpoint,
                    )
                )

        return findings

    @staticmethod
    def _mutation_succeeded(resp: httpx.Response) -> bool:
        """Return True if a GraphQL mutation response contains data (not just errors)."""
        if resp.status_code != 200:
            return False
        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            return False
        # A successful mutation has a "data" key with at least one non-null value
        data = body.get("data")
        if not isinstance(data, dict):
            return False
        return any(v is not None for v in data.values())

    # ------------------------------------------------------------------
    # Check 6: Field-level authorization bypass (CWE-200)
    # ------------------------------------------------------------------

    async def _check_field_auth(
        self,
        endpoint: str,
        parsed_headers: dict[str, str],
        types: list[dict[str, Any]],
        client: httpx.AsyncClient,
    ) -> list[GraphQLVulnerability]:
        """Test if sensitive fields are accessible on user-defined types.

        Uses introspection results to identify types with fields named like
        ``password``, ``secret``, ``token``, ``ssn``, etc., then queries
        those fields explicitly.

        Args:
            endpoint: GraphQL endpoint URL.
            parsed_headers: Headers to include in requests.
            types: User-defined types from introspection (list of dicts with
                   ``name`` and ``fields`` keys).
            client: Active httpx client.

        Returns:
            List of ``GraphQLVulnerability`` for each exposed sensitive field.
        """
        findings: list[GraphQLVulnerability] = []

        for gql_type in types:
            type_name = gql_type.get("name", "")
            fields = gql_type.get("fields") or []
            if not fields or not type_name:
                continue

            # Collect sensitive field names present on this type
            sensitive_hits = [
                f.get("name", "")
                for f in fields
                if f.get("name", "").lower() in _SENSITIVE_FIELD_NAMES
            ]
            if not sensitive_hits:
                continue

            # Build a query asking for id + the sensitive fields
            # Use a lowercase plural as the root field name (common convention)
            root_field = type_name[0].lower() + type_name[1:]
            all_field_names = ["id"] + sensitive_hits
            field_selection = " ".join(all_field_names)
            query = f"{{ {root_field} {{ {field_selection} }} }}"

            # Also try plural form
            plural_field = root_field + "s" if not root_field.endswith("s") else root_field
            query_plural = f"{{ {plural_field} {{ {field_selection} }} }}"

            for probe_query in (query, query_plural):
                try:
                    resp = await client.post(
                        endpoint,
                        json={"query": probe_query},
                        headers=parsed_headers,
                    )
                except httpx.HTTPError:
                    continue

                if resp.status_code != 200:
                    continue

                try:
                    body = resp.json()
                except (json.JSONDecodeError, ValueError):
                    continue

                data = body.get("data")
                if not isinstance(data, dict):
                    continue

                # Check if any of the sensitive fields actually returned data
                returned_sensitive = self._extract_sensitive_values(data, sensitive_hits)
                if returned_sensitive:
                    findings.append(
                        GraphQLVulnerability(
                            vuln_type="sensitive_field_exposed",
                            severity="high",
                            evidence=(
                                f"Sensitive fields accessible on type '{type_name}': "
                                f"{', '.join(returned_sensitive)}. "
                                f"Query '{probe_query[:80]}...' returned data for restricted fields. "
                                f"Information exposure through accessible sensitive fields (CWE-200)."
                            ),
                            endpoint=endpoint,
                        )
                    )
                    break  # One confirmation per type is sufficient

        return findings

    @staticmethod
    def _extract_sensitive_values(data: dict[str, Any], field_names: list[str]) -> list[str]:
        """Walk a GraphQL data dict and return names of sensitive fields that have non-null values."""
        found: list[str] = []

        def _walk(obj: Any) -> None:
            if isinstance(obj, dict):
                for key, val in obj.items():
                    if key in field_names and val is not None and key not in found:
                        found.append(key)
                    _walk(val)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item)

        _walk(data)
        return found

    # ------------------------------------------------------------------
    # Check 7: Alias-based resource exhaustion
    # ------------------------------------------------------------------

    async def _check_alias_dos(
        self,
        endpoint: str,
        parsed_headers: dict[str, str],
        client: httpx.AsyncClient,
    ) -> list[GraphQLVulnerability]:
        """Test if the server limits the number of aliases in a single query.

        Sends a query with ``_ALIAS_COUNT`` aliased copies of ``__typename``
        and measures the response.

        Returns:
            List with zero or one ``GraphQLVulnerability``.
        """
        aliases = " ".join(f"a{i}: __typename" for i in range(_ALIAS_COUNT))
        query = f"{{ {aliases} }}"

        try:
            start = time.monotonic()
            resp = await client.post(
                endpoint,
                json={"query": query},
                headers=parsed_headers,
            )
            elapsed = time.monotonic() - start
        except httpx.HTTPError:
            return []

        if resp.status_code != 200:
            return []

        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            return []

        data = body.get("data")
        if not isinstance(data, dict):
            return []

        # Server processed all aliases -- no limit enforced
        if elapsed > 5.0:
            # Server struggled but still responded -- higher severity
            return [
                GraphQLVulnerability(
                    vuln_type="no_alias_limit",
                    severity="high",
                    evidence=(
                        f"Server processed {_ALIAS_COUNT} aliased queries in {elapsed:.1f}s "
                        f"(above 5s threshold). No alias limit enforced. "
                        f"The slow response indicates resource strain — "
                        f"alias-based denial-of-service is feasible."
                    ),
                    endpoint=endpoint,
                )
            ]

        return [
            GraphQLVulnerability(
                vuln_type="no_alias_limit",
                severity="medium",
                evidence=(
                    f"Server processed {_ALIAS_COUNT} aliased queries in {elapsed:.1f}s. "
                    f"No alias limit enforced — resource exhaustion possible "
                    f"with higher alias counts or heavier field selections."
                ),
                endpoint=endpoint,
            )
        ]

    # ------------------------------------------------------------------
    # Check 8: Persisted query (APQ) bypass
    # ------------------------------------------------------------------

    async def _check_persisted_query_bypass(
        self,
        endpoint: str,
        parsed_headers: dict[str, str],
        client: httpx.AsyncClient,
    ) -> list[GraphQLVulnerability]:
        """Test if Automatic Persisted Query (APQ) enforcement can be bypassed.

        1. Probe whether the server supports APQ by sending a hash-only request.
        2. If APQ is supported, try sending a full query alongside an invalid
           hash.  If the server executes the full query, APQ enforcement is
           bypassable.

        Returns:
            List with zero or one ``GraphQLVulnerability``.
        """
        # Step 1: Probe for APQ support
        apq_probe = {
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38",
                }
            }
        }
        try:
            resp = await client.post(endpoint, json=apq_probe, headers=parsed_headers)
        except httpx.HTTPError:
            return []

        if resp.status_code != 200:
            return []

        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            return []

        # Check for PersistedQueryNotFound error — indicates APQ is active
        errors = body.get("errors", [])
        is_apq = any("PersistedQueryNotFound" in str(e) for e in errors)
        if not is_apq:
            return []

        logger.info("APQ support detected at %s — testing bypass", endpoint)

        # Step 2: Try bypass — send full query + wrong hash
        bypass_payload = {
            "query": "{ __typename }",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "0000000000000000000000000000000000000000000000000000000000000000",
                }
            },
        }
        try:
            resp = await client.post(endpoint, json=bypass_payload, headers=parsed_headers)
        except httpx.HTTPError:
            return []

        if resp.status_code != 200:
            return []

        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            return []

        data = body.get("data")
        if isinstance(data, dict) and data.get("__typename") is not None:
            return [
                GraphQLVulnerability(
                    vuln_type="persisted_query_bypass",
                    severity="medium",
                    evidence=(
                        "Automatic Persisted Query (APQ) enforcement is bypassable. "
                        "Server executed a full query sent alongside an invalid persisted "
                        "query hash. Attackers can send arbitrary queries even when APQ "
                        "allowlisting is configured."
                    ),
                    endpoint=endpoint,
                )
            ]

        return []


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_graphql_test(url: str, headers: str = "") -> str:
    """Test a target for GraphQL security vulnerabilities.

    Probes common GraphQL endpoint paths (``/graphql``, ``/gql``, etc.),
    then checks for introspection disclosure, field suggestion leaks,
    missing depth limits, batch query support, mutation auth bypass,
    field-level auth bypass, alias-based DoS, and persisted query bypass.

    Args:
        url: Target base URL or specific GraphQL endpoint.
        headers: Optional comma-separated ``key:value`` headers to include
                 in requests (e.g. ``"Authorization:Bearer xyz"``).

    Returns:
        JSON string with ``GraphQLResult`` data.
    """
    parsed_headers: dict[str, str] = {}
    if headers:
        for pair in headers.split(","):
            pair = pair.strip()
            if ":" in pair:
                k, v = pair.split(":", 1)
                parsed_headers[k.strip()] = v.strip()

    tester = GraphQLTester()
    result = await tester.test(url, parsed_headers=parsed_headers)
    return json.dumps(result.to_dict(), indent=2)
