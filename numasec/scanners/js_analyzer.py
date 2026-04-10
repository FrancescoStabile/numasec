"""Python-native JavaScript security analyzer.

Fetches JS bundles from a target URL and extracts security-relevant
information via regex analysis:

1. API endpoints — ``/api/...``, ``/rest/...``, fetch/XHR patterns
2. Hardcoded secrets — API keys, tokens, passwords, AWS credentials
3. Admin / sensitive routes — ``/admin``, ``/debug``, ``/metrics``
4. DOM XSS sinks — ``innerHTML``, ``document.write``, ``eval()``
5. Information disclosure — source maps, debug flags, version strings

Designed to run in the MAPPING phase after browser crawling has
discovered JS file URLs.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from numasec.core.http import create_client

logger = logging.getLogger("numasec.scanners.js_analyzer")

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# API endpoint patterns in JS source
_API_ENDPOINT_PATTERNS: list[re.Pattern[str]] = [
    # String literals: "/api/...", '/rest/...', "/v1/..."
    re.compile(r"""['"`](/(?:api|rest|v[0-9]+)/[a-zA-Z0-9/_\-]+)['"`]"""),
    # fetch/axios calls: fetch("/...", axios.get("/..."
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`](/[a-zA-Z0-9/_\-]+)['"`]"""),
    # Template literals: `${base}/api/...`
    re.compile(r"""\$\{[^}]*\}(/(?:api|rest)/[a-zA-Z0-9/_\-]+)"""),
    # XMLHttpRequest: .open("GET", "/api/..."
    re.compile(r"""\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"],\s*['"`](/[a-zA-Z0-9/_\-]+)['"`]"""),
    # SPA service calls without leading slash: "api/Users", "rest/products"
    re.compile(r"""['"`]((?:api|rest|admin|internal)/[a-zA-Z0-9/_\-]+)['"`]"""),
]

# Secret patterns — key + value in proximity
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"""(?:AKIA[0-9A-Z]{16})""")),
    ("aws_secret_key", re.compile(r"""(?:aws.{0,20}secret.{0,20}['"`]([A-Za-z0-9/+=]{40})['"`])""", re.IGNORECASE)),
    (
        "api_key",
        re.compile(
            r"""(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{16,})['"`]""",
            re.IGNORECASE,
        ),
    ),
    ("jwt_token", re.compile(r"""['"`](eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+)['"`]""")),
    (
        "password",
        re.compile(
            r"""(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`]{4,})['"`]""",
            re.IGNORECASE,
        ),
    ),
    ("private_key", re.compile(r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----""")),
    ("google_api_key", re.compile(r"""AIza[0-9A-Za-z_-]{35}""")),
    ("github_token", re.compile(r"""(?:ghp|gho|ghs|ghr)_[A-Za-z0-9_]{36,}""")),
    (
        "generic_secret",
        re.compile(
            r"""(?:secret|token|auth)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})['"`]""",
            re.IGNORECASE,
        ),
    ),
]

# Sensitive routes
_SENSITIVE_ROUTE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"""['"`](/(?:admin|administrator|dashboard|debug|_debug|metrics|prometheus|actuator|console|phpmyadmin|graphql|swagger|api-docs|internal|chat|chatbot|assistant|llm|ai|bot|copilot)[/'"` ]?)""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""['"`](/(?:\.env|\.git|\.svn|wp-admin|wp-login|server-status|phpinfo|elmah)\.?[a-z]*)['"`]""", re.IGNORECASE
    ),
    # SPA framework routes: path:"administration", path:'dashboard', path:'chatbot'
    re.compile(
        r"""path\s*:\s*['"](?P<route>(?:admin|administrator|dashboard|debug|_debug|metrics|console|graphql|swagger|internal|chat|chatbot|assistant|llm|ai|bot)[a-zA-Z0-9/_\-]*)['"]""",
        re.IGNORECASE,
    ),
]

# DOM XSS sinks
_DOM_XSS_SINKS: list[tuple[str, re.Pattern[str]]] = [
    ("innerHTML", re.compile(r"""\.innerHTML\s*=""")),
    ("outerHTML", re.compile(r"""\.outerHTML\s*=""")),
    ("document.write", re.compile(r"""document\.(?:write|writeln)\s*\(""")),
    ("eval", re.compile(r"""(?<!\w)eval\s*\(""")),
    ("setTimeout_string", re.compile(r"""setTimeout\s*\(\s*['"`]""")),
    ("setInterval_string", re.compile(r"""setInterval\s*\(\s*['"`]""")),
    ("location_assign", re.compile(r"""(?:location|window\.location)\s*(?:\.href\s*)?=""")),
    ("jquery_html", re.compile(r"""\.\$?\s*(?:html|append|prepend|after|before)\s*\(""")),
]

# Source map reference
_SOURCE_MAP_PATTERN = re.compile(r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+)""")

# Debug flags
_DEBUG_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""(?:debug|DEBUG)\s*[:=]\s*(?:true|1|['"`]true['"`])"""),
    re.compile(r"""(?:devMode|DEV_MODE|development)\s*[:=]\s*(?:true|1)"""),
    re.compile(r"""console\.\s*(?:log|debug|info|warn)\s*\("""),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class JSFinding:
    """A single security-relevant finding from JS analysis."""

    finding_type: str  # endpoint, secret, sensitive_route, dom_xss_sink, source_map, debug_flag
    value: str
    source_file: str
    severity: str = "info"  # info, low, medium, high, critical
    context: str = ""  # Surrounding code snippet

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.finding_type,
            "value": self.value,
            "source_file": self.source_file,
            "severity": self.severity,
            "context": self.context,
        }


@dataclass
class JSAnalysisResult:
    """Result from JavaScript security analysis."""

    target: str
    js_files_analyzed: int = 0
    endpoints: list[str] = field(default_factory=list)
    secrets: list[JSFinding] = field(default_factory=list)
    sensitive_routes: list[str] = field(default_factory=list)
    dom_xss_sinks: list[JSFinding] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    debug_flags: int = 0
    findings: list[JSFinding] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "js_files_analyzed": self.js_files_analyzed,
            "endpoints": sorted(set(self.endpoints)),
            "secrets_count": len(self.secrets),
            "secrets": [s.to_dict() for s in self.secrets],
            "sensitive_routes": sorted(set(self.sensitive_routes)),
            "dom_xss_sinks": [s.to_dict() for s in self.dom_xss_sinks],
            "source_maps": sorted(set(self.source_maps)),
            "debug_flags": self.debug_flags,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "duration_ms": round(self.duration_ms, 2),
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class JSAnalyzer:
    """Fetches and analyzes JS files for security-relevant patterns."""

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout

    async def analyze(
        self,
        url: str,
        js_urls: list[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> JSAnalysisResult:
        """Run JS security analysis.

        Args:
            url: Target page URL (used to discover JS files if js_urls is empty).
            js_urls: Explicit list of JS file URLs to analyze.
            headers: Optional headers for HTTP requests.

        Returns:
            ``JSAnalysisResult`` with all discovered findings.
        """
        start = time.monotonic()
        result = JSAnalysisResult(target=url)

        async with create_client(
            timeout=self.timeout,
            headers=headers or {},
        ) as client:
            # Step 1: Discover JS files if not provided
            if not js_urls:
                js_urls = await self._discover_js_files(client, url)

            # Step 2: Fetch and analyze each JS file
            for js_url in js_urls[:20]:  # Cap at 20 files to avoid excess
                content = await self._fetch_js(client, js_url)
                if content:
                    result.js_files_analyzed += 1
                    self._analyze_content(content, js_url, result)

        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    async def _discover_js_files(self, client: httpx.AsyncClient, url: str) -> list[str]:
        """Fetch the HTML page and extract <script src="..."> URLs."""
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
        except httpx.HTTPError:
            logger.warning("Failed to fetch page for JS discovery: %s", url)
            return []

        html = resp.text
        js_urls: list[str] = []

        # Match <script src="...">
        for match in re.finditer(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", html, re.IGNORECASE):
            src = match.group(1)
            if src.endswith(".js") or ".js?" in src or "/js/" in src:
                full_url = urljoin(url, src)
                js_urls.append(full_url)

        # Also grab inline scripts that might reference JS files
        for match in re.finditer(r"""(?:src|import)\s*[:=]\s*['"]([^'"]+\.js(?:\?[^'"]*)?)['"  ]""", html):
            full_url = urljoin(url, match.group(1))
            if full_url not in js_urls:
                js_urls.append(full_url)

        logger.info("Discovered %d JS files from %s", len(js_urls), url)
        return js_urls

    async def _fetch_js(self, client: httpx.AsyncClient, js_url: str) -> str | None:
        """Download a single JS file, capped at 2 MB."""
        try:
            resp = await client.get(js_url)
            if resp.status_code != 200:
                return None
            # Cap content size to avoid memory issues
            text = resp.text
            if len(text) > 2_000_000:
                text = text[:2_000_000]
            return text
        except httpx.HTTPError:
            logger.warning("Failed to fetch JS file: %s", js_url)
            return None

    def _analyze_content(self, content: str, source_file: str, result: JSAnalysisResult) -> None:
        """Run all regex analyses on a single JS file's content."""
        short_name = urlparse(source_file).path.split("/")[-1] or source_file

        self._extract_endpoints(content, short_name, result)
        self._extract_secrets(content, short_name, result)
        self._extract_sensitive_routes(content, short_name, result)
        self._extract_dom_xss_sinks(content, short_name, result)
        self._extract_source_maps(content, short_name, result)
        self._count_debug_flags(content, result)

    def _extract_endpoints(self, content: str, source_file: str, result: JSAnalysisResult) -> None:
        """Extract API endpoint paths from JS source."""
        seen: set[str] = set()
        for pattern in _API_ENDPOINT_PATTERNS:
            for match in pattern.finditer(content):
                endpoint = match.group(1)
                if endpoint not in seen and len(endpoint) > 3:
                    seen.add(endpoint)
                    result.endpoints.append(endpoint)
                    finding = JSFinding(
                        finding_type="endpoint",
                        value=endpoint,
                        source_file=source_file,
                        severity="info",
                    )
                    result.findings.append(finding)

    def _extract_secrets(self, content: str, source_file: str, result: JSAnalysisResult) -> None:
        """Extract hardcoded secrets, API keys, tokens."""
        for secret_type, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                # Skip very short or clearly placeholder values
                if len(value) < 8 or value in ("undefined", "null", "true", "false", "password"):
                    continue
                # Get surrounding context (40 chars each side)
                start = max(0, match.start() - 40)
                end = min(len(content), match.end() + 40)
                context = content[start:end].replace("\n", " ").strip()

                severity = "high"
                if secret_type in ("aws_access_key", "aws_secret_key", "private_key"):
                    severity = "critical"
                elif secret_type in ("generic_secret", "debug_flag"):
                    severity = "medium"

                finding = JSFinding(
                    finding_type="secret",
                    value=f"{secret_type}: {value[:60]}{'...' if len(value) > 60 else ''}",
                    source_file=source_file,
                    severity=severity,
                    context=context[:120],
                )
                result.secrets.append(finding)
                result.findings.append(finding)

    def _extract_sensitive_routes(self, content: str, source_file: str, result: JSAnalysisResult) -> None:
        """Extract admin/debug/sensitive route paths."""
        seen: set[str] = set()
        for pattern in _SENSITIVE_ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                route = match.group(1).rstrip("'\"` ")
                if route not in seen:
                    seen.add(route)
                    result.sensitive_routes.append(route)
                    finding = JSFinding(
                        finding_type="sensitive_route",
                        value=route,
                        source_file=source_file,
                        severity="medium" if "admin" in route.lower() else "low",
                    )
                    result.findings.append(finding)

    def _extract_dom_xss_sinks(self, content: str, source_file: str, result: JSAnalysisResult) -> None:
        """Extract DOM XSS sinks from JS source."""
        for sink_type, pattern in _DOM_XSS_SINKS:
            matches = list(pattern.finditer(content))
            if matches:
                # Report once per sink type per file, with count
                start = max(0, matches[0].start() - 30)
                end = min(len(content), matches[0].end() + 30)
                context = content[start:end].replace("\n", " ").strip()

                finding = JSFinding(
                    finding_type="dom_xss_sink",
                    value=f"{sink_type} ({len(matches)} occurrence{'s' if len(matches) > 1 else ''})",
                    source_file=source_file,
                    severity="medium",
                    context=context[:120],
                )
                result.dom_xss_sinks.append(finding)
                result.findings.append(finding)

    def _extract_source_maps(self, content: str, source_file: str, result: JSAnalysisResult) -> None:
        """Detect source map references."""
        for match in _SOURCE_MAP_PATTERN.finditer(content):
            map_url = match.group(1)
            result.source_maps.append(map_url)
            finding = JSFinding(
                finding_type="source_map",
                value=map_url,
                source_file=source_file,
                severity="low",
                context="Source map exposes original source code structure",
            )
            result.findings.append(finding)

    def _count_debug_flags(self, content: str, result: JSAnalysisResult) -> None:
        """Count debug/dev-mode flags."""
        for pattern in _DEBUG_PATTERNS:
            result.debug_flags += len(pattern.findall(content))


# ---------------------------------------------------------------------------
# Tool wrapper
# ---------------------------------------------------------------------------


async def python_js_analyze(
    url: str,
    js_files: str | None = None,
    headers: str | None = None,
) -> str:
    """Analyze JavaScript files from a target URL for security issues.

    Discovers JS bundles via ``<script>`` tags, then extracts API endpoints,
    hardcoded secrets, admin routes, and DOM XSS sinks via regex analysis.

    Args:
        url: Target page URL (will discover JS files automatically).
        js_files: Optional comma-separated list of JS file URLs to analyze directly.
        headers: Optional JSON string of HTTP headers.

    Returns:
        JSON string with analysis results.
    """
    parsed_headers: dict[str, str] | None = None
    if headers:
        with contextlib.suppress(json.JSONDecodeError):
            parsed_headers = headers if isinstance(headers, dict) else json.loads(headers)

    js_url_list: list[str] | None = None
    if js_files:
        js_url_list = [f.strip() for f in js_files.split(",") if f.strip()]

    analyzer = JSAnalyzer()
    result = await analyzer.analyze(url, js_urls=js_url_list, headers=parsed_headers)
    return json.dumps(result.to_dict(), indent=2)
