"""Python-native CRLF injection tester.

Detects HTTP response splitting and header injection via CRLF sequences:

1. Header injection: injected header appears in response
2. Response splitting: injected body content via double CRLF
3. Log injection: CRLF in parameters causes behavioral change
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from numasec.core.http import create_client

logger = logging.getLogger("numasec.scanners.crlf_tester")

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

CRLF_PAYLOADS: list[tuple[str, str]] = [
    # (payload, category)
    # URL-encoded CRLF + custom header
    ("%0d%0aX-CRLF-Test:%20numasec", "header_injection"),
    ("%0d%0aX-CRLF-Test: numasec", "header_injection"),
    # Double URL-encoded
    ("%250d%250aX-CRLF-Test:%20numasec", "header_injection"),
    # Response splitting
    ("%0d%0a%0d%0a<html>numasec-crlf</html>", "response_splitting"),
    # Unicode variants
    ("%E5%98%8A%E5%98%8DX-CRLF-Test:%20numasec", "header_injection"),
    # Raw CRLF (for POST bodies)
    ("\r\nX-CRLF-Test: numasec", "header_injection"),
    # Header injection via newline only
    ("%0aX-CRLF-Test:%20numasec", "header_injection"),
]

# Headers to inject payloads into (besides query parameters)
_INJECTABLE_HEADERS = ["Referer", "User-Agent"]

# Marker we look for in response headers
_HEADER_MARKER = "numasec"
_HEADER_NAME = "x-crlf-test"

# Marker we look for in response body (response splitting)
_BODY_MARKER = "numasec-crlf"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CrlfVulnerability:
    """A single CRLF injection finding."""

    parameter: str
    payload: str
    evidence: str
    severity: str
    confidence: float
    injection_type: str  # header_injection | response_splitting | log_injection


@dataclass
class CrlfResult:
    """Complete CRLF test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[CrlfVulnerability] = field(default_factory=list)
    params_tested: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "type": "crlf_injection",
                    "parameter": v.parameter,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "injection_type": v.injection_type,
                }
                for v in self.vulnerabilities
            ],
            "params_tested": self.params_tested,
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"CRLF injection confirmed ({len(self.vulnerabilities)} finding(s): "
                + ", ".join(v.injection_type for v in self.vulnerabilities)
                + ")"
                if self.vulnerabilities
                else "No CRLF injection found"
            ),
            "next_steps": (
                [
                    "Verify header injection can be escalated to cache poisoning or XSS",
                    "Test if response splitting allows HTTP response smuggling",
                    "Check if Set-Cookie or Location headers can be injected",
                ]
                if self.vulnerabilities
                else []
            ),
        }


# ---------------------------------------------------------------------------
# CRLF detection engine
# ---------------------------------------------------------------------------


class CrlfTester:
    """Multi-technique CRLF injection tester.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    extra_headers:
        Additional headers for authenticated testing.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self._extra_headers = extra_headers or {}

    async def test(
        self,
        url: str,
        params: list[str] | None = None,
        method: str = "GET",
        body: dict[str, str] | None = None,
    ) -> CrlfResult:
        """Run CRLF injection tests against a target URL.

        Args:
            url: Target URL (with or without query parameters).
            params: Specific parameter names to test. ``None`` auto-detects.
            method: HTTP method (``GET`` or ``POST``).
            body: POST body parameters.

        Returns:
            ``CrlfResult`` with all discovered vulnerabilities.
        """
        start = time.monotonic()
        result = CrlfResult(target=url)

        test_params = self._detect_params(url, params, body)
        result.params_tested = len(test_params)

        async with create_client(
            timeout=self.timeout,
            headers=self._extra_headers or None,
        ) as client:
            # Fetch baseline response for log injection comparison
            baseline = await self._get_baseline(client, url, method, body)

            # Test each detected parameter
            for param_name, location in test_params:
                vulns = await self._test_param(
                    client,
                    url,
                    param_name,
                    location,
                    method,
                    body,
                    baseline,
                )
                for vuln in vulns:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True

            # Test header injection points (Referer, User-Agent)
            header_vulns = await self._test_headers(client, url, method, body, baseline)
            for vuln in header_vulns:
                result.vulnerabilities.append(vuln)
                result.vulnerable = True

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "CRLF test complete: %s — %d params, %d vulns, %.0fms",
            url,
            result.params_tested,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

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
    # Baseline fetch
    # ------------------------------------------------------------------

    async def _get_baseline(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        body: dict[str, str] | None,
    ) -> tuple[int, int]:
        """Fetch a baseline response and return (status_code, content_length)."""
        try:
            if method.upper() == "POST" and body:
                resp = await client.post(url, data=body)
            else:
                resp = await client.get(url)
            return (resp.status_code, len(resp.text))
        except httpx.HTTPError as exc:
            logger.debug("CRLF baseline error: %s", exc)
            return (0, 0)

    # ------------------------------------------------------------------
    # HTTP helpers
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
            logger.debug("CRLF HTTP error (param=%s): %s", param, exc)
            return None

    async def _send_with_header_payload(
        self,
        client: httpx.AsyncClient,
        url: str,
        header_name: str,
        payload: str,
        method: str,
        body: dict[str, str] | None,
    ) -> httpx.Response | None:
        """Inject payload into a request header and send."""
        try:
            headers = {header_name: payload}
            if method.upper() == "POST" and body:
                return await client.post(url, data=body, headers=headers)
            else:
                return await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            logger.debug("CRLF header HTTP error (%s): %s", header_name, exc)
            return None

    # ------------------------------------------------------------------
    # Detection: check response for CRLF indicators
    # ------------------------------------------------------------------

    @staticmethod
    def _check_header_injection(resp: httpx.Response) -> bool:
        """Check if the injected header appears in response headers."""
        for name in resp.headers:
            if name.lower() == _HEADER_NAME and _HEADER_MARKER in resp.headers[name].lower():
                return True
        return False

    @staticmethod
    def _check_response_splitting(resp: httpx.Response) -> bool:
        """Check if injected body marker appears in response text."""
        return _BODY_MARKER in resp.text

    @staticmethod
    def _check_log_injection(
        resp: httpx.Response,
        baseline: tuple[int, int],
    ) -> bool:
        """Check for behavioral differences indicating log injection."""
        baseline_status, baseline_length = baseline
        if baseline_status == 0:
            return False
        # Status code changed
        if resp.status_code != baseline_status:
            return True
        # Significant content-length difference (>30%)
        resp_length = len(resp.text)
        if baseline_length > 0:
            diff_ratio = abs(resp_length - baseline_length) / baseline_length
            if diff_ratio > 0.3:
                return True
        return False

    # ------------------------------------------------------------------
    # Per-parameter testing
    # ------------------------------------------------------------------

    async def _test_param(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
        baseline: tuple[int, int],
    ) -> list[CrlfVulnerability]:
        """Test one parameter for CRLF injection using all payload categories."""
        vulns: list[CrlfVulnerability] = []
        found_types: set[str] = set()

        for payload, category in CRLF_PAYLOADS:
            # Skip if we already confirmed this injection type for this param
            if category in found_types:
                continue

            resp = await self._send_with_payload(
                client,
                url,
                param,
                payload,
                location,
                method,
                body,
            )
            if resp is None:
                continue

            # Check for header injection
            if category == "header_injection" and self._check_header_injection(resp):
                vulns.append(
                    CrlfVulnerability(
                        parameter=param,
                        payload=payload,
                        evidence=(
                            f"Injected header 'X-CRLF-Test: {_HEADER_MARKER}' "
                            f"appeared in response headers via parameter '{param}'"
                        ),
                        severity="high",
                        confidence=1.0,
                        injection_type="header_injection",
                    )
                )
                found_types.add("header_injection")
                logger.info("CRLF header injection confirmed: param=%s", param)
                continue

            # Check for response splitting
            if category == "response_splitting" and self._check_response_splitting(resp):
                vulns.append(
                    CrlfVulnerability(
                        parameter=param,
                        payload=payload,
                        evidence=(
                            f"Response splitting marker '{_BODY_MARKER}' found in "
                            f"response body via parameter '{param}'. "
                            f"Injected content rendered after double CRLF."
                        ),
                        severity="critical",
                        confidence=0.9,
                        injection_type="response_splitting",
                    )
                )
                found_types.add("response_splitting")
                logger.info("CRLF response splitting confirmed: param=%s", param)
                continue

            # Check for log injection (behavioral difference)
            if "log_injection" not in found_types and self._check_log_injection(resp, baseline):
                vulns.append(
                    CrlfVulnerability(
                        parameter=param,
                        payload=payload,
                        evidence=(
                            f"Behavioral change detected via parameter '{param}': "
                            f"baseline status={baseline[0]}, response status={resp.status_code}; "
                            f"baseline length={baseline[1]}, response length={len(resp.text)}. "
                            f"Possible log injection or header manipulation."
                        ),
                        severity="medium",
                        confidence=0.5,
                        injection_type="log_injection",
                    )
                )
                found_types.add("log_injection")
                logger.info("CRLF log injection suspected: param=%s", param)

        return vulns

    # ------------------------------------------------------------------
    # Header injection testing (Referer, User-Agent)
    # ------------------------------------------------------------------

    async def _test_headers(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        body: dict[str, str] | None,
        baseline: tuple[int, int],
    ) -> list[CrlfVulnerability]:
        """Test CRLF injection via request headers (Referer, User-Agent)."""
        vulns: list[CrlfVulnerability] = []

        for header_name in _INJECTABLE_HEADERS:
            for payload, category in CRLF_PAYLOADS:
                if category != "header_injection":
                    continue

                resp = await self._send_with_header_payload(
                    client,
                    url,
                    header_name,
                    f"https://example.com/{payload}",
                    method,
                    body,
                )
                if resp is None:
                    continue

                if self._check_header_injection(resp):
                    vulns.append(
                        CrlfVulnerability(
                            parameter=f"header:{header_name}",
                            payload=payload,
                            evidence=(
                                f"Injected header 'X-CRLF-Test: {_HEADER_MARKER}' "
                                f"appeared in response via {header_name} header"
                            ),
                            severity="high",
                            confidence=1.0,
                            injection_type="header_injection",
                        )
                    )
                    logger.info(
                        "CRLF header injection via %s confirmed",
                        header_name,
                    )
                    break  # One finding per header is enough

        return vulns


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_crlf_test(
    url: str,
    params: str | None = None,
    method: str = "GET",
    body: str | None = None,
    headers: str = "",
) -> str:
    """Test URL parameters for CRLF injection (header injection / response splitting).

    Args:
        url: Target URL with query parameters to test.
        params: Comma-separated parameter names. Auto-detect if omitted.
        method: HTTP method (``GET`` or ``POST``).
        body: Request body (for POST). JSON string.
        headers: JSON string of extra HTTP headers for authenticated testing,
            e.g. ``'{"Authorization": "Bearer token123"}'``. Default: ``""``.

    Returns:
        JSON string with ``CrlfResult`` data.
    """
    param_list = [p.strip() for p in params.split(",") if p.strip()] if params else None
    extra_headers: dict[str, str] = headers if isinstance(headers, dict) else (json.loads(headers) if headers else {})
    body_dict: dict[str, str] | None = None
    if body:
        try:
            body_dict = json.loads(body)
        except json.JSONDecodeError as exc:
            return json.dumps({"error": f"Invalid JSON body: {exc}"})

    tester = CrlfTester(extra_headers=extra_headers)
    result = await tester.test(url, params=param_list, method=method, body=body_dict)
    return json.dumps(result.to_dict(), indent=2)
