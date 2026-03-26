"""Python-native CORS (Cross-Origin Resource Sharing) misconfiguration tester.

Detects permissive CORS policies that allow arbitrary origins or expose
credentials to untrusted origins:

1. Wildcard ACAO: ``Access-Control-Allow-Origin: *`` with credentials
2. Reflected origin: server echoes back any Origin value
3. Null origin: server accepts ``Origin: null``
4. Subdomain bypass: ``evil.example.com`` accepted
5. Credentials exposure: ACAC=true + permissive ACAO = critical
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("security_mcp.scanners.cors_tester")

# Test origins to probe CORS policy
_EVIL_ORIGIN = "https://evil.example.com"
_NULL_ORIGIN = "null"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CorsVulnerability:
    """A single CORS misconfiguration finding."""

    vuln_type: str  # "reflected_origin" | "null_origin" | "wildcard_credentials" | "prefix_bypass"
    origin_sent: str
    acao_received: str
    acac: bool  # Access-Control-Allow-Credentials: true
    severity: str  # "critical" | "high" | "medium"
    evidence: str


@dataclass
class CorsResult:
    """Complete CORS test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[CorsVulnerability] = field(default_factory=list)
    acao_header: str = ""
    acac_header: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "type": v.vuln_type,
                    "origin_sent": v.origin_sent,
                    "acao_received": v.acao_received,
                    "credentials_exposed": v.acac,
                    "severity": v.severity,
                    "evidence": v.evidence,
                }
                for v in self.vulnerabilities
            ],
            "acao_header": self.acao_header,
            "acac_header": self.acac_header,
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"{len(self.vulnerabilities)} CORS "
                f"{'misconfiguration' if len(self.vulnerabilities) == 1 else 'misconfigurations'} found"
                if self.vulnerabilities
                else "No CORS issues found"
            ),
            "next_steps": (
                ["Verify if credentials are exposed cross-origin"]
                if self.vulnerabilities
                else []
            ),
        }


# ---------------------------------------------------------------------------
# CORS detection engine
# ---------------------------------------------------------------------------


class CorsTester:
    """Multi-probe CORS misconfiguration detector.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(self, timeout: float = 10.0, extra_headers: dict[str, str] | None = None) -> None:
        self.timeout = timeout
        self._extra_headers: dict[str, str] = extra_headers or {}

    async def test(self, url: str) -> CorsResult:
        """Run CORS tests against a target URL.

        Sends probes with crafted Origin headers and inspects
        ``Access-Control-Allow-Origin`` and
        ``Access-Control-Allow-Credentials`` response headers.

        Args:
            url: Target URL to test.

        Returns:
            ``CorsResult`` with all discovered misconfigurations.
        """
        start = time.monotonic()
        result = CorsResult(target=url)

        parsed = urlparse(url)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"

        test_origins = [
            _EVIL_ORIGIN,
            _NULL_ORIGIN,
            f"https://{parsed.netloc}.evil.example.com",  # suffix bypass
            f"https://evil{parsed.netloc}",  # prefix bypass
        ]

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            for origin in test_origins:
                try:
                    vuln = await self._probe(client, url, origin, target_origin)
                    if vuln:
                        result.vulnerabilities.append(vuln)
                        result.vulnerable = True
                except Exception as exc:
                    logger.warning("CORS test error on origin %s: %s", origin, exc)
                    continue

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "CORS test complete: %s — %d vulns, %.0fms",
            url,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    async def _probe(
        self,
        client: httpx.AsyncClient,
        url: str,
        origin: str,
        target_origin: str,
    ) -> CorsVulnerability | None:
        """Send one CORS probe and evaluate the response headers."""
        try:
            resp = await client.get(url, headers={**self._extra_headers, "Origin": origin})
        except httpx.HTTPError as exc:
            logger.debug("CORS probe error (origin=%s): %s", origin, exc)
            return None

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

        if not acao:
            return None

        # Case 1: wildcard ACAO + credentials — critical
        if acao == "*" and acac:
            return CorsVulnerability(
                vuln_type="wildcard_credentials",
                origin_sent=origin,
                acao_received=acao,
                acac=acac,
                severity="critical",
                evidence=(
                    "Access-Control-Allow-Origin: * combined with "
                    "Access-Control-Allow-Credentials: true. "
                    "Credentials are exposed to any origin."
                ),
            )

        # Case 2: reflected evil origin
        if acao in (_EVIL_ORIGIN, origin) and acao != target_origin:
            severity = "critical" if acac else "high"
            return CorsVulnerability(
                vuln_type="reflected_origin",
                origin_sent=origin,
                acao_received=acao,
                acac=acac,
                severity=severity,
                evidence=(
                    f"Server reflected Origin header verbatim: "
                    f"Access-Control-Allow-Origin: {acao}. "
                    f"{'Credentials are exposed (ACAC: true).' if acac else ''}"
                ),
            )

        # Case 3: null origin accepted
        if origin == _NULL_ORIGIN and acao == "null":
            severity = "critical" if acac else "high"
            return CorsVulnerability(
                vuln_type="null_origin",
                origin_sent=origin,
                acao_received=acao,
                acac=acac,
                severity=severity,
                evidence=(
                    f"Server accepts 'null' origin: Access-Control-Allow-Origin: null. "
                    f"Sandboxed iframes can exploit this. "
                    f"{'Credentials exposed (ACAC: true).' if acac else ''}"
                ),
            )

        return None


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_cors_test(url: str, headers: str = "") -> str:
    """Test a URL for CORS misconfiguration vulnerabilities.

    Args:
        url: Target URL to test.
        headers: Optional JSON string of extra HTTP headers for authenticated testing.

    Returns:
        JSON string with ``CorsResult`` data.
    """
    extra_headers = json.loads(headers) if headers else {}
    tester = CorsTester(extra_headers=extra_headers)
    result = await tester.test(url)
    return json.dumps(result.to_dict(), indent=2)
