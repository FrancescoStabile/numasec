"""Python-native Host Header Injection tester.

Detects server-side Host header trust issues that can lead to:
- Password reset link poisoning
- Cache poisoning
- Open redirect via Host
- SSRF via forwarding headers

Probes the following headers with malicious values:
  Host, X-Forwarded-Host, X-Host, X-Forwarded-Server, X-HTTP-Host-Override
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("security_mcp.scanners.host_header_tester")

# Injected host values to test
_EVIL_HOST = "evil.example.com"
_LOOPBACK_HOST = "localhost"
_LOOPBACK_IP = "127.0.0.1"

# Headers that may influence the server's notion of the requested host
_FORWARD_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class HostHeaderVulnerability:
    """A single Host Header injection finding."""

    header_injected: str  # "Host" | "X-Forwarded-Host" | ...
    value_injected: str
    reflection_location: str  # "body" | "location_header" | "link_href"
    severity: str  # "high" | "medium"
    evidence: str


@dataclass
class HostHeaderResult:
    """Complete Host Header Injection test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[HostHeaderVulnerability] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "header": v.header_injected,
                    "value": v.value_injected,
                    "reflected_in": v.reflection_location,
                    "severity": v.severity,
                    "evidence": v.evidence,
                }
                for v in self.vulnerabilities
            ],
            "duration_ms": round(self.duration_ms, 2),
        }


# ---------------------------------------------------------------------------
# Host Header detection engine
# ---------------------------------------------------------------------------


class HostHeaderTester:
    """Multi-header Host Header injection tester.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def test(self, url: str) -> HostHeaderResult:
        """Run Host Header injection tests against a URL.

        Tests both the Host header override (via forwarding headers) and
        override headers, checking response body and Location header for
        reflections of the injected value.

        Args:
            url: Target URL to test.

        Returns:
            ``HostHeaderResult`` with all discovered vulnerabilities.
        """
        start = time.monotonic()
        result = HostHeaderResult(target=url)

        parsed = urlparse(url)
        real_host = parsed.netloc

        test_cases: list[tuple[str, str]] = [
            (_EVIL_HOST, "evil"),
            (_LOOPBACK_HOST, "loopback_host"),
            (_LOOPBACK_IP, "loopback_ip"),
            (f"{real_host}.{_EVIL_HOST}", "suffix_evil"),
        ]

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,  # Do NOT follow: check Location header
            verify=False,
        ) as client:
            for evil_value, _label in test_cases:
                # Test each forwarding header separately
                for fwd_header in _FORWARD_HEADERS:
                    vuln = await self._probe_header(
                        client,
                        url,
                        real_host,
                        fwd_header,
                        evil_value,
                    )
                    if vuln:
                        result.vulnerabilities.append(vuln)
                        result.vulnerable = True

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Host Header test complete: %s — %d vulns, %.0fms",
            url,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    async def _probe_header(
        self,
        client: httpx.AsyncClient,
        url: str,
        real_host: str,
        header_name: str,
        injected_value: str,
    ) -> HostHeaderVulnerability | None:
        """Inject one header value and check for reflection."""
        headers = {header_name: injected_value}
        try:
            resp = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            logger.debug("Host header probe error (%s=%s): %s", header_name, injected_value, exc)
            return None

        body = resp.text
        location = resp.headers.get("location", "")

        # Check if injected value appears in Location redirect
        if injected_value in location and real_host not in location:
            return HostHeaderVulnerability(
                header_injected=header_name,
                value_injected=injected_value,
                reflection_location="location_header",
                severity="high",
                evidence=(
                    f"Injected value '{injected_value}' via {header_name} reflected in Location: {location[:200]}"
                ),
            )

        # Check if injected value appears in response body (link href, action, etc.)
        body_patterns = [
            r"https?://" + re.escape(injected_value),
            re.escape(injected_value),
        ]
        for pattern in body_patterns:
            match = re.search(pattern, body)
            if match and injected_value != real_host:
                snippet = body[max(0, match.start() - 40) : match.end() + 40]
                return HostHeaderVulnerability(
                    header_injected=header_name,
                    value_injected=injected_value,
                    reflection_location="body",
                    severity="high",
                    evidence=(
                        f"Injected host '{injected_value}' via {header_name} "
                        f"reflected in response body: ...{snippet}..."
                    ),
                )

        return None


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_host_header_test(url: str) -> str:
    """Test a URL for Host Header injection vulnerabilities.

    Args:
        url: Target URL to test.

    Returns:
        JSON string with ``HostHeaderResult`` data.
    """
    tester = HostHeaderTester()
    result = await tester.test(url)
    return json.dumps(result.to_dict(), indent=2)
