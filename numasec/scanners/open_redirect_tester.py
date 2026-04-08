"""Python-native Open Redirect tester.

Detects endpoints that redirect users to arbitrary attacker-controlled URLs
by injecting redirect payloads into URL query parameters:

1. Absolute URL redirect (https://evil.example.com)
2. Protocol-relative redirect (//evil.example.com)
3. Backslash bypass (/\\\\evil.example.com)
4. Credential-confusion redirect (https://evil.example.com%2f@target)

Three strategies are combined:
- Replace existing query parameter values with redirect payloads
- Inject known redirect parameter names if none are present in the URL
- Discover common redirect endpoints on the target (e.g. ``/redirect``,
  ``/go``, ``/out``) and inject redirect payloads into them

The tester follows redirects and checks whether the final URL contains
the attacker-controlled domain.
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

logger = logging.getLogger("numasec.scanners.open_redirect_tester")

# ---------------------------------------------------------------------------
# Payloads and known redirect parameter names
# ---------------------------------------------------------------------------

_REDIRECT_PAYLOADS: list[str] = [
    # Standard payloads
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https://evil.example.com%2f@target",
    # Allowlist bypass payloads
    "https://target@evil.example.com",
    "https://target.evil.example.com",
    "https://evil.example.com#target",
    "https://evil.example.com%23target",
    "https://evil.example.com?target",
    "/\t/evil.example.com",
    "///evil.example.com",
    "https://evil.example.com/%2e%2e/",
]

# Allowlist-aware bypass payloads -- use common trusted domains with evasion
# techniques to test whether redirect allowlists are properly implemented
_ALLOWLIST_BYPASS_PAYLOADS: list[str] = [
    # OAuth-style redirect bypasses
    "https://accounts.google.com/o/oauth2/auth?redirect_uri=https://evil.example.com",
    "https://login.microsoftonline.com/common/oauth2?redirect_uri=https://evil.example.com",
    # Trusted domain as subdomain of attacker domain
    "https://google.com.evil.example.com",
    "https://github.com.evil.example.com",
    # @ symbol credential trick
    "https://google.com@evil.example.com",
    "https://github.com@evil.example.com",
    # Null byte / double encoding bypasses
    "https://evil.example.com%00https://google.com",
    "https://evil.example.com%23https://google.com",
    # CRLF injection in redirect URL
    "https://google.com%0d%0aLocation:%20https://evil.example.com",
]

_REDIRECT_PARAMS: list[str] = [
    "url",
    "redirect",
    "next",
    "return",
    "returnUrl",
    "return_url",
    "goto",
    "target",
    "redir",
    "redirect_uri",
    "callback",
    "to",
    "dest",
    "destination",
    "continue",
    "forward",
]

_EVIL_DOMAIN = "evil.example.com"

_COMMON_REDIRECT_PATHS: list[str] = [
    "/redirect",
    "/redir",
    "/go",
    "/out",
    "/external",
    "/link",
    "/away",
    "/forward",
    "/jump",
    "/cgi-bin/redirect.cgi",
    "/oauth/redirect",
    "/login/redirect",
    "/sso/redirect",
    "/auth/callback",
]

# Subset of params and payloads used for endpoint discovery to bound request count
_DISCOVERY_PARAMS: list[str] = ["url", "redirect", "to", "dest", "next", "target"]
_DISCOVERY_PAYLOADS: list[str] = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class RedirectVulnerability:
    """A single open-redirect finding."""

    parameter: str
    payload: str
    final_url: str
    evidence: str
    severity: str = "medium"


@dataclass
class RedirectResult:
    """Complete open-redirect test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[RedirectVulnerability] = field(default_factory=list)
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
                    "final_url": v.final_url,
                    "evidence": v.evidence,
                    "severity": v.severity,
                }
                for v in self.vulnerabilities
            ],
            "duration_ms": round(self.duration_ms, 2),
        }


# ---------------------------------------------------------------------------
# Open-redirect detection engine
# ---------------------------------------------------------------------------


class OpenRedirectTester:
    """Multi-payload open-redirect detector.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def test(self, url: str, headers: dict[str, str] | None = None) -> RedirectResult:
        """Run open-redirect tests against a target URL.

        Three strategies are employed:
        1. Replace existing query parameter values with redirect payloads.
        2. Inject common redirect parameter names if none are currently present.
        3. Discover common redirect endpoints on the target origin and inject
           redirect payloads into them.

        The tester follows up to 5 redirects and checks whether the final
        resolved URL contains the attacker-controlled domain.

        Args:
            url: Target URL to test.
            headers: Optional HTTP headers for authenticated testing.

        Returns:
            ``RedirectResult`` with all discovered open-redirect vulnerabilities.
        """
        start = time.monotonic()
        result = RedirectResult(target=url)

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        async with create_client(
            timeout=self.timeout,
            max_redirects=5,
            headers=headers or {},
        ) as client:
            # Strategy 1: replace existing parameter values
            for param_name in params:
                for payload in _REDIRECT_PAYLOADS:
                    vuln = await self._probe_param(client, parsed, params, param_name, payload)
                    if vuln:
                        result.vulnerabilities.append(vuln)
                        result.vulnerable = True

            # Strategy 2: inject known redirect parameters if not already present
            existing_lower = {p.lower() for p in params}
            for redirect_param in _REDIRECT_PARAMS:
                if redirect_param.lower() not in existing_lower:
                    for payload in _REDIRECT_PAYLOADS:
                        vuln = await self._probe_inject(client, parsed, params, redirect_param, payload)
                        if vuln:
                            result.vulnerabilities.append(vuln)
                            result.vulnerable = True

            # Strategy 3: discover common redirect endpoints on the target origin
            base_origin = f"{parsed.scheme}://{parsed.netloc}"
            for redir_path in _COMMON_REDIRECT_PATHS:
                found_on_path = False
                for param_name in _DISCOVERY_PARAMS:
                    if found_on_path:
                        break
                    for payload in _DISCOVERY_PAYLOADS:
                        endpoint_url = f"{base_origin}{redir_path}?{param_name}={payload}"
                        vuln = await self._send_and_check(client, endpoint_url, param_name, payload)
                        if vuln:
                            result.vulnerabilities.append(vuln)
                            result.vulnerable = True
                            found_on_path = True
                            break

            # Strategy 4: Allowlist bypass — if standard payloads failed on known
            # redirect endpoints, try allowlist-aware bypass payloads
            if not result.vulnerable:
                for redir_path in ("/redirect", "/go", "/out", "/forward"):
                    for param_name in ("to", "url", "redirect", "dest", "next"):
                        for payload in _ALLOWLIST_BYPASS_PAYLOADS:
                            endpoint_url = f"{base_origin}{redir_path}?{param_name}={payload}"
                            vuln = await self._send_and_check(client, endpoint_url, param_name, payload)
                            if vuln:
                                result.vulnerabilities.append(vuln)
                                result.vulnerable = True
                                break
                        if result.vulnerable:
                            break
                    if result.vulnerable:
                        break

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Open-redirect test complete: %s — %d vulns, %.0fms",
            url,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    async def _probe_param(
        self,
        client: httpx.AsyncClient,
        parsed: Any,
        params: dict[str, list[str]],
        param_name: str,
        payload: str,
    ) -> RedirectVulnerability | None:
        """Replace an existing parameter value with *payload* and follow redirects."""
        modified_params = dict(params)
        modified_params[param_name] = [payload]
        new_query = urlencode(modified_params, doseq=True)
        modified_url = urlunparse(parsed._replace(query=new_query))
        return await self._send_and_check(client, modified_url, param_name, payload)

    async def _probe_inject(
        self,
        client: httpx.AsyncClient,
        parsed: Any,
        params: dict[str, list[str]],
        redirect_param: str,
        payload: str,
    ) -> RedirectVulnerability | None:
        """Inject a new redirect parameter with *payload* and follow redirects."""
        injected_params = dict(params)
        injected_params[redirect_param] = [payload]
        new_query = urlencode(injected_params, doseq=True)
        modified_url = urlunparse(parsed._replace(query=new_query))
        return await self._send_and_check(client, modified_url, redirect_param, payload)

    async def _send_and_check(
        self,
        client: httpx.AsyncClient,
        test_url: str,
        param_name: str,
        payload: str,
    ) -> RedirectVulnerability | None:
        """Send the request and check if the final URL contains the evil domain."""
        try:
            resp = await client.get(test_url)
        except httpx.HTTPError as exc:
            logger.debug(
                "Open-redirect probe error (param=%s, payload=%s): %s",
                param_name,
                payload,
                exc,
            )
            return None

        final_url = str(resp.url)
        final_parsed = urlparse(final_url)
        original_parsed = urlparse(test_url)

        # Only flag if the HOSTNAME actually changed to an attacker-controlled domain.
        # A substring check on the full URL would false-positive when the evil
        # domain appears URL-encoded in a query parameter without a real redirect.
        is_evil = _EVIL_DOMAIN in final_parsed.netloc or (
            final_parsed.netloc != original_parsed.netloc
            and final_parsed.netloc != ""
            and not final_parsed.netloc.startswith(original_parsed.netloc)
        )
        if not is_evil:
            return None

        # Determine severity: "high" if the host is completely different,
        # "medium" for same-host path manipulation
        severity = "high" if final_parsed.netloc != original_parsed.netloc else "medium"

        return RedirectVulnerability(
            parameter=param_name,
            payload=payload,
            final_url=final_url,
            evidence=(
                f"Request was redirected to '{final_url}' after injecting payload "
                f"'{payload}' into parameter '{param_name}'."
            ),
            severity=severity,
        )


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_open_redirect_test(url: str, headers: str | None = None) -> str:
    """Test a URL for open-redirect vulnerabilities.

    Injects redirect payloads into URL query parameters, discovers common
    redirect endpoints on the target origin, and follows redirects to detect
    whether the server redirects users to attacker-controlled domains.

    Args:
        url: Target URL to test.
        headers: Optional JSON string of HTTP headers for authenticated testing.

    Returns:
        JSON string with ``RedirectResult`` data.
    """
    import contextlib

    parsed_headers: dict[str, str] | None = None
    if headers:
        with contextlib.suppress(json.JSONDecodeError):
            parsed_headers = headers if isinstance(headers, dict) else json.loads(headers)

    tester = OpenRedirectTester()
    result = await tester.test(url, headers=parsed_headers)
    return json.dumps(result.to_dict(), indent=2)
