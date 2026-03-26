"""Python-native CSRF (Cross-Site Request Forgery) tester.

Performs three complementary passive and active checks to detect CSRF exposure:

1. **SameSite cookie check** — GET the target, inspect Set-Cookie headers.
   Cookies lacking ``SameSite=Strict`` or ``SameSite=Lax`` are flagged
   as ``weak_samesite`` (medium severity).

2. **CSRF token check** — GET the target, parse HTML for hidden input fields
   whose names contain "csrf", "_token", "authenticity_token", or "nonce".
   Forms without a CSRF token are flagged as ``missing_token`` (high severity).

3. **Origin header validation** — POST to the target with
   ``Origin: https://evil.example.com`` and a short form payload.  A 200
   response (not 403/401) indicates the server does not validate the Origin
   header, flagged as ``origin_not_validated`` (high severity).
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger("security_mcp.scanners.csrf_tester")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EVIL_ORIGIN = "https://evil.example.com"

# Regex patterns for HTML form analysis (intentionally lightweight)
_FORM_RE = re.compile(r"<form[^>]*>", re.IGNORECASE)
_HIDDEN_INPUT_RE = re.compile(r'<input[^>]+type=["\']hidden["\'][^>]*>', re.IGNORECASE)

# CSRF token name substrings (case-insensitive match)
_CSRF_TOKEN_NAMES: list[str] = [
    "csrf",
    "_token",
    "authenticity_token",
    "nonce",
]

# HTTP status codes that indicate the server rejected the cross-origin request
_REJECTION_CODES: set[int] = {401, 403, 405, 422}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CsrfVulnerability:
    """A single CSRF finding."""

    vuln_type: str  # "missing_token" | "weak_samesite" | "origin_not_validated"
    evidence: str
    severity: str = "medium"


@dataclass
class CsrfResult:
    """Complete CSRF test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[CsrfVulnerability] = field(default_factory=list)
    has_csrf_token: bool = False
    forms_found: int = 0
    samesite_policy: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "type": v.vuln_type,
                    "evidence": v.evidence,
                    "severity": v.severity,
                }
                for v in self.vulnerabilities
            ],
            "has_csrf_token": self.has_csrf_token,
            "forms_found": self.forms_found,
            "samesite_policy": self.samesite_policy,
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"{len(self.vulnerabilities)} CSRF "
                f"{'weakness' if len(self.vulnerabilities) == 1 else 'weaknesses'} found"
                if self.vulnerabilities
                else "No CSRF issues found"
            ),
            "next_steps": (
                ["Test state-changing endpoints (password change, email change) for CSRF"]
                if self.vulnerabilities
                else []
            ),
        }


# ---------------------------------------------------------------------------
# CSRF detection engine
# ---------------------------------------------------------------------------


class CsrfTester:
    """Three-check CSRF misconfiguration detector.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(self, timeout: float = 10.0, extra_headers: dict[str, str] | None = None) -> None:
        self.timeout = timeout
        self._extra_headers: dict[str, str] = extra_headers or {}

    async def test(self, url: str) -> CsrfResult:
        """Run CSRF checks against a target URL.

        Performs SameSite cookie inspection, CSRF token presence check,
        and Origin header validation in a single client session.

        Args:
            url: Target URL to test.

        Returns:
            ``CsrfResult`` with all discovered CSRF vulnerabilities.
        """
        start = time.monotonic()
        result = CsrfResult(target=url)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            try:
                # Check 1 & 2: GET-based checks (SameSite + token)
                await self._check_get(client, url, result)

                # Check 3: Origin header validation via POST
                await self._check_origin(client, url, result)
            except Exception as exc:
                logger.warning("CSRF test error on %s: %s", url, exc)

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "CSRF test complete: %s — %d vulns, %.0fms",
            url,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    async def _check_get(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: CsrfResult,
    ) -> None:
        """Perform SameSite cookie check and CSRF token presence check."""
        try:
            resp = await client.get(url, headers=self._extra_headers)
        except httpx.HTTPError as exc:
            logger.debug("CSRF GET check error: %s", exc)
            return

        # --- Check 1: SameSite cookie policy ---
        samesite_policies: list[str] = []
        weak_cookies: list[str] = []

        for cookie_header in resp.headers.get_list("set-cookie"):
            cookie_lower = cookie_header.lower()
            if "samesite=strict" in cookie_lower:
                samesite_policies.append("Strict")
            elif "samesite=lax" in cookie_lower:
                samesite_policies.append("Lax")
            elif "samesite=none" in cookie_lower:
                samesite_policies.append("None")
                weak_cookies.append(cookie_header.split(";")[0].strip())
            else:
                # No SameSite attribute at all
                samesite_policies.append("absent")
                weak_cookies.append(cookie_header.split(";")[0].strip())

        if samesite_policies:
            result.samesite_policy = ", ".join(sorted(set(samesite_policies)))

        if weak_cookies:
            result.vulnerabilities.append(
                CsrfVulnerability(
                    vuln_type="weak_samesite",
                    evidence=(
                        f"Cookie(s) set without SameSite=Strict or SameSite=Lax: "
                        f"{'; '.join(weak_cookies[:3])}{'...' if len(weak_cookies) > 3 else ''}. "
                        f"CSRF attacks can include these cookies cross-site."
                    ),
                    severity="medium",
                )
            )
            result.vulnerable = True

        # --- Check 2: CSRF token presence in HTML forms ---
        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type.lower():
            return

        html = resp.text
        forms = _FORM_RE.findall(html)
        result.forms_found = len(forms)
        if not forms:
            return  # No forms — CSRF token check not applicable

        hidden_inputs = _HIDDEN_INPUT_RE.findall(html)
        has_token = any(any(token_name in inp.lower() for token_name in _CSRF_TOKEN_NAMES) for inp in hidden_inputs)
        result.has_csrf_token = has_token

        if not has_token:
            result.vulnerabilities.append(
                CsrfVulnerability(
                    vuln_type="missing_token",
                    evidence=(
                        f"Found {len(forms)} HTML form(s) but no hidden CSRF token input "
                        f"(checked for: {', '.join(_CSRF_TOKEN_NAMES)}). "
                        f"State-changing requests may be forgeable."
                    ),
                    severity="high",
                )
            )
            result.vulnerable = True

    async def _check_origin(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: CsrfResult,
    ) -> None:
        """Send a cross-origin POST and check if the server accepts it."""
        headers = {
            **self._extra_headers,
            "Origin": _EVIL_ORIGIN,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            resp = await client.post(url, headers=headers, data={"test": "csrf"})
        except httpx.HTTPError as exc:
            logger.debug("CSRF Origin POST check error: %s", exc)
            return

        if resp.status_code not in _REJECTION_CODES:
            result.vulnerabilities.append(
                CsrfVulnerability(
                    vuln_type="origin_not_validated",
                    evidence=(
                        f"POST with 'Origin: {_EVIL_ORIGIN}' returned HTTP {resp.status_code} "
                        f"(expected 401/403). Server does not validate the Origin header, "
                        f"making it susceptible to cross-origin state-changing requests."
                    ),
                    severity="high",
                )
            )
            result.vulnerable = True


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_csrf_test(url: str, headers: str = "") -> str:
    """Test a URL for CSRF (Cross-Site Request Forgery) vulnerabilities.

    Performs three checks: SameSite cookie policy, CSRF token presence
    in HTML forms, and Origin header validation on POST requests.

    Args:
        url: Target URL to test.
        headers: Optional JSON string of extra HTTP headers for authenticated testing.

    Returns:
        JSON string with ``CsrfResult`` data.
    """
    extra_headers = json.loads(headers) if headers else {}
    tester = CsrfTester(extra_headers=extra_headers)
    result = await tester.test(url)
    return json.dumps(result.to_dict(), indent=2)
