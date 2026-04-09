"""Python-native CSRF (Cross-Site Request Forgery) tester.

Five complementary passive and active checks to detect CSRF exposure:

1. **SameSite cookie analysis** -- GET the target, inspect Set-Cookie headers.
   Cookies with ``SameSite=None`` or missing SameSite are flagged as
   ``weak_samesite`` (medium severity).

2. **Token presence with state-change awareness** -- Parse HTML forms, classify
   as state-changing (POST/DELETE/PATCH or action URL contains state keywords).
   Only flag ``missing_token`` on state-changing forms (high severity).

3. **Origin/Referer validation** -- Send 4 cross-origin POST combinations.
   If any returns non-rejection status, flag ``origin_not_validated`` (high).

4. **Token validation bypass** -- If forms with tokens are found, submit with
   empty, invalid, and missing token to check if the server actually validates.
   Flag ``token_not_validated`` (high) if any bypass works.

5. **JSON content-type bypass** -- POST JSON from evil origin. Many CSRF
   protections only check form submissions, not JSON payloads.
   Flag ``json_csrf_bypass`` (high) if accepted.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from numasec.core.http import create_client

logger = logging.getLogger("numasec.scanners.csrf_tester")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EVIL_ORIGIN = "https://evil.example.com"
_EVIL_REFERER = "https://evil.example.com/page"

# Regex patterns for HTML form analysis (lightweight, no extra deps)
_FORM_TAG_RE = re.compile(
    r"<form\b([^>]*)>(.*?)</form>",
    re.IGNORECASE | re.DOTALL,
)
_ATTR_RE = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_HIDDEN_INPUT_RE = re.compile(r'<input[^>]+type=["\']hidden["\'][^>]*>', re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r'name=["\']([^"\']*)["\']', re.IGNORECASE)

# CSRF token name substrings (case-insensitive match)
_CSRF_TOKEN_NAMES: list[str] = [
    "csrf",
    "_token",
    "authenticity_token",
    "nonce",
    "xsrf",
    "__requestverificationtoken",
]

# State-changing method keywords
_STATE_METHODS = {"post", "delete", "patch", "put"}

# Action URL keywords that suggest state-changing behavior
_STATE_KEYWORDS = {"delete", "update", "remove", "transfer", "change", "submit", "edit", "create", "add", "modify"}

# HTTP status codes that indicate the server rejected the cross-origin request
_REJECTION_CODES: set[int] = {401, 403, 405, 422}


# ---------------------------------------------------------------------------
# Parsed form helper
# ---------------------------------------------------------------------------


@dataclass
class _ParsedForm:
    """Internal representation of an HTML form."""

    method: str  # GET, POST, etc.
    action: str
    is_state_changing: bool
    hidden_inputs: dict[str, str]  # name -> value
    has_csrf_token: bool
    csrf_token_name: str  # name of the token field, if found


def _parse_forms(html: str) -> list[_ParsedForm]:
    """Extract forms from HTML with method, action, and hidden inputs."""
    forms: list[_ParsedForm] = []
    for match in _FORM_TAG_RE.finditer(html):
        attrs_str = match.group(1)
        body = match.group(2)

        attrs = dict(_ATTR_RE.findall(attrs_str))
        method = attrs.get("method", "GET").upper()
        action = attrs.get("action", "")

        is_state_changing = method.lower() in _STATE_METHODS or any(kw in action.lower() for kw in _STATE_KEYWORDS)

        hidden_inputs: dict[str, str] = {}
        csrf_token_name = ""
        has_csrf_token = False

        for inp_match in _HIDDEN_INPUT_RE.finditer(body):
            inp_tag = inp_match.group(0)
            name_m = _INPUT_NAME_RE.search(inp_tag)
            if not name_m:
                continue
            name = name_m.group(1)
            val_m = re.search(r'value=["\']([^"\']*)["\']', inp_tag, re.IGNORECASE)
            value = val_m.group(1) if val_m else ""
            hidden_inputs[name] = value

            if any(tok in name.lower() for tok in _CSRF_TOKEN_NAMES):
                has_csrf_token = True
                csrf_token_name = name

        forms.append(
            _ParsedForm(
                method=method,
                action=action,
                is_state_changing=is_state_changing,
                hidden_inputs=hidden_inputs,
                has_csrf_token=has_csrf_token,
                csrf_token_name=csrf_token_name,
            )
        )
    return forms


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CsrfVulnerability:
    """A single CSRF finding."""

    vuln_type: str
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
    """Five-check CSRF misconfiguration detector.

    Checks: SameSite cookies, token presence on state-changing forms,
    Origin/Referer validation (4 combinations), token validation bypass,
    and JSON content-type bypass.
    """

    def __init__(self, timeout: float = 10.0, extra_headers: dict[str, str] | None = None) -> None:
        self.timeout = timeout
        self._extra_headers: dict[str, str] = extra_headers or {}
        self._forms: list[_ParsedForm] = []

    async def test(self, url: str) -> CsrfResult:
        """Run all 5 CSRF checks against a target URL."""
        start = time.monotonic()
        result = CsrfResult(target=url)

        async with create_client(timeout=self.timeout) as client:
            try:
                # Check 1 + 2: SameSite cookies + token presence
                await self._check_cookies_and_tokens(client, url, result)

                # Check 3: Origin/Referer validation (4 combinations)
                await self._check_origin(client, url, result)

                # Check 4: Token validation bypass
                await self._check_token_bypass(client, url, result)

                # Check 5: JSON content-type bypass
                await self._check_json_bypass(client, url, result)
            except Exception as exc:
                logger.warning("CSRF test error on %s: %s", url, exc)

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "CSRF test complete: %s - %d vulns, %.0fms",
            url,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    # -- Check 1 + 2: Cookies and token presence ----------------------------

    async def _check_cookies_and_tokens(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: CsrfResult,
    ) -> None:
        """SameSite cookie analysis + token presence on state-changing forms."""
        try:
            resp = await client.get(url, headers=self._extra_headers)
        except httpx.HTTPError as exc:
            logger.debug("CSRF GET check error: %s", exc)
            return

        # -- Check 1: SameSite cookie policy --
        samesite_policies: list[str] = []
        weak_cookies: list[str] = []

        for cookie_header in resp.headers.get_list("set-cookie"):
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split(";")[0].strip()

            if "samesite=strict" in cookie_lower:
                samesite_policies.append("Strict")
            elif "samesite=lax" in cookie_lower:
                samesite_policies.append("Lax")
            elif "samesite=none" in cookie_lower:
                samesite_policies.append("None")
                weak_cookies.append(cookie_name)
            else:
                samesite_policies.append("absent")
                weak_cookies.append(cookie_name)

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

        # -- Check 2: CSRF token presence on state-changing forms --
        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type.lower():
            return

        html = resp.text
        self._forms = _parse_forms(html)
        result.forms_found = len(self._forms)

        if not self._forms:
            return

        # Check if any form has a CSRF token
        result.has_csrf_token = any(f.has_csrf_token for f in self._forms)

        # Only flag missing tokens on state-changing forms
        state_changing_no_token = [f for f in self._forms if f.is_state_changing and not f.has_csrf_token]

        if state_changing_no_token:
            methods = ", ".join(sorted({f.method for f in state_changing_no_token}))
            result.vulnerabilities.append(
                CsrfVulnerability(
                    vuln_type="missing_token",
                    evidence=(
                        f"Found {len(state_changing_no_token)} state-changing form(s) "
                        f"({methods}) without CSRF token. "
                        f"Checked for: {', '.join(_CSRF_TOKEN_NAMES[:4])}."
                    ),
                    severity="high",
                )
            )
            result.vulnerable = True

    # -- Check 3: Origin/Referer validation (4 combinations) ----------------

    async def _check_origin(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: CsrfResult,
    ) -> None:
        """Send 4 cross-origin POST combinations to test Origin/Referer validation."""
        origin_tests = [
            {"Origin": _EVIL_ORIGIN, "Referer": _EVIL_REFERER},
            {"Origin": "null"},
            {"Referer": _EVIL_REFERER},
            {"Origin": _EVIL_ORIGIN},
        ]

        for extra in origin_tests:
            headers = {
                **self._extra_headers,
                "Content-Type": "application/x-www-form-urlencoded",
                **extra,
            }
            try:
                resp = await client.post(url, headers=headers, data={"test": "csrf"})
            except httpx.HTTPError:
                continue

            if resp.status_code not in _REJECTION_CODES:
                tested = ", ".join(f"{k}: {v}" for k, v in extra.items())
                result.vulnerabilities.append(
                    CsrfVulnerability(
                        vuln_type="origin_not_validated",
                        evidence=(
                            f"POST with [{tested}] returned HTTP {resp.status_code} "
                            f"(expected 401/403/405/422). Server does not validate "
                            f"cross-origin requests."
                        ),
                        severity="high",
                    )
                )
                result.vulnerable = True
                return  # One proof is enough

    # -- Check 4: Token validation bypass -----------------------------------

    async def _check_token_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: CsrfResult,
    ) -> None:
        """Submit forms with empty, invalid, and missing tokens."""
        forms_with_tokens = [f for f in self._forms if f.has_csrf_token and f.is_state_changing]
        if not forms_with_tokens:
            return

        form = forms_with_tokens[0]
        token_name = form.csrf_token_name

        bypass_payloads = [
            ("empty token", {**form.hidden_inputs, token_name: ""}),
            ("invalid token", {**form.hidden_inputs, token_name: "INVALID_TOKEN_12345"}),
            ("missing token", {k: v for k, v in form.hidden_inputs.items() if k != token_name}),
        ]

        for label, data in bypass_payloads:
            headers = {
                **self._extra_headers,
                "Content-Type": "application/x-www-form-urlencoded",
            }
            try:
                resp = await client.post(url, headers=headers, data=data)
            except httpx.HTTPError:
                continue

            if resp.status_code not in _REJECTION_CODES:
                result.vulnerabilities.append(
                    CsrfVulnerability(
                        vuln_type="token_not_validated",
                        evidence=(
                            f"POST with {label} for field '{token_name}' returned "
                            f"HTTP {resp.status_code}. Server does not properly "
                            f"validate the CSRF token."
                        ),
                        severity="high",
                    )
                )
                result.vulnerable = True
                return  # One proof is enough

    # -- Check 5: JSON content-type bypass ----------------------------------

    async def _check_json_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: CsrfResult,
    ) -> None:
        """POST JSON from evil origin to test for CSRF bypasses."""
        headers = {
            **self._extra_headers,
            "Origin": _EVIL_ORIGIN,
            "Content-Type": "application/json",
        }
        try:
            resp = await client.post(url, headers=headers, content='{"test":"csrf"}')
        except httpx.HTTPError:
            return

        if resp.status_code not in _REJECTION_CODES:
            result.vulnerabilities.append(
                CsrfVulnerability(
                    vuln_type="json_csrf_bypass",
                    evidence=(
                        f"JSON POST from Origin: {_EVIL_ORIGIN} returned HTTP "
                        f"{resp.status_code}. CSRF protection may only cover "
                        f"form submissions, not JSON API requests."
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

    Runs 5 checks: SameSite cookies, token presence on state-changing forms,
    Origin/Referer validation (4 combinations), token validation bypass,
    and JSON content-type bypass.

    Args:
        url: Target URL to test.
        headers: Optional JSON string of extra HTTP headers for authenticated testing.

    Returns:
        JSON string with ``CsrfResult`` data.
    """
    extra_headers = headers if isinstance(headers, dict) else (json.loads(headers) if headers else {})
    tester = CsrfTester(extra_headers=extra_headers)
    result = await tester.test(url)
    return json.dumps(result.to_dict(), indent=2)
