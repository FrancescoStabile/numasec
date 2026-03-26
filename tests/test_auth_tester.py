"""Tests for security_mcp.scanners.auth_tester — JWT/OAuth authentication testing."""

from __future__ import annotations

import json

import httpx
import pytest

from security_mcp.scanners.auth_tester import (
    AuthResult,
    AuthTester,
    AuthVulnerability,
    _JWT_PATTERN,
    _b64url_decode,
    _b64url_encode,
    _build_kid_injection_token,
    _build_none_alg_token,
    _decode_jwt_header,
    _sign_hs256,
    _split_jwt,
    python_auth_test,
)


# ---------------------------------------------------------------------------
# Helpers: build valid-looking JWTs for testing
# ---------------------------------------------------------------------------


def _make_jwt(header: dict, payload: dict, secret: str = "test-secret") -> str:
    """Build a properly signed HS256 JWT for testing."""
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _sign_hs256(secret, h_b64, p_b64)
    return f"{h_b64}.{p_b64}.{sig}"


_SAMPLE_JWT = _make_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "1234567890", "name": "Test User", "iat": 1516239022},
    secret="test-secret",
)


# ---------------------------------------------------------------------------
# JWT utility functions
# ---------------------------------------------------------------------------


class TestJwtUtilities:
    def test_b64url_roundtrip(self):
        data = b"Hello, World!"
        encoded = _b64url_encode(data)
        decoded = _b64url_decode(encoded)
        assert decoded == data

    def test_b64url_decode_with_padding(self):
        # JSON without proper padding
        raw = b'{"alg":"HS256"}'
        encoded = _b64url_encode(raw)
        decoded = _b64url_decode(encoded)
        assert decoded == raw

    def test_split_jwt_three_parts(self):
        parts = _split_jwt(_SAMPLE_JWT)
        assert parts is not None
        assert len(parts) == 3

    def test_split_jwt_invalid(self):
        assert _split_jwt("not.a.valid.jwt.token.here") is None
        assert _split_jwt("onlytwoparts.here") is None

    def test_decode_jwt_header(self):
        header = _decode_jwt_header(_SAMPLE_JWT)
        assert header is not None
        assert header["alg"] == "HS256"
        assert header["typ"] == "JWT"

    def test_decode_jwt_header_invalid(self):
        assert _decode_jwt_header("not_a_jwt") is None

    def test_sign_hs256_deterministic(self):
        """Signing the same input twice should produce the same result."""
        sig1 = _sign_hs256("secret", "header_b64", "payload_b64")
        sig2 = _sign_hs256("secret", "header_b64", "payload_b64")
        assert sig1 == sig2

    def test_sign_hs256_different_secrets(self):
        """Different secrets should produce different signatures."""
        sig1 = _sign_hs256("secret1", "header", "payload")
        sig2 = _sign_hs256("secret2", "header", "payload")
        assert sig1 != sig2


# ---------------------------------------------------------------------------
# JWT manipulation attacks
# ---------------------------------------------------------------------------


class TestBuildNoneAlgToken:
    def test_none_alg_token_has_no_signature(self):
        tampered = _build_none_alg_token(_SAMPLE_JWT)
        assert tampered is not None
        assert tampered.endswith(".")  # empty signature

    def test_none_alg_token_has_none_alg(self):
        tampered = _build_none_alg_token(_SAMPLE_JWT)
        assert tampered is not None
        header = _decode_jwt_header(tampered)
        assert header is not None
        assert header["alg"] == "none"

    def test_none_alg_preserves_payload(self):
        original_parts = _split_jwt(_SAMPLE_JWT)
        tampered = _build_none_alg_token(_SAMPLE_JWT)
        tampered_parts = _split_jwt(tampered + "x")  # trick to get 3 parts with empty sig
        # Check payload unchanged
        assert original_parts is not None
        tampered_split = tampered.split(".")
        assert len(tampered_split) == 3
        assert tampered_split[1] == original_parts[1]  # payload unchanged

    def test_none_alg_invalid_jwt_returns_none(self):
        assert _build_none_alg_token("not_valid") is None


class TestBuildKidInjectionToken:
    def test_kid_injection_token_has_path_traversal(self):
        jwt_with_kid = _make_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key-001"},
            {"sub": "user123"},
            secret="mysecret",
        )
        tampered = _build_kid_injection_token(jwt_with_kid)
        assert tampered is not None
        header = _decode_jwt_header(tampered)
        assert header is not None
        assert "dev/null" in header["kid"] or ".." in header["kid"]

    def test_kid_injection_invalid_jwt_returns_none(self):
        assert _build_kid_injection_token("not_valid") is None


# ---------------------------------------------------------------------------
# AuthResult data model
# ---------------------------------------------------------------------------


class TestAuthResult:
    def test_to_dict_empty(self):
        r = AuthResult(target="http://example.com")
        d = r.to_dict()
        assert d["target"] == "http://example.com"
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []
        assert d["jwts_found"] == []

    def test_to_dict_with_vuln(self):
        r = AuthResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=[
                AuthVulnerability(
                    vuln_type="jwt_none_alg",
                    severity="critical",
                    evidence="alg:none accepted",
                )
            ],
            jwts_found=["eyJ..."],
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert d["vulnerabilities"][0]["type"] == "jwt_none_alg"
        assert d["vulnerabilities"][0]["severity"] == "critical"
        assert len(d["jwts_found"]) == 1


# ---------------------------------------------------------------------------
# Passive checks
# ---------------------------------------------------------------------------


class TestApiKeyInUrl:
    def test_api_key_param_detected(self):
        tester = AuthTester()
        result = AuthResult(target="http://example.com/api?api_key=s3cr3t")
        tester._check_api_key_in_url("http://example.com/api?api_key=s3cr3t", result)
        assert result.vulnerable is True
        assert any(v.vuln_type == "api_key_in_url" for v in result.vulnerabilities)

    def test_token_param_detected(self):
        tester = AuthTester()
        result = AuthResult(target="http://example.com")
        tester._check_api_key_in_url("http://example.com/api?access_token=abc123", result)
        assert result.vulnerable is True

    def test_regular_param_not_flagged(self):
        tester = AuthTester()
        result = AuthResult(target="http://example.com")
        tester._check_api_key_in_url("http://example.com/?page=1&sort=asc", result)
        assert result.vulnerable is False

    def test_no_params_not_flagged(self):
        tester = AuthTester()
        result = AuthResult(target="http://example.com")
        tester._check_api_key_in_url("http://example.com/", result)
        assert result.vulnerable is False


class TestBearerExposed:
    def test_jwt_in_body_detected(self):
        tester = AuthTester()
        result = AuthResult(target="http://example.com")
        body = f"Welcome! Your token is: {_SAMPLE_JWT}"
        tester._check_bearer_exposed(body, result)
        assert result.vulnerable is True
        assert any(v.vuln_type == "bearer_exposed" for v in result.vulnerabilities)

    def test_no_jwt_not_flagged(self):
        tester = AuthTester()
        result = AuthResult(target="http://example.com")
        tester._check_bearer_exposed("<html><body>Welcome!</body></html>", result)
        assert result.vulnerable is False


class TestOAuthStateCheck:
    def test_oauth_without_state_detected(self):
        tester = AuthTester()
        result = AuthResult(target="http://example.com")
        body = """<a href="/oauth/authorize?response_type=code&client_id=app123">Login</a>"""
        tester._check_oauth_state(body, "http://example.com/login", result)
        assert result.vulnerable is True
        assert any(v.vuln_type == "oauth_state_missing" for v in result.vulnerabilities)

    def test_oauth_with_state_not_flagged(self):
        tester = AuthTester()
        result = AuthResult(target="http://example.com")
        body = """<a href="/oauth/authorize?response_type=code&client_id=app&state=a1b2c3d4e5f6g7h8">Login</a>"""
        tester._check_oauth_state(body, "http://example.com/login", result)
        # With sufficient entropy, no vuln
        assert not any(
            v.vuln_type == "oauth_state_missing" and v.severity == "high"
            for v in result.vulnerabilities
        )

    def test_non_oauth_page_not_flagged(self):
        tester = AuthTester()
        result = AuthResult(target="http://example.com")
        tester._check_oauth_state(
            "<html><body>Regular page</body></html>",
            "http://example.com/about",
            result,
        )
        assert result.vulnerable is False


# ---------------------------------------------------------------------------
# JWT extraction
# ---------------------------------------------------------------------------


class TestJwtExtraction:
    def test_extracts_jwt_from_body(self):
        tester = AuthTester()
        body = f'<script>var token = "{_SAMPLE_JWT}";</script>'
        jwts = tester._extract_jwts(body)
        assert len(jwts) == 1
        assert jwts[0] == _SAMPLE_JWT

    def test_no_jwt_returns_empty(self):
        tester = AuthTester()
        jwts = tester._extract_jwts("<html><body>nothing here</body></html>")
        assert jwts == []

    def test_deduplicates_same_jwt(self):
        tester = AuthTester()
        body = f"token={_SAMPLE_JWT} and again={_SAMPLE_JWT}"
        jwts = tester._extract_jwts(body)
        assert len(jwts) == 1


# ---------------------------------------------------------------------------
# Active JWT checks (with mocked HTTP)
# ---------------------------------------------------------------------------


def _mock_transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


class TestCheckNoneAlg:
    @pytest.mark.asyncio
    async def test_none_alg_accepted_flagged(self):
        """Server that returns 200 for alg:none token should be flagged."""

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("authorization", "")
            # Accept any bearer token with empty signature (none alg)
            if auth.startswith("Bearer ") and auth.endswith("."):
                return httpx.Response(200, text="authenticated")
            return httpx.Response(401, text="unauthorized")

        tester = AuthTester(timeout=5.0)
        result = AuthResult(target="http://test.local")
        async with httpx.AsyncClient(transport=_mock_transport(handler)) as client:
            await tester._check_none_alg(client, "http://test.local", _SAMPLE_JWT, result)

        assert result.vulnerable is True
        assert any(v.vuln_type == "jwt_none_alg" for v in result.vulnerabilities)

    @pytest.mark.asyncio
    async def test_none_alg_rejected_not_flagged(self):
        """Server that rejects alg:none token should not be flagged."""

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("authorization", "")
            if auth.endswith("."):
                return httpx.Response(401, text="invalid token")
            return httpx.Response(200, text="ok")

        tester = AuthTester(timeout=5.0)
        result = AuthResult(target="http://test.local")
        async with httpx.AsyncClient(transport=_mock_transport(handler)) as client:
            await tester._check_none_alg(client, "http://test.local", _SAMPLE_JWT, result)

        assert result.vulnerable is False


class TestCheckWeakSecret:
    @pytest.mark.asyncio
    async def test_weak_secret_detected(self):
        """JWT signed with 'secret' should trigger weak secret finding."""
        # Build a JWT signed with a weak secret from our list
        weak_jwt = _make_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "user1"},
            secret="secret",  # this is in _WEAK_SECRETS
        )
        tester = AuthTester(timeout=5.0)
        result = AuthResult(target="http://test.local")

        # The check doesn't need an HTTP client — it's purely computational
        async with httpx.AsyncClient() as client:
            await tester._check_weak_secret(client, "http://test.local", weak_jwt, result)

        assert result.vulnerable is True
        assert any(v.vuln_type == "jwt_weak_secret" for v in result.vulnerabilities)
        found = next(v for v in result.vulnerabilities if v.vuln_type == "jwt_weak_secret")
        assert "secret" in found.evidence

    @pytest.mark.asyncio
    async def test_strong_secret_not_detected(self):
        """JWT signed with a random strong secret should not be brute-forced."""
        strong_jwt = _make_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "user1"},
            secret="x$K9!zQ#mR2pL@nV5wB0dF3sY7hC1jT4",  # not in weak list
        )
        tester = AuthTester(timeout=5.0)
        result = AuthResult(target="http://test.local")

        async with httpx.AsyncClient() as client:
            await tester._check_weak_secret(client, "http://test.local", strong_jwt, result)

        assert result.vulnerable is False

    @pytest.mark.asyncio
    async def test_non_hmac_jwt_skipped(self):
        """Non-HS256 JWT (e.g. RS256) should not be brute-forced."""
        rs256_jwt = _make_jwt(
            {"alg": "RS256", "typ": "JWT"},
            {"sub": "user1"},
            secret="secret",
        )
        # Modify the alg to RS256 (signature will be invalid, but we only check alg)
        parts = rs256_jwt.split(".")
        new_header = _b64url_encode(b'{"alg":"RS256","typ":"JWT"}')
        rs256_jwt_fake = f"{new_header}.{parts[1]}.{parts[2]}"

        tester = AuthTester(timeout=5.0)
        result = AuthResult(target="http://test.local")

        async with httpx.AsyncClient() as client:
            await tester._check_weak_secret(client, "http://test.local", rs256_jwt_fake, result)

        assert result.vulnerable is False


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# JWT extraction from headers/cookies
# ---------------------------------------------------------------------------


class TestExtractAllJwts:
    def test_extract_jwt_from_set_cookie(self):
        """JWT in Set-Cookie header should be found."""
        tester = AuthTester()
        resp = httpx.Response(
            200,
            text="<html>No JWT here</html>",
            headers={"Set-Cookie": f"token={_SAMPLE_JWT}; Path=/; HttpOnly"},
        )
        jwts = tester._extract_all_jwts(resp)
        assert len(jwts) == 1

    def test_extract_jwt_from_auth_header(self):
        """JWT in Authorization response header should be found."""
        tester = AuthTester()
        resp = httpx.Response(
            200,
            text="<html>No JWT here</html>",
            headers={"Authorization": f"Bearer {_SAMPLE_JWT}"},
        )
        jwts = tester._extract_all_jwts(resp)
        assert len(jwts) == 1

    def test_extract_jwt_deduplicates(self):
        """Same JWT in body and cookie should be returned only once."""
        tester = AuthTester()
        resp = httpx.Response(
            200,
            text=f'<html><p>Token: {_SAMPLE_JWT}</p></html>',
            headers={"Set-Cookie": f"jwt={_SAMPLE_JWT}; Path=/"},
        )
        jwts = tester._extract_all_jwts(resp)
        assert len(jwts) == 1


class TestAuthToolRegistration:
    def test_auth_test_registered(self):
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "auth_test" in registry.available_tools

    def test_auth_test_schema(self):
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        schemas = registry.get_schemas()
        schema = next(s for s in schemas if s["function"]["name"] == "auth_test")
        assert "url" in schema["function"]["parameters"]["properties"]
        assert schema["function"]["parameters"]["required"] == ["url"]
