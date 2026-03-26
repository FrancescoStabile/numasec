"""Tests for P1-B: JWT password leak and no-expiry checks in auth_tester."""

import json

from security_mcp.scanners.auth_tester import (
    AuthResult,
    AuthTester,
    _b64url_encode,
    _decode_jwt_payload,
)


def _make_jwt(payload: dict, header: dict | None = None, secret: str = "test") -> str:
    """Build a minimal JWT for testing (header.payload.signature)."""
    import hashlib
    import hmac

    hdr = header or {"alg": "HS256", "typ": "JWT"}
    hdr_b64 = _b64url_encode(json.dumps(hdr, separators=(",", ":")).encode())
    pay_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{hdr_b64}.{pay_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{hdr_b64}.{pay_b64}.{sig_b64}"


class TestDecodeJwtPayload:
    def test_decodes_valid_jwt(self):
        token = _make_jwt({"sub": "user1", "role": "admin"})
        payload = _decode_jwt_payload(token)
        assert payload is not None
        assert payload["sub"] == "user1"
        assert payload["role"] == "admin"

    def test_returns_none_for_invalid(self):
        assert _decode_jwt_payload("not-a-jwt") is None
        assert _decode_jwt_payload("a.b") is None

    def test_returns_none_for_bad_base64(self):
        assert _decode_jwt_payload("!!!.!!!.!!!") is None


class TestPasswordInJwt:
    def test_detects_password_field(self):
        token = _make_jwt({"sub": "1", "email": "a@b.com", "password": "0c2719..."})
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_password_in_jwt(token, result)
        assert result.vulnerable is True
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].vuln_type == "jwt_password_leak"
        assert result.vulnerabilities[0].param == "password"

    def test_detects_totpsecret_field(self):
        token = _make_jwt({"sub": "1", "totpSecret": "JBSWY3DPEHPK3PXP"})
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_password_in_jwt(token, result)
        assert result.vulnerable is True
        assert any(v.param == "totpSecret" for v in result.vulnerabilities)

    def test_detects_secret_field(self):
        token = _make_jwt({"sub": "1", "secret": "my-api-secret"})
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_password_in_jwt(token, result)
        assert result.vulnerable is True
        assert any(v.param == "secret" for v in result.vulnerabilities)

    def test_no_false_positive_on_safe_payload(self):
        token = _make_jwt({"sub": "1", "email": "a@b.com", "role": "customer", "exp": 9999999999})
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_password_in_jwt(token, result)
        assert result.vulnerable is False
        assert len(result.vulnerabilities) == 0

    def test_multiple_sensitive_fields(self):
        token = _make_jwt({"sub": "1", "password": "hash", "totpSecret": "TOTP"})
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_password_in_jwt(token, result)
        assert len(result.vulnerabilities) == 2

    def test_truncates_long_values(self):
        token = _make_jwt({"sub": "1", "password": "a" * 100})
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_password_in_jwt(token, result)
        assert "…" in result.vulnerabilities[0].evidence


class TestNoExpiry:
    def test_detects_missing_exp(self):
        token = _make_jwt({"sub": "1", "role": "admin"})
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_no_expiry(token, result)
        assert result.vulnerable is True
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].vuln_type == "jwt_no_expiry"

    def test_no_flag_when_exp_present(self):
        token = _make_jwt({"sub": "1", "role": "admin", "exp": 9999999999})
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_no_expiry(token, result)
        assert result.vulnerable is False
        assert len(result.vulnerabilities) == 0

    def test_exp_zero_still_counts(self):
        """exp=0 is technically present (even though it's expired)."""
        token = _make_jwt({"sub": "1", "exp": 0})
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_no_expiry(token, result)
        assert result.vulnerable is False

    def test_invalid_token_ignored(self):
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_no_expiry("not-a-jwt", result)
        assert result.vulnerable is False


class TestBothChecksIntegrated:
    def test_both_password_and_no_expiry(self):
        """A JWT with password hash AND no expiry should produce 2 findings."""
        token = _make_jwt({"sub": "1", "password": "md5hash", "role": "admin"})
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_password_in_jwt(token, result)
        tester._check_no_expiry(token, result)
        assert result.vulnerable is True
        assert len(result.vulnerabilities) == 2
        types = {v.vuln_type for v in result.vulnerabilities}
        assert types == {"jwt_password_leak", "jwt_no_expiry"}

    def test_safe_token_passes_both(self):
        """A token with exp and no sensitive fields should pass both checks."""
        token = _make_jwt({"sub": "1", "email": "a@b.com", "exp": 9999999999})
        tester = AuthTester()
        result = AuthResult(target="http://test")
        tester._check_password_in_jwt(token, result)
        tester._check_no_expiry(token, result)
        assert result.vulnerable is False
        assert len(result.vulnerabilities) == 0
