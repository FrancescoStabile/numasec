"""Tests for security_mcp.mcp module (legacy tools + server utilities)."""

from __future__ import annotations

import pytest

from security_mcp.mcp.server import (
    InvalidTarget,
    RateLimiter,
    SessionRateLimiter,
    _is_internal_ip,
    validate_target,
)


class TestValidateTarget:
    def test_valid_external_url(self):
        result = validate_target("https://example.com")
        assert result == "https://example.com"

    def test_valid_ip(self):
        result = validate_target("93.184.216.34")
        assert result == "93.184.216.34"

    def test_valid_bare_hostname(self):
        result = validate_target("example.com")
        assert result == "example.com"

    def test_rejects_internal_127(self):
        with pytest.raises(InvalidTarget, match="Internal"):
            validate_target("http://127.0.0.1")

    def test_rejects_localhost(self):
        with pytest.raises(InvalidTarget, match="Internal"):
            validate_target("http://localhost")

    def test_rejects_10_network(self):
        with pytest.raises(InvalidTarget, match="Internal"):
            validate_target("http://10.0.0.1")

    def test_rejects_172_16(self):
        with pytest.raises(InvalidTarget, match="Internal"):
            validate_target("http://172.16.0.1")

    def test_rejects_192_168(self):
        with pytest.raises(InvalidTarget, match="Internal"):
            validate_target("http://192.168.1.1")

    def test_rejects_long_target(self):
        with pytest.raises(InvalidTarget, match="too long"):
            validate_target("a" * 254)

    def test_rejects_ftp_scheme(self):
        with pytest.raises(InvalidTarget, match="Scheme not allowed"):
            validate_target("ftp://example.com")

    def test_allows_https(self):
        assert validate_target("https://test.example.com") == "https://test.example.com"


class TestIsInternalIp:
    def test_localhost(self):
        assert _is_internal_ip("localhost") is True

    def test_loopback(self):
        assert _is_internal_ip("127.0.0.1") is True

    def test_private_10(self):
        assert _is_internal_ip("10.0.0.1") is True

    def test_private_172(self):
        assert _is_internal_ip("172.16.5.1") is True

    def test_private_192(self):
        assert _is_internal_ip("192.168.0.1") is True

    def test_ipv6_loopback(self):
        assert _is_internal_ip("::1") is True

    def test_external_ip(self):
        assert _is_internal_ip("93.184.216.34") is False

    def test_hostname(self):
        # Non-IP hostnames that aren't in blocklist
        assert _is_internal_ip("example.com") is False


class TestRateLimiter:
    def test_allows_under_limit(self):
        rl = RateLimiter(max_per_minute=10, max_concurrent=3)
        assert rl.check() is True

    def test_blocks_over_per_minute(self):
        rl = RateLimiter(max_per_minute=2, max_concurrent=10)
        rl.acquire()
        rl.release()
        rl.acquire()
        rl.release()
        assert rl.check() is False

    def test_blocks_over_concurrent(self):
        rl = RateLimiter(max_per_minute=100, max_concurrent=2)
        rl.acquire()
        rl.acquire()
        assert rl.check() is False

    def test_release_decrements(self):
        rl = RateLimiter(max_per_minute=100, max_concurrent=1)
        rl.acquire()
        assert rl.check() is False
        rl.release()
        assert rl.check() is True

    def test_release_never_negative(self):
        rl = RateLimiter()
        rl.release()
        rl.release()
        assert rl._active == 0


class TestSessionRateLimiter:
    """Tests for per-session rate limiting (multi-agent support)."""

    def test_separate_buckets_per_session(self):
        srl = SessionRateLimiter(per_minute=2, concurrent=1, global_per_minute=100, global_concurrent=10)
        # Session A fills its bucket
        srl.acquire(session_id="sess-a")
        assert srl.check(session_id="sess-a") is False  # concurrent=1, already active
        # Session B is independent
        assert srl.check(session_id="sess-b") is True
        srl.acquire(session_id="sess-b")
        assert srl.check(session_id="sess-b") is False

    def test_global_bucket_for_none_session(self):
        srl = SessionRateLimiter(per_minute=100, concurrent=100, global_per_minute=2, global_concurrent=1)
        srl.acquire(session_id=None)
        assert srl.check(session_id=None) is False  # global concurrent=1

    def test_session_does_not_affect_global(self):
        srl = SessionRateLimiter(per_minute=1, concurrent=1, global_per_minute=100, global_concurrent=10)
        srl.acquire(session_id="sess-a")
        assert srl.check(session_id="sess-a") is False
        # Global bucket is unaffected
        assert srl.check(session_id=None) is True

    def test_release_restores_capacity(self):
        srl = SessionRateLimiter(per_minute=100, concurrent=1, global_per_minute=100, global_concurrent=10)
        srl.acquire(session_id="sess-a")
        assert srl.check(session_id="sess-a") is False
        srl.release(session_id="sess-a")
        assert srl.check(session_id="sess-a") is True

    def test_remove_session_cleans_bucket(self):
        srl = SessionRateLimiter(per_minute=100, concurrent=5, global_per_minute=100, global_concurrent=10)
        srl.acquire(session_id="sess-a")
        assert srl.active_sessions == 1
        srl.remove_session("sess-a")
        assert srl.active_sessions == 0

    def test_per_minute_limit_per_session(self):
        srl = SessionRateLimiter(per_minute=2, concurrent=10, global_per_minute=100, global_concurrent=10)
        srl.acquire(session_id="sess-a")
        srl.release(session_id="sess-a")
        srl.acquire(session_id="sess-a")
        srl.release(session_id="sess-a")
        # 2 calls/min exhausted for sess-a
        assert srl.check(session_id="sess-a") is False
        # sess-b still has budget
        assert srl.check(session_id="sess-b") is True

    def test_env_var_defaults(self, monkeypatch):
        monkeypatch.setenv("SECMCP_RATE_PER_MINUTE", "42")
        monkeypatch.setenv("SECMCP_RATE_CONCURRENT", "7")
        monkeypatch.setenv("SECMCP_RATE_GLOBAL_PER_MINUTE", "200")
        monkeypatch.setenv("SECMCP_RATE_GLOBAL_CONCURRENT", "15")
        srl = SessionRateLimiter()
        assert srl.per_minute == 42
        assert srl.concurrent == 7
        assert srl._global.max_per_minute == 200
        assert srl._global.max_concurrent == 15

    def test_many_sessions_independent(self):
        """Simulate 5 concurrent agents, each with their own session."""
        srl = SessionRateLimiter(per_minute=10, concurrent=2, global_per_minute=200, global_concurrent=50)
        sessions = [f"mcp-{i:08x}" for i in range(5)]
        # Each session acquires 2 (hitting concurrent limit)
        for sid in sessions:
            srl.acquire(session_id=sid)
            srl.acquire(session_id=sid)
        # All sessions are at concurrent limit
        for sid in sessions:
            assert srl.check(session_id=sid) is False
        # Release one slot each
        for sid in sessions:
            srl.release(session_id=sid)
        # Now each has capacity again
        for sid in sessions:
            assert srl.check(session_id=sid) is True
        assert srl.active_sessions == 5


