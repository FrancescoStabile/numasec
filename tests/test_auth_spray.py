"""Tests for password spray functionality in security_mcp.scanners.auth_tester."""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from security_mcp.scanners.auth_tester import (
    AuthResult,
    AuthTester,
    _SPRAY_DELAY,
    _SPRAY_MAX_ATTEMPTS,
    _SPRAY_PASSWORDS,
    _SPRAY_USERNAMES,
)


def _transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# Spray not run by default
# ---------------------------------------------------------------------------


class TestSprayNotRunByDefault:
    @pytest.mark.asyncio
    async def test_spray_not_run_with_default_checks(self):
        """Default checks='jwt,creds' should NOT invoke the spray method."""
        tester = AuthTester(timeout=5.0)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>Hello</html>")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _transport(handler)
            kwargs.pop("verify", None)
            original_init(self_client, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            with patch.object(tester, "_spray_credentials", new_callable=AsyncMock) as mock_spray:
                result = await tester.test("http://example.com", checks="jwt,creds")

        mock_spray.assert_not_called()


# ---------------------------------------------------------------------------
# Spray requires explicit opt-in
# ---------------------------------------------------------------------------


class TestSprayRequiresExplicitOptin:
    @pytest.mark.asyncio
    async def test_spray_runs_when_checks_include_spray(self):
        """checks='spray' should invoke the spray method."""
        tester = AuthTester(timeout=5.0)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>Hello</html>")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _transport(handler)
            kwargs.pop("verify", None)
            original_init(self_client, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            with patch.object(
                tester, "_spray_credentials", new_callable=AsyncMock, return_value=[]
            ) as mock_spray:
                result = await tester.test("http://example.com", checks="spray")

        mock_spray.assert_called_once()


# ---------------------------------------------------------------------------
# Spray rate limiting
# ---------------------------------------------------------------------------


class TestSprayRateLimiting:
    def test_spray_delay_constant(self):
        """Verify the spray delay is at least 2 seconds (hardcoded constant)."""
        assert _SPRAY_DELAY >= 2.0

    @pytest.mark.asyncio
    async def test_spray_delays_between_attempts(self):
        """The spray method sleeps between each attempt."""
        tester = AuthTester(timeout=5.0)
        sleep_calls = []

        original_sleep = asyncio.sleep

        async def tracked_sleep(delay):
            sleep_calls.append(delay)
            # Don't actually sleep in tests

        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            path = request.url.path
            # OPTIONS probe: report as live
            if request.method == "OPTIONS":
                return httpx.Response(200)
            # POST login format detection: accept username format
            if request.method == "POST" and "__probe__" in (request.content or b"").decode("utf-8", "ignore"):
                return httpx.Response(401, text="Unauthorized")
            # All login attempts fail
            return httpx.Response(401, text="Invalid credentials")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _transport(handler)
            kwargs.pop("verify", None)
            original_init(self_client, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            with patch("asyncio.sleep", side_effect=tracked_sleep):
                # Limit to just a few attempts by patching constants
                with patch("security_mcp.scanners.auth_tester._SPRAY_MAX_ATTEMPTS", 3):
                    findings = await tester._spray_credentials("http://example.com", {})

        # Every failed attempt should be followed by a delay
        for delay in sleep_calls:
            assert delay >= _SPRAY_DELAY


# ---------------------------------------------------------------------------
# Spray max attempts cap
# ---------------------------------------------------------------------------


class TestSprayMaxAttemptsCap:
    def test_max_attempts_constant(self):
        """Verify the max attempts cap is 100."""
        assert _SPRAY_MAX_ATTEMPTS == 100

    @pytest.mark.asyncio
    async def test_spray_stops_at_max(self):
        """Spray stops after hitting the max attempts cap."""
        tester = AuthTester(timeout=5.0)
        attempt_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt_count
            if request.method == "OPTIONS":
                return httpx.Response(200)
            if request.method == "POST":
                content = (request.content or b"").decode("utf-8", "ignore")
                if "__probe__" in content:
                    return httpx.Response(401, text="Unauthorized")
                attempt_count += 1
            return httpx.Response(401, text="Invalid")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _transport(handler)
            kwargs.pop("verify", None)
            original_init(self_client, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with patch("security_mcp.scanners.auth_tester._SPRAY_MAX_ATTEMPTS", 5):
                    findings = await tester._spray_credentials("http://example.com", {})

        assert attempt_count <= 5


# ---------------------------------------------------------------------------
# Spray stops on first success
# ---------------------------------------------------------------------------


class TestSprayStopsOnFirstSuccess:
    @pytest.mark.asyncio
    async def test_spray_returns_on_success(self):
        """Spray returns immediately after finding valid credentials."""
        tester = AuthTester(timeout=5.0)
        attempt_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt_count
            if request.method == "OPTIONS":
                return httpx.Response(200)
            if request.method == "POST":
                content = (request.content or b"").decode("utf-8", "ignore")
                if "__probe__" in content:
                    return httpx.Response(401, text="Unauthorized")
                attempt_count += 1
                body = json.loads(content) if content else {}
                # admin/admin succeeds
                if body.get("username") == "admin" and body.get("password") == "admin":
                    return httpx.Response(
                        200,
                        text='{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}',
                        headers={"Content-Type": "application/json"},
                    )
            return httpx.Response(401, text="Invalid")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _transport(handler)
            kwargs.pop("verify", None)
            original_init(self_client, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                findings = await tester._spray_credentials("http://example.com", {})

        assert len(findings) == 1
        assert findings[0]["type"] == "spray_valid_creds"
        assert findings[0]["severity"] == "critical"
        # Should have stopped early -- not exhausted all username x password combos
        total_possible = len(_SPRAY_USERNAMES) * len(_SPRAY_PASSWORDS)
        assert attempt_count < total_possible


# ---------------------------------------------------------------------------
# Spray uses built-in wordlists only
# ---------------------------------------------------------------------------


class TestSprayNoCustomWordlists:
    def test_spray_passwords_are_builtin(self):
        """Verify the password list is a fixed built-in list (not user-configurable)."""
        assert isinstance(_SPRAY_PASSWORDS, list)
        assert len(_SPRAY_PASSWORDS) > 0
        assert all(isinstance(p, str) for p in _SPRAY_PASSWORDS)

    def test_spray_usernames_are_builtin(self):
        """Verify the username list is a fixed built-in list."""
        assert isinstance(_SPRAY_USERNAMES, list)
        assert len(_SPRAY_USERNAMES) > 0
        assert all(isinstance(u, str) for u in _SPRAY_USERNAMES)
