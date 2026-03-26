"""Tests for security_mcp.security.sandbox module."""

from __future__ import annotations

import pytest

from security_mcp.security.sandbox import TargetNotAllowed, ToolOutput, ToolSandbox, ToolTimeout


class TestToolOutput:
    def test_defaults(self):
        out = ToolOutput()
        assert out.stdout == b""
        assert out.stderr == b""
        assert out.rc == 0

    def test_with_data(self):
        out = ToolOutput(stdout=b"hello", stderr=b"warn", rc=1)
        assert out.stdout == b"hello"
        assert out.rc == 1


class TestToolSandbox:
    def test_extract_target_host_flag(self):
        sandbox = ToolSandbox()
        assert sandbox._extract_target(["naabu", "-host", "example.com"]) == "example.com"

    def test_extract_target_url_flag(self):
        sandbox = ToolSandbox()
        assert sandbox._extract_target(["curl", "--url", "http://test.com"]) == "http://test.com"

    def test_extract_target_equals_syntax(self):
        sandbox = ToolSandbox()
        assert sandbox._extract_target(["tool", "--host=example.com"]) == "example.com"

    def test_extract_target_last_arg_fallback(self):
        sandbox = ToolSandbox()
        assert sandbox._extract_target(["nmap", "-sT", "example.com"]) == "example.com"

    def test_extract_target_no_target(self):
        sandbox = ToolSandbox()
        assert sandbox._extract_target(["echo"]) == ""

    def test_is_allowed_exact_match(self):
        sandbox = ToolSandbox()
        assert sandbox._is_allowed_target("example.com", ["example.com"]) is True

    def test_is_allowed_wildcard(self):
        sandbox = ToolSandbox()
        assert sandbox._is_allowed_target("sub.example.com", ["*.example.com"]) is True

    def test_is_allowed_wildcard_base_domain(self):
        sandbox = ToolSandbox()
        assert sandbox._is_allowed_target("example.com", ["*.example.com"]) is True

    def test_is_not_allowed(self):
        sandbox = ToolSandbox()
        assert sandbox._is_allowed_target("evil.com", ["example.com"]) is False

    def test_is_allowed_cidr(self):
        sandbox = ToolSandbox()
        assert sandbox._is_allowed_target("192.168.1.5", ["192.168.1.0/24"]) is True

    def test_is_not_allowed_cidr(self):
        sandbox = ToolSandbox()
        assert sandbox._is_allowed_target("10.0.0.1", ["192.168.1.0/24"]) is False

    def test_empty_target_not_allowed(self):
        sandbox = ToolSandbox()
        assert sandbox._is_allowed_target("", ["example.com"]) is False

    @pytest.mark.asyncio
    async def test_run_simple_command(self):
        sandbox = ToolSandbox()
        result = await sandbox.run(["python", "-c", "print('hello')"], timeout=10)
        assert result.rc == 0
        assert b"hello" in result.stdout

    @pytest.mark.asyncio
    async def test_run_target_not_allowed(self):
        sandbox = ToolSandbox()
        with pytest.raises(TargetNotAllowed):
            await sandbox.run(
                ["nmap", "-host", "evil.com"],
                allowed_targets=["example.com"],
            )

    @pytest.mark.asyncio
    async def test_run_timeout(self):
        sandbox = ToolSandbox()
        with pytest.raises(ToolTimeout):
            await sandbox.run(
                ["python", "-c", "import time; time.sleep(10)"],
                timeout=1,
            )

    @pytest.mark.asyncio
    async def test_run_no_target_validation(self):
        """When allowed_targets is None, skip validation."""
        sandbox = ToolSandbox()
        result = await sandbox.run(
            ["python", "-c", "print('ok')"],
            allowed_targets=None,
            timeout=10,
        )
        assert result.rc == 0

    def test_has_bwrap_returns_bool(self):
        result = ToolSandbox._has_bwrap()
        assert isinstance(result, bool)
