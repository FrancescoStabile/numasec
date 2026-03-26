"""Tests for MCP tool bridge."""

from __future__ import annotations

import json

import pytest

from security_mcp.mcp.tool_bridge import DEFAULT_EXCLUDED, bridge_tools_to_mcp
from security_mcp.tools._base import ToolRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_registry(*names: str) -> ToolRegistry:
    """Build a minimal ToolRegistry with dummy async tools."""
    reg = ToolRegistry()
    for name in names:

        async def _dummy(_name: str = name, **kwargs):  # noqa: ARG001
            return {"tool": _name, "ok": True}

        reg.register(name, _dummy, {
            "name": name,
            "description": f"Dummy {name}",
            "parameters": {"type": "object", "properties": {}, "required": []},
        })
    return reg


class _FakeMCP:
    """Minimal stand-in for FastMCP that records tool() calls."""

    def __init__(self) -> None:
        self.registered: dict[str, dict] = {}

    def tool(self, *, name: str, description: str):
        """Mimics FastMCP.tool() decorator pattern."""
        def decorator(func):
            self.registered[name] = {
                "func": func,
                "description": description,
            }
            return func
        return decorator


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDefaultExcluded:
    def test_run_command_excluded(self):
        assert "run_command" in DEFAULT_EXCLUDED

    def test_is_frozenset(self):
        assert isinstance(DEFAULT_EXCLUDED, frozenset)


class TestBridgeToolsToMcp:
    def test_registers_non_excluded_tools(self):
        reg = _make_registry("http_request", "fetch_page", "run_command")
        mcp = _FakeMCP()

        count = bridge_tools_to_mcp(mcp, reg)

        assert count == 2
        assert "http_request" in mcp.registered
        assert "fetch_page" in mcp.registered
        assert "run_command" not in mcp.registered

    def test_custom_exclusion(self):
        reg = _make_registry("http_request", "dns_lookup", "fetch_page")
        mcp = _FakeMCP()

        count = bridge_tools_to_mcp(
            mcp, reg, excluded={"http_request", "dns_lookup"},
        )

        assert count == 1
        assert "fetch_page" in mcp.registered

    def test_empty_exclusion_registers_all(self):
        reg = _make_registry("http_request", "run_command")
        mcp = _FakeMCP()

        count = bridge_tools_to_mcp(mcp, reg, excluded=set())

        assert count == 2
        assert "run_command" in mcp.registered

    def test_empty_registry(self):
        reg = ToolRegistry()
        mcp = _FakeMCP()

        count = bridge_tools_to_mcp(mcp, reg)

        assert count == 0
        assert mcp.registered == {}

    def test_description_propagated(self):
        reg = _make_registry("http_request")
        mcp = _FakeMCP()

        bridge_tools_to_mcp(mcp, reg)

        assert mcp.registered["http_request"]["description"] == "Dummy http_request"

    def test_respects_scope(self):
        """Only scoped tools should be bridged."""
        reg = _make_registry("http_request", "dns_lookup", "fetch_page")
        reg.set_scope({"http_request", "dns_lookup"})
        mcp = _FakeMCP()

        count = bridge_tools_to_mcp(mcp, reg)

        assert count == 2
        assert "fetch_page" not in mcp.registered


class TestMcpWrapper:
    """Test the async wrapper functions produced by the bridge."""

    @pytest.mark.asyncio
    async def test_wrapper_returns_json_for_dict(self):
        reg = _make_registry("http_request")
        mcp = _FakeMCP()
        bridge_tools_to_mcp(mcp, reg)

        wrapper = mcp.registered["http_request"]["func"]
        result = await wrapper()

        parsed = json.loads(result)
        assert parsed["tool"] == "http_request"
        assert parsed["ok"] is True

    @pytest.mark.asyncio
    async def test_wrapper_returns_error_json_on_failure(self):
        reg = ToolRegistry()

        async def _failing(**kwargs):  # noqa: ARG001
            raise RuntimeError("boom")

        reg.register("bad_tool", _failing, {
            "name": "bad_tool",
            "description": "A tool that fails",
            "parameters": {"type": "object", "properties": {}},
        })

        mcp = _FakeMCP()
        bridge_tools_to_mcp(mcp, reg)

        wrapper = mcp.registered["bad_tool"]["func"]
        result = await wrapper()

        parsed = json.loads(result)
        assert "error" in parsed
        assert parsed["tool"] == "bad_tool"
        assert "boom" in parsed["error"]

    @pytest.mark.asyncio
    async def test_wrapper_delegates_kwargs(self):
        """Verify keyword arguments are forwarded to the underlying tool."""
        reg = ToolRegistry()
        received = {}

        async def _echo(**kwargs):
            received.update(kwargs)
            return kwargs

        reg.register("echo", _echo, {
            "name": "echo",
            "description": "echo",
            "parameters": {"type": "object", "properties": {}},
        })

        mcp = _FakeMCP()
        bridge_tools_to_mcp(mcp, reg)

        wrapper = mcp.registered["echo"]["func"]
        await wrapper(url="https://example.com", method="POST")

        assert received["url"] == "https://example.com"
        assert received["method"] == "POST"
