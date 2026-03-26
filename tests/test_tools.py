"""Tests for security_mcp.tools — ToolRegistry."""

from __future__ import annotations

import pytest

from security_mcp.tools._base import ToolRegistry


async def _dummy_tool(**kwargs):
    return {"result": "ok", **kwargs}


async def _echo_tool(message: str = "hello"):
    return message


class TestToolRegistryRegister:
    def test_register_tool(self):
        reg = ToolRegistry()
        reg.register("dummy", _dummy_tool, {"description": "A dummy tool"})
        assert "dummy" in reg.available_tools

    def test_register_without_schema(self):
        reg = ToolRegistry()
        reg.register("simple", _dummy_tool)
        assert "simple" in reg.available_tools


class TestToolRegistryCall:
    @pytest.mark.asyncio
    async def test_call_registered_tool(self):
        reg = ToolRegistry()
        reg.register("dummy", _dummy_tool)
        result = await reg.call("dummy", target="example.com")
        assert result["result"] == "ok"
        assert result["target"] == "example.com"

    @pytest.mark.asyncio
    async def test_call_unknown_tool_raises(self):
        reg = ToolRegistry()
        with pytest.raises(KeyError, match="not registered"):
            await reg.call("nonexistent")

    @pytest.mark.asyncio
    async def test_call_echo_tool(self):
        reg = ToolRegistry()
        reg.register("echo", _echo_tool)
        result = await reg.call("echo", message="test")
        assert result == "test"


class TestToolRegistryScope:
    def test_set_scope_restricts_tools(self):
        reg = ToolRegistry()
        reg.register("tool_a", _dummy_tool)
        reg.register("tool_b", _dummy_tool)
        reg.register("tool_c", _dummy_tool)

        reg.set_scope({"tool_a", "tool_b"})
        assert set(reg.available_tools) == {"tool_a", "tool_b"}

    @pytest.mark.asyncio
    async def test_scope_blocks_out_of_scope_tool(self):
        reg = ToolRegistry()
        reg.register("tool_a", _dummy_tool)
        reg.register("tool_b", _dummy_tool)

        reg.set_scope({"tool_a"})
        with pytest.raises(PermissionError, match="not in current scope"):
            await reg.call("tool_b")

    def test_clear_scope_restores_all(self):
        reg = ToolRegistry()
        reg.register("tool_a", _dummy_tool)
        reg.register("tool_b", _dummy_tool)

        reg.set_scope({"tool_a"})
        reg.clear_scope()
        assert set(reg.available_tools) == {"tool_a", "tool_b"}


class TestToolRegistrySchemas:
    def test_get_schemas(self):
        reg = ToolRegistry()
        reg.register("dummy", _dummy_tool, {"description": "A dummy tool", "parameters": {}})
        schemas = reg.get_schemas()
        assert len(schemas) == 1
        assert schemas[0]["type"] == "function"
        assert schemas[0]["function"]["name"] == "dummy"

    def test_schemas_respect_scope(self):
        reg = ToolRegistry()
        reg.register("a", _dummy_tool, {"description": "Tool A"})
        reg.register("b", _dummy_tool, {"description": "Tool B"})

        reg.set_scope({"a"})
        schemas = reg.get_schemas()
        names = [s["function"]["name"] for s in schemas]
        assert "a" in names
        assert "b" not in names
