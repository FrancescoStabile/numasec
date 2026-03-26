"""Tests for MCP singleton module."""
from security_mcp.mcp._singletons import (
    get_kb,
    get_mcp_session_store,
    get_tool_registry,
    reset_all,
)


class TestMCPSingletons:
    def setup_method(self):
        reset_all()

    def test_get_kb_creates_on_first_call(self):
        kb = get_kb()
        assert kb is not None
        # Verify it has chunks loaded
        results = kb.query("SQL injection", top_k=1)
        assert len(results) > 0

    def test_get_kb_returns_same_instance(self):
        kb1 = get_kb()
        kb2 = get_kb()
        assert kb1 is kb2

    def test_get_tool_registry_creates_on_first_call(self):
        reg = get_tool_registry()
        assert reg is not None
        tools = reg.available_tools
        assert len(tools) > 0

    def test_get_tool_registry_returns_same_instance(self):
        reg1 = get_tool_registry()
        reg2 = get_tool_registry()
        assert reg1 is reg2

    def test_reset_all_clears_singletons(self):
        kb1 = get_kb()
        reset_all()
        kb2 = get_kb()
        assert kb1 is not kb2  # New instance after reset

    def test_get_mcp_session_store_creates_on_first_call(self):
        store = get_mcp_session_store()
        assert store is not None

    def test_get_mcp_session_store_returns_same_instance(self):
        store1 = get_mcp_session_store()
        store2 = get_mcp_session_store()
        assert store1 is store2

    def test_reset_all_clears_mcp_session_store(self):
        store1 = get_mcp_session_store()
        reset_all()
        store2 = get_mcp_session_store()
        assert store1 is not store2  # New instance after reset
