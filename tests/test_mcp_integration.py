"""MCP integration tests — verify all atomic tools, intel tools, state tools register correctly."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from security_mcp.tools import create_default_tool_registry


# ---------------------------------------------------------------------------
# Mock FastMCP for testing without the actual mcp package
# ---------------------------------------------------------------------------


class MockFastMCP:
    """Minimal mock of FastMCP that records tool/resource/prompt registrations."""

    def __init__(self, name: str = "test"):
        self.name = name
        self._tools: dict[str, Any] = {}
        self._resources: dict[str, Any] = {}
        self._prompts: dict[str, Any] = {}

    def tool(self, name: str = "", description: str = ""):
        """Decorator/registrar for tools."""

        def decorator(func):
            tool_name = name or func.__name__
            self._tools[tool_name] = {
                "func": func,
                "description": description,
                "name": tool_name,
            }
            return func

        return decorator

    def resource(self, uri: str):
        """Decorator for resources."""

        def decorator(func):
            self._resources[uri] = func
            return func

        return decorator

    def prompt(self):
        """Decorator for prompts."""

        def decorator(func):
            self._prompts[func.__name__] = func
            return func

        return decorator


# ---------------------------------------------------------------------------
# ToolRegistry completeness
# ---------------------------------------------------------------------------


class TestToolRegistry:
    """Verify the ToolRegistry has all expected tools."""

    def test_registry_created_successfully(self):
        registry = create_default_tool_registry()
        assert registry is not None

    def test_expected_tools_present(self):
        registry = create_default_tool_registry()
        expected_tools = {
            "http_request",
            "recon",
            "crawl",
            "injection_test",
            "xss_test",
            "access_control_test",
            "auth_test",
            "ssrf_test",
            "path_test",
            "dir_fuzz",
            "js_analyze",
            "browser",
            "oob",
            "run_command",
        }
        actual_tools = set(registry.available_tools)
        for tool in expected_tools:
            assert tool in actual_tools, f"Missing tool: {tool}"

    def test_all_tools_have_schemas(self):
        registry = create_default_tool_registry()
        for tool_name in registry.available_tools:
            schema = registry._schemas.get(tool_name)
            assert schema is not None, f"Tool {tool_name} missing schema"
            assert "name" in schema
            assert "description" in schema
            assert "parameters" in schema

    def test_at_least_14_tools(self):
        registry = create_default_tool_registry()
        assert len(registry.available_tools) >= 14


# ---------------------------------------------------------------------------
# Tool bridge to MCP
# ---------------------------------------------------------------------------


class TestToolBridge:
    """Test bridge_tools_to_mcp correctly registers tools."""

    def test_bridge_registers_tools(self):
        from security_mcp.mcp.tool_bridge import bridge_tools_to_mcp

        mcp = MockFastMCP()
        registry = create_default_tool_registry()
        count = bridge_tools_to_mcp(mcp, registry, excluded={"run_command"})

        assert count > 0
        assert "run_command" not in mcp._tools
        assert "http_request" in mcp._tools
        assert "recon" in mcp._tools

    def test_bridge_excludes_run_command(self):
        from security_mcp.mcp.tool_bridge import bridge_tools_to_mcp

        mcp = MockFastMCP()
        registry = create_default_tool_registry()
        bridge_tools_to_mcp(mcp, registry)

        assert "run_command" not in mcp._tools

    def test_bridged_count_matches_registry_minus_excluded(self):
        from security_mcp.mcp.tool_bridge import bridge_tools_to_mcp

        mcp = MockFastMCP()
        registry = create_default_tool_registry()
        count = bridge_tools_to_mcp(mcp, registry, excluded={"run_command"})

        expected = len(registry.available_tools) - 1  # minus run_command
        assert count == expected

    def test_all_bridged_tools_have_descriptions(self):
        from security_mcp.mcp.tool_bridge import bridge_tools_to_mcp

        mcp = MockFastMCP()
        registry = create_default_tool_registry()
        bridge_tools_to_mcp(mcp, registry, excluded={"run_command"})

        for name, info in mcp._tools.items():
            assert info["description"], f"Tool {name} missing description"


# ---------------------------------------------------------------------------
# Intel tools registration
# ---------------------------------------------------------------------------


class TestIntelTools:
    """Test intelligence tools register correctly (consolidated: kb_search + plan)."""

    def test_register_adds_two_tools(self):
        from security_mcp.mcp.intel_tools import register

        mcp = MockFastMCP()
        register(mcp)

        expected = {"kb_search", "plan"}
        assert set(mcp._tools.keys()) == expected

    def test_kb_search_registered(self):
        from security_mcp.mcp.intel_tools import register

        mcp = MockFastMCP()
        register(mcp)
        assert "kb_search" in mcp._tools
        assert "knowledge base" in mcp._tools["kb_search"]["description"].lower()

    def test_kb_search_covers_cwe(self):
        from security_mcp.mcp.intel_tools import register

        mcp = MockFastMCP()
        register(mcp)
        assert "cwe" in mcp._tools["kb_search"]["description"].lower()

    def test_plan_registered(self):
        from security_mcp.mcp.intel_tools import register

        mcp = MockFastMCP()
        register(mcp)
        assert "plan" in mcp._tools
        assert "planning" in mcp._tools["plan"]["description"].lower()


# ---------------------------------------------------------------------------
# CWE lookup
# ---------------------------------------------------------------------------


class TestCWELookup:
    """Test CWE lookup table directly."""

    def test_lookup_cwe_89(self):
        from security_mcp.mcp.intel_tools import _lookup_cwe

        result = _lookup_cwe("CWE-89")
        assert result is not None
        assert "SQL Injection" in result["name"]
        assert result["severity"] == "critical"

    def test_lookup_bare_id(self):
        from security_mcp.mcp.intel_tools import _lookup_cwe

        result = _lookup_cwe("79")
        assert result is not None
        assert "Scripting" in result["name"] or "XSS" in result["name"]

    def test_lookup_nonexistent(self):
        from security_mcp.mcp.intel_tools import _lookup_cwe

        result = _lookup_cwe("CWE-99999")
        assert result is None


# ---------------------------------------------------------------------------
# State tools registration
# ---------------------------------------------------------------------------


class TestStateTools:
    """Test state management tools register correctly."""

    def test_register_adds_four_tools(self):
        from security_mcp.mcp.state_tools import register

        mcp = MockFastMCP()
        register(mcp)

        expected = {"create_session", "save_finding", "get_findings", "generate_report"}
        assert expected.issubset(set(mcp._tools.keys()))

    def test_save_finding_registered(self):
        from security_mcp.mcp.state_tools import register

        mcp = MockFastMCP()
        register(mcp)
        assert "save_finding" in mcp._tools

    def test_generate_report_registered(self):
        from security_mcp.mcp.state_tools import register

        mcp = MockFastMCP()
        register(mcp)
        assert "generate_report" in mcp._tools


# ---------------------------------------------------------------------------
# State tools functional
# ---------------------------------------------------------------------------


class TestStateToolsFunctional:
    """Test state tools actually work (create_session, save/retrieve findings).

    Uses McpSessionStore directly to verify the v2.0 state layer.
    """

    async def test_create_session(self, tmp_path):
        from unittest.mock import patch

        from security_mcp.mcp.mcp_session_store import McpSessionStore

        store = McpSessionStore(db_path=str(tmp_path / "st_integ.db"))
        with patch("security_mcp.mcp._singletons.get_mcp_session_store", return_value=store):
            from security_mcp.mcp import state_tools

            fake = MockFastMCP()
            state_tools.register(fake)
            result = await fake._tools["create_session"]["func"](target="http://test.com")

        data = json.loads(result)
        assert data["session_id"].startswith("mcp-")
        assert data["target"] == "http://test.com"
        assert data["status"] == "active"

    async def test_save_and_get_findings(self, tmp_path):
        from unittest.mock import patch

        from security_mcp.mcp.mcp_session_store import McpSessionStore

        store = McpSessionStore(db_path=str(tmp_path / "st_findings.db"))
        with patch("security_mcp.mcp._singletons.get_mcp_session_store", return_value=store):
            from security_mcp.mcp import state_tools

            fake = MockFastMCP()
            state_tools.register(fake)

            # 1. create session
            create_resp = json.loads(await fake._tools["create_session"]["func"](target="http://test.com"))
            sid = create_resp["session_id"]

            # 2. save finding
            save_resp = json.loads(
                await fake._tools["save_finding"]["func"](
                    session_id=sid,
                    title="SQL Injection",
                    severity="high",
                    url="http://test.com/login",
                )
            )
            assert save_resp["session_id"] == sid
            assert save_resp["total_findings"] == 1

            # 3. get findings
            get_resp = json.loads(await fake._tools["get_findings"]["func"](session_id=sid))
            assert get_resp["summary"]["total"] == 1
            assert get_resp["findings"][0]["title"] == "SQL Injection"


# ---------------------------------------------------------------------------
# Resources registration
# ---------------------------------------------------------------------------


class TestResourcesRegistration:
    """Test MCP resources register correctly."""

    def test_resources_registered(self):
        from security_mcp.mcp.resources import register_resources

        mcp = MockFastMCP()
        register_resources(mcp)

        # Should have at least the findings and report resource templates
        assert len(mcp._resources) >= 2


# ---------------------------------------------------------------------------
# Prompts registration
# ---------------------------------------------------------------------------


class TestPromptsRegistration:
    """Test MCP prompts register correctly."""

    def test_prompts_registered(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        assert "threat_model" in mcp._prompts
        assert "code_review" in mcp._prompts

    def test_threat_model_prompt_callable(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        result = mcp._prompts["threat_model"](target="http://example.com")
        assert "STRIDE" in result
        assert "http://example.com" in result

    def test_code_review_prompt_callable(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        result = mcp._prompts["code_review"](code="eval(user_input)")
        assert "eval(user_input)" in result
        assert "CWE" in result

    def test_security_assessment_contains_spa_workflow(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        result = mcp._prompts["security_assessment"](target="http://localhost:3000")
        assert "browser" in result

    def test_security_assessment_contains_auth_flow(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        result = mcp._prompts["security_assessment"](target="http://localhost:3000")
        assert "auth_test" in result or "auth" in result.lower()

    def test_security_assessment_contains_idor(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        result = mcp._prompts["security_assessment"](target="http://localhost:3000")
        assert "IDOR" in result or "BOLA" in result

    def test_security_assessment_reporting_no_html(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        result = mcp._prompts["security_assessment"](target="http://localhost:3000")
        # Find the REPORTING decision line and ensure it doesn't recommend "html"
        for line in result.split("\n"):
            if "Choose format:" in line:
                assert "html" not in line.lower(), f"REPORTING decision should not mention html: {line}"
                break

    def test_security_assessment_contains_coverage_gate(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        result = mcp._prompts["security_assessment"](target="http://localhost:3000")
        # The rewritten prompt enforces coverage via plan(action='coverage_gaps')
        assert "coverage" in result.lower()
        assert "mandatory" in result.lower()

    def test_security_assessment_coverage_gate_lists_all_mandatory_tools(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        result = mcp._prompts["security_assessment"](target="http://localhost:3000")
        # Consolidated tool names used in the rewritten prompt
        mandatory_tools = [
            "injection_test",
            "xss_test",
            "access_control_test",
            "auth_test",
            "ssrf_test",
            "path_test",
        ]
        for tool in mandatory_tools:
            assert tool in result, f"Coverage gate missing mandatory tool: {tool}"

    def test_security_assessment_pre_report_gate(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        result = mcp._prompts["security_assessment"](target="http://localhost:3000")
        assert "coverage_gaps" in result
        assert "plan" in result

    def test_security_assessment_owasp_reference(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        result = mcp._prompts["security_assessment"](target="http://localhost:3000")
        # The rewritten prompt references OWASP Top 10 coverage via plan(action='coverage_gaps')
        assert "OWASP" in result

    def test_security_assessment_reporting_phase_references_coverage_gaps(self):
        from security_mcp.mcp.prompts import register_prompts

        mcp = MockFastMCP()
        register_prompts(mcp)

        result = mcp._prompts["security_assessment"](target="http://localhost:3000")
        # REPORTING phase details should reference coverage_gaps via plan()
        reporting_idx = result.find("REPORTING")
        assert reporting_idx > 0, "REPORTING phase not found"
        reporting_section = result[reporting_idx : reporting_idx + 500]
        assert "coverage_gaps" in reporting_section


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------


class TestSSRFProtection:
    """Test SSRF protection in MCP server module."""

    def test_validate_target_rejects_localhost(self):
        from security_mcp.mcp.server import InvalidTarget, validate_target

        with pytest.raises(InvalidTarget):
            validate_target("http://localhost/admin")

    def test_validate_target_rejects_127(self):
        from security_mcp.mcp.server import InvalidTarget, validate_target

        with pytest.raises(InvalidTarget):
            validate_target("http://127.0.0.1/secret")

    def test_validate_target_rejects_10_network(self):
        from security_mcp.mcp.server import InvalidTarget, validate_target

        with pytest.raises(InvalidTarget):
            validate_target("http://10.0.0.1/internal")

    def test_validate_target_accepts_public(self):
        from security_mcp.mcp.server import validate_target

        result = validate_target("http://example.com")
        assert result == "http://example.com"

    def test_validate_target_rejects_long_url(self):
        from security_mcp.mcp.server import InvalidTarget, validate_target

        with pytest.raises(InvalidTarget, match="too long"):
            validate_target("http://" + "a" * 300)

    def test_validate_target_rejects_ftp(self):
        from security_mcp.mcp.server import InvalidTarget, validate_target

        with pytest.raises(InvalidTarget, match="Scheme"):
            validate_target("ftp://example.com")


# ---------------------------------------------------------------------------
# Full server creation (without actual mcp package)
# ---------------------------------------------------------------------------


class TestServerCreation:
    """Test the server factory logic (mock the FastMCP import)."""

    def test_create_mcp_server_import_error(self):
        """If mcp package is not installed, create_mcp_server raises ImportError."""
        import importlib
        import sys

        # Only test if mcp is not actually installed
        if "mcp" not in sys.modules and importlib.util.find_spec("mcp") is None:
            from security_mcp.mcp.server import create_mcp_server

            with pytest.raises(ImportError, match="mcp"):
                create_mcp_server()
