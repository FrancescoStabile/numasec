"""
Tests for Agent — core agent loop (v3).
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from numasec.agent import Agent, AgentEvent, TOOL_TIMEOUTS


class TestAgentEvent:
    def test_event_creation(self):
        event = AgentEvent("text", content="Hello")
        assert event.type == "text"
        assert event.content == "Hello"

    def test_event_tool_properties(self):
        event = AgentEvent("tool_start", tool_name="nmap", arguments={"target": "10.10.10.1"})
        assert event.tool_name == "nmap"

    def test_event_defaults(self):
        event = AgentEvent("done")
        assert event.content == ""
        assert event.tool_name == ""


class TestAgent:
    def test_agent_creation(self):
        agent = Agent()
        assert agent.max_iterations == 50
        assert agent.is_running is False
        assert agent.state is not None

    def test_agent_custom_params(self):
        agent = Agent(max_iterations=10, tool_timeout=60)
        assert agent.max_iterations == 10
        assert agent.tool_timeout == 60

    def test_load_system_prompt(self):
        agent = Agent()
        assert len(agent._base_system_prompt) > 0

    def test_build_dynamic_system_prompt(self):
        agent = Agent()
        prompt = agent._build_dynamic_system_prompt()
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_compute_tool_hash(self):
        agent = Agent()
        hash1 = agent._compute_tool_hash("nmap", {"target": "10.10.10.1"})
        hash2 = agent._compute_tool_hash("nmap", {"target": "10.10.10.1"})
        hash3 = agent._compute_tool_hash("nmap", {"target": "10.10.10.2"})
        assert hash1 == hash2
        assert hash1 != hash3

    def test_detect_loop(self):
        agent = Agent()
        # First call — not a loop
        assert not agent._detect_loop("nmap", {"target": "10.10.10.1"})
        # Second call — loop detected (threshold = 1, block on first repeat)
        assert agent._detect_loop("nmap", {"target": "10.10.10.1"})

    def test_detect_loop_different_args(self):
        agent = Agent()
        assert not agent._detect_loop("nmap", {"target": "10.10.10.1"})
        assert not agent._detect_loop("nmap", {"target": "10.10.10.2"})
        assert not agent._detect_loop("nmap", {"target": "10.10.10.3"})
        # No loop — all different args

    def test_get_tool_timeout(self):
        agent = Agent()
        assert agent._get_tool_timeout("nmap") == 600
        assert agent._get_tool_timeout("http") == 30
        assert agent._get_tool_timeout("unknown_tool") == agent.tool_timeout

    def test_is_failure_http(self):
        agent = Agent()
        # HTTP responses are NOT failures
        assert not agent._is_failure("http", '{"status_code": 404, "body": "Not found"}')
        assert not agent._is_failure("http", '{"status_code": 403, "body": "Forbidden"}')
        # Connection errors ARE failures
        assert agent._is_failure("http", "connection refused")
        assert agent._is_failure("http", "timeout")

    def test_is_failure_scan(self):
        agent = Agent()
        assert not agent._is_failure("nmap", "22/tcp open ssh OpenSSH 8.2")
        assert agent._is_failure("nmap", "command failed with exit code 1")

    def test_is_failure_generic(self):
        agent = Agent()
        assert agent._is_failure("run_command", "Error executing command: permission denied")
        assert not agent._is_failure("run_command", "root:x:0:0:root:/root:/bin/bash")

    def test_extract_finding(self):
        agent = Agent()
        text = "[FINDING: CRITICAL] SQL Injection in /api/users\n**Description**: Error-based SQLi\n**Evidence**: id=1' AND 1=1--"
        finding = agent._extract_finding(text)
        assert finding is not None
        assert finding.severity == "critical"
        assert "SQL Injection" in finding.title

    def test_extract_finding_no_match(self):
        agent = Agent()
        finding = agent._extract_finding("Just some normal text without findings.")
        assert finding is None

    def test_clean_rich_tags(self):
        agent = Agent()
        assert agent._clean_rich_tags("[bold]Hello[/bold]") == "Hello"
        assert agent._clean_rich_tags("[#ff0000]Red text[/]") == "Red text"
        assert agent._clean_rich_tags("") == ""

    def test_truncate_tool_result_short(self):
        agent = Agent()
        result = "Short result"
        truncated = agent._truncate_tool_result("nmap", result)
        assert truncated == result

    def test_truncate_tool_result_long(self):
        agent = Agent()
        result = "x" * 20000
        truncated = agent._truncate_tool_result("nmap", result, max_chars=5000)
        assert len(truncated) < len(result)
        assert "TRUNCATED" in truncated

    def test_pause(self):
        agent = Agent()
        agent.is_running = True
        agent.pause()
        assert agent.is_running is False

    def test_reset(self):
        agent = Agent()
        agent.state.add_message("user", "test")
        agent._recent_tool_hashes.append("abc")
        agent.error_counter["err"] = 3
        agent.reset()
        assert len(agent.state.messages) == 0
        assert len(agent._recent_tool_hashes) == 0
        assert len(agent.error_counter) == 0


class TestToolTimeouts:
    def test_timeouts_defined(self):
        assert "nmap" in TOOL_TIMEOUTS
        assert "http" in TOOL_TIMEOUTS
        assert TOOL_TIMEOUTS["nmap"] > TOOL_TIMEOUTS["http"]

    def test_all_tools_have_reasonable_timeouts(self):
        for tool, timeout in TOOL_TIMEOUTS.items():
            assert timeout > 0
            assert timeout <= 600, f"{tool} timeout {timeout} is too high"
