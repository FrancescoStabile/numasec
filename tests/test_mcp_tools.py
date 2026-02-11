"""
Tests for MCP Tools — formatting, quick check, mid-level wrappers.

Tests the tool implementation layer that sits between MCP server
and the NumaSec engine. These tests mock the engine to be fast.
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from numasec.mcp_tools import (
    format_assessment_markdown,
    format_quick_check_markdown,
    SEVERITY_ICONS,
    SEVERITY_ORDER,
    _extract_tech_summary,
    _extract_port_summary,
    _extract_vuln_summary,
)


# ═══════════════════════════════════════════════════════════════════════════
# Markdown Formatting
# ═══════════════════════════════════════════════════════════════════════════


class TestFormatAssessmentMarkdown:
    def test_with_findings(self):
        findings = [
            {"title": "SQL Injection in /api", "severity": "critical",
             "description": "Error-based SQLi", "evidence": "id=1' AND 1=1--"},
            {"title": "Missing CSP header", "severity": "low",
             "description": "No Content-Security-Policy", "evidence": ""},
        ]
        md = format_assessment_markdown(
            target="http://localhost:3000",
            findings=findings,
            cost=0.12,
            duration=120.0,
            provider="deepseek",
            tools_used=15,
        )
        # Check structure
        assert "NumaSec Assessment" in md
        assert "localhost:3000" in md
        assert "2 vulnerabilities" in md
        assert "$0.12" in md
        assert "120s" in md
        # Check severity icons
        assert "🔴" in md  # critical
        assert "🔵" in md  # low
        # Check ordering: critical before low
        crit_pos = md.index("CRITICAL")
        low_pos = md.index("LOW")
        assert crit_pos < low_pos
        # Check evidence included
        assert "1=1--" in md

    def test_no_findings(self):
        md = format_assessment_markdown(
            target="http://secure.app",
            findings=[],
            cost=0.08,
            duration=60.0,
            provider="deepseek",
            tools_used=10,
        )
        assert "No vulnerabilities found" in md
        assert "secure" in md.lower() or "appears secure" in md.lower() or "No vulnerabilities" in md

    def test_footer_has_powered_by(self):
        md = format_assessment_markdown(
            target="http://test",
            findings=[],
            cost=0.05,
            duration=30.0,
            provider="deepseek",
            tools_used=5,
        )
        assert "NumaSec" in md
        assert "$0.05" in md


class TestFormatQuickCheckMarkdown:
    def test_basic_format(self):
        md = format_quick_check_markdown(
            target="http://localhost:3000",
            tech_info='{"status_code": 200, "title": "Test App", "tech": ["React", "Express"]}',
            port_info='{"ports": [{"port": 22, "state": "open", "service": "ssh"}]}',
            vuln_info='{"findings": [{"severity": "critical", "name": "Log4Shell"}]}',
            cost=0.01,
            duration=25.0,
        )
        assert "Quick Check" in md
        assert "localhost:3000" in md
        assert "$0.01" in md

    def test_suggests_full_assessment(self):
        md = format_quick_check_markdown(
            target="http://test",
            tech_info="",
            port_info="",
            vuln_info="",
            cost=0.01,
            duration=10.0,
        )
        assert "numasec_assess" in md

    def test_with_error_info(self):
        """Should handle error responses gracefully."""
        md = format_quick_check_markdown(
            target="http://unreachable",
            tech_info='{"error": "connection refused"}',
            port_info='{"error": "host down"}',
            vuln_info='{"error": "scan failed"}',
            cost=0.01,
            duration=5.0,
        )
        # Should not crash, should still produce valid Markdown
        assert "Quick Check" in md


# ═══════════════════════════════════════════════════════════════════════════
# Extract Helpers
# ═══════════════════════════════════════════════════════════════════════════


class TestExtractHelpers:
    def test_extract_tech_summary_json(self):
        raw = json.dumps({"status_code": 200, "title": "My App", "tech": ["React", "Node.js"], "webserver": "nginx"})
        result = _extract_tech_summary(raw)
        assert "200" in result
        assert "My App" in result
        assert "React" in result
        assert "nginx" in result

    def test_extract_tech_summary_invalid_json(self):
        result = _extract_tech_summary("This is not JSON at all")
        assert "This is not JSON" in result  # Falls back to raw[:500]

    def test_extract_port_summary_json(self):
        raw = json.dumps({"ports": [
            {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH 8.2"},
            {"port": 80, "state": "open", "service": "http"},
        ]})
        result = _extract_port_summary(raw)
        assert "22" in result
        assert "ssh" in result
        assert "OpenSSH 8.2" in result
        assert "80" in result
        assert "http" in result

    def test_extract_port_summary_raw(self):
        result = _extract_port_summary("22/tcp open ssh\n80/tcp open http")
        assert "22/tcp" in result

    def test_extract_vuln_summary_json(self):
        raw = json.dumps({"findings": [
            {"severity": "critical", "name": "Log4Shell"},
            {"severity": "high", "name": "XSS"},
        ]})
        result = _extract_vuln_summary(raw)
        assert "🔴" in result
        assert "CRITICAL" in result
        assert "Log4Shell" in result
        assert "🟠" in result

    def test_extract_vuln_summary_empty(self):
        raw = json.dumps({"findings": []})
        result = _extract_vuln_summary(raw)
        assert result == ""


# ═══════════════════════════════════════════════════════════════════════════
# Severity Icons
# ═══════════════════════════════════════════════════════════════════════════


class TestSeverityIcons:
    def test_all_severities_have_icons(self):
        for sev in SEVERITY_ORDER:
            assert sev in SEVERITY_ICONS

    def test_icon_values(self):
        assert SEVERITY_ICONS["critical"] == "🔴"
        assert SEVERITY_ICONS["high"] == "🟠"
        assert SEVERITY_ICONS["medium"] == "🟡"
        assert SEVERITY_ICONS["low"] == "🔵"
        assert SEVERITY_ICONS["info"] == "⚪"


# ═══════════════════════════════════════════════════════════════════════════
# run_create_finding (standalone, no mocks needed)
# ═══════════════════════════════════════════════════════════════════════════


class TestRunCreateFinding:
    @pytest.mark.asyncio
    async def test_create_finding_markdown(self):
        from numasec.mcp_tools import run_create_finding
        result = await run_create_finding(
            title="SQL Injection in /api/users",
            severity="critical",
            description="Error-based SQL injection in the id parameter.",
            evidence="GET /api/users?id=1' AND 1=1-- → 200 OK",
        )
        assert "🔴" in result
        assert "CRITICAL" in result
        assert "SQL Injection" in result
        assert "Error-based" in result
        assert "1=1--" in result
        assert "Finding registered" in result

    @pytest.mark.asyncio
    async def test_create_finding_no_evidence(self):
        from numasec.mcp_tools import run_create_finding
        result = await run_create_finding(
            title="Missing X-Frame-Options",
            severity="low",
            description="Missing clickjacking protection header.",
        )
        assert "🔵" in result
        assert "LOW" in result
        assert "Missing X-Frame-Options" in result


# ═══════════════════════════════════════════════════════════════════════════
# run_quick_check (mock external tools)
# ═══════════════════════════════════════════════════════════════════════════


class TestRunQuickCheck:
    @pytest.mark.asyncio
    async def test_quick_check_python_native(self):
        """Quick check should work using only Python httpx library (no external tools)."""
        from numasec.mcp_tools import run_quick_check

        # Mock httpx.AsyncClient to avoid real network calls
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><title>Test App</title></html>"
        mock_response.headers = MagicMock()
        mock_response.headers.get = MagicMock(side_effect=lambda k, d="": {
            "server": "nginx", "content-type": "text/html",
            "x-content-type-options": "nosniff",
        }.get(k.lower(), d) if isinstance(d, str) else d)
        mock_response.headers.multi_items = MagicMock(return_value=[
            ("server", "nginx"), ("content-type", "text/html"),
            ("x-content-type-options", "nosniff"),
        ])

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("numasec.mcp_tools.httpx_lib.AsyncClient", return_value=mock_client):
            result = await run_quick_check(
                target="http://localhost:3000",
                progress_callback=None,
            )

        assert "Quick Check" in result
        assert "localhost:3000" in result

    @pytest.mark.asyncio
    async def test_quick_check_with_progress(self):
        """Progress callback should be called for each check phase."""
        from numasec.mcp_tools import run_quick_check

        progress_calls = []

        async def progress(step, total, msg):
            progress_calls.append((step, total, msg))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><title>Test</title></html>"
        mock_response.headers = MagicMock()
        mock_response.headers.get = MagicMock(side_effect=lambda k, d="": {
            "server": "test", "content-type": "text/html",
        }.get(k.lower(), d) if isinstance(d, str) else d)
        mock_response.headers.multi_items = MagicMock(return_value=[("server", "test")])

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("numasec.mcp_tools.httpx_lib.AsyncClient", return_value=mock_client):
            await run_quick_check(target="http://test", progress_callback=progress)

        assert len(progress_calls) == 3

    @pytest.mark.asyncio
    async def test_quick_check_handles_connection_error(self):
        """Should not crash if connection fails."""
        from numasec.mcp_tools import run_quick_check

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("numasec.mcp_tools.httpx_lib.AsyncClient", return_value=mock_client):
            result = await run_quick_check(target="http://test")

        # Should still produce output, not crash
        assert "Quick Check" in result


# ═══════════════════════════════════════════════════════════════════════════
# run_recon (mock external tools)
# ═══════════════════════════════════════════════════════════════════════════


class TestRunRecon:
    @pytest.mark.asyncio
    async def test_recon_with_external_tools(self):
        """When external tools are available, recon uses registry."""
        from numasec.mcp_tools import run_recon

        mock_registry = MagicMock()
        mock_registry.call = AsyncMock(return_value='{"status_code": 200}')
        mock_registry.close = AsyncMock()
        mock_registry.set_scope = MagicMock()

        with patch("numasec.mcp_tools.shutil.which", return_value="/usr/bin/nmap"):
            with patch("numasec.tools.create_tool_registry", return_value=mock_registry):
                result = await run_recon(target="http://10.0.0.1")

        assert mock_registry.call.call_count >= 1
        assert "Recon" in result

    @pytest.mark.asyncio
    async def test_recon_fallback_python_native(self):
        """When no external tools, recon falls back to Python httpx."""
        from numasec.mcp_tools import run_recon

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><title>Test</title></html>"
        mock_response.headers = MagicMock()
        mock_response.headers.get = MagicMock(side_effect=lambda k, d="": {
            "server": "nginx", "content-type": "text/html",
        }.get(k.lower(), d) if isinstance(d, str) else d)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("numasec.mcp_tools.shutil.which", return_value=None):
            with patch("numasec.mcp_tools.httpx_lib.AsyncClient", return_value=mock_client):
                with patch("numasec.mcp_tools.socket.socket") as mock_sock:
                    mock_sock_inst = MagicMock()
                    mock_sock_inst.__enter__ = MagicMock(return_value=mock_sock_inst)
                    mock_sock_inst.__exit__ = MagicMock(return_value=False)
                    mock_sock_inst.connect_ex = MagicMock(return_value=1)  # Port closed
                    mock_sock.return_value = mock_sock_inst
                    result = await run_recon(target="http://test")

        assert "Recon" in result
        assert "Python-native" in result

    @pytest.mark.asyncio
    async def test_recon_full_vs_quick_with_nmap(self):
        """Full scan should use top 1000 ports, quick top 100."""
        from numasec.mcp_tools import run_recon

        calls_full = []
        calls_quick = []

        async def mock_call_full(name, args):
            calls_full.append((name, args))
            return "{}"

        async def mock_call_quick(name, args):
            calls_quick.append((name, args))
            return "{}"

        for scan_type, calls, mock_fn in [("full", calls_full, mock_call_full), ("quick", calls_quick, mock_call_quick)]:
            mr = MagicMock()
            mr.call = mock_fn
            mr.close = AsyncMock()
            mr.set_scope = MagicMock()

            with patch("numasec.mcp_tools.shutil.which", return_value="/usr/bin/nmap"):
                with patch("numasec.tools.create_tool_registry", return_value=mr):
                    await run_recon(target="http://test", scan_type=scan_type)

        # Full should have --top-ports 1000
        nmap_full = [c for c in calls_full if c[0] == "nmap"][0]
        assert "1000" in nmap_full[1].get("options", "")

        # Quick should have --top-ports 100
        nmap_quick = [c for c in calls_quick if c[0] == "nmap"][0]
        assert "100" in nmap_quick[1].get("options", "")


# ═══════════════════════════════════════════════════════════════════════════
# run_http_request (mock external tools)
# ═══════════════════════════════════════════════════════════════════════════


class TestRunHttpRequest:
    @pytest.mark.asyncio
    async def test_http_get_formats_markdown(self):
        from numasec.mcp_tools import run_http_request

        mock_registry = MagicMock()
        mock_registry.call = AsyncMock(return_value=json.dumps({
            "status_code": 200,
            "headers": {"Server": "nginx/1.18", "Content-Type": "text/html"},
            "body": "<html><body>Hello</body></html>",
        }))
        mock_registry.close = AsyncMock()
        mock_registry.set_scope = MagicMock()

        with patch("numasec.tools.create_tool_registry", return_value=mock_registry):
            result = await run_http_request(url="http://test/api")

        assert "HTTP GET" in result
        assert "200" in result
        assert "nginx" in result

    @pytest.mark.asyncio
    async def test_http_with_custom_headers(self):
        from numasec.mcp_tools import run_http_request

        mock_registry = MagicMock()
        mock_registry.call = AsyncMock(return_value='{"status_code": 401}')
        mock_registry.close = AsyncMock()
        mock_registry.set_scope = MagicMock()

        with patch("numasec.tools.create_tool_registry", return_value=mock_registry):
            result = await run_http_request(
                url="http://test/api",
                method="POST",
                headers={"Authorization": "Bearer token123"},
                data='{"user": "test"}',
            )

        # Verify the call was made with headers
        call_args = mock_registry.call.call_args
        assert call_args[0][1].get("headers") == {"Authorization": "Bearer token123"}


# ═══════════════════════════════════════════════════════════════════════════
# run_browser_action (mock external tools)
# ═══════════════════════════════════════════════════════════════════════════


class TestRunBrowserAction:
    @pytest.mark.asyncio
    async def test_navigate_action(self):
        from numasec.mcp_tools import run_browser_action

        mock_registry = MagicMock()
        mock_registry.call = AsyncMock(return_value='{"title": "Test Page"}')
        mock_registry.close = AsyncMock()
        mock_registry.set_scope = MagicMock()

        with patch("numasec.tools.create_tool_registry", return_value=mock_registry):
            result = await run_browser_action(url="http://test", action="navigate")

        mock_registry.call.assert_called_once_with("browser_navigate", {"url": "http://test"})
        assert "Browser" in result
        assert "navigate" in result

    @pytest.mark.asyncio
    async def test_fill_action(self):
        from numasec.mcp_tools import run_browser_action

        mock_registry = MagicMock()
        mock_registry.call = AsyncMock(return_value="OK")
        mock_registry.close = AsyncMock()
        mock_registry.set_scope = MagicMock()

        with patch("numasec.tools.create_tool_registry", return_value=mock_registry):
            result = await run_browser_action(
                url="http://test",
                action="fill",
                selector="#username",
                value="admin",
            )

        mock_registry.call.assert_called_once_with(
            "browser_fill",
            {"url": "http://test", "selector": "#username", "value": "admin"},
        )
