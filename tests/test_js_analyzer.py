"""Tests for P1-D: JSAnalyzer scanner."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from security_mcp.scanners.js_analyzer import (
    JSAnalysisResult,
    JSAnalyzer,
    JSFinding,
    python_js_analyze,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(
    status_code: int = 200,
    text: str = "",
    content_type: str = "text/html",
) -> httpx.Response:
    """Build a fake httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        headers={"content-type": content_type},
        text=text,
        request=httpx.Request("GET", "http://test"),
    )


# ---------------------------------------------------------------------------
# Data model tests
# ---------------------------------------------------------------------------


class TestJSFinding:
    def test_defaults(self):
        f = JSFinding(
            finding_type="endpoint",
            value="/api/Users",
            source_file="main.js",
        )
        assert f.severity == "info"
        assert f.context == ""

    def test_to_dict(self):
        f = JSFinding(
            finding_type="secret",
            value="api_key: AKIAIOSFODNN7EXAMPLE",
            source_file="app.js",
            severity="critical",
            context="apiKey = 'AKIAIOSFODNN7EXAMPLE'",
        )
        d = f.to_dict()
        assert d["type"] == "secret"
        assert d["value"] == "api_key: AKIAIOSFODNN7EXAMPLE"
        assert d["source_file"] == "app.js"
        assert d["severity"] == "critical"


class TestJSAnalysisResult:
    def test_empty_result(self):
        r = JSAnalysisResult(target="http://test")
        d = r.to_dict()
        assert d["target"] == "http://test"
        assert d["js_files_analyzed"] == 0
        assert d["endpoints"] == []
        assert d["secrets_count"] == 0
        assert d["total_findings"] == 0

    def test_with_findings(self):
        r = JSAnalysisResult(
            target="http://test",
            js_files_analyzed=3,
            endpoints=["/api/Users", "/api/Products", "/api/Users"],  # duplicate
            secrets=[
                JSFinding(finding_type="secret", value="api_key: abc123", source_file="a.js", severity="high"),
            ],
            sensitive_routes=["/admin", "/debug"],
            duration_ms=456.789,
        )
        d = r.to_dict()
        assert d["js_files_analyzed"] == 3
        assert d["endpoints"] == ["/api/Products", "/api/Users"]  # sorted, deduped
        assert d["secrets_count"] == 1
        assert d["sensitive_routes"] == ["/admin", "/debug"]
        assert d["duration_ms"] == 456.79


# ---------------------------------------------------------------------------
# JS file discovery
# ---------------------------------------------------------------------------


class TestDiscoverJsFiles:
    async def test_extracts_script_tags(self):
        html = """
        <html>
        <head>
            <script src="/static/main.js"></script>
            <script src="/static/vendor.js?v=123"></script>
        </head>
        <body><script src="https://cdn.example.com/lib.js"></script></body>
        </html>
        """
        analyzer = JSAnalyzer()
        resp = _mock_response(200, text=html)

        with patch("security_mcp.scanners.js_analyzer.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            js_urls = await analyzer._discover_js_files(mock_client, "http://test")

        assert len(js_urls) >= 2
        assert any("main.js" in u for u in js_urls)
        assert any("vendor.js" in u for u in js_urls)

    async def test_handles_404(self):
        analyzer = JSAnalyzer()
        resp = _mock_response(404)

        with patch("security_mcp.scanners.js_analyzer.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            js_urls = await analyzer._discover_js_files(mock_client, "http://test")

        assert js_urls == []

    async def test_handles_http_error(self):
        analyzer = JSAnalyzer()

        with patch("security_mcp.scanners.js_analyzer.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.ConnectError("timeout"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            js_urls = await analyzer._discover_js_files(mock_client, "http://test")

        assert js_urls == []


# ---------------------------------------------------------------------------
# Endpoint extraction
# ---------------------------------------------------------------------------


class TestEndpointExtraction:
    def test_string_literal_api_paths(self):
        js = """
        const url = "/api/Users/1";
        fetch("/api/Products");
        const another = '/rest/v1/orders';
        """
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_endpoints(js, "app.js", result)

        assert "/api/Users/1" in result.endpoints
        assert "/api/Products" in result.endpoints
        assert "/rest/v1/orders" in result.endpoints

    def test_fetch_calls(self):
        js = """
        fetch("/api/checkout");
        axios.get("/api/basket/items");
        axios.post("/api/Users/login");
        """
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_endpoints(js, "app.js", result)

        assert "/api/checkout" in result.endpoints
        assert "/api/basket/items" in result.endpoints

    def test_deduplication(self):
        js = """
        fetch("/api/Users");
        fetch("/api/Users");
        const a = "/api/Users";
        """
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_endpoints(js, "app.js", result)

        assert result.endpoints.count("/api/Users") == 1

    def test_skips_short_paths(self):
        js = """const a = "/a";"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_endpoints(js, "app.js", result)

        assert len(result.endpoints) == 0


# ---------------------------------------------------------------------------
# Secret extraction
# ---------------------------------------------------------------------------


class TestSecretExtraction:
    def test_aws_access_key(self):
        js = """const key = "AKIAIOSFODNN7EXAMPLE";"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_secrets(js, "config.js", result)

        assert len(result.secrets) == 1
        assert "aws_access_key" in result.secrets[0].value
        assert result.secrets[0].severity == "critical"

    def test_api_key(self):
        js = """const apiKey = "sk_live_abcdef1234567890";"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_secrets(js, "app.js", result)

        assert len(result.secrets) >= 1
        assert any("api_key" in s.value or "generic_secret" in s.value for s in result.secrets)

    def test_jwt_token(self):
        js = """const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_secrets(js, "app.js", result)

        assert len(result.secrets) >= 1
        assert any("jwt_token" in s.value for s in result.secrets)

    def test_password_in_code(self):
        js = """const password = "SuperSecret123!";"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_secrets(js, "app.js", result)

        assert len(result.secrets) >= 1

    def test_skips_placeholder(self):
        js = """const password = "password";"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_secrets(js, "app.js", result)

        # "password" literal should be skipped (placeholder)
        pwd_secrets = [s for s in result.secrets if "password" in s.value.lower() and "password:" in s.value.lower()]
        assert len(pwd_secrets) == 0

    def test_github_token(self):
        js = """const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234";"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_secrets(js, "app.js", result)

        assert len(result.secrets) >= 1
        assert any("github_token" in s.value for s in result.secrets)

    def test_no_false_positive_on_clean_code(self):
        js = """
        function calculate(a, b) { return a + b; }
        const x = 42;
        console.log("hello world");
        """
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_secrets(js, "app.js", result)

        assert len(result.secrets) == 0


# ---------------------------------------------------------------------------
# Sensitive route extraction
# ---------------------------------------------------------------------------


class TestSensitiveRoutes:
    def test_admin_route(self):
        js = """const url = "/admin/dashboard";"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_sensitive_routes(js, "app.js", result)

        assert any("admin" in r for r in result.sensitive_routes)

    def test_debug_route(self):
        js = """const debugUrl = "/debug";"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_sensitive_routes(js, "app.js", result)

        assert any("debug" in r for r in result.sensitive_routes)

    def test_metrics_route(self):
        js = """fetch("/metrics");"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_sensitive_routes(js, "app.js", result)

        assert any("metrics" in r for r in result.sensitive_routes)

    def test_env_file_reference(self):
        js = """const config = "/.env";"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_sensitive_routes(js, "app.js", result)

        assert any(".env" in r for r in result.sensitive_routes)


# ---------------------------------------------------------------------------
# DOM XSS sink detection
# ---------------------------------------------------------------------------


class TestDomXssSinks:
    def test_innerhtml(self):
        js = """document.getElementById("x").innerHTML = userInput;"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_dom_xss_sinks(js, "app.js", result)

        assert len(result.dom_xss_sinks) >= 1
        assert any("innerHTML" in s.value for s in result.dom_xss_sinks)

    def test_document_write(self):
        js = """document.write("<h1>" + title + "</h1>");"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_dom_xss_sinks(js, "app.js", result)

        assert any("document.write" in s.value for s in result.dom_xss_sinks)

    def test_eval(self):
        js = """eval(userCode);"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_dom_xss_sinks(js, "app.js", result)

        assert any("eval" in s.value for s in result.dom_xss_sinks)

    def test_location_assign(self):
        js = """window.location = redirectUrl;"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_dom_xss_sinks(js, "app.js", result)

        assert any("location_assign" in s.value for s in result.dom_xss_sinks)

    def test_counts_occurrences(self):
        js = """
        el1.innerHTML = a;
        el2.innerHTML = b;
        el3.innerHTML = c;
        """
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_dom_xss_sinks(js, "app.js", result)

        assert len(result.dom_xss_sinks) == 1  # One entry per type
        assert "3 occurrences" in result.dom_xss_sinks[0].value

    def test_no_false_positive_on_literal_eval(self):
        js = """const evaluate = function(x) { return x * 2; };"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_dom_xss_sinks(js, "app.js", result)

        # "evaluate" should NOT trigger eval detection
        eval_sinks = [s for s in result.dom_xss_sinks if "eval" in s.value and "setTimeout" not in s.value]
        assert len(eval_sinks) == 0


# ---------------------------------------------------------------------------
# Source map detection
# ---------------------------------------------------------------------------


class TestSourceMaps:
    def test_detects_source_map(self):
        js = """
        function add(a, b) { return a + b; }
        //# sourceMappingURL=main.js.map
        """
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_source_maps(js, "main.js", result)

        assert len(result.source_maps) == 1
        assert "main.js.map" in result.source_maps[0]

    def test_detects_at_source_map(self):
        js = """
        var x = 1;
        //@ sourceMappingURL=app.bundle.js.map
        """
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._extract_source_maps(js, "app.js", result)

        assert len(result.source_maps) == 1


# ---------------------------------------------------------------------------
# Debug flag detection
# ---------------------------------------------------------------------------


class TestDebugFlags:
    def test_debug_true(self):
        js = """const debug = true;"""
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._count_debug_flags(js, result)

        assert result.debug_flags >= 1

    def test_console_log(self):
        js = """
        console.log("user data:", data);
        console.debug("token:", token);
        """
        analyzer = JSAnalyzer()
        result = JSAnalysisResult(target="http://test")
        analyzer._count_debug_flags(js, result)

        assert result.debug_flags >= 2


# ---------------------------------------------------------------------------
# Full analysis integration
# ---------------------------------------------------------------------------


class TestFullAnalysis:
    async def test_analyze_with_explicit_js_urls(self):
        js_content = """
        fetch("/api/Users");
        const apiKey = "sk_live_1234567890abcdef";
        document.getElementById("x").innerHTML = data;
        //# sourceMappingURL=main.js.map
        """
        analyzer = JSAnalyzer()

        async def mock_get(url, **kwargs):
            return _mock_response(200, text=js_content, content_type="application/javascript")

        with patch("security_mcp.scanners.js_analyzer.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=mock_get)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await analyzer.analyze(
                "http://test",
                js_urls=["http://test/static/main.js"],
            )

        assert result.js_files_analyzed == 1
        assert len(result.endpoints) >= 1
        assert len(result.dom_xss_sinks) >= 1
        assert len(result.source_maps) >= 1
        assert result.duration_ms > 0

    async def test_analyze_discovers_js_files(self):
        html = '<html><head><script src="/static/app.js"></script></head></html>'
        js_content = """fetch("/api/Products");"""

        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_response(200, text=html)
            return _mock_response(200, text=js_content, content_type="application/javascript")

        with patch("security_mcp.scanners.js_analyzer.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=mock_get)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            analyzer = JSAnalyzer()
            result = await analyzer.analyze("http://test")

        assert result.js_files_analyzed == 1
        assert "/api/Products" in result.endpoints


# ---------------------------------------------------------------------------
# Tool wrapper tests
# ---------------------------------------------------------------------------


class TestToolWrapper:
    async def test_returns_json_string(self):
        with patch(
            "security_mcp.scanners.js_analyzer.JSAnalyzer.analyze",
            new_callable=AsyncMock,
            return_value=JSAnalysisResult(target="http://test", js_files_analyzed=2, duration_ms=100.0),
        ):
            output = await python_js_analyze("http://test")
            data = json.loads(output)
            assert data["target"] == "http://test"
            assert data["js_files_analyzed"] == 2

    async def test_parses_js_files_csv(self):
        with patch(
            "security_mcp.scanners.js_analyzer.JSAnalyzer.analyze",
            new_callable=AsyncMock,
            return_value=JSAnalysisResult(target="http://test"),
        ) as mock_analyze:
            await python_js_analyze(
                "http://test",
                js_files="http://test/a.js, http://test/b.js",
            )
            call_kwargs = mock_analyze.call_args
            assert call_kwargs[1]["js_urls"] == ["http://test/a.js", "http://test/b.js"]

    async def test_parses_headers_json(self):
        with patch(
            "security_mcp.scanners.js_analyzer.JSAnalyzer.analyze",
            new_callable=AsyncMock,
            return_value=JSAnalysisResult(target="http://test"),
        ) as mock_analyze:
            await python_js_analyze(
                "http://test",
                headers='{"Authorization": "Bearer token123"}',
            )
            call_kwargs = mock_analyze.call_args
            assert call_kwargs[1]["headers"] == {"Authorization": "Bearer token123"}

    async def test_handles_invalid_headers_json(self):
        with patch(
            "security_mcp.scanners.js_analyzer.JSAnalyzer.analyze",
            new_callable=AsyncMock,
            return_value=JSAnalysisResult(target="http://test"),
        ) as mock_analyze:
            await python_js_analyze("http://test", headers="not-valid-json")
            call_kwargs = mock_analyze.call_args
            assert call_kwargs[1]["headers"] is None


# ---------------------------------------------------------------------------
# Tool registration test
# ---------------------------------------------------------------------------


class TestToolRegistration:
    def test_registry_has_js_analyze(self):
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        names = [
            s.get("function", s).get("name", "") if isinstance(s, dict) else ""
            for s in registry.get_schemas()
        ]
        assert "js_analyze" in names


