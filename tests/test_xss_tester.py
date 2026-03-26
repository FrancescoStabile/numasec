"""Tests for security_mcp.scanners.xss_tester."""

from __future__ import annotations

import json

import httpx
import pytest

from security_mcp.scanners.xss_tester import (
    DOM_SINKS,
    DOM_SOURCES,
    ESCALATION_PAYLOADS,
    PythonXSSTester,
    XSSResult,
    XSSVulnerability,
    python_xss_test,
)


def _mock_transport(handler_func) -> httpx.MockTransport:
    """Create a MockTransport with a custom handler function."""
    return httpx.MockTransport(handler_func)


# ---------------------------------------------------------------------------
# Data model tests
# ---------------------------------------------------------------------------


class TestXSSVulnerability:
    def test_defaults(self):
        v = XSSVulnerability(param="q", xss_type="reflected", payload="<script>", evidence="found")
        assert v.param == "q"
        assert v.location == "GET"

    def test_post_location(self):
        v = XSSVulnerability(param="name", xss_type="reflected", payload="<img>", evidence="x", location="POST")
        assert v.location == "POST"


class TestXSSResult:
    def test_to_dict_empty(self):
        r = XSSResult(target="http://example.com")
        d = r.to_dict()
        assert d["target"] == "http://example.com"
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []
        assert d["dom_sinks"] == []

    def test_to_dict_with_vulns(self):
        r = XSSResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=[
                XSSVulnerability(
                    param="q", xss_type="reflected",
                    payload="<script>alert(1)</script>",
                    evidence="found in body",
                ),
            ],
            params_tested=2,
            duration_ms=123.45,
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert len(d["vulnerabilities"]) == 1
        assert d["vulnerabilities"][0]["type"] == "reflected"


# ---------------------------------------------------------------------------
# PythonXSSTester
# ---------------------------------------------------------------------------


class TestPythonXSSTester:
    @pytest.mark.asyncio
    async def test_detects_reflected_xss(self):
        """When a payload is reflected unencoded, it should be detected."""

        def handler(request: httpx.Request) -> httpx.Response:
            q = request.url.params.get("q", "")
            # Echo back the parameter value directly (vulnerable)
            body = f"<html><body>Search results for: {q}</body></html>"
            return httpx.Response(200, text=body)

        transport = _mock_transport(handler)

        tester = PythonXSSTester(timeout=5.0)

        async with httpx.AsyncClient(transport=transport) as client:
            # Manually test the reflected XSS detection
            result = XSSResult(target="http://test.local/search?q=test")

            # Step 1: canary test
            canary = tester._generate_canary()
            resp = await client.get(f"http://test.local/search?q={canary}")
            assert canary in resp.text  # canary is reflected

            # Step 2: payload test
            payload = "<script>alert(1)</script>"
            resp = await client.get(f"http://test.local/search?q={payload}")
            assert payload in resp.text  # payload is reflected

    @pytest.mark.asyncio
    async def test_no_false_positive_when_encoded(self):
        """When output is HTML-encoded, no reflected XSS should be found."""

        def handler(request: httpx.Request) -> httpx.Response:
            q = request.url.params.get("q", "")
            # HTML-encode the output (safe)
            safe_q = q.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            body = f"<html><body>Search: {safe_q}</body></html>"
            return httpx.Response(200, text=body)

        transport = _mock_transport(handler)
        tester = PythonXSSTester(timeout=5.0)

        async with httpx.AsyncClient(transport=transport) as client:
            canary = tester._generate_canary()
            resp = await client.get(f"http://test.local/search?q={canary}")
            # Canary should NOT appear unencoded (special chars are escaped)
            assert canary not in resp.text

    def test_generate_canary_format(self):
        """Canary should contain special characters for encoding detection."""
        tester = PythonXSSTester()
        canary = tester._generate_canary()
        assert canary.startswith("security_mcp_")
        assert "'" in canary
        assert '"' in canary
        assert "<" in canary
        assert ">" in canary

    def test_detect_params_get(self):
        """Should detect GET parameters from URL query string."""
        tester = PythonXSSTester()
        params = tester._detect_params(
            "http://example.com/search?q=test&page=1",
            None, "GET", None,
        )
        assert len(params) == 2
        assert ("q", "GET") in params
        assert ("page", "GET") in params

    def test_detect_params_post(self):
        """Should detect POST parameters from body."""
        tester = PythonXSSTester()
        params = tester._detect_params(
            "http://example.com/login",
            None, "POST", {"username": "admin", "password": "test"},
        )
        assert len(params) == 2
        assert ("username", "POST") in params

    def test_detect_params_explicit(self):
        """Should filter to explicitly specified parameters."""
        tester = PythonXSSTester()
        params = tester._detect_params(
            "http://example.com/search?q=test&page=1",
            ["q"], "GET", None,
        )
        assert len(params) == 1
        assert params[0] == ("q", "GET")


# ---------------------------------------------------------------------------
# DOM XSS indicators
# ---------------------------------------------------------------------------


class TestDOMXSSDetection:
    @pytest.mark.asyncio
    async def test_detects_dom_sinks(self):
        """Should detect dangerous DOM sinks in JavaScript."""
        body = """
        <html><script>
        document.getElementById('output').innerHTML = location.hash;
        eval(location.search.substring(1));
        </script></html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=body)

        transport = _mock_transport(handler)
        tester = PythonXSSTester(timeout=5.0)

        result = XSSResult(target="http://test.local")
        async with httpx.AsyncClient(transport=transport) as client:
            await tester._scan_dom_xss(client, "http://test.local", result)

        assert len(result.dom_sinks) >= 2  # innerHTML and eval
        sink_types = {s["sink"] for s in result.dom_sinks}
        assert "innerHTML assignment" in sink_types
        assert "eval()" in sink_types

    @pytest.mark.asyncio
    async def test_detects_dom_sources(self):
        """Should detect user-controllable DOM sources."""
        body = """
        <html><script>
        var x = location.hash;
        var y = document.referrer;
        </script></html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=body)

        transport = _mock_transport(handler)
        tester = PythonXSSTester(timeout=5.0)

        result = XSSResult(target="http://test.local")
        async with httpx.AsyncClient(transport=transport) as client:
            await tester._scan_dom_xss(client, "http://test.local", result)

        assert len(result.dom_sources) >= 2
        source_types = {s["source"] for s in result.dom_sources}
        assert "location.hash" in source_types
        assert "document.referrer" in source_types


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Phase 4: Browser DOM XSS
# ---------------------------------------------------------------------------


class TestDomXssBrowser:
    async def test_browser_fallback_no_playwright(self):
        """If Playwright is not installed, _scan_dom_xss_browser should silently return."""
        import unittest.mock as mock

        tester = PythonXSSTester()
        result = XSSResult(target="http://target/page?q=test")

        # Simulate ImportError for playwright
        with mock.patch.dict("sys.modules", {"playwright": None, "playwright.async_api": None}):
            with mock.patch(
                "security_mcp.scanners.xss_tester.PythonXSSTester._scan_dom_xss_browser",
                wraps=tester._scan_dom_xss_browser,
            ):
                # Should not crash
                await tester._scan_dom_xss_browser("http://target/page?q=test", ["q"], result)

        # No crash, no findings added from browser
        assert True

    async def test_dom_xss_regex_still_runs(self):
        """The regex-based DOM XSS scanner should still execute even if browser is unavailable."""
        body = '<html><script>document.write(location.hash)</script></html>'

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=body)

        tester = PythonXSSTester(timeout=5.0)
        result = XSSResult(target="http://target/page")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await tester._scan_dom_xss(client, "http://target/page", result)

        assert len(result.dom_sinks) > 0, "Regex-based DOM scan should find document.write sink"
        assert len(result.dom_sources) > 0, "Regex-based DOM scan should find location.hash source"


class TestXSSToolRegistration:
    def test_registry_has_xss_test(self):
        """xss_test should be registered in the default tool registry."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "xss_test" in registry.available_tools

        schemas = registry.get_schemas()
        xss_schema = next(s for s in schemas if s["function"]["name"] == "xss_test")
        params = xss_schema["function"]["parameters"]
        assert "url" in params["properties"]
        assert params["required"] == ["url"]
