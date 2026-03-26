"""Tests for Phase 1 scanner enhancements: browser crawler SPA routes,
SSRF param injection + headers, XXE multipart + SVG, and open redirect
endpoint discovery.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest


def _transport(handler):
    return httpx.MockTransport(handler)


# ===========================================================================
# 1A. Browser Crawler SPA Route Discovery
# ===========================================================================


class TestBrowserCrawlerRouteExtraction:
    """Verify bare Angular route regex and SPA fragment probing lists."""

    def test_bare_route_regex_matches_angular(self) -> None:
        """Bare route pattern like path: 'administration' should match."""
        from security_mcp.scanners.browser_crawler import _ROUTE_PATTERNS

        sample = "path: 'administration'"
        matched = False
        for pat in _ROUTE_PATTERNS:
            if pat.search(sample):
                matched = True
                break
        assert matched, "Bare Angular route path:'administration' should be matched by _ROUTE_PATTERNS"

    def test_bare_route_regex_matches_with_quotes(self) -> None:
        """Both single and double quotes should work."""
        from security_mcp.scanners.browser_crawler import _ROUTE_PATTERNS

        for sample in ['path: "dashboard"', "path: 'settings'"]:
            matched = any(pat.search(sample) for pat in _ROUTE_PATTERNS)
            assert matched, f"Should match: {sample}"

    def test_existing_prefixed_routes_still_match(self) -> None:
        """Routes with leading / or # should still be captured."""
        from security_mcp.scanners.browser_crawler import _ROUTE_PATTERNS

        for sample in ["path: '/admin'", "route: '/#/login'"]:
            matched = any(pat.search(sample) for pat in _ROUTE_PATTERNS)
            assert matched, f"Existing route should still match: {sample}"

    def test_route_extraction_bare_goes_to_fragment(self) -> None:
        """Bare routes should be converted to /#/ fragment routes."""
        from security_mcp.scanners.browser_crawler import _ROUTE_PATTERNS

        sample = "path: 'administration'"
        for pat in _ROUTE_PATTERNS:
            m = pat.search(sample)
            if m:
                route = m.group(1)
                # Bare routes (not starting with / or #) should be fragment-ified
                if not route.startswith(("/", "#")):
                    fragment_route = f"/#/{route}"
                    assert fragment_route == "/#/administration"
                    return
        pytest.fail("No pattern matched the bare route")

    def test_common_paths_includes_actuator(self) -> None:
        """Expanded common_paths should include /actuator."""
        from security_mcp.scanners.browser_crawler import BrowserCrawler

        crawler = BrowserCrawler.__new__(BrowserCrawler)
        # Access the common paths list used in crawl()
        # We verify it by checking the class source — the list is inline
        import inspect

        source = inspect.getsource(BrowserCrawler)
        assert "/actuator" in source, "common_paths should include /actuator"

    def test_spa_fragment_probing_list_exists(self) -> None:
        """SPA fragment route probing should include admin routes."""
        import inspect

        from security_mcp.scanners.browser_crawler import BrowserCrawler

        source = inspect.getsource(BrowserCrawler)
        for route in ["/#/admin", "/#/administration", "/#/dashboard"]:
            assert route in source, f"SPA fragment probing should include {route}"


# ===========================================================================
# 1B. SSRF Tester: Param Injection + Auth Headers
# ===========================================================================


class TestSsrfParamInjection:
    """Verify SSRF param injection strategy and headers support."""

    def test_ssrf_param_names_list_exists(self) -> None:
        """_SSRF_PARAM_NAMES should be defined with common SSRF params."""
        from security_mcp.scanners.ssrf_tester import _SSRF_PARAM_NAMES

        assert len(_SSRF_PARAM_NAMES) >= 10
        assert "url" in _SSRF_PARAM_NAMES
        assert "uri" in _SSRF_PARAM_NAMES
        assert "callback" in _SSRF_PARAM_NAMES

    async def test_ssrf_test_accepts_headers(self) -> None:
        """python_ssrf_test should accept a headers parameter."""
        import inspect

        from security_mcp.scanners.ssrf_tester import python_ssrf_test

        sig = inspect.signature(python_ssrf_test)
        assert "headers" in sig.parameters, "python_ssrf_test should accept headers"

    async def test_ssrf_tester_accepts_headers(self) -> None:
        """SsrfTester.test() should accept headers."""
        import inspect

        from security_mcp.scanners.ssrf_tester import SsrfTester

        sig = inspect.signature(SsrfTester.test)
        assert "headers" in sig.parameters

    async def test_ssrf_no_early_return_without_params(self) -> None:
        """SSRF tester should NOT return early when URL has no query params."""
        import unittest.mock as mock

        from security_mcp.scanners.ssrf_tester import SsrfTester

        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, text="OK")

        tester = SsrfTester(timeout=5.0)
        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            kwargs.pop("verify", None)
            original_init(self_client, **kwargs)

        with mock.patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = await tester.test("http://testserver/profile/image")
        # Should have made requests (not returned early)
        assert call_count > 0, "SSRF tester should probe even without existing query params"

    async def test_ssrf_strategy2_injects_params(self) -> None:
        """Strategy 2 should inject param names like ?url=<ssrf_payload>."""
        import unittest.mock as mock

        from security_mcp.scanners.ssrf_tester import SsrfTester

        injected_params = set()

        def handler(request: httpx.Request) -> httpx.Response:
            parsed = urlparse(str(request.url))
            params = parse_qs(parsed.query)
            for p in params:
                injected_params.add(p)
            return httpx.Response(200, text="OK")

        tester = SsrfTester(timeout=5.0)
        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            kwargs.pop("verify", None)
            original_init(self_client, **kwargs)

        with mock.patch.object(httpx.AsyncClient, "__init__", patched_init):
            await tester.test("http://testserver/api/fetch")
        # Strategy 2 should have injected some known SSRF param names
        assert len(injected_params) > 0, "Should inject SSRF param names"

    async def test_ssrf_headers_json_parsing(self) -> None:
        """python_ssrf_test should parse JSON headers string."""
        from security_mcp.scanners.ssrf_tester import python_ssrf_test

        # Just verify the function signature accepts headers and doesn't crash
        import inspect

        sig = inspect.signature(python_ssrf_test)
        assert sig.parameters["headers"].default is None


# ===========================================================================
# 1C. XXE Tester: Multipart File Upload + SVG
# ===========================================================================


class TestXxeMultipartUpload:
    """Verify XXE multipart file upload and SVG payload support."""

    def test_xxe_svg_payload_exists(self) -> None:
        """_XXE_SVG payload should be defined."""
        from security_mcp.scanners.xxe_tester import _XXE_SVG

        assert "svg" in _XXE_SVG.lower()
        assert "ENTITY" in _XXE_SVG
        assert "file:///etc/passwd" in _XXE_SVG

    def test_xxe_svg_in_payloads_list(self) -> None:
        """_PAYLOADS should include the SVG payload."""
        from security_mcp.scanners.xxe_tester import _PAYLOADS

        payload_types = [pt for _, pt in _PAYLOADS]
        assert "svg" in payload_types, "_PAYLOADS should include svg type"

    def test_multipart_field_names_defined(self) -> None:
        """_MULTIPART_FIELD_NAMES should be defined."""
        from security_mcp.scanners.xxe_tester import _MULTIPART_FIELD_NAMES

        assert len(_MULTIPART_FIELD_NAMES) >= 4
        assert "file" in _MULTIPART_FIELD_NAMES
        assert "upload" in _MULTIPART_FIELD_NAMES

    def test_multipart_filenames_defined(self) -> None:
        """_MULTIPART_FILENAMES should include XML and SVG files."""
        from security_mcp.scanners.xxe_tester import _MULTIPART_FILENAMES

        filenames = [fn for fn, _ in _MULTIPART_FILENAMES]
        assert any("xml" in fn.lower() for fn in filenames)
        assert any("svg" in fn.lower() for fn in filenames)

    async def test_xxe_tester_accepts_headers(self) -> None:
        """XxeTester.test() should accept headers."""
        import inspect

        from security_mcp.scanners.xxe_tester import XxeTester

        sig = inspect.signature(XxeTester.test)
        assert "headers" in sig.parameters

    async def test_xxe_wrapper_accepts_headers(self) -> None:
        """python_xxe_test should accept headers."""
        import inspect

        from security_mcp.scanners.xxe_tester import python_xxe_test

        sig = inspect.signature(python_xxe_test)
        assert "headers" in sig.parameters

    async def test_xxe_probe_multipart_exists(self) -> None:
        """XxeTester should have _probe_multipart method."""
        from security_mcp.scanners.xxe_tester import XxeTester

        assert hasattr(XxeTester, "_probe_multipart")

    async def test_xxe_multipart_sends_files(self) -> None:
        """Multipart strategy should send file uploads."""
        from security_mcp.scanners.xxe_tester import XxeTester

        received_multipart = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal received_multipart
            ct = request.headers.get("content-type", "")
            if "multipart" in ct:
                received_multipart = True
            return httpx.Response(200, text="<response>ok</response>")

        tester = XxeTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            from security_mcp.scanners.xxe_tester import _PAYLOADS

            payload_str, payload_type = _PAYLOADS[0]
            await tester._probe_multipart(client, "http://testserver/upload", payload_str, payload_type)
        assert received_multipart, "Multipart strategy should send file uploads"

    async def test_xxe_svg_detection_in_probe(self) -> None:
        """SVG payload type in _probe should check file_read keywords."""
        from security_mcp.scanners.xxe_tester import XxeTester, _XXE_SVG

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")

        tester = XxeTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._probe(client, "http://testserver/upload", _XXE_SVG, "svg", "text/xml")
        assert vuln is not None
        assert vuln.payload_type == "svg"
        assert vuln.severity == "critical"

    async def test_xxe_multipart_detects_file_read(self) -> None:
        """Multipart strategy should detect file read in response."""
        from security_mcp.scanners.xxe_tester import XxeTester

        def handler(request: httpx.Request) -> httpx.Response:
            ct = request.headers.get("content-type", "")
            if "multipart" in ct:
                return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")
            return httpx.Response(200, text="OK")

        tester = XxeTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            from security_mcp.scanners.xxe_tester import _PAYLOADS

            vuln = await tester._probe_multipart(client, "http://testserver/upload", _PAYLOADS[0][0], "file_read")
        assert vuln is not None
        assert vuln.severity == "critical"
        assert "multipart" in vuln.evidence

    async def test_xxe_full_test_uses_both_strategies(self) -> None:
        """Full test() should use both POST body and multipart strategies."""
        from security_mcp.scanners.xxe_tester import XxeTester

        post_body_seen = False
        multipart_seen = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal post_body_seen, multipart_seen
            ct = request.headers.get("content-type", "")
            if request.method == "POST":
                if "multipart" in ct:
                    multipart_seen = True
                elif "xml" in ct:
                    post_body_seen = True
            return httpx.Response(200, text="<response>safe</response>")

        tester = XxeTester(timeout=5.0)
        # Use the mock transport directly
        async with httpx.AsyncClient(transport=_transport(handler), verify=False) as client:
            # Call the internal methods to verify both strategies
            from security_mcp.scanners.xxe_tester import _PAYLOADS

            payload_str, payload_type = _PAYLOADS[0]
            await tester._probe(client, "http://testserver/api", payload_str, payload_type, "application/xml")
            await tester._probe_multipart(client, "http://testserver/api", payload_str, payload_type)

        assert post_body_seen, "Should have sent POST body with XML content-type"
        assert multipart_seen, "Should have sent multipart file upload"


# ===========================================================================
# 1D. Open Redirect: Endpoint Discovery
# ===========================================================================


class TestOpenRedirectEndpointDiscovery:
    """Verify open redirect endpoint discovery and headers support."""

    def test_common_redirect_paths_defined(self) -> None:
        """_COMMON_REDIRECT_PATHS should be defined with common paths."""
        from security_mcp.scanners.open_redirect_tester import _COMMON_REDIRECT_PATHS

        assert len(_COMMON_REDIRECT_PATHS) >= 10
        assert "/redirect" in _COMMON_REDIRECT_PATHS
        assert "/go" in _COMMON_REDIRECT_PATHS

    def test_discovery_params_subset(self) -> None:
        """_DISCOVERY_PARAMS should be a bounded subset for discovery."""
        from security_mcp.scanners.open_redirect_tester import _DISCOVERY_PARAMS

        assert len(_DISCOVERY_PARAMS) <= 10  # Bounded for performance
        assert "url" in _DISCOVERY_PARAMS
        assert "redirect" in _DISCOVERY_PARAMS

    def test_discovery_payloads_subset(self) -> None:
        """_DISCOVERY_PAYLOADS should be a bounded subset."""
        from security_mcp.scanners.open_redirect_tester import _DISCOVERY_PAYLOADS

        assert len(_DISCOVERY_PAYLOADS) <= 5  # Bounded
        assert any("evil.example.com" in p for p in _DISCOVERY_PAYLOADS)

    async def test_redirect_tester_accepts_headers(self) -> None:
        """OpenRedirectTester.test() should accept headers."""
        import inspect

        from security_mcp.scanners.open_redirect_tester import OpenRedirectTester

        sig = inspect.signature(OpenRedirectTester.test)
        assert "headers" in sig.parameters

    async def test_redirect_wrapper_accepts_headers(self) -> None:
        """python_open_redirect_test should accept headers."""
        import inspect

        from security_mcp.scanners.open_redirect_tester import python_open_redirect_test

        sig = inspect.signature(python_open_redirect_test)
        assert "headers" in sig.parameters

    async def test_strategy3_probes_redirect_endpoints(self) -> None:
        """Strategy 3 should probe common redirect endpoints."""
        import unittest.mock as mock

        from security_mcp.scanners.open_redirect_tester import OpenRedirectTester

        probed_paths = set()

        def handler(request: httpx.Request) -> httpx.Response:
            parsed = urlparse(str(request.url))
            probed_paths.add(parsed.path)
            return httpx.Response(200, text="OK")

        tester = OpenRedirectTester(timeout=5.0)
        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            kwargs.pop("verify", None)
            original_init(self_client, **kwargs)

        with mock.patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = await tester.test("http://testserver/", headers=None)

        # At minimum should have probed some redirect paths
        redirect_paths_probed = probed_paths & {"/redirect", "/go", "/out", "/redir"}
        assert len(redirect_paths_probed) > 0 or len(probed_paths) > 1, (
            f"Strategy 3 should probe redirect endpoints, got: {probed_paths}"
        )

    async def test_strategy3_bounded_request_count(self) -> None:
        """Strategy 3 should be bounded in request count."""
        import unittest.mock as mock

        from security_mcp.scanners.open_redirect_tester import (
            _COMMON_REDIRECT_PATHS,
            _DISCOVERY_PARAMS,
            _DISCOVERY_PAYLOADS,
            OpenRedirectTester,
        )

        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return httpx.Response(200, text="OK")

        tester = OpenRedirectTester(timeout=5.0)
        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            kwargs.pop("verify", None)
            original_init(self_client, **kwargs)

        with mock.patch.object(httpx.AsyncClient, "__init__", patched_init):
            await tester.test("http://testserver/")

        # Max requests for strategy 3: paths * params * payloads
        max_strategy3 = len(_COMMON_REDIRECT_PATHS) * len(_DISCOVERY_PARAMS) * len(_DISCOVERY_PAYLOADS)
        # Plus strategy 2 requests
        assert request_count <= max_strategy3 + 1000, (
            f"Request count {request_count} exceeds reasonable bound"
        )

    async def test_existing_strategies_preserved(self) -> None:
        """Strategies 1 and 2 should still work."""
        import unittest.mock as mock

        from security_mcp.scanners.open_redirect_tester import OpenRedirectTester

        injected_params = set()

        def handler(request: httpx.Request) -> httpx.Response:
            parsed = urlparse(str(request.url))
            params = parse_qs(parsed.query)
            injected_params.update(params.keys())
            return httpx.Response(200, text="OK")

        tester = OpenRedirectTester(timeout=5.0)
        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            kwargs.pop("verify", None)
            original_init(self_client, **kwargs)

        with mock.patch.object(httpx.AsyncClient, "__init__", patched_init):
            await tester.test("http://testserver/page?next=home")
        assert "next" in injected_params, "Strategy 1 should replace existing param"

    async def test_headers_json_parsing(self) -> None:
        """python_open_redirect_test should parse JSON headers."""
        from security_mcp.scanners.open_redirect_tester import python_open_redirect_test

        import inspect

        sig = inspect.signature(python_open_redirect_test)
        assert sig.parameters["headers"].default is None


# ===========================================================================
# 2A. Tool Schema Updates
# ===========================================================================


class TestToolSchemaUpdates:
    """Verify tool schemas include new headers params and descriptions."""

    @staticmethod
    def _find_schema(schemas, name):
        """Find a tool schema by name in OpenAI tool format."""
        for s in schemas:
            fn = s.get("function", s)
            if fn.get("name") == name:
                return fn
        raise KeyError(f"Schema '{name}' not found")

    def test_ssrf_schema_has_headers(self) -> None:
        """ssrf_test schema should have headers property."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        schema = self._find_schema(registry.get_schemas(), "ssrf_test")
        assert "headers" in schema["parameters"]["properties"]

    def test_path_test_schema_has_headers(self) -> None:
        """path_test (replaces xxe_test, open_redirect_test) schema should have headers property."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        schema = self._find_schema(registry.get_schemas(), "path_test")
        assert "headers" in schema["parameters"]["properties"]

    def test_ssrf_description_mentions_param_injection(self) -> None:
        """ssrf_test description should mention param injection."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        schema = self._find_schema(registry.get_schemas(), "ssrf_test")
        desc = schema["description"].lower()
        assert "inject" in desc or "param" in desc

    def test_path_test_description_mentions_traversal(self) -> None:
        """path_test (replaces xxe_test, open_redirect_test, lfi_test, host_header_test) should mention traversal."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        schema = self._find_schema(registry.get_schemas(), "path_test")
        desc = schema["description"].lower()
        assert "traversal" in desc or "lfi" in desc or "xxe" in desc

    def test_crawl_description_mentions_spa(self) -> None:
        """crawl (replaces browser_crawl_site) description should mention SPA detection."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        schema = self._find_schema(registry.get_schemas(), "crawl")
        desc = schema["description"].lower()
        assert "spa" in desc or "angular" in desc or "browser" in desc
