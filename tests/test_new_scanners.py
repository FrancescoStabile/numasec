"""Tests for Sprint 3 new scanners: CORS, Host Header, SSTI, LFI."""

from __future__ import annotations

import json

import httpx
import pytest

from security_mcp.scanners.cors_tester import (
    CorsResult,
    CorsVulnerability,
    CorsTester,
    python_cors_test,
)
from security_mcp.scanners.host_header_tester import (
    HostHeaderResult,
    HostHeaderTester,
    HostHeaderVulnerability,
    python_host_header_test,
)
from security_mcp.scanners.lfi_tester import (
    LfiResult,
    LfiTester,
    LfiVulnerability,
    python_lfi_test,
)
from security_mcp.scanners.ssti_tester import (
    SstiResult,
    SstiTester,
    SstiVulnerability,
    python_ssti_test,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


# ===========================================================================
# CORS Tester
# ===========================================================================


class TestCorsResult:
    def test_to_dict_empty(self):
        r = CorsResult(target="http://example.com")
        d = r.to_dict()
        assert d["target"] == "http://example.com"
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []

    def test_to_dict_with_vuln(self):
        r = CorsResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=[
                CorsVulnerability(
                    vuln_type="reflected_origin",
                    origin_sent="https://evil.example.com",
                    acao_received="https://evil.example.com",
                    acac=False,
                    severity="high",
                    evidence="origin reflected",
                )
            ],
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert len(d["vulnerabilities"]) == 1
        assert d["vulnerabilities"][0]["type"] == "reflected_origin"


class TestCorsDetection:
    @pytest.mark.asyncio
    async def test_reflected_evil_origin_detected(self):
        """Server that reflects any Origin value should be flagged."""

        def handler(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("origin", "")
            headers = {"access-control-allow-origin": origin}
            return httpx.Response(200, headers=headers)

        tester = CorsTester(timeout=5.0)
        # Directly call _probe with an httpx.AsyncClient using the mock transport
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._probe(client, "http://test.local", "https://evil.example.com", "http://test.local")

        assert vuln is not None
        assert vuln.vuln_type == "reflected_origin"
        assert vuln.severity in ("high", "critical")

    @pytest.mark.asyncio
    async def test_reflected_origin_with_credentials_is_critical(self):
        """Reflected origin + ACAC:true must be 'critical'."""

        def handler(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("origin", "")
            headers = {
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
            }
            return httpx.Response(200, headers=headers)

        tester = CorsTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._probe(
                client, "http://test.local", "https://evil.example.com", "http://test.local"
            )

        assert vuln is not None
        assert vuln.severity == "critical"
        assert vuln.acac is True

    @pytest.mark.asyncio
    async def test_null_origin_detected(self):
        """Server that accepts 'null' Origin should be flagged."""

        def handler(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("origin", "")
            if origin == "null":
                headers = {"access-control-allow-origin": "null"}
            else:
                headers = {}
            return httpx.Response(200, headers=headers)

        tester = CorsTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._probe(client, "http://test.local", "null", "http://test.local")

        assert vuln is not None
        # acao == origin ("null" == "null") → classified as reflected_origin (Case 2 fires first)
        assert vuln.vuln_type in ("null_origin", "reflected_origin")

    @pytest.mark.asyncio
    async def test_no_cors_headers_no_vuln(self):
        """Server with no CORS headers should not be flagged."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="no cors here")

        tester = CorsTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._probe(
                client, "http://test.local", "https://evil.example.com", "http://test.local"
            )

        assert vuln is None

    @pytest.mark.asyncio
    async def test_proper_cors_no_vuln(self):
        """Server that only allows its own origin should not be flagged."""

        def handler(request: httpx.Request) -> httpx.Response:
            headers = {"access-control-allow-origin": "http://test.local"}
            return httpx.Response(200, headers=headers)

        tester = CorsTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._probe(
                client, "http://test.local", "https://evil.example.com", "http://test.local"
            )

        assert vuln is None


class TestCorsToolWrapper:
    @pytest.mark.asyncio
    async def test_python_cors_test_returns_json(self):
        """python_cors_test should return a valid JSON string."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="no cors")

        # Cannot inject transport into the wrapper, but we can verify the output format
        # by testing against a real (localhost) URL — instead we just call with a URL
        # that will fail gracefully
        result_json = await python_cors_test("http://127.0.0.1:1")
        data = json.loads(result_json)
        assert "target" in data
        assert "vulnerable" in data
        assert "vulnerabilities" in data

    def test_access_control_test_registered(self):
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "access_control_test" in registry.available_tools
        schemas = registry.get_schemas()
        schema = next(s for s in schemas if s["function"]["name"] == "access_control_test")
        assert "url" in schema["function"]["parameters"]["properties"]


# ===========================================================================
# Host Header Tester
# ===========================================================================


class TestHostHeaderResult:
    def test_to_dict_empty(self):
        r = HostHeaderResult(target="http://example.com")
        d = r.to_dict()
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []

    def test_to_dict_with_vuln(self):
        r = HostHeaderResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=[
                HostHeaderVulnerability(
                    header_injected="X-Forwarded-Host",
                    value_injected="evil.example.com",
                    reflection_location="location_header",
                    severity="high",
                    evidence="reflected",
                )
            ],
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert d["vulnerabilities"][0]["header"] == "X-Forwarded-Host"


class TestHostHeaderDetection:
    @pytest.mark.asyncio
    async def test_location_header_reflection_detected(self):
        """Injected X-Forwarded-Host reflected in Location header → high severity."""

        def handler(request: httpx.Request) -> httpx.Response:
            fwd = request.headers.get("x-forwarded-host", "")
            if fwd:
                return httpx.Response(301, headers={"location": f"http://{fwd}/path"})
            return httpx.Response(200)

        tester = HostHeaderTester(timeout=5.0)
        async with httpx.AsyncClient(
            transport=_transport(handler), follow_redirects=False
        ) as client:
            vuln = await tester._probe_header(
                client, "http://test.local", "test.local", "X-Forwarded-Host", "evil.example.com"
            )

        assert vuln is not None
        assert vuln.reflection_location == "location_header"
        assert vuln.severity == "high"

    @pytest.mark.asyncio
    async def test_body_reflection_detected(self):
        """Injected value appearing in response body is flagged."""

        def handler(request: httpx.Request) -> httpx.Response:
            fwd = request.headers.get("x-forwarded-host", "")
            if fwd:
                body = f"<html><a href='http://{fwd}/reset'>Reset password</a></html>"
                return httpx.Response(200, text=body)
            return httpx.Response(200, text="<html>normal</html>")

        tester = HostHeaderTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler), follow_redirects=False) as client:
            vuln = await tester._probe_header(
                client, "http://test.local", "test.local", "X-Forwarded-Host", "evil.example.com"
            )

        assert vuln is not None
        assert vuln.reflection_location == "body"

    @pytest.mark.asyncio
    async def test_no_reflection_no_vuln(self):
        """Server that ignores Host headers produces no finding."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>normal</html>")

        tester = HostHeaderTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler), follow_redirects=False) as client:
            vuln = await tester._probe_header(
                client, "http://test.local", "test.local", "X-Forwarded-Host", "evil.example.com"
            )

        assert vuln is None

    def test_path_test_registered(self):
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "path_test" in registry.available_tools


# ===========================================================================
# SSTI Tester
# ===========================================================================


class TestSstiResult:
    def test_to_dict_empty(self):
        r = SstiResult(target="http://example.com")
        d = r.to_dict()
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []

    def test_to_dict_with_vuln(self):
        r = SstiResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=[
                SstiVulnerability(
                    param="template",
                    probe="{{7*7}}",
                    expected="49",
                    engine="Jinja2/Twig/Handlebars",
                    evidence="49 found in response",
                )
            ],
            params_tested=1,
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert d["vulnerabilities"][0]["probe"] == "{{7*7}}"


class TestSstiDetection:
    @pytest.mark.asyncio
    async def test_jinja2_math_probe_detected(self):
        """Unique canary math probe should trigger SSTI detection."""

        def handler(request: httpx.Request) -> httpx.Response:
            q = request.url.params.get("q", "")
            # Simulate template evaluation for the unique canary
            if "83621" in q and "91433" in q:
                return httpx.Response(200, text="Result: 7645846693 items found")
            if "7*'7'" in q or "7%2A%277%27" in q:
                return httpx.Response(200, text="Result: 7777777")
            return httpx.Response(200, text=f"Result: {q}")

        tester = SstiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._test_param(
                client, "http://test.local/search?q=test", "q", "GET", "GET", None
            )

        assert vuln is not None
        assert "7645846693" in vuln.expected or "7777777" in vuln.expected
        assert vuln.engine != ""

    @pytest.mark.asyncio
    async def test_no_false_positive_when_no_evaluation(self):
        """Server that echoes input without evaluating templates should not trigger."""

        def handler(request: httpx.Request) -> httpx.Response:
            q = request.url.params.get("q", "")
            # Safe: echo the literal probe back (no evaluation)
            return httpx.Response(200, text=f"Search: {q}")

        tester = SstiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._test_param(
                client, "http://test.local/search?q=test", "q", "GET", "GET", None
            )

        # The response would contain the literal probe, not the computed result
        assert vuln is None

    def test_detect_params_from_url(self):
        tester = SstiTester()
        params = tester._detect_params("http://example.com/?name=foo&page=1", None, None)
        param_names = [p for p, _ in params]
        assert "name" in param_names
        assert "page" in param_names

    def test_injection_test_registered(self):
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "injection_test" in registry.available_tools
        schemas = registry.get_schemas()
        schema = next(s for s in schemas if s["function"]["name"] == "injection_test")
        assert "url" in schema["function"]["parameters"]["properties"]


# ===========================================================================
# LFI Tester
# ===========================================================================


class TestLfiResult:
    def test_to_dict_empty(self):
        r = LfiResult(target="http://example.com")
        d = r.to_dict()
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []

    def test_to_dict_with_vuln(self):
        r = LfiResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=[
                LfiVulnerability(
                    param="file",
                    payload="../../../etc/passwd",
                    platform="linux",
                    encoding="plain",
                    evidence="root:x:0:0 found",
                )
            ],
            params_tested=2,
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert d["vulnerabilities"][0]["payload"] == "../../../etc/passwd"
        assert d["vulnerabilities"][0]["platform"] == "linux"


class TestLfiDetection:
    @pytest.mark.asyncio
    async def test_linux_lfi_detected(self):
        """Path traversal to /etc/passwd should be detected."""

        def handler(request: httpx.Request) -> httpx.Response:
            file_param = request.url.params.get("file", "")
            if ".." in file_param:
                # Vulnerable: return passwd content
                return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:")
            return httpx.Response(200, text="normal page")

        tester = LfiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._test_param(
                client, "http://test.local/?file=home", "file", "GET", "GET", None
            )

        assert vuln is not None
        assert vuln.platform == "linux"
        assert "passwd" in vuln.payload.lower() or ".." in vuln.payload

    @pytest.mark.asyncio
    async def test_php_filter_detected(self):
        """PHP filter wrapper response (base64) should be detected."""

        def handler(request: httpx.Request) -> httpx.Response:
            file_param = request.url.params.get("file", "")
            if "php://filter" in file_param.lower():
                # Return a base64-encoded "file" response
                return httpx.Response(
                    200,
                    text="PD9waHAgZWNobyAnSGVsbG8gV29ybGQnOyA/Pg==AAAAAAAAAAAAAAAAAAAAAA",
                )
            return httpx.Response(200, text="normal")

        tester = LfiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._test_param(
                client, "http://test.local/?file=index", "file", "GET", "GET", None
            )

        assert vuln is not None
        assert vuln.platform == "php"

    @pytest.mark.asyncio
    async def test_no_false_positive_clean_page(self):
        """Server that returns normal content should not trigger LFI detection."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html><body>Welcome to our site!</body></html>")

        tester = LfiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._test_param(
                client, "http://test.local/?file=home", "file", "GET", "GET", None
            )

        assert vuln is None

    def test_path_params_prioritized(self):
        """Parameters with path-like names should be tested before others."""
        tester = LfiTester()
        params = tester._detect_params(
            "http://example.com/?page=home&id=1&file=about",
            None,
            None,
        )
        names = [p for p, _ in params]
        # "page" and "file" should appear before "id" in priority ordering
        page_idx = names.index("page") if "page" in names else 99
        file_idx = names.index("file") if "file" in names else 99
        id_idx = names.index("id") if "id" in names else 99
        assert min(page_idx, file_idx) < id_idx or "id" not in names

    def test_path_test_registered_with_url(self):
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "path_test" in registry.available_tools
        schemas = registry.get_schemas()
        schema = next(s for s in schemas if s["function"]["name"] == "path_test")
        assert "url" in schema["function"]["parameters"]["properties"]
