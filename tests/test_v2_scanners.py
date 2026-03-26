"""Tests for v2.0 new scanners: SSRF, Open Redirect, NoSQL, CSRF, XXE."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from security_mcp.scanners.csrf_tester import CsrfResult, CsrfTester, CsrfVulnerability, python_csrf_test
from security_mcp.scanners.nosql_tester import NoSqlResult, NoSqlTester, NoSqlVulnerability, python_nosql_test
from security_mcp.scanners.open_redirect_tester import (
    OpenRedirectTester,
    RedirectResult,
    RedirectVulnerability,
    python_open_redirect_test,
)
from security_mcp.scanners.ssrf_tester import SsrfResult, SsrfTester, SsrfVulnerability, python_ssrf_test
from security_mcp.scanners.xxe_tester import XxeResult, XxeTester, XxeVulnerability, python_xxe_test


def _transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


# ===========================================================================
# SSRF Tester
# ===========================================================================


class TestSsrfResult:
    def test_to_dict_empty(self) -> None:
        r = SsrfResult(target="http://example.com")
        d = r.to_dict()
        assert d["target"] == "http://example.com"
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []

    def test_to_dict_with_vuln(self) -> None:
        r = SsrfResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=[
                SsrfVulnerability(
                    parameter="url",
                    payload="http://169.254.169.254/latest/meta-data/",
                    evidence="ami-id found in response",
                    severity="critical",
                )
            ],
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert len(d["vulnerabilities"]) == 1
        assert d["vulnerabilities"][0]["severity"] == "critical"


class TestSsrfTesterNoParams:
    async def test_no_params_returns_clean_result(self) -> None:
        """URL with no query params should produce no findings (but still probe via Strategy 2)."""
        import unittest.mock as mock

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="OK")

        tester = SsrfTester(timeout=5.0)
        # Patch AsyncClient to inject mock transport
        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            kwargs.pop("verify", None)
            original_init(self_client, **kwargs)

        with mock.patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = await tester.test("http://example.com/page")

        assert result.target == "http://example.com/page"
        assert result.vulnerable is False


class TestSsrfDetection:
    async def test_cloud_metadata_detected_as_critical(self) -> None:
        """Response containing cloud metadata keywords → critical SSRF."""
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            # Simulate metadata endpoint response when SSRF payload is in the URL
            if "169.254.169.254" in str(request.url) or "url=" in str(request.url):
                return httpx.Response(200, text="ami-id: ami-12345678\ninstance-id: i-abc")
            return httpx.Response(200, text="normal response")

        tester = SsrfTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            url = "http://test.local/?url=http://original.com"
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            vuln = await tester._probe(
                client,
                url,
                parsed,
                params,
                "url",
                "http://169.254.169.254/latest/meta-data/",
            )

        assert vuln is not None
        assert vuln.severity == "critical"

    async def test_normal_response_no_ssrf(self) -> None:
        """Server that returns normal content without SSRF indicators → no finding."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="Welcome to our website!")

        tester = SsrfTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            url = "http://test.local/?url=http://original.com"
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            vuln = await tester._probe(
                client,
                url,
                parsed,
                params,
                "url",
                "http://169.254.169.254/",
            )

        assert vuln is None


class TestPythonSsrfTest:
    async def test_returns_json_string(self) -> None:
        """python_ssrf_test must always return a JSON string."""
        # Use a URL with no params to get a quick, clean result
        import unittest.mock as mock

        with mock.patch.object(SsrfTester, "test") as mock_test:
            mock_test.return_value = SsrfResult(target="http://example.com")
            result = await python_ssrf_test("http://example.com")

        data = json.loads(result)
        assert "target" in data
        assert "vulnerable" in data


# ===========================================================================
# Open Redirect Tester
# ===========================================================================


class TestRedirectResult:
    def test_to_dict_empty(self) -> None:
        r = RedirectResult(target="http://example.com")
        d = r.to_dict()
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []

    def test_to_dict_with_vuln(self) -> None:
        r = RedirectResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=[
                RedirectVulnerability(
                    parameter="redirect",
                    payload="https://evil.example.com",
                    final_url="https://evil.example.com/",
                    evidence="Redirected to evil.example.com",
                    severity="high",
                )
            ],
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert len(d["vulnerabilities"]) == 1


class TestOpenRedirectDetection:
    async def test_off_domain_redirect_detected(self) -> None:
        """Server that redirects to evil.example.com should be flagged."""
        def handler(request: httpx.Request) -> httpx.Response:
            # Check HOST (not full URL) so the redirect param value doesn't match
            if request.url.host == "evil.example.com":
                return httpx.Response(200, text="You've been redirected!")
            if "redirect=" in str(request.url) or "url=" in str(request.url) or "next=" in str(request.url):
                return httpx.Response(302, headers={"Location": "https://evil.example.com/"})
            return httpx.Response(200, text="normal")

        tester = OpenRedirectTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler), follow_redirects=True) as client:
            # Use _send_and_check which follows redirects and checks final URL
            test_url = "http://test.local/?redirect=https://evil.example.com"
            vuln = await tester._send_and_check(client, test_url, "redirect", "https://evil.example.com")

        assert vuln is not None
        assert "evil.example.com" in vuln.final_url

    async def test_no_redirect_no_vuln(self) -> None:
        """Server that returns 200 without redirecting → no finding."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="same domain response")

        tester = OpenRedirectTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler), follow_redirects=True) as client:
            # URL without the evil domain embedded — server returns 200, no redirect
            vuln = await tester._send_and_check(
                client, "http://test.local/safe", "redirect", "https://evil.example.com"
            )

        assert vuln is None


class TestOpenRedirectHostnameCheck:
    async def test_evil_domain_in_query_param_not_flagged(self) -> None:
        """Evil domain appearing in a query parameter (not the hostname) should NOT be flagged."""

        def handler(request: httpx.Request) -> httpx.Response:
            # Server echoes the URL back without redirecting — final host stays target.com
            return httpx.Response(200, text="Page with echoed param")

        tester = OpenRedirectTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler), follow_redirects=True) as client:
            # The evil domain is in the query param value, but the server never redirects
            test_url = "http://target.com/page?url=http%3A//evil.example.com"
            vuln = await tester._send_and_check(
                client, test_url, "url", "http://evil.example.com"
            )

        assert vuln is None, "Should not flag when evil domain is only in query param, not hostname"

    async def test_actual_redirect_to_evil_domain_flagged(self) -> None:
        """Redirect where the hostname is evil.example.com SHOULD be flagged."""

        def handler(request: httpx.Request) -> httpx.Response:
            if "evil.example.com" in str(request.url) and request.url.host == "evil.example.com":
                return httpx.Response(200, text="Evil page")
            return httpx.Response(302, headers={"Location": "https://evil.example.com/"})

        tester = OpenRedirectTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler), follow_redirects=True) as client:
            test_url = "http://target.com/?redirect=https://evil.example.com"
            vuln = await tester._send_and_check(
                client, test_url, "redirect", "https://evil.example.com"
            )

        assert vuln is not None, "Should flag when server redirects to evil.example.com"


class TestPythonOpenRedirectTest:
    async def test_returns_json_string(self) -> None:
        import unittest.mock as mock

        with mock.patch.object(OpenRedirectTester, "test") as mock_test:
            mock_test.return_value = RedirectResult(target="http://example.com")
            result = await python_open_redirect_test("http://example.com")

        data = json.loads(result)
        assert "target" in data
        assert "vulnerable" in data


# ===========================================================================
# NoSQL Tester
# ===========================================================================


class TestNoSqlResult:
    def test_to_dict_empty(self) -> None:
        r = NoSqlResult(target="http://example.com")
        d = r.to_dict()
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []

    def test_to_dict_with_vuln(self) -> None:
        r = NoSqlResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=[
                NoSqlVulnerability(
                    parameter="username",
                    payload='{"$ne": null}',
                    evidence="Login bypassed",
                    severity="high",
                )
            ],
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert d["vulnerabilities"][0]["parameter"] == "username"


class TestNoSqlDetection:
    async def test_mongodb_error_detected(self) -> None:
        """Response containing MongoDB-specific keywords → NoSQL injection."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="MongoError: CastError: Cast to number failed")

        tester = NoSqlTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            url = "http://test.local/?user=admin"
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            vuln = await tester._probe_get(
                client,
                parsed,
                params,
                "user",
                '{"$ne": null}',
                "normal response",
            )

        assert vuln is not None

    async def test_success_indicator_detected(self) -> None:
        """Response containing success keywords after injection → NoSQL injection."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="Welcome! You are now logged in as admin")

        tester = NoSqlTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            url = "http://test.local/?user=admin"
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            vuln = await tester._probe_get(
                client,
                parsed,
                params,
                "user",
                '{"$ne": null}',
                "Invalid credentials",
            )

        assert vuln is not None

    async def test_normal_response_no_vuln(self) -> None:
        """Identical response after injection → no NoSQL injection."""
        baseline = "Login failed"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=baseline)

        tester = NoSqlTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            url = "http://test.local/?user=admin"
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            vuln = await tester._probe_get(
                client,
                parsed,
                params,
                "user",
                '{"$ne": null}',
                baseline,
            )

        assert vuln is None


class TestNoSqlPostJsonProbe:
    async def test_no_params_still_probes_post_json(self) -> None:
        """URL without query params should still try POST JSON operator injection."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                body = request.content.decode()
                if '"$ne"' in body or "$ne" in body:
                    return httpx.Response(
                        200, text='{"authentication": {"token": "fake-jwt-token", "user": "admin"}}'
                    )
            return httpx.Response(401, text="Unauthorized")

        tester = NoSqlTester(timeout=5.0)
        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _transport(handler)
            original_init(self_client, **kwargs)

        httpx.AsyncClient.__init__ = patched_init
        try:
            result = await tester.test("http://target/rest/user/login", method="POST")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.vulnerable is True
        assert len(result.vulnerabilities) >= 1

    async def test_no_params_post_safe_no_false_positive(self) -> None:
        """POST JSON probe on safe endpoint should not produce false positives."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text="Unauthorized")

        tester = NoSqlTester(timeout=5.0)
        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _transport(handler)
            original_init(self_client, **kwargs)

        httpx.AsyncClient.__init__ = patched_init
        try:
            result = await tester.test("http://target/rest/user/login", method="POST")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.vulnerable is False
        assert len(result.vulnerabilities) == 0


class TestPythonNoSqlTest:
    async def test_returns_json_string(self) -> None:
        import unittest.mock as mock

        with mock.patch.object(NoSqlTester, "test") as mock_test:
            mock_test.return_value = NoSqlResult(target="http://example.com")
            result = await python_nosql_test("http://example.com")

        data = json.loads(result)
        assert "target" in data
        assert "vulnerable" in data


# ===========================================================================
# CSRF Tester
# ===========================================================================


class TestCsrfResult:
    def test_to_dict_empty(self) -> None:
        r = CsrfResult(target="http://example.com")
        d = r.to_dict()
        assert d["vulnerable"] is False
        assert d["has_csrf_token"] is False
        assert d["forms_found"] == 0
        assert d["samesite_policy"] == ""

    def test_to_dict_with_vuln(self) -> None:
        r = CsrfResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=[
                CsrfVulnerability(
                    vuln_type="missing_token",
                    evidence="Form without CSRF token",
                    severity="high",
                )
            ],
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        # to_dict() serialises vuln_type as "type"
        assert d["vulnerabilities"][0]["type"] == "missing_token"


class TestCsrfSameSiteCheck:
    async def test_missing_samesite_detected(self) -> None:
        """Cookie without SameSite attribute should be flagged."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly"},
                text="<html><body>page</body></html>",
            )

        tester = CsrfTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            csrf_result = CsrfResult(target="http://test.local/")
            await tester._check_get(client, "http://test.local/", csrf_result)

        weak_samesite = [v for v in csrf_result.vulnerabilities if v.vuln_type == "weak_samesite"]
        assert len(weak_samesite) >= 1

    async def test_strict_samesite_ok(self) -> None:
        """Cookie with SameSite=Strict should not be flagged."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Set-Cookie": "session=abc123; SameSite=Strict; HttpOnly"},
                text="<html><body>ok</body></html>",
            )

        tester = CsrfTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            csrf_result = CsrfResult(target="http://test.local/")
            await tester._check_get(client, "http://test.local/", csrf_result)

        assert len(csrf_result.vulnerabilities) == 0


class TestCsrfTokenCheck:
    async def test_form_without_csrf_token_detected(self) -> None:
        """HTML form without CSRF token should be flagged."""
        html = """
        <html><body>
        <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit" value="Login">
        </form>
        </body></html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text=html, headers={"Content-Type": "text/html; charset=utf-8"}
            )

        tester = CsrfTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            csrf_result = CsrfResult(target="http://test.local/login")
            await tester._check_get(client, "http://test.local/login", csrf_result)

        missing_token = [v for v in csrf_result.vulnerabilities if v.vuln_type == "missing_token"]
        assert len(missing_token) >= 1

    async def test_form_with_csrf_token_ok(self) -> None:
        """HTML form with CSRF token should NOT be flagged."""
        html = """
        <html><body>
        <form action="/login" method="POST">
            <input type="hidden" name="_csrf_token" value="abc123">
            <input type="text" name="username">
            <input type="submit" value="Login">
        </form>
        </body></html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text=html, headers={"Content-Type": "text/html; charset=utf-8"}
            )

        tester = CsrfTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            csrf_result = CsrfResult(target="http://test.local/login")
            await tester._check_get(client, "http://test.local/login", csrf_result)

        missing_token = [v for v in csrf_result.vulnerabilities if v.vuln_type == "missing_token"]
        assert len(missing_token) == 0


class TestCsrfFormsFound:
    async def test_forms_found_count(self) -> None:
        """forms_found should report the number of HTML forms detected."""
        html = """
        <html><body>
        <form action="/login" method="POST">
            <input type="text" name="username">
        </form>
        <form action="/register" method="POST">
            <input type="text" name="email">
        </form>
        </body></html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text=html, headers={"Content-Type": "text/html; charset=utf-8"}
            )

        tester = CsrfTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            csrf_result = CsrfResult(target="http://test.local/")
            await tester._check_get(client, "http://test.local/", csrf_result)

        assert csrf_result.forms_found == 2

    async def test_forms_found_zero_when_no_forms(self) -> None:
        """forms_found should be 0 when page has no forms."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text="<html><body>No forms</body></html>",
                headers={"Content-Type": "text/html; charset=utf-8"},
            )

        tester = CsrfTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            csrf_result = CsrfResult(target="http://test.local/")
            await tester._check_get(client, "http://test.local/", csrf_result)

        assert csrf_result.forms_found == 0


class TestPythonCsrfTest:
    async def test_returns_json_string(self) -> None:
        import unittest.mock as mock

        with mock.patch.object(CsrfTester, "test") as mock_test:
            mock_test.return_value = CsrfResult(target="http://example.com")
            result = await python_csrf_test("http://example.com")

        data = json.loads(result)
        assert "target" in data
        assert "vulnerable" in data


# ===========================================================================
# XXE Tester
# ===========================================================================


class TestXxeResult:
    def test_to_dict_empty(self) -> None:
        r = XxeResult(target="http://example.com")
        d = r.to_dict()
        assert d["vulnerable"] is False
        assert d["accepts_xml"] is False
        assert d["vulnerabilities"] == []

    def test_to_dict_with_vuln(self) -> None:
        r = XxeResult(
            target="http://example.com",
            vulnerable=True,
            accepts_xml=True,
            vulnerabilities=[
                XxeVulnerability(
                    endpoint="http://example.com/api",
                    payload_type="file_read",
                    evidence="root:x:0:0:",
                    severity="critical",
                )
            ],
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert d["accepts_xml"] is True
        assert d["vulnerabilities"][0]["payload_type"] == "file_read"


class TestXxeDetection:
    async def test_passwd_file_content_detected(self) -> None:
        """Response containing /etc/passwd content → critical file_read XXE."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(
                    200,
                    text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
                    headers={"Content-Type": "text/xml"},
                )
            return httpx.Response(200, headers={"Content-Type": "application/xml"})

        tester = XxeTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._probe(
                client,
                "http://test.local/xml",
                "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><r>&x;</r>",
                "file_read",
                "application/xml",
            )

        assert vuln is not None
        assert vuln.payload_type == "file_read"
        assert vuln.severity == "critical"

    async def test_xml_parse_error_detected(self) -> None:
        """Response with XML parser error keywords → error-based XXE."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(
                    500,
                    text="XML parser error: System identifier 'file:///nonexistent' not found",
                )
            return httpx.Response(200, text="ok")

        tester = XxeTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._probe(
                client,
                "http://test.local/xml",
                "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY % x SYSTEM 'file:///bad'>%x;]><r/>",
                "error_based",
                "application/xml",
            )

        assert vuln is not None
        assert vuln.payload_type == "error_based"
        assert vuln.severity == "high"

    async def test_normal_xml_response_no_vuln(self) -> None:
        """Server that returns normal XML response should not be flagged."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                text="<response><status>OK</status></response>",
                headers={"Content-Type": "application/xml"},
            )

        tester = XxeTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._probe(
                client,
                "http://test.local/xml",
                "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><r>&x;</r>",
                "file_read",
                "application/xml",
            )

        assert vuln is None


class TestPythonXxeTest:
    async def test_returns_json_string(self) -> None:
        import unittest.mock as mock

        with mock.patch.object(XxeTester, "test") as mock_test:
            mock_test.return_value = XxeResult(target="http://example.com")
            result = await python_xxe_test("http://example.com")

        data = json.loads(result)
        assert "target" in data
        assert "vulnerable" in data


# ===========================================================================
# Extractor tests
# ===========================================================================


# ===========================================================================
# Tool registry tests
# ===========================================================================


class TestV2ToolRegistration:
    def test_new_tools_registered(self) -> None:
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        tool_names = set(registry._tools.keys())
        assert "ssrf_test" in tool_names
        assert "path_test" in tool_names  # replaces open_redirect_test, xxe_test, lfi_test, host_header_test
        assert "injection_test" in tool_names  # replaces nosql_test, sqli_test, ssti_test, cmdi_test, graphql_test
        assert "access_control_test" in tool_names  # replaces csrf_test, idor_test, cors_test

    def test_total_tool_count_at_least_14(self) -> None:
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert len(registry._tools) >= 14
