"""Tests for security_mcp.scanners.vuln_scanner — Python-native vuln scanner."""

from __future__ import annotations

import json

import httpx

from security_mcp.scanners.vuln_scanner import (
    SECURITY_HEADERS,
    PythonVulnScanner,
    ScanResult,
    VulnFinding,
    python_vuln_scan,
)

# ---------------------------------------------------------------------------
# Helpers — httpx.MockTransport responders
# ---------------------------------------------------------------------------


def _make_transport(
    body: str = "<html>OK</html>",
    headers: dict[str, str] | None = None,
    status_code: int = 200,
) -> httpx.MockTransport:
    """Create a mock transport returning a fixed response."""
    resp_headers = headers or {}

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=status_code,
            headers=resp_headers,
            text=body,
        )

    return httpx.MockTransport(_handler)


# ---------------------------------------------------------------------------
# VulnFinding / ScanResult dataclass tests
# ---------------------------------------------------------------------------


class TestVulnFinding:
    def test_defaults(self):
        f = VulnFinding(
            vuln_type="xss",
            severity="high",
            title="Reflected XSS",
            description="XSS in search param",
            url="http://example.com",
        )
        assert f.vuln_type == "xss"
        assert f.evidence == ""
        assert f.parameter == ""
        assert f.cwe_id == ""
        assert f.template_id == ""

    def test_all_fields(self):
        f = VulnFinding(
            vuln_type="sqli",
            severity="critical",
            title="SQL Injection",
            description="Error-based SQLi",
            url="http://example.com/api?id=1",
            evidence="SQL syntax error",
            parameter="id",
            cwe_id="CWE-89",
            template_id="sqli-error-based",
        )
        assert f.cwe_id == "CWE-89"
        assert f.template_id == "sqli-error-based"


class TestScanResult:
    def test_empty_result(self):
        r = ScanResult(target="http://example.com")
        assert r.target == "http://example.com"
        assert r.findings == []
        assert r.technologies == []
        assert r.missing_headers == []
        assert r.dangerous_headers == []
        assert r.checks_run == 0

    def test_to_dict_serialisation(self):
        r = ScanResult(target="http://example.com")
        r.checks_run = 3
        r.checks_passed = 2
        r.duration_ms = 123.456
        r.missing_headers = ["content-security-policy"]
        r.technologies = [{"name": "nginx", "version": "1.18", "confidence": 0.8}]
        r.findings.append(VulnFinding(
            vuln_type="missing_header",
            severity="high",
            title="Missing CSP",
            description="No CSP header",
            url="http://example.com",
            cwe_id="CWE-693",
        ))

        d = r.to_dict()
        assert d["target"] == "http://example.com"
        assert d["checks_run"] == 3
        assert d["checks_passed"] == 2
        assert d["duration_ms"] == 123.46
        assert len(d["findings"]) == 1
        assert d["findings"][0]["type"] == "missing_header"
        assert d["findings"][0]["cwe_id"] == "CWE-693"
        assert d["technologies"][0]["name"] == "nginx"
        assert d["missing_headers"] == ["content-security-policy"]

    def test_to_dict_is_json_serialisable(self):
        r = ScanResult(target="http://example.com", duration_ms=42.0)
        r.findings.append(VulnFinding(
            vuln_type="test", severity="info", title="Test",
            description="Test finding", url="http://example.com",
        ))
        serialised = json.dumps(r.to_dict())
        assert isinstance(serialised, str)
        parsed = json.loads(serialised)
        assert parsed["target"] == "http://example.com"


# ---------------------------------------------------------------------------
# Header check tests
# ---------------------------------------------------------------------------


class TestHeaderCheck:
    async def test_missing_headers_detected(self):
        """Response with no security headers should flag all missing."""
        transport = _make_transport(
            body="<html>Hello</html>",
            headers={"content-type": "text/html"},
        )

        scanner = PythonVulnScanner()
        async with httpx.AsyncClient(transport=transport) as client:
            result = ScanResult(target="http://example.com")
            await scanner._check_headers(client, "http://example.com", result)

        assert len(result.missing_headers) == len(SECURITY_HEADERS)
        header_findings = [f for f in result.findings if f.vuln_type == "missing_header"]
        assert len(header_findings) == len(SECURITY_HEADERS)

    async def test_all_headers_present(self):
        """Response with all security headers should pass cleanly."""
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "camera=()",
        }
        transport = _make_transport(body="OK", headers=headers)

        scanner = PythonVulnScanner()
        async with httpx.AsyncClient(transport=transport) as client:
            result = ScanResult(target="http://example.com")
            await scanner._check_headers(client, "http://example.com", result)

        assert result.missing_headers == []
        assert result.dangerous_headers == []
        # No findings at all means passed
        assert result.checks_passed == 1

    async def test_dangerous_header_detected(self):
        """Server header should be flagged as information disclosure."""
        headers = {
            "server": "Apache/2.4.41",
            "x-powered-by": "PHP/7.4.3",
            # Also include all security headers so we isolate the test
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "camera=()",
        }
        transport = _make_transport(body="OK", headers=headers)

        scanner = PythonVulnScanner()
        async with httpx.AsyncClient(transport=transport) as client:
            result = ScanResult(target="http://example.com")
            await scanner._check_headers(client, "http://example.com", result)

        assert len(result.dangerous_headers) == 2
        dangerous_types = [f for f in result.findings if f.vuln_type == "dangerous_header"]
        assert len(dangerous_types) == 2


# ---------------------------------------------------------------------------
# Technology detection tests
# ---------------------------------------------------------------------------


class TestTechnologyDetection:
    async def test_detects_wordpress(self):
        body = '<html><link rel="stylesheet" href="/wp-content/themes/theme/style.css"></html>'
        transport = _make_transport(body=body)

        scanner = PythonVulnScanner()
        async with httpx.AsyncClient(transport=transport) as client:
            result = ScanResult(target="http://example.com")
            await scanner._detect_technologies(client, "http://example.com", result)

        names = [t["name"] for t in result.technologies]
        assert "WordPress" in names
        assert result.checks_passed == 1

    async def test_detects_php_from_header(self):
        transport = _make_transport(
            body="<html>Hello</html>",
            headers={"X-Powered-By": "PHP/8.1.2"},
        )

        scanner = PythonVulnScanner()
        async with httpx.AsyncClient(transport=transport) as client:
            result = ScanResult(target="http://example.com")
            await scanner._detect_technologies(client, "http://example.com", result)

        php_matches = [t for t in result.technologies if t["name"] == "PHP"]
        assert len(php_matches) == 1
        assert php_matches[0]["version"] == "8.1"
        assert php_matches[0]["confidence"] == 0.8

    async def test_detects_jquery_with_version(self):
        body = '<script src="/js/jquery-3.6.0.min.js"></script>'
        transport = _make_transport(body=body)

        scanner = PythonVulnScanner()
        async with httpx.AsyncClient(transport=transport) as client:
            result = ScanResult(target="http://example.com")
            await scanner._detect_technologies(client, "http://example.com", result)

        jquery = [t for t in result.technologies if t["name"] == "jQuery"]
        assert len(jquery) == 1
        assert jquery[0]["version"] == "3.6.0"

    async def test_no_tech_in_plain_page(self):
        transport = _make_transport(body="<html><body>Hello World</body></html>")

        scanner = PythonVulnScanner()
        async with httpx.AsyncClient(transport=transport) as client:
            result = ScanResult(target="http://example.com")
            await scanner._detect_technologies(client, "http://example.com", result)

        assert result.technologies == []
        assert result.checks_passed == 1


# ---------------------------------------------------------------------------
# Response match tests
# ---------------------------------------------------------------------------


class TestResponseMatch:
    async def test_detects_sql_error(self):
        body = '<html><body>Error: You have an error in your SQL syntax near ...</body></html>'
        transport = _make_transport(body=body)

        scanner = PythonVulnScanner()
        async with httpx.AsyncClient(transport=transport) as client:
            result = ScanResult(target="http://example.com")
            await scanner._check_response_match(client, "http://example.com", result)

        sqli_findings = [f for f in result.findings if f.vuln_type == "sqli_error_disclosure"]
        assert len(sqli_findings) >= 1
        assert sqli_findings[0].cwe_id == "CWE-209"

    async def test_detects_python_traceback(self):
        body = '<html><pre>Traceback (most recent call last):\n  File "app.py"</pre></html>'
        transport = _make_transport(body=body)

        scanner = PythonVulnScanner()
        async with httpx.AsyncClient(transport=transport) as client:
            result = ScanResult(target="http://example.com")
            await scanner._check_response_match(client, "http://example.com", result)

        disclosure = [f for f in result.findings if f.vuln_type == "info_disclosure"]
        assert len(disclosure) >= 1
        assert any("traceback" in f.title.lower() for f in disclosure)

    async def test_detects_directory_listing(self):
        body = '<html><title>Index of /uploads</title><body>Parent Directory</body></html>'
        transport = _make_transport(body=body)

        scanner = PythonVulnScanner()
        async with httpx.AsyncClient(transport=transport) as client:
            result = ScanResult(target="http://example.com")
            await scanner._check_response_match(client, "http://example.com", result)

        findings = [f for f in result.findings if "directory" in f.title.lower() or "index" in f.title.lower()]
        assert len(findings) >= 1

    async def test_clean_page_passes(self):
        transport = _make_transport(body="<html><body>Welcome to our site</body></html>")

        scanner = PythonVulnScanner()
        async with httpx.AsyncClient(transport=transport) as client:
            result = ScanResult(target="http://example.com")
            await scanner._check_response_match(client, "http://example.com", result)

        assert result.findings == []
        assert result.checks_passed == 1


# ---------------------------------------------------------------------------
# Tool wrapper test
# ---------------------------------------------------------------------------


class TestToolWrapper:
    async def test_python_vuln_scan_returns_json(self, monkeypatch):
        """The tool wrapper should return valid JSON."""
        async def _fake_scan(self, url, checks=None):
            return ScanResult(
                target=url,
                checks_run=1,
                checks_passed=1,
                duration_ms=42.0,
            )

        monkeypatch.setattr(PythonVulnScanner, "scan", _fake_scan)
        output = await python_vuln_scan("http://example.com", checks="headers")
        data = json.loads(output)
        assert data["target"] == "http://example.com"
        assert data["checks_run"] == 1

    async def test_python_vuln_scan_no_checks_param(self, monkeypatch):
        """Calling without checks should default to all passive."""
        captured_checks = {}

        async def _fake_scan(self, url, checks=None):
            captured_checks["value"] = checks
            return ScanResult(target=url, duration_ms=1.0)

        monkeypatch.setattr(PythonVulnScanner, "scan", _fake_scan)
        await python_vuln_scan("http://example.com")
        assert captured_checks["value"] is None
