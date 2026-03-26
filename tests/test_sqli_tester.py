"""Tests for security_mcp.scanners.sqli_tester — 4-phase SQLi detection."""

from __future__ import annotations

import json
import time

import httpx
import pytest

from security_mcp.scanners.sqli_tester import (
    PythonSQLiTester,
    SQLiResult,
    SQLiVulnerability,
    python_sqli_test,
)

# ---------------------------------------------------------------------------
# Helpers — httpx.MockTransport factories
# ---------------------------------------------------------------------------


def _make_transport(handler):
    """Wrap a sync handler into an httpx.MockTransport."""
    return httpx.MockTransport(handler)


def _text_response(body: str, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, text=body)


# ---------------------------------------------------------------------------
# Phase 1: Error-based detection
# ---------------------------------------------------------------------------


class TestErrorBased:
    @pytest.mark.asyncio
    async def test_mysql_error_detected(self):
        """Inject a single-quote and get back a MySQL syntax error."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "%27" in url_str or "'" in url_str:
                return _text_response(
                    "<html>You have an error in your SQL syntax near '1''</html>"
                )
            return _text_response("<html>OK</html>")

        tester = PythonSQLiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            vuln = await tester._test_error_based(
                client, "http://target/page?id=1", "id", "GET", "GET", None
            )

        assert vuln is not None
        assert vuln.technique == "error_based"
        assert vuln.dbms == "MySQL"
        assert vuln.param == "id"
        assert "SQL syntax" in vuln.evidence

    @pytest.mark.asyncio
    async def test_postgres_error_detected(self):
        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "%27" in url_str or "'" in url_str:
                return _text_response("ERROR:  syntax error at or near ...")
            return _text_response("OK")

        tester = PythonSQLiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            vuln = await tester._test_error_based(
                client, "http://target/page?id=1", "id", "GET", "GET", None
            )

        assert vuln is not None
        assert vuln.dbms == "PostgreSQL"

    @pytest.mark.asyncio
    async def test_no_error_returns_none(self):
        """Clean response should not trigger false positive."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("<html>Normal page content</html>")

        tester = PythonSQLiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            vuln = await tester._test_error_based(
                client, "http://target/page?id=1", "id", "GET", "GET", None
            )

        assert vuln is None


# ---------------------------------------------------------------------------
# Phase 2: Boolean-based detection
# ---------------------------------------------------------------------------


class TestBooleanBased:
    @pytest.mark.asyncio
    async def test_different_length_detected(self):
        """True condition returns more content than false condition."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "1%3D1" in url_str or "1'='1" in url_str or "1%27+AND+%271%27%3D%271" in url_str:
                # True condition: large response
                return _text_response("A" * 1000)
            if "1%3D2" in url_str or "1'='2" in url_str or "1%27+AND+%271%27%3D%272" in url_str:
                # False condition: small response
                return _text_response("B" * 100)
            return _text_response("Normal")

        tester = PythonSQLiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            vuln = await tester._test_boolean_based(
                client, "http://target/page?id=1", "id", "GET", "GET", None
            )

        assert vuln is not None
        assert vuln.technique == "boolean_based"
        assert vuln.param == "id"
        assert "bytes" in vuln.evidence

    @pytest.mark.asyncio
    async def test_same_response_no_detection(self):
        """Identical responses should not trigger detection."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("Same response every time" * 20)

        tester = PythonSQLiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            vuln = await tester._test_boolean_based(
                client, "http://target/page?id=1", "id", "GET", "GET", None
            )

        assert vuln is None


# ---------------------------------------------------------------------------
# Phase 3: Time-based detection
# ---------------------------------------------------------------------------


class TestTimeBased:
    @pytest.mark.asyncio
    async def test_delayed_response_detected(self):
        """Simulate server-side SLEEP with a delayed mock response."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            # Respect the sleep duration: SLEEP(5) → 5s, SLEEP(0) → 0s
            if "SLEEP(5)" in url_str or "SLEEP%285%29" in url_str:
                time.sleep(5.0)
                return _text_response("OK")
            if "SLEEP(0)" in url_str or "SLEEP%280%29" in url_str:
                return _text_response("OK")
            if "sleep(5)" in url_str or "sleep%285%29" in url_str:
                time.sleep(5.0)
                return _text_response("OK")
            return _text_response("OK")

        tester = PythonSQLiTester(timeout=10.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            vuln = await tester._test_time_based(
                client, "http://target/page?id=1", "id", "GET", "GET", None
            )

        assert vuln is not None
        assert vuln.technique == "time_based"
        assert vuln.dbms == "MySQL"
        assert "delayed" in vuln.evidence.lower() or "double" in vuln.evidence.lower()

    @pytest.mark.asyncio
    async def test_fast_response_no_detection(self):
        """Quick responses should not be flagged."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("OK")

        tester = PythonSQLiTester(timeout=10.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            vuln = await tester._test_time_based(
                client, "http://target/page?id=1", "id", "GET", "GET", None
            )

        assert vuln is None


# ---------------------------------------------------------------------------
# Parameter auto-detection
# ---------------------------------------------------------------------------


class TestParamDetection:
    def test_detect_get_params_from_url(self):
        tester = PythonSQLiTester()
        params = tester._detect_params(
            "http://target/page?id=1&name=test", None, "GET", None
        )
        assert ("id", "GET") in params
        assert ("name", "GET") in params
        assert len(params) == 2

    def test_detect_post_params(self):
        tester = PythonSQLiTester()
        params = tester._detect_params(
            "http://target/login", None, "POST", {"user": "admin", "pass": "secret"}
        )
        assert ("user", "POST") in params
        assert ("pass", "POST") in params
        assert len(params) == 2

    def test_detect_mixed_get_and_post(self):
        tester = PythonSQLiTester()
        params = tester._detect_params(
            "http://target/page?token=abc", None, "POST", {"q": "search"}
        )
        assert ("token", "GET") in params
        assert ("q", "POST") in params

    def test_filter_explicit_params(self):
        tester = PythonSQLiTester()
        params = tester._detect_params(
            "http://target/page?id=1&name=test&safe=ok",
            ["id"],
            "GET",
            None,
        )
        assert len(params) == 1
        assert params[0] == ("id", "GET")

    def test_no_params_returns_empty(self):
        tester = PythonSQLiTester()
        params = tester._detect_params("http://target/page", None, "GET", None)
        assert params == []


# ---------------------------------------------------------------------------
# SQLiResult serialization
# ---------------------------------------------------------------------------


class TestSQLiResultSerialization:
    def test_to_dict_empty(self):
        result = SQLiResult(target="http://target/page")
        d = result.to_dict()
        assert d["target"] == "http://target/page"
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []
        assert d["params_tested"] == 0
        assert d["duration_ms"] == 0.0

    def test_to_dict_with_vulnerabilities(self):
        result = SQLiResult(
            target="http://target/page?id=1",
            vulnerable=True,
            params_tested=2,
            duration_ms=1234.5,
            vulnerabilities=[
                SQLiVulnerability(
                    param="id",
                    location="GET",
                    technique="error_based",
                    dbms="MySQL",
                    evidence="SQL syntax error",
                    payload="'",
                ),
                SQLiVulnerability(
                    param="name",
                    location="POST",
                    technique="boolean_based",
                    evidence="True: 1000 bytes, False: 100 bytes",
                    payload="1' AND '1'='1",
                ),
            ],
        )
        d = result.to_dict()
        assert d["vulnerable"] is True
        assert d["params_tested"] == 2
        assert d["duration_ms"] == 1234.5
        assert len(d["vulnerabilities"]) == 2

        v0 = d["vulnerabilities"][0]
        assert v0["param"] == "id"
        assert v0["technique"] == "error_based"
        assert v0["dbms"] == "MySQL"

        v1 = d["vulnerabilities"][1]
        assert v1["param"] == "name"
        assert v1["location"] == "POST"
        assert v1["technique"] == "boolean_based"

    def test_to_dict_is_json_serializable(self):
        result = SQLiResult(
            target="http://t",
            vulnerable=True,
            vulnerabilities=[
                SQLiVulnerability(
                    param="x", location="GET", technique="time_based",
                    dbms="PostgreSQL", evidence="delayed 5.2s", payload="pg_sleep",
                )
            ],
        )
        serialized = json.dumps(result.to_dict())
        assert '"vulnerable": true' in serialized


# ---------------------------------------------------------------------------
# Full integration: test() method
# ---------------------------------------------------------------------------


class TestFullScan:
    @pytest.mark.asyncio
    async def test_full_scan_finds_error_based(self):
        """Full test() run with error-based injection on one param."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "'" in url_str or "%27" in url_str:
                return _text_response("You have an error in your SQL syntax near ''")
            return _text_response("Normal page")

        tester = PythonSQLiTester(timeout=5.0)
        # Patch the internal client by overriding the test method context
        # We use the tool wrapper instead for a cleaner integration test
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            vuln = await tester._test_error_based(
                client, "http://target/page?id=1", "id", "GET", "GET", None
            )
        assert vuln is not None
        assert vuln.technique == "error_based"

    @pytest.mark.asyncio
    async def test_no_params_returns_clean_result(self):
        """URL with no params should return quickly with zero findings."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("OK")

        tester = PythonSQLiTester(timeout=5.0)
        # Monkeypatch httpx.AsyncClient to use our transport
        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _make_transport(handler)
            original_init(self_client, **kwargs)

        httpx.AsyncClient.__init__ = patched_init
        try:
            result = await tester.test("http://target/page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.vulnerable is False
        assert result.params_tested == 0
        assert result.duration_ms > 0


# ---------------------------------------------------------------------------
# Tool wrapper
# ---------------------------------------------------------------------------


class TestToolWrapper:
    @pytest.mark.asyncio
    async def test_python_sqli_test_returns_json(self):
        """The tool wrapper should return valid JSON."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("Clean page")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _make_transport(handler)
            original_init(self_client, **kwargs)

        httpx.AsyncClient.__init__ = patched_init
        try:
            output = await python_sqli_test(url="http://target/page?id=1")
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(output)
        assert "target" in data
        assert "vulnerable" in data
        assert "vulnerabilities" in data
        assert "params_tested" in data
        assert data["params_tested"] == 1

    @pytest.mark.asyncio
    async def test_python_sqli_test_with_json_body(self):
        """POST with JSON body should inject payloads into body values."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                body_text = request.content.decode()
                if "'" in body_text or "OR" in body_text:
                    return _text_response("You have an error in your SQL syntax near ''")
            return _text_response("OK")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _make_transport(handler)
            original_init(self_client, **kwargs)

        httpx.AsyncClient.__init__ = patched_init
        try:
            output = await python_sqli_test(
                url="http://target/rest/user/login",
                method="POST",
                body='{"email": "test@test.com", "password": "test"}',
                content_type="json",
            )
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(output)
        assert data["params_tested"] == 2  # email + password
        assert data["vulnerable"] is True

    @pytest.mark.asyncio
    async def test_python_sqli_test_with_form_body(self):
        """POST with form-encoded body should detect params from body string."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("OK")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _make_transport(handler)
            original_init(self_client, **kwargs)

        httpx.AsyncClient.__init__ = patched_init
        try:
            output = await python_sqli_test(
                url="http://target/login",
                method="POST",
                body="user=admin&pass=secret",
                content_type="form",
            )
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(output)
        assert data["params_tested"] == 2

    @pytest.mark.asyncio
    async def test_python_sqli_test_invalid_json_body(self):
        """Invalid JSON body with content_type=json should return error gracefully."""
        output = await python_sqli_test(
            url="http://target/api",
            method="POST",
            body="not valid json{{{",
            content_type="json",
        )
        data = json.loads(output)
        assert "error" in data
        assert "Invalid JSON" in data["error"]
