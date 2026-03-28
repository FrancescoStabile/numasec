"""Tests for numasec.scanners.smuggling_tester — HTTP request smuggling detection."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from numasec.scanners.smuggling_tester import (
    TE_OBFUSCATION_VARIANTS,
    SmugglingResult,
    SmugglingTester,
    SmugglingVulnerability,
    python_smuggling_test,
)

# ---------------------------------------------------------------------------
# Helpers — mock asyncio.open_connection
# ---------------------------------------------------------------------------


def _make_mock_connection(
    response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
    delay: float = 0.0,
):
    """Create a mock (reader, writer) pair for asyncio.open_connection.

    Parameters
    ----------
    response:
        Bytes to return when reading from the connection.
    delay:
        Simulated delay in seconds before the response is available.
        If *delay* exceeds the probe timeout the reader will raise
        ``asyncio.TimeoutError`` (simulating a server waiting for data).
    """

    async def mock_open_connection(*args, **kwargs):
        reader = AsyncMock(spec=asyncio.StreamReader)

        async def mock_read(n):
            if delay > 0:
                await asyncio.sleep(delay)
            return response

        reader.read = mock_read

        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.write = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        drain_mock = AsyncMock()
        writer.drain = drain_mock

        return reader, writer

    return mock_open_connection


def _make_slow_connection(timeout_s: float = 15.0):
    """Return a mock connection that always times out (simulates server waiting)."""
    return _make_mock_connection(response=b"", delay=timeout_s)


def _make_fast_connection(
    response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
):
    """Return a mock connection that responds instantly."""
    return _make_mock_connection(response=response, delay=0.0)


def _make_error_connection(
    status: int = 400,
    body: str = "Bad Request: invalid transfer-encoding",
):
    """Return a mock connection that returns an error response."""
    resp = f"HTTP/1.1 {status} Bad Request\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    return _make_mock_connection(response=resp.encode(), delay=0.0)


def _make_differential_connection(
    standard_response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
    variant_response: bytes = b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n",
):
    """Return a mock connection that returns different responses for TE variants.

    Requests containing an obfuscated Transfer-Encoding header (non-standard
    variant) get the variant_response.  All other requests get the
    standard_response.
    """

    async def mock_open_connection(*args, **kwargs):
        written_data: list[bytes] = []

        reader = AsyncMock(spec=asyncio.StreamReader)

        async def mock_read(n):
            raw = b"".join(written_data)
            raw_lower = raw.lower()
            # Detect obfuscated TE headers
            is_obfuscated = any(
                marker in raw_lower
                for marker in [
                    b"transfer-encoding : ",  # space before colon
                    b"transfer-encoding: xchunked",
                    b"transfer-encoding: chunked, cow",
                    b"transfer-encoding:\tchunked",
                    b"x-transfer-encoding:",
                ]
            )
            # Also detect duplicate TE header (chunked followed by cow)
            if raw_lower.count(b"transfer-encoding:") >= 2:
                is_obfuscated = True

            return variant_response if is_obfuscated else standard_response

        reader.read = mock_read

        writer = MagicMock(spec=asyncio.StreamWriter)

        def capture_write(data):
            written_data.append(data)

        writer.write = capture_write
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        writer.drain = AsyncMock()

        return reader, writer

    return mock_open_connection


# ---------------------------------------------------------------------------
# Helper to patch both httpx (baseline) and asyncio (probes)
# ---------------------------------------------------------------------------


def _patch_httpx_baseline(status: int = 200, body: str = "OK"):
    """Return (original_init, patched_init) for httpx.AsyncClient."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body)

    original_init = httpx.AsyncClient.__init__

    def patched_init(self_client, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        kwargs.pop("proxy", None)
        kwargs.pop("http2", None)
        original_init(self_client, **kwargs)

    return original_init, patched_init


# ---------------------------------------------------------------------------
# SmugglingVulnerability dataclass tests
# ---------------------------------------------------------------------------


class TestSmugglingVulnerability:
    def test_defaults(self):
        vuln = SmugglingVulnerability(smuggle_type="cl_te", evidence="test evidence")
        assert vuln.severity == "critical"
        assert vuln.confidence == 0.7

    def test_custom_values(self):
        vuln = SmugglingVulnerability(
            smuggle_type="te_cl",
            evidence="custom evidence",
            severity="high",
            confidence=0.9,
        )
        assert vuln.smuggle_type == "te_cl"
        assert vuln.severity == "high"
        assert vuln.confidence == 0.9


# ---------------------------------------------------------------------------
# SmugglingResult serialisation tests
# ---------------------------------------------------------------------------


class TestSmugglingResult:
    def test_to_dict_no_vulns(self):
        result = SmugglingResult(
            target="http://example.com",
            techniques_tested=["cl_te", "te_cl"],
            duration_ms=123.456,
        )
        d = result.to_dict()
        assert d["target"] == "http://example.com"
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []
        assert d["techniques_tested"] == ["cl_te", "te_cl"]
        assert d["duration_ms"] == 123.46
        assert "No HTTP request smuggling found" in d["summary"]
        assert d["next_steps"] == []

    def test_to_dict_with_vulns(self):
        vuln = SmugglingVulnerability(
            smuggle_type="cl_te",
            evidence="CL.TE timing anomaly detected",
            severity="critical",
            confidence=0.6,
        )
        result = SmugglingResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=[vuln],
            techniques_tested=["cl_te", "te_cl", "te_te", "h2_smuggling"],
            duration_ms=5000.0,
        )
        d = result.to_dict()
        assert d["vulnerable"] is True
        assert len(d["vulnerabilities"]) == 1
        assert d["vulnerabilities"][0]["type"] == "http_request_smuggling"
        assert d["vulnerabilities"][0]["smuggle_type"] == "cl_te"
        assert d["vulnerabilities"][0]["confidence"] == 0.6
        assert "cl_te" in d["summary"]
        assert len(d["next_steps"]) > 0

    def test_to_dict_multiple_vulns(self):
        vulns = [
            SmugglingVulnerability(smuggle_type="cl_te", evidence="e1"),
            SmugglingVulnerability(smuggle_type="te_te", evidence="e2"),
        ]
        result = SmugglingResult(
            target="http://example.com",
            vulnerable=True,
            vulnerabilities=vulns,
            techniques_tested=["cl_te", "te_cl", "te_te"],
        )
        d = result.to_dict()
        assert len(d["vulnerabilities"]) == 2
        assert "cl_te" in d["summary"]
        assert "te_te" in d["summary"]


# ---------------------------------------------------------------------------
# CL.TE Detection
# ---------------------------------------------------------------------------


class TestCLTEDetection:
    @pytest.mark.asyncio
    async def test_clte_timing_detected(self):
        """Server waits for data (CL-first) → CL.TE detected via timing."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = SmugglingTester(timeout=10.0)
            # Mock _send_raw_request to return slow response (simulating CL wait)
            call_idx = 0

            async def mock_send(host, port, raw, timeout=None, use_tls=False):
                nonlocal call_idx
                call_idx += 1
                # Return empty response with 8s elapsed (exceeds threshold)
                return b"", 8.0

            tester._send_raw_request = mock_send
            result = await tester.test("http://target.example.com/")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert "cl_te" in result.techniques_tested
        cl_te_vulns = [v for v in result.vulnerabilities if v.smuggle_type == "cl_te"]
        assert len(cl_te_vulns) >= 1
        assert cl_te_vulns[0].confidence == 0.6
        assert "CL.TE" in cl_te_vulns[0].evidence

    @pytest.mark.asyncio
    async def test_clte_parser_confusion_detected(self):
        """Server returns 400 with parser error keywords → CL.TE response anomaly."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            with patch(
                "asyncio.open_connection",
                side_effect=_make_error_connection(
                    status=400,
                    body="400 Bad Request: invalid transfer-encoding header",
                ),
            ):
                tester = SmugglingTester(timeout=10.0)
                result = await tester.test("http://target.example.com/")
        finally:
            httpx.AsyncClient.__init__ = original_init

        cl_te_vulns = [v for v in result.vulnerabilities if v.smuggle_type == "cl_te"]
        assert len(cl_te_vulns) >= 1
        assert cl_te_vulns[0].confidence == 0.8

    @pytest.mark.asyncio
    async def test_clte_not_detected_fast_response(self):
        """Fast response from server → no CL.TE finding."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            with patch(
                "asyncio.open_connection",
                side_effect=_make_fast_connection(),
            ):
                tester = SmugglingTester(timeout=10.0)
                result = await tester.test("http://target.example.com/")
        finally:
            httpx.AsyncClient.__init__ = original_init

        cl_te_vulns = [v for v in result.vulnerabilities if v.smuggle_type == "cl_te"]
        assert len(cl_te_vulns) == 0


# ---------------------------------------------------------------------------
# TE.CL Detection
# ---------------------------------------------------------------------------


class TestTECLDetection:
    @pytest.mark.asyncio
    async def test_tecl_timing_detected(self):
        """Server waits for data (CL-first) → TE.CL detected via timing."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = SmugglingTester(timeout=10.0)

            async def mock_send(host, port, raw, timeout=None, use_tls=False):
                return b"", 8.0

            tester._send_raw_request = mock_send
            result = await tester.test("http://target.example.com/")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert "te_cl" in result.techniques_tested
        te_cl_vulns = [v for v in result.vulnerabilities if v.smuggle_type == "te_cl"]
        assert len(te_cl_vulns) >= 1
        assert te_cl_vulns[0].confidence == 0.6

    @pytest.mark.asyncio
    async def test_tecl_parser_confusion_detected(self):
        """Server returns 400 with parser error → TE.CL response anomaly."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            with patch(
                "asyncio.open_connection",
                side_effect=_make_error_connection(
                    status=400,
                    body="400 Bad Request: content-length mismatch",
                ),
            ):
                tester = SmugglingTester(timeout=10.0)
                result = await tester.test("http://target.example.com/")
        finally:
            httpx.AsyncClient.__init__ = original_init

        te_cl_vulns = [v for v in result.vulnerabilities if v.smuggle_type == "te_cl"]
        assert len(te_cl_vulns) >= 1
        assert te_cl_vulns[0].confidence == 0.8

    @pytest.mark.asyncio
    async def test_tecl_not_detected_fast_response(self):
        """Fast response → no TE.CL finding."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            with patch(
                "asyncio.open_connection",
                side_effect=_make_fast_connection(),
            ):
                tester = SmugglingTester(timeout=10.0)
                result = await tester.test("http://target.example.com/")
        finally:
            httpx.AsyncClient.__init__ = original_init

        te_cl_vulns = [v for v in result.vulnerabilities if v.smuggle_type == "te_cl"]
        assert len(te_cl_vulns) == 0


# ---------------------------------------------------------------------------
# TE.TE Obfuscation Detection
# ---------------------------------------------------------------------------


class TestTETEDetection:
    @pytest.mark.asyncio
    async def test_te_te_status_difference_detected(self):
        """Different status code for TE variant → TE.TE finding."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            with patch(
                "asyncio.open_connection",
                side_effect=_make_differential_connection(
                    standard_response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
                    variant_response=b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n",
                ),
            ):
                tester = SmugglingTester(timeout=10.0)
                result = await tester.test("http://target.example.com/")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert "te_te" in result.techniques_tested
        te_te_vulns = [v for v in result.vulnerabilities if v.smuggle_type == "te_te"]
        assert len(te_te_vulns) >= 1
        assert te_te_vulns[0].confidence == 0.8

    @pytest.mark.asyncio
    async def test_te_te_consistent_no_finding(self):
        """All TE variants get same response → no TE.TE finding."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            with patch(
                "asyncio.open_connection",
                side_effect=_make_fast_connection(),
            ):
                tester = SmugglingTester(timeout=10.0)
                result = await tester.test("http://target.example.com/")
        finally:
            httpx.AsyncClient.__init__ = original_init

        te_te_vulns = [v for v in result.vulnerabilities if v.smuggle_type == "te_te"]
        assert len(te_te_vulns) == 0

    def test_te_obfuscation_variants_list(self):
        """Sanity check: at least 6 obfuscation variants defined."""
        assert len(TE_OBFUSCATION_VARIANTS) >= 6
        names = [name for _, name in TE_OBFUSCATION_VARIANTS]
        assert "standard" in names
        assert "space_before_colon" in names
        assert "tab_separator" in names


# ---------------------------------------------------------------------------
# Consistent server — no findings
# ---------------------------------------------------------------------------


class TestConsistentServer:
    @pytest.mark.asyncio
    async def test_no_smuggling_on_consistent_server(self):
        """A server that responds consistently should produce no findings."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            with patch(
                "asyncio.open_connection",
                side_effect=_make_fast_connection(),
            ):
                tester = SmugglingTester(timeout=10.0)
                result = await tester.test("http://target.example.com/")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.vulnerable is False
        assert len(result.vulnerabilities) == 0
        assert len(result.techniques_tested) == 4

    @pytest.mark.asyncio
    async def test_empty_host_returns_empty_result(self):
        """Malformed URL with no host returns empty result."""
        tester = SmugglingTester(timeout=5.0)
        result = await tester.test("not-a-url")
        assert result.vulnerable is False
        assert len(result.techniques_tested) == 0


# ---------------------------------------------------------------------------
# Raw request sending
# ---------------------------------------------------------------------------


class TestRawRequestSending:
    @pytest.mark.asyncio
    async def test_send_raw_request_success(self):
        """Raw request returns response bytes and elapsed time."""
        response_data = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
        with patch(
            "asyncio.open_connection",
            side_effect=_make_fast_connection(response=response_data),
        ):
            tester = SmugglingTester(timeout=10.0)
            response, elapsed = await tester._send_raw_request(
                "example.com", 80, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
        assert response == response_data
        assert elapsed >= 0

    @pytest.mark.asyncio
    async def test_send_raw_request_connection_error(self):
        """Connection error returns empty bytes and timeout as elapsed."""

        async def failing_connection(*args, **kwargs):
            raise OSError("Connection refused")

        with patch("asyncio.open_connection", side_effect=failing_connection):
            tester = SmugglingTester(timeout=5.0)
            response, elapsed = await tester._send_raw_request(
                "example.com", 80, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
        assert response == b""
        assert elapsed == 5.0

    @pytest.mark.asyncio
    async def test_send_raw_request_with_tls(self):
        """TLS connection uses ssl context."""
        response_data = b"HTTP/1.1 200 OK\r\n\r\nOK"

        async def mock_open(*args, **kwargs):
            assert kwargs.get("ssl") is not None
            reader = AsyncMock(spec=asyncio.StreamReader)

            async def mock_read(n):
                return response_data

            reader.read = mock_read
            writer = MagicMock(spec=asyncio.StreamWriter)
            writer.write = MagicMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            writer.drain = AsyncMock()
            return reader, writer

        with patch("asyncio.open_connection", side_effect=mock_open):
            tester = SmugglingTester(timeout=10.0)
            response, elapsed = await tester._send_raw_request(
                "example.com", 443, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                use_tls=True,
            )
        assert response == response_data


# ---------------------------------------------------------------------------
# Timeout handling
# ---------------------------------------------------------------------------


class TestTimeoutHandling:
    @pytest.mark.asyncio
    async def test_read_timeout_returns_empty(self):
        """When the server never responds, we get empty bytes after timeout."""

        async def mock_open(*args, **kwargs):
            reader = AsyncMock(spec=asyncio.StreamReader)

            async def mock_read(n):
                await asyncio.sleep(100)  # never finishes
                return b""

            reader.read = mock_read
            writer = MagicMock(spec=asyncio.StreamWriter)
            writer.write = MagicMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            writer.drain = AsyncMock()
            return reader, writer

        with patch("asyncio.open_connection", side_effect=mock_open):
            tester = SmugglingTester(timeout=1.0)
            response, elapsed = await tester._send_raw_request(
                "example.com", 80, b"GET / HTTP/1.1\r\n\r\n", timeout=1.0,
            )
        assert response == b""
        assert elapsed >= 1.0

    @pytest.mark.asyncio
    async def test_connection_timeout(self):
        """When connection itself times out."""

        async def mock_open(*args, **kwargs):
            await asyncio.sleep(100)  # never connects
            raise OSError("unreachable")

        with patch("asyncio.open_connection", side_effect=mock_open):
            tester = SmugglingTester(timeout=1.0)
            response, elapsed = await tester._send_raw_request(
                "example.com", 80, b"GET / HTTP/1.1\r\n\r\n", timeout=1.0,
            )
        assert response == b""


# ---------------------------------------------------------------------------
# Helper method tests
# ---------------------------------------------------------------------------


class TestHelperMethods:
    def test_extract_status_code_200(self):
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        assert SmugglingTester._extract_status_code(resp) == 200

    def test_extract_status_code_400(self):
        resp = b"HTTP/1.1 400 Bad Request\r\n\r\n"
        assert SmugglingTester._extract_status_code(resp) == 400

    def test_extract_status_code_empty(self):
        assert SmugglingTester._extract_status_code(b"") is None

    def test_extract_status_code_garbage(self):
        assert SmugglingTester._extract_status_code(b"not http") is None

    def test_indicates_parser_confusion_true(self):
        resp = b"HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request: invalid transfer-encoding"
        assert SmugglingTester._indicates_parser_confusion(resp) is True

    def test_indicates_parser_confusion_false_200(self):
        resp = b"HTTP/1.1 200 OK\r\n\r\nAll good"
        assert SmugglingTester._indicates_parser_confusion(resp) is False

    def test_indicates_parser_confusion_empty(self):
        assert SmugglingTester._indicates_parser_confusion(b"") is False

    def test_indicates_parser_confusion_400_no_keywords(self):
        resp = b"HTTP/1.1 400 Bad Request\r\n\r\nGeneric error with no hints"
        assert SmugglingTester._indicates_parser_confusion(resp) is False

    def test_format_extra_headers_empty(self):
        tester = SmugglingTester()
        assert tester._format_extra_headers() == ""

    def test_format_extra_headers_with_values(self):
        tester = SmugglingTester(extra_headers={"Authorization": "Bearer xyz"})
        formatted = tester._format_extra_headers()
        assert "Authorization: Bearer xyz\r\n" in formatted


# ---------------------------------------------------------------------------
# Tool wrapper
# ---------------------------------------------------------------------------


class TestToolWrapper:
    @pytest.mark.asyncio
    async def test_python_smuggling_test_returns_json(self):
        """Tool wrapper returns valid JSON."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            with patch(
                "asyncio.open_connection",
                side_effect=_make_fast_connection(),
            ):
                raw = await python_smuggling_test("http://target.example.com/")
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(raw)
        assert "target" in data
        assert "vulnerable" in data
        assert "techniques_tested" in data
        assert data["target"] == "http://target.example.com/"

    @pytest.mark.asyncio
    async def test_python_smuggling_test_with_headers(self):
        """Tool wrapper parses JSON headers."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            with patch(
                "asyncio.open_connection",
                side_effect=_make_fast_connection(),
            ):
                raw = await python_smuggling_test(
                    "http://target.example.com/",
                    headers='{"Authorization": "Bearer test123"}',
                )
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(raw)
        assert data["target"] == "http://target.example.com/"

    @pytest.mark.asyncio
    async def test_python_smuggling_test_invalid_headers_ignored(self):
        """Invalid headers JSON is silently ignored."""
        original_init, patched_init = _patch_httpx_baseline()
        httpx.AsyncClient.__init__ = patched_init
        try:
            with patch(
                "asyncio.open_connection",
                side_effect=_make_fast_connection(),
            ):
                raw = await python_smuggling_test(
                    "http://target.example.com/",
                    headers="not-valid-json",
                )
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(raw)
        assert "target" in data
