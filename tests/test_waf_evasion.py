"""Tests for WAF evasion payload expansion via PayloadEncoder integration.

Verifies that ``waf_evasion=True`` produces expanded payload sets in all four
scanners that support it (SQLi, XSS, SSTI, LFI), that the default behaviour
remains unchanged when disabled, and that composite tools correctly propagate
the flag to underlying scanners.

Run with: ``pytest tests/test_waf_evasion.py -v``
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch
from urllib.parse import unquote

import httpx
import pytest

from security_mcp.scanners._encoder import PayloadEncoder
from security_mcp.scanners.lfi_tester import LfiTester
from security_mcp.scanners.sqli_tester import ERROR_PAYLOADS, BOOLEAN_PAIRS, PythonSQLiTester
from security_mcp.scanners.ssti_tester import SstiTester, _MATH_PROBES
from security_mcp.scanners.xss_tester import ESCALATION_PAYLOADS, PythonXSSTester


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_transport(handler):
    """Wrap a sync handler into an httpx.MockTransport."""
    return httpx.MockTransport(handler)


def _text_response(body: str, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, text=body)


def _collecting_handler(log: list[httpx.Request]):
    """Return a handler that records every request and replies with a clean page."""

    def handler(request: httpx.Request) -> httpx.Response:
        log.append(request)
        return _text_response("<html>OK</html>")

    return handler


# ===========================================================================
# PayloadEncoder unit tests
# ===========================================================================


class TestPayloadEncoderVariants:
    """Verify PayloadEncoder produces valid, distinct variants."""

    def test_sql_variants_non_empty(self):
        variants = PayloadEncoder.sql_variants("' OR 1=1--")
        assert len(variants) > 1, "sql_variants should produce at least 2 items (original + encoded)"
        # First element is always the original
        assert variants[0] == "' OR 1=1--"
        # At least one variant differs from the original
        assert any(v != "' OR 1=1--" for v in variants[1:])

    def test_sql_variants_deduplication(self):
        variants = PayloadEncoder.sql_variants("' OR 1=1--")
        assert len(variants) == len(set(variants)), "sql_variants should not contain duplicates"

    def test_xss_variants_non_empty(self):
        variants = PayloadEncoder.xss_variants("<script>alert(1)</script>")
        assert len(variants) > 1
        assert variants[0] == "<script>alert(1)</script>"

    def test_xss_variants_deduplication(self):
        variants = PayloadEncoder.xss_variants("<script>alert(1)</script>")
        assert len(variants) == len(set(variants))

    def test_all_variants_includes_multiple_encodings(self):
        variants = PayloadEncoder.all_variants("' OR 1=1--")
        assert len(variants) >= 4, "all_variants should produce at least 4 encodings"

    def test_url_encode(self):
        result = PayloadEncoder.url_encode("' OR 1=1--")
        assert result != "' OR 1=1--"
        assert "%27" in result  # single-quote URL-encoded

    def test_url_double_encode(self):
        result = PayloadEncoder.url_double_encode("../../../etc/passwd")
        assert result != "../../../etc/passwd"
        assert "%25" in result  # double-encoded % sign

    def test_url_double_encode_quote(self):
        result = PayloadEncoder.url_double_encode("'")
        assert "%2527" in result

    def test_unicode_normalize(self):
        result = PayloadEncoder.unicode_normalize("<script>alert(1)</script>")
        assert result != "<script>alert(1)</script>"
        # Should contain full-width less-than U+FF1C
        assert "\uff1c" in result

    def test_null_byte_insert(self):
        result = PayloadEncoder.null_byte_insert("../etc/passwd")
        assert "%00" in result
        # null bytes inserted between every character
        assert len(result) > len("../etc/passwd")

    def test_hex_encode_sql(self):
        result = PayloadEncoder.hex_encode_sql("admin")
        assert result.startswith("0x")
        # hex of 'admin' is 61646d696e
        assert "61646d696e" in result

    def test_comment_injection_sql(self):
        result = PayloadEncoder.comment_injection_sql("UNION SELECT")
        assert "/**/" in result

    def test_case_alternate(self):
        result = PayloadEncoder.case_alternate("select")
        assert result != "select"
        assert result.lower() == "select"

    def test_html_entity_encode(self):
        result = PayloadEncoder.html_entity_encode("<script>")
        assert "&#" in result
        assert "<" not in result

    def test_html_hex_entity_encode(self):
        result = PayloadEncoder.html_hex_entity_encode("<script>")
        assert "&#x" in result

    def test_concat_split_sql(self):
        result = PayloadEncoder.concat_split_sql("admin")
        assert "'+'" in result

    def test_concat_split_sql_short_string(self):
        result = PayloadEncoder.concat_split_sql("ab")
        assert result == "ab", "Strings shorter than 4 chars should be returned unchanged"


# ===========================================================================
# SQLi WAF evasion
# ===========================================================================


class TestSQLiWAFEvasion:
    """Verify SQLi scanner expands payloads when waf_evasion=True."""

    @pytest.mark.asyncio
    async def test_error_based_more_payloads_with_evasion(self):
        """waf_evasion=True should send more HTTP requests than waf_evasion=False."""
        baseline_log: list[httpx.Request] = []
        evasion_log: list[httpx.Request] = []

        url = "http://target/page?id=1"

        # Baseline: waf_evasion=False
        tester_off = PythonSQLiTester(timeout=5.0, waf_evasion=False)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(baseline_log))) as client:
            await tester_off._test_error_based(client, url, "id", "GET", "GET", None)

        # Evasion: waf_evasion=True
        tester_on = PythonSQLiTester(timeout=5.0, waf_evasion=True)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(evasion_log))) as client:
            await tester_on._test_error_based(client, url, "id", "GET", "GET", None)

        assert len(evasion_log) > len(baseline_log), (
            f"WAF evasion should send more requests: evasion={len(evasion_log)} vs baseline={len(baseline_log)}"
        )

    @pytest.mark.asyncio
    async def test_boolean_based_more_payloads_with_evasion(self):
        """Boolean phase with WAF evasion should produce more request pairs."""
        baseline_log: list[httpx.Request] = []
        evasion_log: list[httpx.Request] = []

        url = "http://target/page?id=1"

        tester_off = PythonSQLiTester(timeout=5.0, waf_evasion=False)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(baseline_log))) as client:
            await tester_off._test_boolean_based(client, url, "id", "GET", "GET", None)

        tester_on = PythonSQLiTester(timeout=5.0, waf_evasion=True)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(evasion_log))) as client:
            await tester_on._test_boolean_based(client, url, "id", "GET", "GET", None)

        assert len(evasion_log) > len(baseline_log), (
            f"WAF evasion should generate more boolean pairs: "
            f"evasion={len(evasion_log)} vs baseline={len(baseline_log)}"
        )

    @pytest.mark.asyncio
    async def test_evasion_payloads_contain_encoded_variants(self):
        """Verify evasion requests contain PayloadEncoder output."""
        evasion_log: list[httpx.Request] = []
        url = "http://target/page?id=1"

        tester = PythonSQLiTester(timeout=5.0, waf_evasion=True)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(evasion_log))) as client:
            await tester._test_error_based(client, url, "id", "GET", "GET", None)

        # Collect all URL query strings
        all_urls = [str(r.url) for r in evasion_log]
        url_text = " ".join(all_urls)

        # At least one request should contain double-encoded or hex-encoded payload
        has_double_encoded = any("%25" in u for u in all_urls)
        has_hex = any("0x" in u for u in all_urls)
        has_comment = any("%2A%2F" in u or "/**/" in u for u in all_urls)

        assert has_double_encoded or has_hex or has_comment, (
            "WAF evasion payloads should include at least one encoded variant "
            "(double-encoded, hex, or SQL comment)"
        )

    @pytest.mark.asyncio
    async def test_default_no_evasion_unchanged(self):
        """Default (waf_evasion=False) should only send base payloads."""
        log: list[httpx.Request] = []
        url = "http://target/page?id=1"

        tester = PythonSQLiTester(timeout=5.0, waf_evasion=False)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(log))) as client:
            await tester._test_error_based(client, url, "id", "GET", "GET", None)

        # Should send exactly len(ERROR_PAYLOADS) requests for a single param
        assert len(log) == len(ERROR_PAYLOADS), (
            f"Without WAF evasion, error-based should send {len(ERROR_PAYLOADS)} requests, got {len(log)}"
        )


# ===========================================================================
# XSS WAF evasion
# ===========================================================================


class TestXSSWAFEvasion:
    """Verify XSS scanner expands payloads when waf_evasion=True."""

    @pytest.mark.asyncio
    async def test_reflected_more_payloads_with_evasion(self):
        """waf_evasion=True should try more XSS payloads after canary reflection."""
        baseline_log: list[httpx.Request] = []
        evasion_log: list[httpx.Request] = []

        url = "http://target/search?q=test"

        def canary_only_handler(log_list):
            """Reflects canary strings but returns static content for escalation payloads.

            This ensures the canary match passes (triggering escalation) but no payload
            ever appears in the response, so the scanner tries all payloads.
            """

            def handler(request: httpx.Request) -> httpx.Response:
                log_list.append(request)
                url_str = str(request.url)
                if "q=" in url_str:
                    param_val = unquote(url_str.split("q=", 1)[1].split("&", 1)[0])
                    if "security_mcp_" in param_val:
                        # Reflect canary unchanged so the scanner sees it in the body
                        return _text_response(f"<html>Results for: {param_val}</html>")
                    else:
                        # Return a static page with no reflection at all
                        return _text_response("<html>Results for: [filtered]</html>")
                return _text_response("<html>OK</html>")

            return handler

        # Baseline: waf_evasion=False
        tester_off = PythonXSSTester(timeout=5.0, waf_evasion=False)
        async with httpx.AsyncClient(transport=_make_transport(canary_only_handler(baseline_log))) as client:
            await tester_off._test_reflected(client, url, "q", "GET", "GET", None)

        # Evasion: waf_evasion=True
        tester_on = PythonXSSTester(timeout=5.0, waf_evasion=True)
        async with httpx.AsyncClient(transport=_make_transport(canary_only_handler(evasion_log))) as client:
            await tester_on._test_reflected(client, url, "q", "GET", "GET", None)

        assert len(evasion_log) > len(baseline_log), (
            f"XSS WAF evasion should send more payloads: "
            f"evasion={len(evasion_log)} vs baseline={len(baseline_log)}"
        )

    @pytest.mark.asyncio
    async def test_evasion_payloads_include_html_entities(self):
        """WAF evasion XSS payloads should include HTML entity variants."""
        log: list[httpx.Request] = []
        url = "http://target/search?q=test"

        def canary_only_handler(request: httpx.Request) -> httpx.Response:
            log.append(request)
            url_str = str(request.url)
            if "q=" in url_str:
                param_val = unquote(url_str.split("q=", 1)[1].split("&", 1)[0])
                if "security_mcp_" in param_val:
                    return _text_response(f"<html>{param_val}</html>")
                else:
                    return _text_response("<html>[filtered]</html>")
            return _text_response("<html>OK</html>")

        tester = PythonXSSTester(timeout=5.0, waf_evasion=True)
        async with httpx.AsyncClient(transport=_make_transport(canary_only_handler)) as client:
            await tester._test_reflected(client, url, "q", "GET", "GET", None)

        all_urls = [str(r.url) for r in log]
        url_text = " ".join(all_urls)

        # HTML entity encoding produces &#60; or &#x3c; for < character
        # In the URL these get URL-encoded: &#  -> %26%23
        # Double-encoding produces %25 in the URL
        has_html_entity = "%26%23" in url_text or "&#" in url_text
        has_double_encode = "%25" in url_text

        assert has_html_entity or has_double_encode, (
            "XSS WAF evasion should include HTML entity or double-encoded variants"
        )

    @pytest.mark.asyncio
    async def test_default_no_evasion_payload_count(self):
        """Default (waf_evasion=False) should try only base escalation payloads + canary."""
        log: list[httpx.Request] = []
        url = "http://target/search?q=test"

        def canary_only_handler(request: httpx.Request) -> httpx.Response:
            log.append(request)
            url_str = str(request.url)
            if "q=" in url_str:
                param_val = unquote(url_str.split("q=", 1)[1].split("&", 1)[0])
                if "security_mcp_" in param_val:
                    # Reflect canary so escalation triggers
                    return _text_response(f"<html>{param_val}</html>")
                else:
                    # Return static page -- no reflection, forcing full loop
                    return _text_response("<html>[filtered]</html>")
            return _text_response("<html>OK</html>")

        tester = PythonXSSTester(timeout=5.0, waf_evasion=False)
        async with httpx.AsyncClient(transport=_make_transport(canary_only_handler)) as client:
            await tester._test_reflected(client, url, "q", "GET", "GET", None)

        # 1 canary request + len(ESCALATION_PAYLOADS) escalation requests
        expected_count = 1 + len(ESCALATION_PAYLOADS)
        assert len(log) == expected_count, (
            f"Without WAF evasion, expected {expected_count} requests (1 canary + "
            f"{len(ESCALATION_PAYLOADS)} payloads), got {len(log)}"
        )


# ===========================================================================
# SSTI WAF evasion
# ===========================================================================


class TestSSTIWAFEvasion:
    """Verify SSTI scanner expands probes when waf_evasion=True."""

    @pytest.mark.asyncio
    async def test_more_probes_with_evasion(self):
        """waf_evasion=True should send more probe requests."""
        baseline_log: list[httpx.Request] = []
        evasion_log: list[httpx.Request] = []

        url = "http://target/render?tpl=hello"

        # Baseline
        tester_off = SstiTester(timeout=5.0, waf_evasion=False)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(baseline_log))) as client:
            await tester_off._test_param(client, url, "tpl", "GET", "GET", None)

        # Evasion
        tester_on = SstiTester(timeout=5.0, waf_evasion=True)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(evasion_log))) as client:
            await tester_on._test_param(client, url, "tpl", "GET", "GET", None)

        assert len(evasion_log) > len(baseline_log), (
            f"SSTI WAF evasion should send more probes: "
            f"evasion={len(evasion_log)} vs baseline={len(baseline_log)}"
        )

    @pytest.mark.asyncio
    async def test_evasion_includes_url_encoded_probes(self):
        """WAF evasion SSTI probes should include URL-encoded variants."""
        log: list[httpx.Request] = []
        url = "http://target/render?tpl=hello"

        tester = SstiTester(timeout=5.0, waf_evasion=True)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(log))) as client:
            await tester._test_param(client, url, "tpl", "GET", "GET", None)

        all_urls = [str(r.url) for r in log]
        url_text = " ".join(all_urls)

        # URL-encoded {{ is %7B%7B; unicode-normalized { could produce fullwidth chars
        has_url_encoded = "%7B" in url_text or "%7b" in url_text
        has_unicode = "\uff08" in url_text or "%EF%BC%88" in url_text.upper()

        assert has_url_encoded or has_unicode, (
            "SSTI WAF evasion should include URL-encoded or unicode-normalized probe variants"
        )

    @pytest.mark.asyncio
    async def test_default_probe_count(self):
        """Default (waf_evasion=False) should send baseline + math probe requests only."""
        log: list[httpx.Request] = []
        url = "http://target/render?tpl=hello"

        tester = SstiTester(timeout=5.0, waf_evasion=False)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(log))) as client:
            await tester._test_param(client, url, "tpl", "GET", "GET", None)

        # 1 baseline request + len(_MATH_PROBES) probe requests
        expected_count = 1 + len(_MATH_PROBES)
        assert len(log) == expected_count, (
            f"Without WAF evasion, expected {expected_count} requests "
            f"(1 baseline + {len(_MATH_PROBES)} probes), got {len(log)}"
        )


# ===========================================================================
# LFI WAF evasion
# ===========================================================================


class TestLFIWAFEvasion:
    """Verify LFI scanner expands payloads when waf_evasion=True."""

    @pytest.mark.asyncio
    async def test_more_payloads_with_evasion(self):
        """waf_evasion=True should send more traversal attempts."""
        baseline_log: list[httpx.Request] = []
        evasion_log: list[httpx.Request] = []

        url = "http://target/view?file=readme.txt"

        # Baseline
        tester_off = LfiTester(timeout=5.0, waf_evasion=False)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(baseline_log))) as client:
            await tester_off._test_param(client, url, "file", "GET", "GET", None)

        # Evasion
        tester_on = LfiTester(timeout=5.0, waf_evasion=True)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(evasion_log))) as client:
            await tester_on._test_param(client, url, "file", "GET", "GET", None)

        assert len(evasion_log) > len(baseline_log), (
            f"LFI WAF evasion should send more payloads: "
            f"evasion={len(evasion_log)} vs baseline={len(baseline_log)}"
        )

    @pytest.mark.asyncio
    async def test_evasion_includes_double_encoded_and_null_bytes(self):
        """WAF evasion LFI payloads should include double-encoded and null-byte variants."""
        log: list[httpx.Request] = []
        url = "http://target/view?file=readme.txt"

        tester = LfiTester(timeout=5.0, waf_evasion=True)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(log))) as client:
            await tester._test_param(client, url, "file", "GET", "GET", None)

        all_urls = [str(r.url) for r in log]

        # Double-encoded payloads contain %25 (encoded %)
        has_double_encoded = any("%25" in u for u in all_urls)
        # Null byte insert produces literal %00 in the payload string, which
        # httpx re-encodes to %2500 in the URL query
        has_null_byte = any("%2500" in u for u in all_urls)

        assert has_double_encoded, "LFI WAF evasion should include double-encoded payloads"
        assert has_null_byte, "LFI WAF evasion should include null-byte-inserted payloads"

    @pytest.mark.asyncio
    async def test_default_payload_count(self):
        """Default (waf_evasion=False) should only send base _LFI_PAYLOADS."""
        from security_mcp.scanners.lfi_tester import _LFI_PAYLOADS

        log: list[httpx.Request] = []
        url = "http://target/view?file=readme.txt"

        tester = LfiTester(timeout=5.0, waf_evasion=False)
        async with httpx.AsyncClient(transport=_make_transport(_collecting_handler(log))) as client:
            await tester._test_param(client, url, "file", "GET", "GET", None)

        assert len(log) == len(_LFI_PAYLOADS), (
            f"Without WAF evasion, expected {len(_LFI_PAYLOADS)} requests, got {len(log)}"
        )


# ===========================================================================
# Composite tool pass-through
# ===========================================================================


class TestCompositeInjectionPassthrough:
    """Verify injection_test() passes waf_evasion=True to underlying scanners."""

    @pytest.mark.asyncio
    async def test_injection_test_passes_waf_evasion_to_sqli(self):
        """injection_test(waf_evasion=True) should create PythonSQLiTester with waf_evasion=True."""
        from security_mcp.tools.composite_injection import injection_test

        captured_kwargs: dict = {}
        original_init = PythonSQLiTester.__init__

        def capture_init(self, **kwargs):
            captured_kwargs.update(kwargs)
            original_init(self, **kwargs)

        with patch.object(PythonSQLiTester, "__init__", capture_init):
            with patch.object(PythonSQLiTester, "test", new_callable=AsyncMock) as mock_test:
                mock_test.return_value = type("FakeResult", (), {
                    "to_dict": lambda self: {"vulnerable": False, "vulnerabilities": []},
                })()
                await injection_test(url="http://target/?id=1", types="sql", waf_evasion=True)

        assert captured_kwargs.get("waf_evasion") is True, (
            "injection_test should pass waf_evasion=True to PythonSQLiTester"
        )

    @pytest.mark.asyncio
    async def test_injection_test_passes_waf_evasion_to_ssti(self):
        """injection_test(waf_evasion=True) should create SstiTester with waf_evasion=True."""
        from security_mcp.tools.composite_injection import injection_test

        captured_kwargs: dict = {}
        original_init = SstiTester.__init__

        def capture_init(self, **kwargs):
            captured_kwargs.update(kwargs)
            original_init(self, **kwargs)

        with patch.object(SstiTester, "__init__", capture_init):
            with patch.object(SstiTester, "test", new_callable=AsyncMock) as mock_test:
                mock_test.return_value = type("FakeResult", (), {
                    "to_dict": lambda self: {"vulnerable": False, "vulnerabilities": []},
                })()
                await injection_test(url="http://target/?tpl=x", types="ssti", waf_evasion=True)

        assert captured_kwargs.get("waf_evasion") is True, (
            "injection_test should pass waf_evasion=True to SstiTester"
        )

    @pytest.mark.asyncio
    async def test_injection_test_default_waf_evasion_false(self):
        """injection_test() without waf_evasion should default to False."""
        from security_mcp.tools.composite_injection import injection_test

        captured_kwargs: dict = {}
        original_init = PythonSQLiTester.__init__

        def capture_init(self, **kwargs):
            captured_kwargs.update(kwargs)
            original_init(self, **kwargs)

        with patch.object(PythonSQLiTester, "__init__", capture_init):
            with patch.object(PythonSQLiTester, "test", new_callable=AsyncMock) as mock_test:
                mock_test.return_value = type("FakeResult", (), {
                    "to_dict": lambda self: {"vulnerable": False, "vulnerabilities": []},
                })()
                await injection_test(url="http://target/?id=1", types="sql")

        assert captured_kwargs.get("waf_evasion") is False, (
            "injection_test should default waf_evasion=False"
        )


class TestCompositePathPassthrough:
    """Verify path_test() passes waf_evasion=True to underlying scanners."""

    @pytest.mark.asyncio
    async def test_path_test_passes_waf_evasion_to_lfi(self):
        """path_test(waf_evasion=True) should create LfiTester with waf_evasion=True."""
        from security_mcp.tools.composite_path import path_test

        captured_kwargs: dict = {}
        original_init = LfiTester.__init__

        def capture_init(self, **kwargs):
            captured_kwargs.update(kwargs)
            original_init(self, **kwargs)

        with patch.object(LfiTester, "__init__", capture_init):
            with patch.object(LfiTester, "test", new_callable=AsyncMock) as mock_test:
                mock_test.return_value = type("FakeResult", (), {
                    "to_dict": lambda self: {"vulnerable": False, "vulnerabilities": []},
                })()
                await path_test(url="http://target/?file=x", checks="lfi", waf_evasion=True)

        assert captured_kwargs.get("waf_evasion") is True, (
            "path_test should pass waf_evasion=True to LfiTester"
        )

    @pytest.mark.asyncio
    async def test_path_test_default_waf_evasion_false(self):
        """path_test() without waf_evasion should default to False."""
        from security_mcp.tools.composite_path import path_test

        captured_kwargs: dict = {}
        original_init = LfiTester.__init__

        def capture_init(self, **kwargs):
            captured_kwargs.update(kwargs)
            original_init(self, **kwargs)

        with patch.object(LfiTester, "__init__", capture_init):
            with patch.object(LfiTester, "test", new_callable=AsyncMock) as mock_test:
                mock_test.return_value = type("FakeResult", (), {
                    "to_dict": lambda self: {"vulnerable": False, "vulnerabilities": []},
                })()
                await path_test(url="http://target/?file=x", checks="lfi")

        assert captured_kwargs.get("waf_evasion") is False, (
            "path_test should default waf_evasion=False"
        )


# ===========================================================================
# Tester construction
# ===========================================================================


class TestTesterConstruction:
    """Verify scanners accept and store the waf_evasion flag."""

    def test_sqli_tester_stores_flag(self):
        t = PythonSQLiTester(waf_evasion=True)
        assert t._waf_evasion is True

    def test_sqli_tester_default_false(self):
        t = PythonSQLiTester()
        assert t._waf_evasion is False

    def test_xss_tester_stores_flag(self):
        t = PythonXSSTester(waf_evasion=True)
        assert t._waf_evasion is True

    def test_xss_tester_default_false(self):
        t = PythonXSSTester()
        assert t._waf_evasion is False

    def test_ssti_tester_stores_flag(self):
        t = SstiTester(waf_evasion=True)
        assert t._waf_evasion is True

    def test_ssti_tester_default_false(self):
        t = SstiTester()
        assert t._waf_evasion is False

    def test_lfi_tester_stores_flag(self):
        t = LfiTester(waf_evasion=True)
        assert t._waf_evasion is True

    def test_lfi_tester_default_false(self):
        t = LfiTester()
        assert t._waf_evasion is False
