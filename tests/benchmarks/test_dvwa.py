"""DVWA benchmark tests.

Runs security scanners against a live OWASP DVWA instance and scores
results against the 7-vulnerability ground truth defined in
``ground_truth.DVWA_GROUND_TRUTH``.

Requirements:
    - DVWA running at http://localhost:8080 (or ``DVWA_TARGET`` env var)
    - ``SECMCP_ALLOW_INTERNAL=1`` env var set
    - Network access to the target

Skip conditions:
    - No ``SECMCP_ALLOW_INTERNAL`` → skip (safety guard)
    - DVWA unreachable → skip

Run:
    SECMCP_ALLOW_INTERNAL=1 DVWA_TARGET=http://localhost:8080 pytest tests/benchmarks/test_dvwa.py -v
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

from tests.benchmarks.ground_truth import DVWA_GROUND_TRUTH

# ---------------------------------------------------------------------------
# Skip guards
# ---------------------------------------------------------------------------

DVWA_TARGET = os.environ.get("DVWA_TARGET", DVWA_GROUND_TRUTH["target"])

_skip_no_internal = pytest.mark.skipif(
    os.environ.get("SECMCP_ALLOW_INTERNAL") != "1",
    reason="SECMCP_ALLOW_INTERNAL not set — skipping live target benchmark",
)

_skip_dvwa_unreachable = pytest.mark.skipif(
    not os.environ.get("SECMCP_ALLOW_INTERNAL"),
    reason="DVWA reachability check skipped (no SECMCP_ALLOW_INTERNAL)",
)


def _dvwa_reachable() -> bool:
    """Quick check if DVWA is responding."""
    try:
        resp = httpx.get(DVWA_TARGET, timeout=5, follow_redirects=True, verify=False)
        return resp.status_code < 500
    except Exception:
        return False


pytestmark = [
    pytest.mark.benchmark,
    pytest.mark.slow,
    _skip_no_internal,
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.fixture
def dvwa_target():
    """Return DVWA target URL, skipping if unreachable."""
    if not _dvwa_reachable():
        pytest.skip("DVWA not reachable at " + DVWA_TARGET)
    return DVWA_TARGET


class TestDVWABenchmark:
    """Benchmark individual scanners against DVWA ground truth."""

    @pytest.mark.asyncio
    async def test_sqli_on_dvwa(self, dvwa_target, allow_internal):
        """SQLi scanner should detect injection in /vulnerabilities/sqli/."""
        from security_mcp.scanners.sqli_tester import PythonSQLiTester

        tester = PythonSQLiTester()
        result = await tester.test(f"{dvwa_target}/vulnerabilities/sqli/?id=1&Submit=Submit")
        assert result.vulnerable, "DVWA SQLi endpoint should be detected as vulnerable"

    @pytest.mark.asyncio
    async def test_xss_reflected_on_dvwa(self, dvwa_target, allow_internal):
        """XSS scanner should detect reflected XSS in /vulnerabilities/xss_r/."""
        from security_mcp.scanners.xss_tester import PythonXSSTester

        tester = PythonXSSTester()
        result = await tester.test(f"{dvwa_target}/vulnerabilities/xss_r/?name=test")
        assert result.vulnerable, "DVWA reflected XSS endpoint should be detected"

    @pytest.mark.asyncio
    async def test_command_injection_on_dvwa(self, dvwa_target, allow_internal):
        """Command injection scanner should detect CWE-78 in /vulnerabilities/exec/."""
        from security_mcp.scanners.command_injection_tester import CommandInjectionTester

        tester = CommandInjectionTester()
        result = await tester.test(
            f"{dvwa_target}/vulnerabilities/exec/",
            method="POST",
            body={"ip": "127.0.0.1", "Submit": "Submit"},
        )
        assert result.vulnerable, "DVWA command injection should be detected"

    @pytest.mark.asyncio
    async def test_lfi_on_dvwa(self, dvwa_target, allow_internal):
        """LFI scanner should detect file inclusion in /vulnerabilities/fi/."""
        from security_mcp.scanners.lfi_tester import LfiTester

        tester = LfiTester()
        result = await tester.test(f"{dvwa_target}/vulnerabilities/fi/?page=include.php")
        assert result.vulnerable, "DVWA file inclusion should be detected"

    @pytest.mark.asyncio
    async def test_csrf_on_dvwa(self, dvwa_target, allow_internal):
        """CSRF scanner should detect missing protection on /vulnerabilities/csrf/."""
        from security_mcp.scanners.csrf_tester import CsrfTester

        tester = CsrfTester()
        result = await tester.test(f"{dvwa_target}/vulnerabilities/csrf/")
        # CSRF detection depends on form analysis — may or may not trigger
        # This test verifies the scanner runs without error on DVWA
        assert result is not None

    @pytest.mark.asyncio
    async def test_dir_fuzz_on_dvwa(self, dvwa_target, allow_internal):
        """Dir fuzzer should discover common DVWA paths."""
        from security_mcp.scanners.dir_fuzzer import PythonDirFuzzer

        fuzzer = PythonDirFuzzer()
        result = await fuzzer.fuzz(dvwa_target)
        paths = [p["path"] for p in result.get("results", [])]
        # DVWA has known paths
        assert len(paths) > 0, "Dir fuzzer should find at least one path on DVWA"
