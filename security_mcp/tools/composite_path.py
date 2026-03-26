"""Composite path test — LFI, XXE, Open Redirect, Host Header Injection."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from security_mcp.scanners._envelope import wrap_result

logger = logging.getLogger(__name__)


async def path_test(
    url: str,
    checks: str = "lfi,xxe,redirect,host_header",
    params: str = "",
    method: str = "GET",
    headers: str = "",
    waf_evasion: bool = False,
) -> dict[str, Any]:
    """Test for path traversal, XXE, open redirect, and host header injection.

    Args:
        url: Target URL to test.
        checks: Comma-separated: lfi, xxe, redirect, host_header.
        params: Comma-separated parameter names. Auto-detect if omitted.
        method: HTTP method (GET or POST).
        headers: Optional JSON string of HTTP headers for authenticated testing.
        waf_evasion: Enable WAF bypass encoding for payloads.
    """
    start = time.monotonic()
    check_set = {c.strip().lower() for c in checks.split(",")}
    extra_headers: dict[str, str] = json.loads(headers) if headers else {}
    param_list: list[str] | None = [p.strip() for p in params.split(",") if p.strip()] or None
    results: dict[str, Any] = {
        "url": url,
        "checks_run": sorted(check_set),
        "vulnerabilities": [],
    }

    if "lfi" in check_set:
        try:
            from security_mcp.scanners.lfi_tester import LfiTester

            tester = LfiTester(extra_headers=extra_headers, waf_evasion=waf_evasion)
            lfi_result = await tester.test(url, params=param_list, method=method)
            result_dict = lfi_result.to_dict()
            results["lfi"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["lfi"] = {"error": str(exc)}

    if "xxe" in check_set:
        try:
            from security_mcp.scanners.xxe_tester import XxeTester

            tester = XxeTester()
            xxe_result = await tester.test(url, headers=extra_headers or None)
            result_dict = xxe_result.to_dict()
            results["xxe"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["xxe"] = {"error": str(exc)}

    if "redirect" in check_set:
        try:
            from security_mcp.scanners.open_redirect_tester import OpenRedirectTester

            tester = OpenRedirectTester()
            redirect_result = await tester.test(url, headers=extra_headers or None)
            result_dict = redirect_result.to_dict()
            results["redirect"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["redirect"] = {"error": str(exc)}

    if "host_header" in check_set:
        try:
            from security_mcp.scanners.host_header_tester import HostHeaderTester

            tester = HostHeaderTester()
            hh_result = await tester.test(url)
            result_dict = hh_result.to_dict()
            results["host_header"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["host_header"] = {"error": str(exc)}

    total = len(results["vulnerabilities"])
    results["summary"] = f"{total} path/redirect {'vulnerability' if total == 1 else 'vulnerabilities'} found"
    return wrap_result("path_test", url, results, start_time=start)
