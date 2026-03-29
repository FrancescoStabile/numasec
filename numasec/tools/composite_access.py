"""Composite access control test — IDOR, CSRF, CORS."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from numasec.scanners._envelope import wrap_result

logger = logging.getLogger(__name__)


async def access_control_test(
    url: str,
    checks: str = "idor,csrf,cors",
    headers: str = "",
) -> dict[str, Any]:
    """Test for access control vulnerabilities (IDOR, CSRF, CORS).

    Args:
        url: Target URL to test.
        checks: Comma-separated checks: idor, csrf, cors.
        headers: Optional JSON string of HTTP headers for authenticated testing.
    """
    start = time.monotonic()
    check_set = {c.strip().lower() for c in checks.split(",")}
    extra_headers: dict[str, str] = headers if isinstance(headers, dict) else (json.loads(headers) if headers else {})
    results: dict[str, Any] = {
        "url": url,
        "checks_run": sorted(check_set),
        "vulnerabilities": [],
    }

    if "idor" in check_set:
        try:
            from numasec.scanners.idor_tester import IDORTester

            tester = IDORTester()
            idor_result = await tester.test(url, headers=extra_headers or None)
            result_dict = idor_result.to_dict()
            results["idor"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["idor"] = {"error": str(exc)}

    if "csrf" in check_set:
        try:
            from numasec.scanners.csrf_tester import CsrfTester

            csrf_tester = CsrfTester(extra_headers=extra_headers)
            csrf_result = await csrf_tester.test(url)
            result_dict = csrf_result.to_dict()
            results["csrf"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["csrf"] = {"error": str(exc)}

    if "cors" in check_set:
        try:
            from numasec.scanners.cors_tester import CorsTester

            cors_tester = CorsTester(extra_headers=extra_headers)
            cors_result = await cors_tester.test(url)
            result_dict = cors_result.to_dict()
            results["cors"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["cors"] = {"error": str(exc)}

    total = len(results["vulnerabilities"])
    results["summary"] = f"{total} access control {'issue' if total == 1 else 'issues'} found"
    return wrap_result("access_control_test", url, results, start_time=start)
