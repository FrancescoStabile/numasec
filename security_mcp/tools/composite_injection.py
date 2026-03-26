"""Composite injection test — SQL, NoSQL, SSTI, Command Injection, GraphQL."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from security_mcp.scanners._envelope import wrap_result

logger = logging.getLogger(__name__)


async def injection_test(
    url: str,
    types: str = "sql,nosql,ssti,cmdi",
    params: str = "",
    method: str = "GET",
    body: str = "",
    content_type: str = "form",
    headers: str = "",
    waf_evasion: bool = False,
) -> dict[str, Any]:
    """Test for injection vulnerabilities (SQL, NoSQL, SSTI, Command Injection, GraphQL).

    Args:
        url: Target URL to test.
        types: Comma-separated injection types: sql, nosql, ssti, cmdi, graphql.
        params: Comma-separated parameter names to test. Auto-detect if omitted.
        method: HTTP method (GET or POST).
        body: Request body (for POST). JSON string for APIs.
        content_type: Body encoding: form or json.
        headers: Optional JSON string of HTTP headers for authenticated testing.
        waf_evasion: Enable WAF bypass encoding for payloads.
    """
    start = time.monotonic()
    type_set = {t.strip().lower() for t in types.split(",")}
    extra_headers: dict[str, str] = json.loads(headers) if headers else {}
    param_list: list[str] | None = [p.strip() for p in params.split(",") if p.strip()] or None
    body_dict: dict[str, str] | None = json.loads(body) if body else None
    results: dict[str, Any] = {
        "url": url,
        "types_tested": sorted(type_set),
        "vulnerabilities": [],
    }

    if "sql" in type_set:
        try:
            from security_mcp.scanners.sqli_tester import PythonSQLiTester

            tester = PythonSQLiTester(extra_headers=extra_headers, waf_evasion=waf_evasion)
            sqli_result = await tester.test(url, params=param_list, method=method, body=body_dict, content_type=content_type)
            result_dict = sqli_result.to_dict()
            results["sql"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["sql"] = {"error": str(exc)}

    if "nosql" in type_set:
        try:
            from security_mcp.scanners.nosql_tester import NoSqlTester

            tester = NoSqlTester(extra_headers=extra_headers)
            nosql_result = await tester.test(url, method=method)
            result_dict = nosql_result.to_dict()
            results["nosql"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["nosql"] = {"error": str(exc)}

    if "ssti" in type_set:
        try:
            from security_mcp.scanners.ssti_tester import SstiTester

            tester = SstiTester(extra_headers=extra_headers, waf_evasion=waf_evasion)
            ssti_result = await tester.test(url, params=param_list, method=method, body=body_dict)
            result_dict = ssti_result.to_dict()
            results["ssti"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["ssti"] = {"error": str(exc)}

    if "cmdi" in type_set:
        try:
            from security_mcp.scanners.command_injection_tester import CommandInjectionTester

            tester = CommandInjectionTester()
            cmdi_result = await tester.test(url, params=param_list, method=method, body=body_dict)
            result_dict = cmdi_result.to_dict()
            results["cmdi"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["cmdi"] = {"error": str(exc)}

    if "graphql" in type_set:
        try:
            from security_mcp.scanners.graphql_tester import GraphQLTester

            tester = GraphQLTester()
            gql_result = await tester.test(url)
            result_dict = gql_result.to_dict()
            results["graphql"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["graphql"] = {"error": str(exc)}

    total = len(results["vulnerabilities"])
    results["summary"] = f"{total} injection {'vulnerability' if total == 1 else 'vulnerabilities'} found across {', '.join(sorted(type_set))}"
    return wrap_result("injection_test", url, results, start_time=start)
