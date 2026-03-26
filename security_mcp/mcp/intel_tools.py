"""MCP intelligence tools -- expose KB, CWE info, and planning to the host LLM.

These tools give the host LLM (Claude, GPT, etc.) access to security-mcp's
domain knowledge without requiring an internal LLM.

Consolidated into 2 unified tools:
  - kb_search: general KB search, CWE lookup, attack patterns
  - plan: scan planning, mandatory tests, coverage gaps, post-auth, chains
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---- CWE lookup — delegates to the canonical CWE_DATABASE (87+ entries) ----

def _lookup_cwe(cwe_id: str) -> dict[str, Any] | None:
    """Look up CWE info by ID, enriching with OWASP category.

    Uses the canonical ``CWE_DATABASE`` from ``standards.cwe_mapping`` (87+
    entries) instead of maintaining a separate hardcoded table.

    Args:
        cwe_id: CWE identifier, e.g. "CWE-89" or "89".

    Returns:
        Dict with cwe_id, name, description, severity, owasp_category, or None.
    """
    from security_mcp.standards.cwe_mapping import CWE_DATABASE
    from security_mcp.standards.owasp import get_owasp_category

    normalized = cwe_id.upper().strip()
    if not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"

    entry = CWE_DATABASE.get(normalized)
    if entry is None:
        return None

    return {
        "cwe_id": normalized,
        "name": entry["name"],
        "description": entry["description"],
        "severity": entry["severity"],
        "owasp_category": get_owasp_category(normalized),
    }


# ---- OWASP category mapping for coverage gap analysis ----

_OWASP_CODE_TO_KEY: dict[str, str] = {
    "A01:2021": "A01_access_control",
    "A02:2021": "A02_crypto_failures",
    "A03:2021": "A03_injection",
    "A04:2021": "A04_insecure_design",
    "A05:2021": "A05_misconfiguration",
    "A06:2021": "A06_vuln_components",
    "A07:2021": "A07_auth_failures",
    "A08:2021": "A08_integrity_failures",
    "A09:2021": "A09_logging_failures",
    "A10:2021": "A10_ssrf",
}

_TITLE_KEYWORDS_TO_OWASP: dict[str, str] = {
    "sql injection": "A03_injection",
    "sqli": "A03_injection",
    "xss": "A03_injection",
    "cross-site scripting": "A03_injection",
    "nosql": "A03_injection",
    "xxe": "A03_injection",
    "xml external": "A03_injection",
    "ssti": "A03_injection",
    "template injection": "A03_injection",
    "command injection": "A03_injection",
    "idor": "A01_access_control",
    "broken access": "A01_access_control",
    "authorization bypass": "A01_access_control",
    "insecure direct": "A01_access_control",
    "csrf": "A08_integrity_failures",
    "cross-site request": "A08_integrity_failures",
    "cors": "A05_misconfiguration",
    "misconfiguration": "A05_misconfiguration",
    "missing header": "A05_misconfiguration",
    "security header": "A05_misconfiguration",
    "verbose error": "A05_misconfiguration",
    "stack trace": "A05_misconfiguration",
    "ssrf": "A10_ssrf",
    "server-side request": "A10_ssrf",
    "open redirect": "A10_ssrf",
    "url redirect": "A10_ssrf",
    "jwt": "A07_auth_failures",
    "authentication": "A07_auth_failures",
    "default credential": "A07_auth_failures",
    "hard-coded": "A07_auth_failures",
    "hardcoded": "A07_auth_failures",
    "weak password": "A07_auth_failures",
    "password change": "A07_auth_failures",
    "crypto": "A02_crypto_failures",
    "weak hash": "A02_crypto_failures",
    "md5": "A02_crypto_failures",
    "information disclosure": "A05_misconfiguration",
    "sensitive data": "A02_crypto_failures",
    "data exposure": "A02_crypto_failures",
    "vulnerable component": "A06_vuln_components",
    "outdated": "A06_vuln_components",
    "known vulnerabilit": "A06_vuln_components",
    "business logic": "A04_insecure_design",
    "price manipulation": "A04_insecure_design",
    "captcha": "A04_insecure_design",
    "negative quantity": "A04_insecure_design",
    "role escalation": "A04_insecure_design",
    "forged feedback": "A04_insecure_design",
}


def _classify_finding_owasp(finding: Any) -> set[str]:
    """Classify a finding into OWASP Top 10 category keys.

    Uses 3-path classification:
    1. CWE-based: finding.cwe_id → CWE_OWASP_MAP → category key
    2. Tool-based: finding.tool_used → _TOOL_TO_OWASP reverse map
    3. Title heuristic: keyword match on finding.title
    """
    from security_mcp.core.coverage import _TOOL_TO_OWASP
    from security_mcp.standards.owasp import CWE_OWASP_MAP

    categories: set[str] = set()

    # Path 1: CWE-based
    cwe_id = getattr(finding, "cwe_id", "") or ""
    if cwe_id:
        normalized = cwe_id.upper().strip()
        if not normalized.startswith("CWE-"):
            normalized = f"CWE-{normalized}"
        owasp_full = CWE_OWASP_MAP.get(normalized, "")
        if owasp_full:
            code = owasp_full.split(" - ")[0].strip()  # "A01:2021 - ..." → "A01:2021"
            key = _OWASP_CODE_TO_KEY.get(code)
            if key:
                categories.add(key)

    # Path 2: Tool-based
    tool_used = getattr(finding, "tool_used", "") or ""
    if tool_used:
        for cat in _TOOL_TO_OWASP.get(tool_used, []):
            categories.add(cat)

    # Path 3: Title heuristic
    title = (getattr(finding, "title", "") or "").lower()
    if title:
        for keyword, cat in _TITLE_KEYWORDS_TO_OWASP.items():
            if keyword in title:
                categories.add(cat)

    return categories


# ---- Internal helper functions (formerly registered as individual tools) ----


async def _search_kb(query: str, category: str = "", top_k: int = 5) -> str:
    """Search security knowledge base."""
    from security_mcp.mcp._singletons import get_kb

    kb = get_kb()
    results = kb.query(query, top_k=top_k, category=category or None)

    return json.dumps(
        {
            "query": query,
            "type": "search",
            "category": category or "all",
            "results": [
                {
                    "text": chunk.text,
                    "template_id": chunk.template_id,
                    "section": chunk.section,
                    "category": chunk.category,
                    "score": round(chunk.score, 2),
                }
                for chunk in results
            ],
            "total_results": len(results),
        },
        indent=2,
    )


async def _get_cwe_info(cwe_id: str) -> str:
    """Get CWE details with related KB content."""
    from security_mcp.mcp._singletons import get_kb

    cwe_data = _lookup_cwe(cwe_id)

    result: dict[str, Any] = {
        "query": cwe_id,
        "type": "cwe",
        "found": cwe_data is not None,
    }

    if cwe_data:
        result.update(cwe_data)

    # Search KB for related content using the CWE name or ID
    kb = get_kb()
    search_term = cwe_data["name"] if cwe_data else cwe_id
    related = kb.query(search_term, top_k=3)

    result["related_kb"] = [
        {
            "text": chunk.text[:500],
            "template_id": chunk.template_id,
            "section": chunk.section,
            "score": round(chunk.score, 2),
        }
        for chunk in related
    ]

    return json.dumps(result, indent=2, default=str)


async def _get_attack_patterns(technology: str) -> str:
    """Get attack patterns for a technology."""
    from security_mcp.mcp._singletons import get_kb

    kb = get_kb()

    # Search for detection patterns
    detection = kb.query(f"{technology} vulnerability detection", top_k=3, category="detection")
    # Search for attack / exploitation content
    chains = kb.query(f"{technology} exploitation", top_k=2)
    # Search for payloads
    payloads = kb.query(f"{technology} payload", top_k=2)

    return json.dumps(
        {
            "technology": technology,
            "type": "attack_patterns",
            "detection_patterns": [
                {
                    "text": c.text[:500],
                    "template_id": c.template_id,
                    "section": c.section,
                    "score": round(c.score, 2),
                }
                for c in detection
            ],
            "attack_chains": [
                {
                    "text": c.text[:500],
                    "template_id": c.template_id,
                    "section": c.section,
                    "score": round(c.score, 2),
                }
                for c in chains
            ],
            "payloads": [
                {
                    "text": c.text[:500],
                    "template_id": c.template_id,
                    "section": c.section,
                    "score": round(c.score, 2),
                }
                for c in payloads
            ],
        },
        indent=2,
    )


async def _get_scan_plan(target: str, scope: str = "quick") -> str:
    """Generate a PTES-based scan plan."""
    from security_mcp.core.planner import DeterministicPlanner
    from security_mcp.models.target import TargetProfile

    if not target or not target.strip():
        return json.dumps(
            {
                "error": "initial requires 'target'",
                "missing": "target",
                "example": {"action": "initial", "target": "http://localhost:3000", "scope": "standard"},
            },
            indent=2,
        )

    valid_scopes = ("quick", "standard", "deep")
    if scope not in valid_scopes:
        return json.dumps(
            {"error": f"Invalid scope '{scope}'. Must be one of: {valid_scopes}"},
            indent=2,
        )

    profile = TargetProfile(target=target)
    planner = DeterministicPlanner()
    plan = planner.create_plan(target=profile, scope=scope)

    # Serialize plan to JSON-safe structure
    phases: list[dict[str, Any]] = []
    for phase in plan.phases:
        steps: list[dict[str, Any]] = []
        for step in phase.steps:
            steps.append(
                {
                    "id": step.id,
                    "description": step.description,
                    "tool": step.tool,
                    "params": step.params,
                }
            )
        phases.append(
            {
                "name": phase.phase.value,
                "parallelizable": phase.parallelizable,
                "timeout_minutes": phase.timeout_minutes,
                "steps": steps,
            }
        )

    # Build actionable checklists that help the host LLM test thoroughly
    checklists: dict[str, Any] = {
        "recon_checklist": [
            "Run recon(target, checks='ports,tech,services') to discover ports, technologies, and probe services (FTP/SSH/SMB/SMTP/Redis/MongoDB/MySQL). CVE enrichment runs automatically.",
            "Run crawl(url) to discover endpoints and forms. If OpenAPI/Swagger spec exists: crawl(url, openapi_url='https://target/swagger.json') for instant endpoint discovery.",
            "If the target is an SPA (Angular, React, Vue): crawl auto-upgrades to browser crawl, or force with force_browser=True.",
            "Run dir_fuzz to discover hidden paths, admin panels, backup files.",
            "Check /robots.txt and /sitemap.xml for hidden paths.",
            "Probe for exposed monitoring endpoints: GET /metrics, /actuator, /actuator/health, /actuator/env, /_health, /debug, /status, /info.",
            "If recon discovered non-HTTP services with CVEs: use kb_search with CVE ID for exploitation details.",
            "If recon found anonymous FTP, null session SMB, or unauthenticated Redis: investigate immediately — these are often critical findings.",
        ],
        "mapping_checklist": [
            "For each discovered endpoint, note the HTTP method, parameters, and content type.",
            "Identify authentication endpoints (login, register, password reset, password change).",
            "Look for API versioning patterns (/api/v1/, /rest/, /api/).",
            "Probe for /graphql, /gql, /api/graphql -- run graphql_test if any respond.",
            "Identify numeric IDs in URLs (e.g., /api/Users/1, /items/2) for IDOR testing.",
            "Look for file upload endpoints, admin panels, and debug endpoints.",
            "Identify ALL endpoints returning user-specific data -- these are IDOR candidates.",
            "Note every endpoint that accepts a JSON body -- these require nosql_test.",
            "Note every state-changing endpoint (POST/PUT/PATCH/DELETE) -- these require csrf_test.",
        ],
        "vulnerability_checklist": [
            "MANDATORY: run ALL tools below. Do NOT skip any item.",
            "",
            "--- Injection ---",
            "sqli_test on EVERY discovered endpoint (content_type='json' for JSON APIs, 'form' for HTML forms).",
            "sqli_test on the login endpoint specifically -- auth bypass SQLi (' OR 1=1--) must be tested explicitly.",
            "nosql_test on ALL endpoints accepting a JSON body -- test every discovered JSON endpoint:",
            "  nosql_test on the login endpoint -- auth bypass via {\"email\":{\"$ne\":\"\"},\"password\":{\"$ne\":\"\"}}",
            "  nosql_test on search/filter endpoints -- query parameter injection",
            "  nosql_test on review/comment endpoints -- data injection",
            "  nosql_test on user/profile endpoints -- user data injection",
            "  nosql_test on feedback/contact endpoints -- form submission injection",
            "  nosql_test on ANY other endpoint accepting a JSON body",
            "  NOTE: nosql_test is NOT limited to MongoDB. Run it on SQLite/PostgreSQL backends too -- operators like {$ne} are sometimes processed by the application layer, not just the DB.",
            "xss_test on all user-input parameters. For SPAs, test fragment-based params (e.g., /#/search?q=).",
            "ssti_test on any field rendered in a template: greeting messages, subject lines, search queries, user bios.",
            "lfi_test on endpoints with filename, path, file, or template parameters.",
            "xxe_test on endpoints accepting XML content-type or file uploads.",
            "",
            "--- Access Control ---",
            "csrf_test on EVERY state-changing endpoint: registration, email/password change, order placement, profile update.",
            "  Method: use http_request with Origin: https://evil.example.com header and verify the response allows it.",
            "idor_test on every endpoint containing a numeric or predictable ID in the path or query string.",
            "auth_test on every JWT token obtained during testing -- checks alg:none, weak HS256 secrets, kid traversal.",
            "cors_test on the main target -- check for wildcard or reflected-origin policy.",
            "host_header_test on the main target.",
            "",
            "--- Business Logic (use http_request with auth token) ---",
            "Use kb_search(query='business logic testing') for methodology, then test with http_request:",
            "  Price manipulation, negative quantity, workflow bypass, role escalation, forged actions on discovered endpoints.",
            "",
            "--- Server-Side ---",
            "ssrf_test on ANY URL -- it auto-injects known SSRF param names even without existing params. Pass headers for authenticated endpoints.",
            "open_redirect_test on the BASE URL -- it auto-discovers redirect endpoints (/redirect, /go, /out, etc.).",
            "xxe_test on file upload endpoints -- it sends both POST body XML AND multipart file uploads (XML/SVG). Target complaint forms, image uploaders, document processors.",
            "",
            "--- Information Disclosure (Unauthenticated -- use http_request, GET, no Authorization header) ---",
            "GET /metrics -- Prometheus metrics (user counts, business data, server version)",
            "GET /actuator, /actuator/health, /actuator/env -- Spring Boot actuator exposure",
            "GET common admin/config endpoints discovered during recon -- OAuth credentials, redirect URIs, product config",
            "GET /robots.txt -- disallowed paths often point to sensitive directories",
            "GET file-serving directories discovered during recon -- look for .bak, .kdbx, .sql, .env files",
            "When file directories are found: also probe subdirectories for additional sensitive files including backup files and database dumps.",
            "For EVERY endpoint that returned 401/403 without a token: retry WITH a valid (non-admin) token.",
            "  Some apps enforce authentication but NOT authorization -- a regular user token may access admin data.",
        ],
        "exploitation_checklist": [
            "IMPORTANT: For ALL exploitation steps, use kb_search first to get DBMS/engine/OS-specific payloads.",
            "",
            "--- SQLi Exploitation ---",
            "Chain SQLi auth-bypass -> JWT obtained -> run plan(action='post_auth') immediately.",
            "CRITICAL: Auth bypass on login does NOT mean search/filter/sort endpoints are safe.",
            "  After auth_bypass: ALSO run sqli_test on search/filter endpoints -- separate SQLi surfaces.",
            "If sqli_test confirms UNION injection: use kb_search('MySQL UNION extraction') (or PostgreSQL/SQLite/MSSQL) for exact payloads:",
            "  The KB provides complete step-by-step: ORDER BY → column detection → schema extraction → data extraction.",
            "  For blind SQLi: use kb_search('blind SQLi extraction') for boolean/time-based character enumeration.",
            "If SQLi extraction succeeds: use extracted credentials with relay_credentials, then plan(action='post_auth').",
            "",
            "--- SSTI / Command Injection Exploitation ---",
            "If SSTI confirmed: use kb_search('SSTI RCE Jinja2') (or Twig/Freemarker/ERB) for engine-specific RCE payloads.",
            "If command injection confirmed: use kb_search('command injection escalation') for reverse shell methodology.",
            "After RCE: use kb_search('reverse shell') for payload one-liners, then kb_search('linux privilege escalation') for privesc.",
            "",
            "--- Access Control Exploitation ---",
            "Chain IDOR findings: test adjacent IDs (+1/-1) to access other users' data.",
            "If JWT is weak: use kb_search('JWT exploitation') for forging methodology. Forge admin tokens.",
            "If CORS misconfigured: use kb_search('CORS exploitation') for data exfiltration payloads.",
            "",
            "--- Server-Side Exploitation ---",
            "If SSRF found: use kb_search('cloud exploitation AWS') for full IAM credential extraction path.",
            "If LFI found: use kb_search('LFI to RCE') for log poisoning and PHP wrapper chains.",
            "If XXE found: use kb_search('XXE exploitation OOB') for blind data exfiltration via external DTD.",
            "If file upload exists: use kb_search('file upload RCE') for extension bypass and polyglot techniques.",
            "",
            "--- Client-Side Exploitation ---",
            "Stored XSS: use kb_search('XSS session theft') for cookie exfiltration payloads.",
            "If open redirect found: use kb_search('open redirect exploitation') for OAuth token theft chains.",
            "",
            "--- Service-Level Exploitation ---",
            "If recon found CVEs: use kb_search with the CVE ID for exploitation methodology.",
            "If anonymous FTP/null SMB/unauth Redis found: use kb_search('Redis RCE') or 'SMB exploitation' for escalation.",
            "",
            "--- Business Logic ---",
            "Business logic: test price/quantity manipulation, negative quantities, workflow bypass.",
            "If dependency files accessible: report each dependency with version (CWE-1035, A06:2021).",
        ],
        "post_auth_checklist": [
            "TRIGGER: run ALL 8 tiers immediately after obtaining ANY token (JWT, session cookie, API key).",
            "Call plan(action='post_auth', target=URL, token=TOKEN) for a structured task list.",
            "Do NOT go deep on any single tier before completing all tiers. Mark each tier done.",
        ],
        "business_logic_tests": [
            "Business logic vulnerabilities require understanding the application's purpose, not just its endpoints.",
            "These tests check for flaws that automated scanners typically miss:",
            "",
            "--- Price Manipulation ---",
            "PUT on product/item update endpoints with {\"price\": -1} -- negative price",
            "PUT on product/item update endpoints with {\"price\": 0} -- zero price",
            "PUT on product/item update endpoints with {\"price\": 0.001} -- extremely low price",
            "",
            "--- Quantity Manipulation ---",
            "PUT on cart/basket item endpoints with {\"quantity\": -1} -- negative quantity for credit",
            "PUT on cart/basket item endpoints with {\"quantity\": 0} -- zero quantity",
            "PUT on cart/basket item endpoints with {\"quantity\": 99999} -- excessive quantity",
            "",
            "--- Workflow Bypass ---",
            "Test password change without current password (GET and POST variants)",
            "Test form submissions without CAPTCHA field or with invalid CAPTCHA values",
            "",
            "--- Role Escalation ---",
            "PUT on user update endpoints with {\"role\": \"admin\"} -- direct role escalation",
            "POST on user registration with {\"role\": \"admin\"} -- admin at signup",
            "",
            "--- Forged Actions ---",
            "POST feedback/review endpoints with arbitrary user IDs -- post as another user",
            "POST order endpoints with modified delivery address for another user's basket",
            "PUT on product endpoints as regular user -- modification without admin",
            "",
            "--- Coupon / Discount Abuse ---",
            "POST coupon endpoints with repeated valid coupon -- stacking discounts",
            "POST order endpoints with couponCode that shouldn't apply -- invalid coupon acceptance",
        ],
        "default_credential_tests": [
            "Use kb_search(query='default credentials') for technology-specific credential lists.",
            "Test discovered credentials on the login endpoint.",
            "  admin / admin, admin / password, test / test, user / user -- generic defaults",
            "  Also check for technology-specific defaults (e.g., WordPress admin, Tomcat manager).",
            "",
            "If ANY credential works: Critical finding (CWE-798).",
            "With admin credentials: access admin panels and all admin API endpoints.",
        ],
        "tips": [
            "Always use browser_navigate for SPAs before testing -- httpx won't render JS routes.",
            "When sqli_test reports 'auth_bypass': decode the JWT immediately and run post_auth_checklist.",
            "Pass headers='{\"Authorization\": \"Bearer <token>\"}' to idor_test for authenticated IDOR checks.",
            "If crawl_site returns few results on a known-complex app, switch to browser_crawl_site.",
            "Check response sizes: a 200 OK with tiny body may be an error page, not real data.",
            "nosql_test false positive filter: only flag if the injected response is DIFFERENT from the baseline -- do not flag if all responses return 'success'.",
            "csrf_test: a finding is valid only if Origin: https://evil.example.com causes a 200/201 response (not just accepted by CORS but actually processed).",
            "Business logic tests require auth -- use http_request with valid JWT/session cookie and kb_search for methodology.",
            "open_redirect_test auto-probes 14 common redirect endpoints -- pass the BASE URL for discovery.",
            "xxe_test supports multipart file upload -- target file upload endpoints (complaint forms, image uploads, document processors) for best results.",
            "ssrf_test auto-injects 20 common SSRF param names -- works even on URLs without existing query params.",
            "After browser_crawl_site: run xss_test on each discovered fragment route, and open_redirect_test on the base URL.",
        ],
    }

    return json.dumps(
        {
            "target": target,
            "scope": scope,
            "phases": phases,
            "total_steps": sum(len(p["steps"]) for p in phases),
            "testing_guidance": checklists,
        },
        indent=2,
        default=str,
    )


async def _get_mandatory_tests(target: str, endpoints: str = "[]") -> str:
    """Generate deterministic test tasks from discovered endpoints."""
    import types

    from security_mcp.core.planner import DeterministicPlanner

    if not target or not target.strip():
        return json.dumps({"error": "target is required"}, indent=2)

    target = target.strip().rstrip("/")

    # Parse endpoints JSON
    try:
        ep_list: list[dict[str, Any]] = json.loads(endpoints)
        if not isinstance(ep_list, list):
            ep_list = []
    except (json.JSONDecodeError, TypeError) as exc:
        return json.dumps(
            {
                "error": f"Invalid endpoints JSON: {exc}",
                "hint": 'Pass a JSON array of objects with at least a "url" key, e.g. '
                '[{"url": "/api/Users", "method": "POST"}]',
            },
            indent=2,
        )

    # Always-run tools against base URL
    always_run: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for tool in DeterministicPlanner._ALWAYS_RUN_TOOLS:
        key = (tool, target)
        if key not in seen:
            seen.add(key)
            always_run.append({"tool": tool, "url": target, "reason": "mandatory_base_url"})

    # Endpoint-specific tool matching
    endpoint_tasks: list[dict[str, str]] = []
    for ep_dict in ep_list:
        if not isinstance(ep_dict, dict) or "url" not in ep_dict:
            continue

        ep_url = ep_dict["url"]
        if not ep_url.startswith("http"):
            ep_url = f"{target}/{ep_url.lstrip('/')}"

        # Wrap dict as namespace for getattr() compatibility with _endpoint_matches_rule
        ep_obj = types.SimpleNamespace(
            url=ep_url,
            method=ep_dict.get("method", "GET"),
            content_type=ep_dict.get("content_type", ""),
            parameters=ep_dict.get("parameters", []),
        )

        for tool, rule in DeterministicPlanner._SCANNER_RULES.items():
            if DeterministicPlanner._endpoint_matches_rule(ep_obj, rule):
                key = (tool, ep_url)
                if key not in seen:
                    seen.add(key)
                    endpoint_tasks.append(
                        {
                            "tool": tool,
                            "url": ep_url,
                            "reason": rule,
                            "endpoint_method": ep_obj.method,
                            "endpoint_content_type": ep_obj.content_type,
                        }
                    )

    all_tools = sorted({t["tool"] for t in always_run + endpoint_tasks})
    total = len(always_run) + len(endpoint_tasks)

    return json.dumps(
        {
            "target": target,
            "total_tasks": total,
            "always_run": always_run,
            "endpoint_tasks": endpoint_tasks,
            "summary": {
                "tools_used": all_tools,
                "endpoints_analyzed": len(ep_list),
                "unique_tool_endpoint_pairs": total,
            },
            "message": f"Execute ALL {total} tasks above. Do not skip any.",
        },
        indent=2,
    )


async def _get_coverage_gaps(session_id: str, target: str) -> str:
    """Identify untested OWASP categories and recommend gap-fill tasks."""
    from security_mcp.core.coverage import _OWASP_LABELS, OWASP_TOOL_MAP
    from security_mcp.mcp._singletons import get_mcp_session_store

    if not target or not target.strip():
        return json.dumps(
            {
                "error": "coverage_gaps requires 'target' and 'session_id'",
                "missing": "target",
                "example": {"action": "coverage_gaps", "target": "http://localhost:3000", "session_id": "mcp-xxx"},
            },
            indent=2,
        )
    if not session_id or not session_id.strip():
        return json.dumps(
            {
                "error": "coverage_gaps requires 'target' and 'session_id'",
                "missing": "session_id",
                "example": {"action": "coverage_gaps", "target": target, "session_id": "mcp-xxx"},
            },
            indent=2,
        )

    target = target.strip().rstrip("/")
    store = get_mcp_session_store()

    try:
        findings = await store.get_findings(session_id)
    except KeyError:
        return json.dumps(
            {"error": f"Session not found: {session_id}", "hint": "Call create_session first"},
            indent=2,
        )

    # Classify each finding into OWASP categories
    tested_categories: set[str] = set()
    for finding in findings:
        cats = _classify_finding_owasp(finding)
        tested_categories.update(cats)

    # Compute untested categories
    all_cats = list(OWASP_TOOL_MAP.keys())
    untested = [cat for cat in all_cats if cat not in tested_categories]
    tested = [cat for cat in all_cats if cat in tested_categories]

    # Generate gap-fill tasks
    gap_tasks: list[dict[str, str]] = []
    for cat in untested:
        tools = OWASP_TOOL_MAP.get(cat, [])
        for tool in tools:
            if tool in ("http_request", "fetch_page"):
                continue
            gap_tasks.append(
                {
                    "tool": tool,
                    "url": target,
                    "owasp_category": cat,
                    "owasp_label": _OWASP_LABELS.get(cat, cat),
                    "reason": "No findings mapped to this OWASP category",
                }
            )
            break  # One tool per untested category is sufficient

    coverage_pct = round(len(tested) / len(all_cats) * 100, 1) if all_cats else 0.0

    return json.dumps(
        {
            "session_id": session_id,
            "target": target,
            "coverage": {
                "tested_categories": tested,
                "untested_categories": untested,
                "tested_count": len(tested),
                "total_count": len(all_cats),
                "coverage_pct": coverage_pct,
            },
            "gap_tasks": gap_tasks,
            "total_gap_tasks": len(gap_tasks),
            "message": (
                f"Coverage is {coverage_pct}%. Execute ALL {len(gap_tasks)} gap tasks before generating the report."
                if gap_tasks
                else f"Coverage is {coverage_pct}%. All OWASP categories have been tested."
            ),
        },
        indent=2,
    )


async def _get_auth_retest_plan(target: str, token: str, token_type: str = "bearer") -> str:
    """Generate structured post-auth exploitation plan with explicit tool calls."""
    if not target or not target.strip():
        return json.dumps(
            {
                "error": "post_auth requires 'target' and 'token'",
                "missing": "target",
                "example": {"action": "post_auth", "target": "http://localhost:3000", "token": "eyJ..."},
            },
            indent=2,
        )
    if not token or not token.strip():
        return json.dumps(
            {
                "error": "post_auth requires 'target' and 'token'",
                "missing": "token",
                "hint": "Pass the JWT, session cookie, or API key obtained during authentication",
                "example": {"action": "post_auth", "target": target, "token": "eyJ...", "token_type": "bearer"},
            },
            indent=2,
        )

    valid_types = ("bearer", "cookie", "api_key")
    if token_type not in valid_types:
        return json.dumps(
            {"error": f"Invalid token_type '{token_type}'. Must be one of: {valid_types}"},
            indent=2,
        )

    target = target.strip().rstrip("/")

    # Build auth header
    if token_type == "bearer":
        auth_header = {"Authorization": f"Bearer {token}"}
    elif token_type == "cookie":
        auth_header = {"Cookie": f"token={token}"}
    else:  # api_key
        auth_header = {"X-API-Key": token}

    auth_json = json.dumps(auth_header)
    auth_ct_json = json.dumps({**auth_header, "Content-Type": "application/json"})

    tiers = [
        {
            "tier": 0,
            "name": "Authenticated Recon",
            "priority": "critical",
            "description": "Re-crawl to discover auth-only endpoints and expand the attack surface",
            "tasks": [
                {"tool": "browser_crawl_site", "params": {"url": target, "headers": auth_json}},
                {"tool": "dir_fuzz", "params": {"url": target, "headers": auth_json}},
                {"tool": "crawl_site", "params": {"url": target, "headers": auth_json}},
                {
                    "action": "probe_auth_endpoints",
                    "description": (
                        "Use http_request with auth header to probe endpoints discovered during recon: "
                        "profile/image URLs (SSRF targets), file upload forms (XXE targets), "
                        "shopping cart/basket endpoints (IDOR targets), payment/card endpoints (PCI data), "
                        "wallet/balance endpoints (sensitive financial data). "
                        "Feed ALL newly discovered endpoints to vulnerability scanners (ssrf_test, xxe_test, idor_test, xss_test)."
                    ),
                },
            ],
        },
        {
            "tier": 1,
            "name": "Token Analysis",
            "priority": "high",
            "description": "Decode and analyze the authentication token",
            "tasks": [
                {
                    "action": "decode_jwt",
                    "description": (
                        "Base64url-decode the JWT payload. Look for: "
                        "password hash (MD5/SHA1 = crackable), role field (admin = escalate), "
                        "totpSecret (MFA bypass), missing exp claim (CWE-613), PII (CWE-200)"
                    ),
                }
            ],
        },
        {
            "tier": 2,
            "name": "JWT Weakness Testing",
            "priority": "high",
            "description": "Test for JWT implementation flaws",
            "tasks": [
                {"tool": "auth_test", "params": {"url": target, "headers": auth_json}},
            ],
        },
        {
            "tier": 3,
            "name": "UNION SQLi Extraction",
            "priority": "high",
            "description": "Escalate confirmed SQL injection to full data extraction",
            "tasks": [
                {
                    "action": "conditional_escalation",
                    "condition": "sqli_test confirmed injection on any endpoint",
                    "description": (
                        "Escalate with http_request: "
                        "1) ORDER BY N-- to find column count, "
                        "2) UNION SELECT NULL,'marker',NULL...-- to find string column, "
                        "3) Extract DB schema (sqlite_master/information_schema), "
                        "4) Use schema to extract user tables, credentials, and sensitive data"
                    ),
                },
                {
                    "action": "test_search_endpoints",
                    "description": (
                        "Test search/filter endpoints separately with sqli_test -- "
                        "auth bypass on login does NOT mean search is safe. "
                        "These are SEPARATE SQLi surfaces."
                    ),
                },
            ],
        },
        {
            "tier": 4,
            "name": "Unauthenticated API Sweep",
            "priority": "high",
            "description": "Test ALL discovered API endpoints WITHOUT auth header -- broken access control detection",
            "tasks": [
                {
                    "action": "unauth_sweep",
                    "description": (
                        "For EVERY /api/* and /rest/* endpoint discovered during recon: "
                        "issue http_request WITHOUT Authorization header. "
                        "Test user lists, payment data, order history, feedback, wallets, "
                        "security questions, admin config, and metrics endpoints. "
                        "Each 200 response = Broken Access Control (A01, CWE-862)."
                    ),
                },
            ],
        },
        {
            "tier": 5,
            "name": "IDOR / BOLA Sweep",
            "priority": "critical",
            "description": "Test IDOR on all endpoints with numeric IDs discovered during recon",
            "tasks": [
                {
                    "action": "idor_sweep",
                    "description": (
                        "Run idor_test on EVERY resource with numeric ID discovered during recon. "
                        "Test baskets, carts, user profiles, orders, cards (PCI-CRITICAL), "
                        "and any other resource with predictable IDs. "
                        "Test adjacent IDs: if you get user 1's data, try user 2, 3, etc."
                    ),
                    "tool_hint": "idor_test",
                    "auth_headers": auth_json,
                },
            ],
        },
        {
            "tier": 6,
            "name": "Business Logic",
            "priority": "high",
            "description": "Test business logic flaws requiring authentication",
            "tasks": [
                {
                    "action": "business_logic",
                    "description": (
                        "Use kb_search(query='business logic testing') for methodology. "
                        "Test price manipulation, negative quantity, workflow bypass, role escalation, "
                        "forged actions on endpoints discovered during mapping — all via http_request."
                    ),
                    "auth_headers": auth_json,
                },
                {
                    "action": "test_ssrf_xxe",
                    "description": (
                        "Run ssrf_test on profile image/URL endpoints discovered during auth recon. "
                        "Run xxe_test on file upload endpoints discovered during auth recon. "
                        "Use kb_search(query='business logic testing') for additional methodology."
                    ),
                },
            ],
        },
        {
            "tier": 7,
            "name": "Stored XSS via Authenticated Endpoints",
            "priority": "medium",
            "description": "Test for stored XSS through authenticated write endpoints",
            "tasks": [
                {
                    "action": "stored_xss",
                    "description": (
                        "Test stored XSS on all write endpoints discovered during auth recon: "
                        "product/item descriptions, feedback/review comments, user profile fields. "
                        "Also test DOM XSS on SPA search/hash routes."
                    ),
                    "auth_headers": auth_ct_json,
                },
            ],
        },
    ]

    total_tasks = sum(len(t["tasks"]) for t in tiers)

    return json.dumps(
        {
            "target": target,
            "token_type": token_type,
            "auth_header": auth_header,
            "total_tiers": len(tiers),
            "total_tasks": total_tasks,
            "tiers": tiers,
            "message": f"Execute ALL {len(tiers)} tiers ({total_tasks} tasks) in order. Do not skip any tier.",
        },
        indent=2,
    )


# -------------------------------------------------------------------
# Chain recommendation engine
# -------------------------------------------------------------------

_CHAIN_RULES: list[dict[str, Any]] = [
    {
        "finding_type": "sqli",
        "keywords": ["sql injection", "sqli", "sql"],
        "condition": "confidence >= 0.8",
        "recommendation": (
            "Use kb_search('MySQL UNION data extraction') or kb_search('PostgreSQL UNION extraction') "
            "for DBMS-specific payloads. Extract credentials via UNION SELECT, then relay_credentials "
            "and run auth_test + access_control_test with extracted token."
        ),
        "next_tools": ["kb_search (DBMS-specific exploitation)", "http_request (UNION extraction)", "relay_credentials", "auth_test", "access_control_test"],
        "priority": "P1",
    },
    {
        "finding_type": "jwt_weak",
        "keywords": ["jwt", "weak secret", "alg:none", "json web token"],
        "condition": "confidence >= 0.7",
        "recommendation": (
            "Use kb_search('JWT exploitation') for forging methodology. "
            "Forge admin JWT token using cracked secret or alg:none, then run "
            "access_control_test and auth_test with forged token for privilege escalation."
        ),
        "next_tools": ["kb_search (JWT forging)", "relay_credentials", "access_control_test", "auth_test"],
        "priority": "P1",
    },
    {
        "finding_type": "default_credentials",
        "keywords": ["default credential", "default password", "admin login", "spray_valid_creds"],
        "condition": "any",
        "recommendation": "Login with discovered credentials, capture session token, call relay_credentials, then run plan(action='post_auth') for full post-auth testing.",
        "next_tools": ["http_request (login)", "relay_credentials", "plan (post_auth)"],
        "priority": "P1",
    },
    {
        "finding_type": "lfi",
        "keywords": ["local file inclusion", "path traversal", "lfi", "file read"],
        "condition": "confidence >= 0.7",
        "recommendation": (
            "Use kb_search('LFI to RCE') for escalation playbooks. "
            "Read config files via LFI: /etc/shadow, wp-config.php, .env, config.py. "
            "Try log poisoning for RCE (kb_search 'log poisoning') or PHP wrapper chains."
        ),
        "next_tools": ["kb_search (LFI exploitation)", "http_request (file read)", "relay_credentials"],
        "priority": "P1",
    },
    {
        "finding_type": "ssrf",
        "keywords": ["ssrf", "server-side request forgery"],
        "condition": "confidence >= 0.6",
        "recommendation": (
            "Use kb_search('cloud exploitation AWS IMDS') for full credential extraction path. "
            "AWS: /latest/meta-data/iam/security-credentials/{role}. "
            "GCP: /computeMetadata/v1/instance/service-accounts/default/token. "
            "Azure: /metadata/identity/oauth2/token."
        ),
        "next_tools": ["kb_search (cloud exploitation)", "http_request (metadata extraction)", "relay_credentials"],
        "priority": "P1",
    },
    {
        "finding_type": "ssti",
        "keywords": ["ssti", "server-side template injection", "template injection"],
        "condition": "confidence >= 0.7",
        "recommendation": (
            "Use kb_search('SSTI RCE Jinja2') or the detected engine name for RCE payloads. "
            "Escalate to command execution, then use kb_search('reverse shell') for callback payloads."
        ),
        "next_tools": ["kb_search (SSTI exploitation)", "http_request (RCE payload)", "kb_search (reverse shells)"],
        "priority": "P1",
    },
    {
        "finding_type": "cmdi",
        "keywords": ["command injection", "os command", "cmdi", "rce"],
        "condition": "confidence >= 0.7",
        "recommendation": (
            "Use kb_search('command injection escalation') for bypass techniques and reverse shell payloads. "
            "Establish a reverse shell, then use kb_search('linux privilege escalation') for privesc."
        ),
        "next_tools": ["kb_search (command injection)", "http_request (shell payload)", "kb_search (post-exploitation)"],
        "priority": "P1",
    },
    {
        "finding_type": "xss_stored",
        "keywords": ["stored xss", "persistent xss"],
        "condition": "confidence >= 0.8",
        "recommendation": (
            "Use kb_search('XSS session theft') for cookie exfiltration payloads. "
            "Inject session-stealing payload, then use stolen session for access_control_test."
        ),
        "next_tools": ["kb_search (XSS exploitation)", "xss_test (session stealer)", "relay_credentials", "access_control_test"],
        "priority": "P2",
    },
    {
        "finding_type": "open_redirect",
        "keywords": ["open redirect", "url redirect"],
        "condition": "any",
        "recommendation": (
            "Use kb_search('open redirect exploitation') for OAuth token theft chains. "
            "Chain open redirect with SSRF to bypass URL validation, or with OAuth for token theft."
        ),
        "next_tools": ["kb_search (redirect chains)", "ssrf_test (via redirect)"],
        "priority": "P2",
    },
    {
        "finding_type": "xxe",
        "keywords": ["xxe", "xml external entity"],
        "condition": "confidence >= 0.6",
        "recommendation": (
            "Use kb_search('XXE exploitation OOB') for blind exfiltration via parameter entities. "
            "Setup OOB callback, use external DTD for data extraction. Chain XXE -> SSRF for internal services."
        ),
        "next_tools": ["kb_search (XXE exploitation)", "oob (setup)", "http_request (XXE payload)", "ssrf_test"],
        "priority": "P1",
    },
    {
        "finding_type": "csrf",
        "keywords": ["csrf", "cross-site request forgery"],
        "condition": "any",
        "recommendation": (
            "Use kb_search('CSRF exploitation') for account takeover chains. "
            "Target password change and email update endpoints without CSRF protection."
        ),
        "next_tools": ["kb_search (CSRF chains)", "http_request (CSRF exploit)"],
        "priority": "P2",
    },
    {
        "finding_type": "idor",
        "keywords": ["idor", "insecure direct object", "bola"],
        "condition": "confidence >= 0.6",
        "recommendation": "Escalate IDOR to access admin resources: enumerate user, order, and admin endpoints with manipulated IDs. Test horizontal and vertical access control.",
        "next_tools": ["access_control_test (admin resources)", "http_request"],
        "priority": "P2",
    },
    {
        "finding_type": "graphql",
        "keywords": ["graphql", "introspection", "query depth", "batch query"],
        "condition": "any",
        "recommendation": (
            "Use introspection data to map all mutations and sensitive fields. "
            "Test mutation authorization, field-level access controls, and alias-based resource exhaustion."
        ),
        "next_tools": ["injection_test (graphql)", "access_control_test"],
        "priority": "P2",
    },
    {
        "finding_type": "service_vuln",
        "keywords": ["cve", "service version", "known vulnerability", "outdated"],
        "condition": "any",
        "recommendation": (
            "Use kb_search with the CVE ID or service name for exploit details. "
            "Check exploit availability and attempt exploitation via http_request or protocol-specific tools."
        ),
        "next_tools": ["kb_search (CVE details)", "http_request (exploit)"],
        "priority": "P1",
    },
    {
        "finding_type": "cors_misconfig",
        "keywords": ["cors", "access-control-allow-origin", "cross-origin"],
        "condition": "any",
        "recommendation": (
            "Use kb_search('CORS exploitation') for data exfiltration via fetch() with credentials. "
            "Craft a malicious page that reads authenticated API responses."
        ),
        "next_tools": ["kb_search (CORS exploitation)", "http_request (verify)"],
        "priority": "P2",
    },
]


async def _get_chain_opportunities(session_id: str) -> str:
    """Identify attack chain opportunities from current findings."""
    from security_mcp.mcp._singletons import get_mcp_session_store

    if not session_id or not session_id.strip():
        return json.dumps(
            {
                "error": "chain requires 'session_id'",
                "missing": "session_id",
                "example": {"action": "chain", "session_id": "mcp-xxx"},
            },
            indent=2,
        )

    store = get_mcp_session_store()
    try:
        findings = await store.get_findings(session_id)
    except KeyError:
        return json.dumps({"error": f"Session not found: {session_id}", "hint": "Call create_session first"}, indent=2)

    if not findings:
        return json.dumps({
            "session_id": session_id,
            "opportunities": [],
            "message": "No findings yet. Run vulnerability scanners first.",
        }, indent=2)

    opportunities: list[dict[str, Any]] = []

    for rule in _CHAIN_RULES:
        for finding in findings:
            title_lower = finding.title.lower()
            desc_lower = (finding.description or "").lower()
            combined = f"{title_lower} {desc_lower}"

            matched = any(kw in combined for kw in rule["keywords"])
            if not matched:
                continue

            # Check confidence condition
            conf = finding.confidence
            if rule["condition"] == "any":
                pass
            elif rule["condition"].startswith("confidence"):
                threshold = float(rule["condition"].split(">=")[1].strip())
                if conf < threshold:
                    continue

            opportunities.append({
                "chain_type": rule["finding_type"],
                "trigger_finding": finding.title,
                "trigger_finding_id": finding.id,
                "trigger_confidence": conf,
                "priority": rule["priority"],
                "recommendation": rule["recommendation"],
                "next_tools": rule["next_tools"],
            })
            break  # One match per rule is enough

    # Sort by priority (P1 first)
    opportunities.sort(key=lambda x: x["priority"])

    return json.dumps(
        {
            "session_id": session_id,
            "findings_analyzed": len(findings),
            "opportunities_found": len(opportunities),
            "opportunities": opportunities,
            "message": (
                f"Found {len(opportunities)} chain escalation opportunities. "
                "Execute them in priority order (P1 first)."
                if opportunities
                else "No chain opportunities found from current findings."
            ),
        },
        indent=2,
    )


# ---- MCP tool registration ----


def register(mcp: Any) -> None:
    """Register consolidated intelligence tools with the FastMCP server."""

    @mcp.tool(
        name="kb_search",
        description=(
            "Search the security knowledge base. Query types: "
            "'search' for general queries, 'cwe' for CWE details + related articles, "
            "'attack_patterns' for technology-specific attack patterns and payloads."
        ),
    )
    async def kb_search(
        query: str,
        type: str = "search",
        category: str = "",
        top_k: int = 5,
    ) -> str:
        """Unified knowledge base search.

        Args:
            query: Search query, CWE ID (e.g. "CWE-89"), or technology name.
            type: Query type: "search" (general), "cwe" (CWE lookup), "attack_patterns" (tech-specific).
            category: Filter by KB category: detection, remediation, reference (for search type only).
            top_k: Number of results (default 5).
        """
        if type == "cwe":
            return await _get_cwe_info(query)
        elif type == "attack_patterns":
            return await _get_attack_patterns(query)
        else:  # type == "search"
            return await _search_kb(query, category=category, top_k=top_k)

    @mcp.tool(
        name="plan",
        description=(
            "Unified planning tool. Pass parameters directly (not as JSON string). Actions: "
            "'initial' -- generate PTES scan plan (requires target); "
            "'mandatory_tests' -- get test tasks from discovered endpoints (requires target, endpoints); "
            "'coverage_gaps' -- check OWASP Top 10 coverage (requires target, session_id); "
            "'post_auth' -- get 8-tier post-auth exploitation plan (requires target, token); "
            "'chain' -- find attack chain escalation from current findings (requires session_id)."
        ),
    )
    async def plan(
        action: str = "",
        target: str = "",
        session_id: str = "",
        scope: str = "standard",
        endpoints: str = "[]",
        token: str = "",
        token_type: str = "bearer",
        kwargs: str = "",
    ) -> str:
        """Unified planning tool.

        Args:
            action: Plan action: initial, mandatory_tests, coverage_gaps, post_auth, chain.
            target: Base target URL (required for initial, mandatory_tests, coverage_gaps, post_auth).
            session_id: Session ID (required for coverage_gaps, chain).
            scope: Scan scope for initial plan: quick, standard, deep.
            endpoints: JSON array of endpoint objects for mandatory_tests.
            token: Auth token for post_auth plan.
            token_type: Token type for post_auth: bearer, cookie, api_key.
            kwargs: Fallback — JSON string of parameters (used when client nests params).
        """
        # Fallback: if action is missing but kwargs is a JSON string, extract params.
        if not action and kwargs:
            try:
                parsed_kw = json.loads(kwargs) if isinstance(kwargs, str) else kwargs
                action = parsed_kw.get("action", action)
                target = target or parsed_kw.get("target", "")
                session_id = session_id or parsed_kw.get("session_id", "")
                scope = parsed_kw.get("scope", scope)
                endpoints = parsed_kw.get("endpoints", endpoints)
                token = token or parsed_kw.get("token", "")
                token_type = parsed_kw.get("token_type", token_type)
            except (json.JSONDecodeError, TypeError, AttributeError):
                pass

        valid_actions = ("initial", "mandatory_tests", "coverage_gaps", "post_auth", "chain")
        if action not in valid_actions:
            return json.dumps(
                {
                    "error": f"Invalid or missing action '{action}'. Must be one of: {', '.join(valid_actions)}",
                    "hint": "Pass 'action' as a direct parameter, e.g.: plan(action='coverage_gaps', ...)",
                },
                indent=2,
            )

        if action == "initial":
            return await _get_scan_plan(target, scope=scope)
        elif action == "mandatory_tests":
            return await _get_mandatory_tests(target, endpoints=endpoints)
        elif action == "coverage_gaps":
            return await _get_coverage_gaps(session_id, target)
        elif action == "post_auth":
            return await _get_auth_retest_plan(target, token, token_type=token_type)
        elif action == "chain":
            return await _get_chain_opportunities(session_id)
        else:
            return json.dumps({"error": f"Unknown action: {action}"}, indent=2)
