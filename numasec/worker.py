"""JSON-RPC worker for the TypeScript agent bridge.

Long-lived subprocess that receives JSON-RPC requests on stdin,
dispatches them to the ToolRegistry, and writes responses to stdout.

Protocol:
  - One JSON object per line (newline-delimited JSON-RPC)
  - Sends {"ready": true} on startup
  - Request:  {"id": "...", "method": "tool_name", "params": {...}}
  - Response: {"id": "...", "result": {...}} or {"id": "...", "error": {"message": "..."}}

Special methods (not tool calls):
  - "list_tools": Returns available tool names and schemas
  - "create_session": Creates a new session
  - "save_finding": Saves a finding
  - "get_findings": Retrieves findings
  - "generate_report": Generates a report
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
import sys
import traceback
from collections.abc import Callable, Coroutine
from typing import Any

logger = logging.getLogger("numasec.worker")

# State management imports (lazy to avoid import-time side effects)
_registry = None
_session_store = None


def _get_registry():
    global _registry
    if _registry is None:
        from numasec.mcp._singletons import get_tool_registry

        _registry = get_tool_registry()
    return _registry


def _get_session_store():
    global _session_store
    if _session_store is None:
        from numasec.mcp._singletons import get_session_store

        _session_store = get_session_store()
    return _session_store


# ---------------------------------------------------------------------------
# Parameter normalisation for registry tools.
# The TS agent schemas use slightly different param names than the Python
# implementations.  This layer maps aliases and strips unknown params
# (mirroring the logic in tool_bridge.py for MCP).
# ---------------------------------------------------------------------------

# Bidirectional aliases applied per-tool.
_PARAM_ALIASES: dict[str, str] = {
    "target": "url",
    "data": "body",
    "max_depth": "depth",
    "tests": "types",  # injection_test: TS "tests" → Python "types"
    "jwt_token": "token",  # auth_test: TS "jwt_token" → Python "token"
    "cwe_id": "cwe",  # save_finding: TS "cwe_id" → Python "cwe"
}

# Reverse aliases (url→target) for tools like recon that use "target".
_PARAM_ALIASES_REV: dict[str, str] = {v: k for k, v in _PARAM_ALIASES.items()}


def _normalise_params(tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
    """Map aliased parameter names and drop unknown kwargs.

    1. Convert TS parameter names to Python names (target→url, data→body, etc.)
    2. If the function doesn't accept the mapped name either, try the reverse.
    3. Drop any parameters the function doesn't accept at all.
    """
    reg = _get_registry()
    func = reg._tools.get(tool_name)
    if func is None:
        return params

    try:
        sig = inspect.signature(func)
    except (ValueError, TypeError):
        return params

    has_var_kw = any(p.kind == p.VAR_KEYWORD for p in sig.parameters.values())
    accepted = set(sig.parameters.keys())

    normalised = dict(params)

    # Forward aliases: target→url, data→body, max_depth→depth, etc.
    for src, dst in _PARAM_ALIASES.items():
        if src in normalised and src not in accepted and dst in accepted and dst not in normalised:
            normalised[dst] = normalised.pop(src)

    # Reverse aliases: url→target (for tools like recon that accept "target")
    for src, dst in _PARAM_ALIASES_REV.items():
        if src in normalised and src not in accepted and dst in accepted and dst not in normalised:
            normalised[dst] = normalised.pop(src)

    # Filter unknown params (unless func accepts **kwargs)
    if not has_var_kw:
        dropped = {k for k in normalised if k not in accepted}
        if dropped:
            logger.debug("Tool %s: dropping unknown params %s", tool_name, dropped)
        normalised = {k: v for k, v in normalised.items() if k in accepted}

    # Coerce JSON-string values to dict where the Python function expects dict.
    # LLMs send headers as '{"Content-Type": "application/json"}' but Python expects dict.
    _JSON_COERCE_PARAMS = {"headers"}
    for pname in _JSON_COERCE_PARAMS:
        if pname in normalised and isinstance(normalised[pname], str):
            val = normalised[pname].strip()
            if val.startswith("{"):
                with contextlib.suppress(json.JSONDecodeError, TypeError):
                    normalised[pname] = json.loads(val)

    return normalised


# ---------------------------------------------------------------------------
# Special method handlers.
# State/intel tools are @mcp.tool closures inside register(), so we call
# the underlying stores directly instead of importing the nested functions.
# ---------------------------------------------------------------------------


async def _handle_list_tools() -> dict[str, Any]:
    """Return available tools and their schemas."""
    reg = _get_registry()
    return {
        "tools": reg.available_tools,
        "schemas": reg.get_schemas(),
    }


async def _handle_create_session(params: dict) -> Any:
    """Create a new pentest session."""
    from numasec.mcp._singletons import get_mcp_session_store

    # TS sends target_url; Python create_session expects target.
    target = params.get("target_url") or params.get("target", "")
    store = get_mcp_session_store()
    session_id = await store.create(target=target)
    logger.info("MCP session created: %s (target=%s)", session_id, target)
    return json.dumps(
        {
            "session_id": session_id,
            "target": target,
            "status": "active",
            "message": (
                f"Session created. Use session_id='{session_id}' in all "
                "save_finding, get_findings, and generate_report calls."
            ),
        },
        indent=2,
    )


async def _handle_save_finding(params: dict) -> Any:
    """Save a security finding."""
    from numasec.mcp._singletons import get_mcp_session_store
    from numasec.models.enums import Severity
    from numasec.models.finding import Finding

    session_id = params.get("session_id", "")
    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    sev = sev_map.get((params.get("severity") or "info").lower(), Severity.INFO)

    # Map TS param names to Python: cwe_id→cwe
    cwe = params.get("cwe_id") or params.get("cwe", "")
    related_to = params.get("related_to", "")
    related_ids = [r.strip() for r in related_to.split(",") if r.strip()] if related_to else []

    finding = Finding(
        title=params.get("title", ""),
        severity=sev,
        url=params.get("url", ""),
        cwe_id=cwe,
        evidence=params.get("evidence", ""),
        description=params.get("description") or params.get("title", ""),
        parameter=params.get("parameter", ""),
        payload=params.get("payload", ""),
        tool_used=params.get("tool_used", ""),
        related_finding_ids=related_ids,
        chain_id=params.get("chain_id", ""),
        confidence=float(params.get("confidence", 0.5)),
    )

    from numasec.standards import enrich_finding

    enrich_finding(finding)

    store = get_mcp_session_store()
    try:
        finding_id = await store.add_finding(session_id, finding)
    except KeyError:
        return json.dumps(
            {"error": f"Session not found: {session_id}. Call create_session first."},
            indent=2,
        )

    logger.info("Finding saved: %s [%s] in session %s", finding.title, sev.value, session_id)
    meta = await store.get_session(session_id)
    total = meta["finding_count"] if meta else 1

    return json.dumps(
        {
            "finding_id": finding_id,
            "session_id": session_id,
            "severity": sev.value,
            "total_findings": total,
            "enriched": {
                "cwe_id": finding.cwe_id,
                "cvss_score": finding.cvss_score,
                "cvss_vector": finding.cvss_vector,
                "owasp_category": finding.owasp_category,
                "attack_technique": finding.attack_technique,
            },
        },
        indent=2,
    )


async def _handle_get_findings(params: dict) -> Any:
    """Retrieve findings."""
    from numasec.mcp._singletons import get_mcp_session_store

    session_id = params.get("session_id", "")
    # TS sends "severity"; Python uses "severity_filter".
    severity_filter = params.get("severity") or params.get("severity_filter", "")

    store = get_mcp_session_store()
    try:
        all_findings = await store.get_findings(session_id)
    except KeyError:
        return json.dumps(
            {"error": f"Session not found: {session_id}", "findings": [], "summary": {}},
            indent=2,
        )

    filtered = (
        [f for f in all_findings if f.severity.value == severity_filter.lower()] if severity_filter else all_findings
    )

    severity_counts: dict[str, int] = {}
    for f in all_findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return json.dumps(
        {
            "session_id": session_id,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "url": f.url,
                    "cwe_id": f.cwe_id,
                    "evidence": (f.evidence or "")[:500],
                    "confidence": f.confidence,
                }
                for f in filtered
            ],
            "summary": {
                "total": len(all_findings),
                "filtered": len(filtered),
                **severity_counts,
            },
        },
        indent=2,
        default=str,
    )


async def _handle_generate_report(params: dict) -> Any:
    """Generate a security report."""
    from numasec.mcp._singletons import get_mcp_session_store

    session_id = params.get("session_id", "")
    fmt = (params.get("format") or "sarif").lower()

    store = get_mcp_session_store()
    try:
        findings = await store.get_findings(session_id)
    except KeyError:
        return json.dumps({"error": f"Session not found: {session_id}"}, indent=2)

    meta = await store.get_session(session_id)
    target = meta.get("target", "") if meta else ""

    # Collect tools used from session events for OWASP coverage
    tools_used: list[str] = []
    try:
        events = await store.get_events(session_id, "tool_call")
        tools_used = [e.get("data", {}).get("tool", "") for e in events if isinstance(e, dict)]
    except Exception:
        pass
    # Also add tools from _SCANNER_TOOLS that produced findings
    for f in findings:
        tool = getattr(f, "tool_used", "") or ""
        if tool:
            tools_used.append(tool)

    if fmt == "sarif":
        from numasec.reporting.sarif import generate_sarif_report

        report = generate_sarif_report(findings)
        return json.dumps(
            {"format": "sarif", "findings_count": len(findings), "content": report}, indent=2, default=str
        )

    if fmt in ("markdown", "html"):
        from numasec.reporting.markdown import generate_markdown_report

        md_report = generate_markdown_report(findings, target=target, tools_used=tools_used)
        return json.dumps(
            {"format": "markdown", "findings_count": len(findings), "content": md_report}, indent=2, default=str
        )

    # Default: json
    from numasec.reporting import build_executive_summary

    return json.dumps(
        {
            "format": "json",
            "findings_count": len(findings),
            "session_id": session_id,
            "target": target,
            "executive_summary": build_executive_summary(findings, target=target, tools_used=tools_used),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "url": f.url,
                    "cwe_id": f.cwe_id,
                    "evidence": f.evidence,
                    "description": f.description,
                }
                for f in findings
            ],
        },
        indent=2,
        default=str,
    )


async def _handle_relay_credentials(params: dict) -> Any:
    """Store discovered credentials."""
    from numasec.mcp._singletons import get_mcp_session_store

    session_id = params.get("session_id", "")

    # TS may send a single "credentials" JSON string; unpack it.
    if "credentials" in params and isinstance(params["credentials"], str):
        try:
            cred_data = json.loads(params["credentials"])
            if isinstance(cred_data, dict):
                params = {**params, **cred_data}
        except (json.JSONDecodeError, TypeError):
            pass

    credential_type = params.get("credential_type", "bearer")
    value = params.get("value", "")
    source = params.get("source", "")
    username = params.get("username", "")
    password = params.get("password", "")

    store = get_mcp_session_store()
    try:
        await store.get_session(session_id)
    except KeyError:
        return json.dumps(
            {"error": f"Session not found: {session_id}. Call create_session first."},
            indent=2,
        )

    stored_item: dict[str, str] = {"type": credential_type, "source": source}
    if credential_type == "password":
        stored_item["username"] = username
        stored_item["password"] = password
    else:
        stored_item["value"] = value

    logger.info("Credential relayed: type=%s source=%s session=%s", credential_type, source, session_id)
    await store.add_event(session_id, "credential_relay", stored_item)

    auth_header: dict[str, str] = {}
    if credential_type == "bearer" and value:
        auth_header = {"Authorization": f"Bearer {value}"}
    elif credential_type == "cookie" and value:
        auth_header = {"Cookie": value}
    elif credential_type == "api_key" and value:
        auth_header = {"X-API-Key": value}

    return json.dumps(
        {
            "status": "stored",
            "session_id": session_id,
            "credential_type": credential_type,
            "source": source,
            "auth_header": auth_header,
            "message": ("Credential stored. Pass the auth_header to subsequent tool calls for authenticated testing."),
        },
        indent=2,
    )


async def _handle_kb_search(params: dict) -> Any:
    """Search the knowledge base."""
    from numasec.knowledge.retriever import KnowledgeRetriever

    query = params.get("query", "")
    search_type = params.get("type", params.get("category", "search"))
    top_k = params.get("top_k", 5)

    if search_type == "cwe":
        # CWE lookup
        from numasec.standards import get_cwe_info

        return json.dumps(get_cwe_info(query), indent=2, default=str)

    # General KB search
    retriever = KnowledgeRetriever()
    category = params.get("category", "")
    results = retriever.query(query, top_k=top_k, category=category)
    return json.dumps(
        {"query": query, "results": [r.to_dict() if hasattr(r, "to_dict") else str(r) for r in results]},
        indent=2,
        default=str,
    )


async def _handle_plan(params: dict) -> Any:
    """Get pentest plan / coverage."""
    from dataclasses import asdict

    from numasec.core.planner import DeterministicPlanner
    from numasec.models.target import TargetProfile

    action = params.get("action", "status")
    target = params.get("target", "")
    session_id = params.get("session_id", "")
    scope = params.get("scope", "standard")

    planner = DeterministicPlanner()
    profile = TargetProfile(target=target)

    if action in ("initial", "status"):
        plan = planner.create_plan(profile, scope=scope)
        return json.dumps(asdict(plan), indent=2, default=str)

    if action == "coverage_gaps":
        from numasec.core.coverage import _OWASP_LABELS, OWASP_TOOL_MAP
        from numasec.mcp._singletons import get_mcp_session_store

        store = get_mcp_session_store()
        try:
            findings = await store.get_findings(session_id)
        except KeyError:
            return json.dumps({"error": f"Session not found: {session_id}"}, indent=2)

        # Classify findings into OWASP categories via CWE mapping
        _cwe_to_owasp = {
            "CWE-89": "A03_injection",
            "CWE-79": "A03_injection",
            "CWE-611": "A03_injection",
            "CWE-94": "A03_injection",
            "CWE-78": "A03_injection",
            "CWE-917": "A03_injection",
            "CWE-943": "A03_injection",
            "CWE-352": "A01_access_control",
            "CWE-639": "A01_access_control",
            "CWE-284": "A01_access_control",
            "CWE-287": "A07_auth_failures",
            "CWE-798": "A07_auth_failures",
            "CWE-521": "A07_auth_failures",
            "CWE-522": "A02_crypto_failures",
            "CWE-327": "A02_crypto_failures",
            "CWE-328": "A02_crypto_failures",
            "CWE-918": "A10_ssrf",
            "CWE-16": "A05_misconfiguration",
            "CWE-942": "A05_misconfiguration",
        }
        tested: set[str] = set()
        for f in findings:
            cwe = getattr(f, "cwe_id", "") or ""
            cat = _cwe_to_owasp.get(cwe)
            if cat:
                tested.add(cat)
            # Also check tool_used → OWASP mapping
            tool = getattr(f, "tool_used", "") or ""
            for owasp_cat, tools in OWASP_TOOL_MAP.items():
                if tool in tools:
                    tested.add(owasp_cat)

        all_cats = list(OWASP_TOOL_MAP.keys())
        untested = [c for c in all_cats if c not in tested]
        coverage_pct = round(len(tested) / len(all_cats) * 100, 1) if all_cats else 0.0

        gap_tasks = []
        for cat in untested:
            tools = OWASP_TOOL_MAP.get(cat, [])
            for t in tools:
                if t not in ("http_request", "fetch_page"):
                    gap_tasks.append(
                        {"tool": t, "url": target, "owasp_category": cat, "owasp_label": _OWASP_LABELS.get(cat, cat)}
                    )
                    break

        return json.dumps(
            {
                "session_id": session_id,
                "target": target,
                "coverage": {
                    "tested_categories": sorted(tested),
                    "untested_categories": untested,
                    "tested_count": len(tested),
                    "total_count": len(all_cats),
                    "coverage_pct": coverage_pct,
                },
                "gap_tasks": gap_tasks,
            },
            indent=2,
            default=str,
        )

    if action == "next":
        plan = planner.create_plan(profile, scope=scope)
        return json.dumps(asdict(plan), indent=2, default=str)

    return json.dumps({"error": f"Unknown plan action: {action}"}, indent=2)


async def _handle_ping(params: dict) -> Any:
    """Health check — returns worker status."""
    import os

    mem = 0
    try:
        import psutil

        proc = psutil.Process(os.getpid())
        mem = proc.memory_info().rss // 1024 // 1024  # MB
    except ImportError:
        pass
    return json.dumps({
        "status": "ok",
        "pid": os.getpid(),
        "memory_mb": mem,
        "active_session": _active_session_id or None,
    })


async def _handle_build_chains(params: dict) -> Any:
    """Auto-detect and assign attack chains across session findings."""
    from numasec.mcp._singletons import get_mcp_session_store

    session_id = params.get("session_id", "")
    if not session_id:
        return json.dumps({"error": "session_id is required"}, indent=2)

    store = get_mcp_session_store()
    try:
        chains = await store.build_chains(session_id)
    except KeyError:
        return json.dumps({"error": f"Session not found: {session_id}"}, indent=2)

    return json.dumps(
        {
            "session_id": session_id,
            "chains": chains,
            "chain_count": len(chains),
            "total_chained_findings": sum(len(v) for v in chains.values()),
        },
        indent=2,
    )


# Method dispatch table
SPECIAL_METHODS: dict[str, Callable[..., Coroutine[Any, Any, Any]]] = {
    "list_tools": _handle_list_tools,
    "create_session": _handle_create_session,
    "save_finding": _handle_save_finding,
    "get_findings": _handle_get_findings,
    "generate_report": _handle_generate_report,
    "relay_credentials": _handle_relay_credentials,
    "kb_search": _handle_kb_search,
    "plan": _handle_plan,
    "build_chains": _handle_build_chains,
    "ping": _handle_ping,
}

# Scanner tools whose results may contain auto-saveable vulnerabilities.
_SCANNER_TOOLS = {
    "injection_test",
    "xss_test",
    "auth_test",
    "access_control_test",
    "ssrf_test",
    "path_test",
    "upload_test",
}

# Map vuln type → (default severity, CWE ID, title template)
_VULN_TYPE_MAP: dict[str, tuple[str, str, str]] = {
    "sql_injection": ("high", "CWE-89", "SQL Injection in '{param}'"),
    "nosql_injection": ("high", "CWE-943", "NoSQL Injection in '{param}'"),
    "nosql": ("high", "CWE-943", "NoSQL Injection in '{param}'"),
    "ssti": ("high", "CWE-94", "Server-Side Template Injection in '{param}'"),
    "command_injection": ("critical", "CWE-78", "OS Command Injection in '{param}'"),
    "reflected": ("medium", "CWE-79", "Reflected XSS in '{param}'"),
    "stored": ("high", "CWE-79", "Stored XSS in '{param}'"),
    "dom_indicator": ("medium", "CWE-79", "DOM-based XSS indicator in '{param}'"),
    "dom_xss": ("high", "CWE-79", "DOM-based XSS in '{param}'"),
    "xss": ("medium", "CWE-79", "Cross-Site Scripting in '{param}'"),
    "lfi": ("high", "CWE-22", "Local File Inclusion via '{param}'"),
    "open_redirect": ("medium", "CWE-601", "Open Redirect via '{param}'"),
    "host_header": ("medium", "CWE-644", "Host Header Injection"),
    "xxe": ("high", "CWE-611", "XML External Entity Injection"),
    "ssrf": ("high", "CWE-918", "Server-Side Request Forgery via '{param}'"),
    "idor": ("high", "CWE-639", "Insecure Direct Object Reference in '{param}'"),
    "csrf": ("medium", "CWE-352", "Cross-Site Request Forgery"),
    "missing_token": ("medium", "CWE-352", "Missing CSRF Token"),
    "origin_not_validated": ("high", "CWE-352", "Origin Header Not Validated (CSRF)"),
    "weak_samesite": ("medium", "CWE-1275", "Weak SameSite Cookie Policy"),
    "cors": ("high", "CWE-942", "CORS Misconfiguration"),
    "reflected_origin": ("critical", "CWE-942", "CORS Reflected Origin"),
    "null_origin": ("high", "CWE-942", "CORS Null Origin Allowed"),
    "wildcard": ("medium", "CWE-942", "CORS Wildcard Origin"),
    "wildcard_credentials": ("critical", "CWE-942", "CORS Wildcard with Credentials"),
    "jwt_none_alg": ("critical", "CWE-287", "JWT None Algorithm Bypass"),
    "jwt_weak_secret": ("high", "CWE-287", "JWT Weak Secret"),
    "jwt_exp_missing": ("low", "CWE-287", "JWT Missing Expiration"),
    "jwt_no_expiry": ("low", "CWE-287", "JWT Missing Expiration"),
    "jwt_kid_injection": ("high", "CWE-287", "JWT KID Path Traversal"),
    "jwt_password_leak": ("critical", "CWE-522", "JWT Leaks Password Hash"),
    "default_credentials": ("critical", "CWE-798", "Default Credentials"),
    "password_spray": ("high", "CWE-521", "Weak Password (Spray)"),
    "spray_valid_creds": ("high", "CWE-521", "Valid Credentials via Password Spray"),
    "missing_rate_limit": ("medium", "CWE-307", "Missing Rate Limiting"),
    "oauth_open_redirect": ("high", "CWE-601", "OAuth Open Redirect"),
    "oauth_state_missing": ("medium", "CWE-352", "OAuth Missing State Parameter"),
    "api_key_in_url": ("medium", "CWE-598", "API Key Exposed in URL"),
    "bearer_exposed": ("high", "CWE-522", "Bearer Token Exposed"),
    "crlf_header": ("high", "CWE-113", "CRLF Header Injection in '{param}'"),
    "crlf_splitting": ("critical", "CWE-113", "HTTP Response Splitting in '{param}'"),
    "crlf_log": ("medium", "CWE-117", "CRLF Log Injection in '{param}'"),
    "crlf_injection": ("high", "CWE-113", "CRLF Injection in '{param}'"),
    "header_injection": ("high", "CWE-113", "CRLF Header Injection in '{param}'"),
    "response_splitting": ("critical", "CWE-113", "HTTP Response Splitting in '{param}'"),
    "log_injection": ("medium", "CWE-117", "CRLF Log Injection in '{param}'"),
    "unrestricted_upload": ("critical", "CWE-434", "Unrestricted File Upload"),
    "webshell": ("critical", "CWE-434", "Web Shell Upload"),
    "file_upload": ("high", "CWE-434", "File Upload Vulnerability"),
    "mime_bypass": ("high", "CWE-434", "MIME Type Bypass Upload"),
    "limit_bypass": ("high", "CWE-362", "Race Condition Limit Bypass"),
    "state_change": ("high", "CWE-362", "Race Condition State Change"),
    "cl_te": ("critical", "CWE-444", "HTTP Request Smuggling (CL.TE)"),
    "te_cl": ("critical", "CWE-444", "HTTP Request Smuggling (TE.CL)"),
    "te_te": ("critical", "CWE-444", "HTTP Request Smuggling (TE.TE)"),
    "http_request_smuggling": ("critical", "CWE-444", "HTTP Request Smuggling"),
}

# Fallback type when scanner doesn't provide a "type" field in vulnerability dict
_TOOL_TYPE_FALLBACK: dict[str, str] = {
    "injection_test": "sql_injection",
    "xss_test": "xss",
    "auth_test": "default_credentials",
    "access_control_test": "idor",
    "ssrf_test": "ssrf",
    "path_test": "lfi",
    "upload_test": "file_upload",
}


async def _auto_save_findings(result: Any, tool_name: str, session_id: str) -> list[dict]:
    """Extract vulnerabilities from scanner results and auto-persist them.

    Returns list of saved finding summaries (for embedding in response).
    """
    if not isinstance(result, dict):
        return []
    vulns = result.get("vulnerabilities", [])
    if not vulns:
        return []

    target_url = result.get("target", result.get("url", ""))
    saved: list[dict] = []

    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue

        vtype = (vuln.get("type") or vuln.get("vuln_type") or "").lower()
        # Fall back to tool-name-derived type if scanner doesn't provide one
        if not vtype:
            vtype = _TOOL_TYPE_FALLBACK.get(tool_name, tool_name.replace("_test", ""))
        param = vuln.get("param") or vuln.get("parameter") or ""
        defaults = _VULN_TYPE_MAP.get(vtype, ("medium", "", "{type} vulnerability"))

        severity = vuln.get("severity", defaults[0])
        cwe = vuln.get("cwe", defaults[1])
        title_tpl = defaults[2]
        title = title_tpl.format(param=param or "endpoint", type=vtype)

        params: dict[str, Any] = {
            "session_id": session_id,
            "title": title,
            "severity": severity,
            "url": target_url,
            "cwe_id": cwe,
            "evidence": (vuln.get("evidence") or "")[:1000],
            "parameter": param,
            "payload": vuln.get("payload") or vuln.get("probe") or "",
            "tool_used": tool_name,
        }

        # Pass confidence if scanner provides it
        if "confidence" in vuln:
            params["confidence"] = vuln["confidence"]

        try:
            resp_json = await _handle_save_finding(params)
            resp = json.loads(resp_json)
            saved.append(
                {
                    "finding_id": resp.get("finding_id", ""),
                    "title": title,
                    "severity": severity,
                    "cwe": cwe,
                    "owasp_category": resp.get("enriched", {}).get("owasp_category", ""),
                }
            )
        except Exception as exc:
            logger.warning("Auto-save failed for '%s': %s", title, exc)

    return saved


# Track active session for auto-save (fallback for calls without explicit session_id)
_active_session_id: str = ""


async def dispatch(method: str, params: dict) -> Any:
    """Route a JSON-RPC call to the appropriate handler."""
    global _active_session_id

    # Check special methods first
    if method in SPECIAL_METHODS:
        handler = SPECIAL_METHODS[method]
        if method == "list_tools":
            return await handler()
        result = await handler(params)
        # Track active session for auto-save
        if method == "create_session" and isinstance(result, str):
            try:
                data = json.loads(result)
                _active_session_id = data.get("session_id", "")
            except (json.JSONDecodeError, TypeError):
                pass
        return result

    # Otherwise dispatch to ToolRegistry with parameter normalisation
    reg = _get_registry()
    if method not in reg.available_tools:
        raise ValueError(f"Unknown tool: {method}")

    normalised = _normalise_params(method, params)

    # Resolve session_id for this specific call (not relying on global alone)
    call_session_id = normalised.get("session_id", "") or params.get("session_id", "") or _active_session_id
    if call_session_id:
        _active_session_id = call_session_id

    result = await reg.call(method, **normalised)

    # Record tool usage for OWASP coverage tracking
    if call_session_id and method in _SCANNER_TOOLS:
        try:
            from numasec.mcp._singletons import get_mcp_session_store

            store = get_mcp_session_store()
            await store.add_event(call_session_id, "tool_call", {"tool": method, "url": normalised.get("url", "")})
        except Exception:
            pass

    # Auto-save findings from scanner tools
    if method in _SCANNER_TOOLS and call_session_id:
        try:
            saved = await _auto_save_findings(result, method, call_session_id)
            if saved and isinstance(result, dict):
                result["findings_auto_saved"] = saved
                result["findings_auto_saved_count"] = len(saved)
        except Exception as exc:
            logger.warning("Auto-save post-hook failed for %s: %s", method, exc)

    return result


# Concurrency primitives
_write_lock = asyncio.Lock()
_semaphore = asyncio.Semaphore(5)


async def _write_json_async(obj: dict) -> None:
    """Write a JSON object to stdout, serialised with a lock."""
    async with _write_lock:
        sys.stdout.write(json.dumps(obj, default=str) + "\n")
        sys.stdout.flush()


def _write_json(obj: dict) -> None:
    """Write a JSON object to stdout as a single line (sync, for startup only)."""
    sys.stdout.write(json.dumps(obj, default=str) + "\n")
    sys.stdout.flush()


async def _handle_request(req_id: str | None, method: str, params: dict) -> None:
    """Dispatch a single request with concurrency control."""
    async with _semaphore:
        try:
            result = await dispatch(method, params)
            if not isinstance(result, (dict, list, str, int, float, bool, type(None))):
                result = str(result)
            await _write_json_async({"id": req_id, "result": result})
        except Exception as e:
            logger.error("error dispatching %s: %s", method, traceback.format_exc())
            await _write_json_async(
                {
                    "id": req_id,
                    "error": {
                        "message": str(e),
                        "type": type(e).__name__,
                    },
                }
            )


async def main() -> None:
    """Main worker loop — read JSON-RPC requests, dispatch concurrently."""
    # Configure logging to stderr so stdout stays clean for JSON-RPC
    logging.basicConfig(
        level=logging.INFO,
        format="%(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    logger.info("numasec worker starting...")

    # Signal readiness (sync write before any async tasks)
    _write_json({"ready": True})

    # Read stdin line by line
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    tasks: set[asyncio.Task[None]] = set()

    while True:
        line = await reader.readline()
        if not line:
            logger.info("stdin closed, shutting down")
            break

        line_str = line.decode("utf-8").strip()
        if not line_str:
            continue

        try:
            request = json.loads(line_str)
        except json.JSONDecodeError as e:
            logger.error("invalid JSON: %s", e)
            continue

        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", {})

        task = asyncio.create_task(_handle_request(req_id, method, params))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    # Wait for in-flight tasks on shutdown
    if tasks:
        logger.info("waiting for %d in-flight tasks", len(tasks))
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
