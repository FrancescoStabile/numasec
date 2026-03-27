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
import inspect
import json
import logging
import sys
import traceback
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
    "tests": "types",       # injection_test: TS "tests" → Python "types"
    "jwt_token": "token",   # auth_test: TS "jwt_token" → Python "token"
    "cwe_id": "cwe",        # save_finding: TS "cwe_id" → Python "cwe"
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
        [f for f in all_findings if f.severity.value == severity_filter.lower()]
        if severity_filter
        else all_findings
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

    if fmt == "sarif":
        from numasec.reporting.sarif import generate_sarif_report
        report = generate_sarif_report(findings)
        return json.dumps({"format": "sarif", "findings_count": len(findings), "content": report}, indent=2, default=str)

    if fmt in ("markdown", "html"):
        from numasec.reporting.markdown import generate_markdown_report
        report = generate_markdown_report(findings, target=target)
        return json.dumps({"format": "markdown", "findings_count": len(findings), "content": report}, indent=2, default=str)

    # Default: json
    from numasec.reporting import build_executive_summary
    return json.dumps(
        {
            "format": "json",
            "findings_count": len(findings),
            "session_id": session_id,
            "target": target,
            "executive_summary": build_executive_summary(findings, target=target),
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
            "message": (
                "Credential stored. Pass the auth_header to subsequent tool calls "
                "for authenticated testing."
            ),
        },
        indent=2,
    )


async def _handle_kb_search(params: dict) -> Any:
    """Search the knowledge base."""
    from numasec.knowledge.retriever import BM25Retriever

    query = params.get("query", "")
    search_type = params.get("type", params.get("category", "search"))
    top_k = params.get("top_k", 5)

    if search_type == "cwe":
        # CWE lookup
        from numasec.standards import get_cwe_info
        return json.dumps(get_cwe_info(query), indent=2, default=str)

    # General KB search
    retriever = BM25Retriever()
    category = params.get("category", "")
    results = retriever.search(query, top_k=top_k, category=category)
    return json.dumps(
        {"query": query, "results": [r.to_dict() if hasattr(r, "to_dict") else str(r) for r in results]},
        indent=2,
        default=str,
    )


async def _handle_plan(params: dict) -> Any:
    """Get pentest plan / coverage."""
    from numasec.core.planner import DeterministicPlanner

    action = params.get("action", "status")
    target = params.get("target", "")
    session_id = params.get("session_id", "")
    scope = params.get("scope", "standard")

    planner = DeterministicPlanner()

    if action in ("initial", "status"):
        plan = planner.generate_plan(target, scope=scope)
        return json.dumps(plan, indent=2, default=str)

    if action == "coverage_gaps":
        from numasec.mcp._singletons import get_mcp_session_store
        store = get_mcp_session_store()
        try:
            findings = await store.get_findings(session_id)
        except KeyError:
            return json.dumps({"error": f"Session not found: {session_id}"}, indent=2)
        from numasec.core.coverage import OWASPCoverageTracker
        tracker = OWASPCoverageTracker()
        for f in findings:
            tracker.record(f)
        return json.dumps(tracker.report(), indent=2, default=str)

    if action == "next":
        plan = planner.generate_plan(target, scope=scope)
        return json.dumps(plan, indent=2, default=str)

    return json.dumps({"error": f"Unknown plan action: {action}"}, indent=2)


# Method dispatch table
SPECIAL_METHODS = {
    "list_tools": _handle_list_tools,
    "create_session": _handle_create_session,
    "save_finding": _handle_save_finding,
    "get_findings": _handle_get_findings,
    "generate_report": _handle_generate_report,
    "relay_credentials": _handle_relay_credentials,
    "kb_search": _handle_kb_search,
    "plan": _handle_plan,
}


async def dispatch(method: str, params: dict) -> Any:
    """Route a JSON-RPC call to the appropriate handler."""
    # Check special methods first
    if method in SPECIAL_METHODS:
        handler = SPECIAL_METHODS[method]
        if method == "list_tools":
            return await handler()
        return await handler(params)

    # Otherwise dispatch to ToolRegistry with parameter normalisation
    reg = _get_registry()
    if method not in reg.available_tools:
        raise ValueError(f"Unknown tool: {method}")

    normalised = _normalise_params(method, params)
    return await reg.call(method, **normalised)


def _write_json(obj: dict) -> None:
    """Write a JSON object to stdout as a single line."""
    sys.stdout.write(json.dumps(obj, default=str) + "\n")
    sys.stdout.flush()


async def main() -> None:
    """Main worker loop — read JSON-RPC requests, dispatch, respond."""
    # Configure logging to stderr so stdout stays clean for JSON-RPC
    logging.basicConfig(
        level=logging.INFO,
        format="%(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    logger.info("numasec worker starting...")

    # Signal readiness
    _write_json({"ready": True})

    # Read stdin line by line
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

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

        try:
            result = await dispatch(method, params)
            # Ensure result is JSON-serializable
            if not isinstance(result, (dict, list, str, int, float, bool, type(None))):
                result = str(result)
            _write_json({"id": req_id, "result": result})
        except Exception as e:
            logger.error("error dispatching %s: %s", method, traceback.format_exc())
            _write_json({
                "id": req_id,
                "error": {
                    "message": str(e),
                    "type": type(e).__name__,
                },
            })


if __name__ == "__main__":
    asyncio.run(main())
