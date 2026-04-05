"""Bridge between ToolRegistry (internal) and FastMCP (external).

Automatically exposes all registered tools as MCP tools,
preserving schemas and adding MCP-specific metadata.

The bridge reads every tool from ToolRegistry._tools / ._schemas,
builds an async MCP wrapper that delegates to registry.call(), and
registers it with FastMCP via mcp.tool().

Why registry.call() instead of calling func directly:
  - Respects scope restrictions (set_scope / clear_scope)
  - Single point for future middleware (logging, cost tracking)
"""

from __future__ import annotations

import contextlib
import inspect
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Tools excluded from MCP exposure by default.
# run_command is intentionally exposed — this server is meant for authorised
# pentesting on controlled targets where full command execution is expected.
DEFAULT_EXCLUDED: frozenset[str] = frozenset()

# ---------------------------------------------------------------------------
# Auto-save: extract vulnerabilities from scanner results and persist them.
# Ported from worker.py to unify behaviour across TUI and standalone MCP.
# ---------------------------------------------------------------------------

_SCANNER_TOOLS = {
    "injection_test",
    "xss_test",
    "auth_test",
    "access_control_test",
    "ssrf_test",
    "path_test",
    "upload_test",
}

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
    """Extract vulnerabilities from scanner results and auto-persist them."""
    if not isinstance(result, dict):
        return []
    vulns = result.get("vulnerabilities", [])
    if not vulns:
        return []

    from numasec.mcp._singletons import get_mcp_session_store
    from numasec.models.enums import Severity
    from numasec.models.finding import Finding
    from numasec.standards import enrich_finding

    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    target_url = result.get("target", result.get("url", ""))
    store = get_mcp_session_store()
    saved: list[dict] = []

    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue

        vtype = (vuln.get("type") or vuln.get("vuln_type") or "").lower()
        if not vtype:
            vtype = _TOOL_TYPE_FALLBACK.get(tool_name, tool_name.replace("_test", ""))
        param = vuln.get("param") or vuln.get("parameter") or ""
        defaults = _VULN_TYPE_MAP.get(vtype, ("medium", "", "{type} vulnerability"))

        severity = vuln.get("severity", defaults[0])
        cwe = vuln.get("cwe", defaults[1])
        title_tpl = defaults[2]
        title = title_tpl.format(param=param or "endpoint", type=vtype)

        finding = Finding(
            title=title,
            severity=sev_map.get(severity, Severity.MEDIUM),
            url=target_url,
            cwe_id=cwe,
            evidence=(vuln.get("evidence") or "")[:1000],
            description=title,
            parameter=param,
            payload=vuln.get("payload") or vuln.get("probe") or "",
            tool_used=tool_name,
            confidence=float(vuln.get("confidence", 0.5)),
        )
        enrich_finding(finding)

        try:
            finding_id = await store.add_finding(session_id, finding)
            saved.append(
                {
                    "finding_id": finding_id,
                    "title": title,
                    "severity": severity,
                    "cwe": cwe,
                    "owasp_category": finding.owasp_category,
                }
            )
        except Exception as exc:
            logger.warning("Auto-save failed for '%s': %s", title, exc)

    return saved


def bridge_tools_to_mcp(
    mcp: Any,  # FastMCP instance
    tool_registry: Any,  # ToolRegistry instance
    *,
    excluded: set[str] | None = None,
) -> int:
    """Register all tools from ToolRegistry as MCP tools.

    Each tool's existing OpenAI-compatible JSON schema is
    converted to MCP tool schema automatically.

    Args:
        mcp: FastMCP server instance.
        tool_registry: ToolRegistry with registered tools.
        excluded: Tool names to skip (default: {"run_command"}).

    Returns:
        Number of tools successfully registered.
    """
    skip = excluded if excluded is not None else DEFAULT_EXCLUDED
    registered = 0

    for tool_name in tool_registry.available_tools:
        if tool_name in skip:
            logger.debug("Skipping excluded tool: %s", tool_name)
            continue

        try:
            # ToolRegistry stores schemas in ._schemas[name] with keys:
            #   name, description, parameters
            schema = tool_registry._schemas.get(tool_name, {})
            description = schema.get("description", f"Execute {tool_name}")

            _register_one(mcp, tool_name, tool_registry, description)
            registered += 1
            logger.debug("Bridged tool to MCP: %s", tool_name)

        except Exception:
            logger.exception("Failed to bridge tool: %s", tool_name)

    logger.info("Bridged %d/%d tools to MCP", registered, len(tool_registry.available_tools))
    return registered


def _register_one(
    mcp: Any,
    tool_name: str,
    registry: Any,
    description: str,
) -> None:
    """Register a single tool as an MCP tool.

    Creates an async closure that delegates to ``registry.call()`` so
    that scope restrictions and future middleware are respected.
    """

    # tool_name is captured from _register_one's parameter — no late-binding issue.
    captured_name = tool_name

    # Pre-compute accepted parameter names so we can filter unknown kwargs.
    _func = registry._tools.get(tool_name)
    _accepted_params: set[str] | None = None
    if _func is not None:
        try:
            sig = inspect.signature(_func)
            has_var_keyword = any(p.kind == p.VAR_KEYWORD for p in sig.parameters.values())
            if not has_var_keyword:
                _accepted_params = set(sig.parameters.keys())
        except (ValueError, TypeError):
            pass

    async def _mcp_wrapper(**kwargs: Any) -> str:
        from numasec.mcp._singletons import get_rate_limiter
        from numasec.mcp.server import RateLimitExceeded

        limiter = get_rate_limiter()

        # Atomic tools don't have session context → global bucket (session_id=None).
        if not limiter.check(session_id=None):
            raise RateLimitExceeded(
                f"Global rate limit exceeded for tool '{captured_name}'. "
                "Too many concurrent tool calls — try again shortly."
            )

        limiter.acquire(session_id=None)
        try:
            # FastMCP wraps **kwargs functions into a single "kwargs" parameter.
            # Unpack if the client sent {"kwargs": {actual params}}.
            if "kwargs" in kwargs and isinstance(kwargs["kwargs"], dict) and len(kwargs) == 1:
                kwargs = kwargs["kwargs"]
            elif "kwargs" in kwargs and isinstance(kwargs["kwargs"], str) and len(kwargs) == 1:
                # Handle kwargs passed as a JSON string (common LLM mistake).
                with contextlib.suppress(json.JSONDecodeError, TypeError):
                    kwargs = json.loads(kwargs["kwargs"])

            # Filter out parameters not accepted by the target function to
            # prevent TypeError on unexpected keyword arguments.
            if _accepted_params is not None:
                dropped = {k for k in kwargs if k not in _accepted_params}
                if dropped:
                    logger.debug("Tool %s: dropping unknown params %s", captured_name, dropped)
                    kwargs = {k: v for k, v in kwargs.items() if k in _accepted_params}

            result = await registry.call(captured_name, **kwargs)

            # Auto-save findings from scanner tools when a session is active.
            if captured_name in _SCANNER_TOOLS:
                sid = kwargs.get("session_id", "")
                if sid and isinstance(result, dict):
                    try:
                        saved = await _auto_save_findings(result, captured_name, sid)
                        if saved:
                            result["findings_auto_saved"] = saved
                            result["findings_auto_saved_count"] = len(saved)
                    except Exception as exc:
                        logger.warning("Auto-save post-hook failed for %s: %s", captured_name, exc)

                    # Record tool usage for OWASP coverage tracking.
                    try:
                        from numasec.mcp._singletons import get_mcp_session_store

                        store = get_mcp_session_store()
                        await store.add_event(sid, "tool_call", {"tool": captured_name, "url": kwargs.get("url", "")})
                    except Exception:
                        pass

            # MCP expects string responses.
            output = json.dumps(result, indent=2, default=str) if isinstance(result, dict | list) else str(result)

            # Safety net: truncate oversized output to avoid MCP protocol errors.
            if len(output) > 32_000:
                try:
                    parsed = json.loads(output)
                    vulns = parsed.get("vulnerabilities", parsed.get("findings", []))
                    if isinstance(vulns, list) and len(vulns) > 5:
                        original_count = len(vulns)
                        parsed["vulnerabilities"] = vulns[:5]
                        parsed["_truncated"] = True
                        parsed["_note"] = (
                            f"Output truncated: showing 5 of {original_count} results (original {len(output)} chars)"
                        )
                        output = json.dumps(parsed, indent=2, default=str)
                except (json.JSONDecodeError, TypeError):
                    output = output[:32_000] + "\n... [truncated]"

            return output

        except RateLimitExceeded:
            raise
        except Exception as exc:
            logger.error("Tool %s failed: %s", captured_name, exc)
            error_response: dict[str, Any] = {"error": str(exc), "tool": captured_name}
            # Surface partial results if the exception carries them
            partial = getattr(exc, "partial_results", None)
            if partial is not None:
                error_response["partial_results"] = partial
                error_response["note"] = "Scanner crashed but produced partial findings before the error."
            return json.dumps(error_response, default=str)
        finally:
            limiter.release(session_id=None)

    # Give the wrapper a readable identity for debugging / MCP listings.
    _mcp_wrapper.__name__ = tool_name
    _mcp_wrapper.__qualname__ = f"mcp_bridge.{tool_name}"
    _mcp_wrapper.__doc__ = description

    # FastMCP's mcp.tool() works both as decorator and as a registrar:
    #   mcp.tool(name=..., description=...)(func)
    mcp.tool(name=tool_name, description=description)(_mcp_wrapper)
