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

import inspect
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Tools excluded from MCP exposure by default (security-sensitive).
DEFAULT_EXCLUDED: frozenset[str] = frozenset({"run_command"})


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
        from security_mcp.mcp._singletons import get_rate_limiter
        from security_mcp.mcp.server import RateLimitExceeded

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
                try:
                    kwargs = json.loads(kwargs["kwargs"])
                except (json.JSONDecodeError, TypeError):
                    pass

            # Filter out parameters not accepted by the target function to
            # prevent TypeError on unexpected keyword arguments.
            if _accepted_params is not None:
                dropped = {k for k in kwargs if k not in _accepted_params}
                if dropped:
                    logger.debug("Tool %s: dropping unknown params %s", captured_name, dropped)
                    kwargs = {k: v for k, v in kwargs.items() if k in _accepted_params}

            result = await registry.call(captured_name, **kwargs)

            # MCP expects string responses.
            if isinstance(result, dict | list):
                output = json.dumps(result, indent=2, default=str)
            else:
                output = str(result)

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
                            f"Output truncated: showing 5 of {original_count} results "
                            f"(original {len(output)} chars)"
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
