"""FastMCP server setup and lifecycle (v2.0).

Tool-server architecture — the host LLM (Claude Desktop / Cursor / VS Code)
drives the assessment. security-mcp MCP exposes atomic tools:

  1. **Atomic security tools** — bridged from ToolRegistry (recon, HTTP, vuln, browser)
  2. **Intelligence tools** — KB search, CWE info, attack patterns, scan planner
  3. **State tools** — create_session, save_finding, get_findings, generate_report
  4. **Resources** — findings, report, KB articles
  5. **Prompt templates** — threat_model, code_review, security_assessment

No background tasks, no polling. Every tool call returns immediately.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("security_mcp.mcp.server")

# ---------------------------------------------------------------------------
# SSRF protection  (legacy helpers kept for backward compat in tests)
# ---------------------------------------------------------------------------

_INTERNAL_PATTERNS = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
]
_BLOCKED_HOSTS = {"localhost", "0.0.0.0", "::1", "[::1]"}


@dataclass
class RateLimiter:
    """Single-bucket rate limiter (calls/minute + concurrency)."""

    max_per_minute: int = 60
    max_concurrent: int = 5
    _calls: list[float] = field(default_factory=list)
    _active: int = 0

    def check(self) -> bool:
        now = time.monotonic()
        self._calls = [t for t in self._calls if now - t < 60]
        if len(self._calls) >= self.max_per_minute:
            return False
        return self._active < self.max_concurrent

    def acquire(self) -> None:
        self._calls.append(time.monotonic())
        self._active += 1

    def release(self) -> None:
        self._active = max(0, self._active - 1)


class SessionRateLimiter:
    """Per-session rate limiter with a global fallback bucket.

    Each session gets its own RateLimiter instance so multiple agents
    (each with their own session) can work concurrently without
    starving each other.  Tool calls without a session_id fall back
    to the ``_global`` bucket.

    Limits are configurable via environment variables:
        SECMCP_RATE_PER_MINUTE  — per-session calls/min  (default 60)
        SECMCP_RATE_CONCURRENT  — per-session concurrency (default 5)
        SECMCP_RATE_GLOBAL_PER_MINUTE  — global calls/min  (default 120)
        SECMCP_RATE_GLOBAL_CONCURRENT  — global concurrency (default 10)
    """

    def __init__(
        self,
        per_minute: int | None = None,
        concurrent: int | None = None,
        global_per_minute: int | None = None,
        global_concurrent: int | None = None,
    ) -> None:
        import os

        self.per_minute = per_minute or int(os.environ.get("SECMCP_RATE_PER_MINUTE", "60"))
        self.concurrent = concurrent or int(os.environ.get("SECMCP_RATE_CONCURRENT", "5"))
        g_rpm = global_per_minute or int(os.environ.get("SECMCP_RATE_GLOBAL_PER_MINUTE", "120"))
        g_conc = global_concurrent or int(os.environ.get("SECMCP_RATE_GLOBAL_CONCURRENT", "10"))

        self._buckets: dict[str, RateLimiter] = {}
        self._global = RateLimiter(max_per_minute=g_rpm, max_concurrent=g_conc)

    def _bucket(self, session_id: str | None) -> RateLimiter:
        if session_id is None:
            return self._global
        if session_id not in self._buckets:
            self._buckets[session_id] = RateLimiter(
                max_per_minute=self.per_minute,
                max_concurrent=self.concurrent,
            )
        return self._buckets[session_id]

    def check(self, session_id: str | None = None) -> bool:
        return self._bucket(session_id).check()

    def acquire(self, session_id: str | None = None) -> None:
        self._bucket(session_id).acquire()

    def release(self, session_id: str | None = None) -> None:
        self._bucket(session_id).release()

    def remove_session(self, session_id: str) -> None:
        """Clean up a session's bucket when the session ends."""
        self._buckets.pop(session_id, None)

    @property
    def active_sessions(self) -> int:
        return len(self._buckets)


class RateLimitExceeded(Exception):
    pass


class InvalidTarget(Exception):
    pass


def _is_internal_ip(host: str) -> bool:
    """Check if host resolves to an internal/private IP."""
    if host in _BLOCKED_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        pass
    return any(pattern.match(host) for pattern in _INTERNAL_PATTERNS)


def validate_target(target: str) -> str:
    """Validate and normalize a target URL/host.

    Raises InvalidTarget for internal IPs, overly long targets, or invalid schemes.
    Internal targets are allowed when SECMCP_ALLOW_INTERNAL=1.
    """
    from security_mcp.mcp._security import is_internal_target

    if len(target) > 253:
        raise InvalidTarget(f"Target too long: {len(target)} chars (max 253)")

    parsed = urlparse(f"http://{target}") if "://" not in target else urlparse(target)

    if parsed.scheme and parsed.scheme not in ("http", "https"):
        raise InvalidTarget(f"Scheme not allowed: {parsed.scheme}")

    if is_internal_target(target):
        raise InvalidTarget("Internal targets not allowed (set SECMCP_ALLOW_INTERNAL=1 to override)")

    return target


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------


def create_mcp_server() -> Any:
    """Create and configure the FastMCP server instance.

    Architecture (v2.0 — tool server, host LLM is the intelligence):
      1. Atomic security tools — bridged from ToolRegistry (recon, HTTP, vuln, browser)
      2. Intelligence tools — KB search, CWE info, attack patterns, scan planner
      3. State tools — create_session, save_finding, get_findings, generate_report
      4. Resources — findings, report, KB articles
      5. Prompt templates — threat_model, code_review, security_assessment

    The host LLM (Claude Desktop / Cursor / VS Code) drives the assessment.
    No background tasks, no polling — every call returns immediately.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:
        raise ImportError("MCP support requires the 'mcp' package. Install with: pip install security_mcp[mcp]") from e

    mcp = FastMCP("security-mcp")

    # 1. Bridge all ToolRegistry tools to MCP (recon, HTTP, vuln, browser)
    from security_mcp.mcp._singletons import get_tool_registry
    from security_mcp.mcp.tool_bridge import bridge_tools_to_mcp

    tool_registry = get_tool_registry()
    n_bridged = bridge_tools_to_mcp(mcp, tool_registry, excluded={"run_command"})
    logger.info("Bridged %d atomic tools to MCP", n_bridged)

    # 2. Intelligence tools (search_kb, get_cwe_info, get_attack_patterns, get_scan_plan)
    from security_mcp.mcp.intel_tools import register as register_intel

    register_intel(mcp)

    # 3. State tools (create_session, save_finding, get_findings, generate_report)
    from security_mcp.mcp.state_tools import register as register_state

    register_state(mcp)
    logger.info("State tools registered (create_session, save_finding, get_findings, generate_report)")

    # 4. Resources (findings, report, KB articles)
    from security_mcp.mcp.resources import register_resources

    register_resources(mcp)

    # 5. Prompt templates
    from security_mcp.mcp.prompts import register_prompts

    register_prompts(mcp)

    return mcp


async def run_mcp_server(transport: str = "stdio") -> None:
    """Start the MCP server with the given transport."""
    server = create_mcp_server()
    logger.info("Starting MCP server with transport: %s", transport)
    await server.run(transport=transport)
