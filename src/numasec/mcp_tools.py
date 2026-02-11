"""
NumaSec — MCP Tool Implementations

Thin wrappers that connect MCP tool calls to the NumaSec engine.

High-level tools (numasec_assess, numasec_quick_check):
    Create an Agent, run the full loop, collect events, return Markdown.

Mid-level tools (numasec_recon, numasec_http, numasec_browser):
    Call ToolRegistry.call() directly with scope checks.

Knowledge tool (numasec_get_knowledge):
    Read from the knowledge base.

All outputs are Markdown — NOT JSON. Markdown renders beautifully in
Claude Desktop, Cursor, VS Code. JSON renders as ugly monospace.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import socket
import time
import uuid
from dataclasses import dataclass, field as dc_field
from enum import Enum as StdEnum
from typing import Any

import httpx as httpx_lib

logger = logging.getLogger("numasec.mcp.tools")


# ═══════════════════════════════════════════════════════════════════════════
# Output Formatting — Markdown, always Markdown
# ═══════════════════════════════════════════════════════════════════════════

SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ═══════════════════════════════════════════════════════════════════════════
# Async Assessment Sessions — non-blocking with live progress
# ═══════════════════════════════════════════════════════════════════════════


class _SessionStatus(str, StdEnum):
    """Lifecycle states for an async assessment."""
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class _AssessmentSession:
    """In-memory state for a background assessment."""
    session_id: str
    target: str
    depth: str
    status: _SessionStatus = _SessionStatus.STARTING
    progress_pct: int = 0
    current_phase: str = ""
    current_tool: str = ""
    findings: list = dc_field(default_factory=list)
    tools_used: int = 0
    cost: float = 0.0
    start_time: float = 0.0
    error: str = ""
    max_iterations: int = 80
    step: int = 0
    provider: str = "deepseek"
    _task: Any = None
    _est_duration: float = 600.0  # estimated seconds for progress calc
    _update_event: asyncio.Event = dc_field(default_factory=asyncio.Event)


# Global session store — protected by _sessions_lock at await points
_active_sessions: dict[str, _AssessmentSession] = {}
_sessions_lock = asyncio.Lock()
_MAX_CONCURRENT = 2
_SESSION_TTL = int(os.environ.get("NUMASEC_SESSION_TTL", "3600"))  # seconds


def _cleanup_sessions():
    """Remove completed/failed sessions older than TTL."""
    now = time.time()
    terminal = {_SessionStatus.COMPLETED, _SessionStatus.FAILED, _SessionStatus.CANCELLED}
    expired = [
        sid for sid, s in list(_active_sessions.items())
        if s.status in terminal and (now - s.start_time) > _SESSION_TTL
    ]
    for sid in expired:
        _active_sessions.pop(sid, None)


def _text_progress_bar(pct: int, width: int = 20) -> str:
    """Text-based progress bar for Markdown."""
    filled = int(width * pct / 100)
    return "█" * filled + "░" * (width - filled)


def _task_done_callback(task: asyncio.Task) -> None:
    """Log unhandled exceptions from background assessment tasks."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        logger.error(f"Background assessment task raised: {exc}", exc_info=exc)


async def start_assess_async(
    target: str,
    scope: str = "",
    budget: float = 5.0,
    depth: str = "standard",
) -> str:
    """Start an assessment as a background task — returns immediately.

    The host LLM calls ``get_assess_status_longpoll()`` which waits internally
    for new findings or completion before returning.

    Returns:
        Markdown with session ID for progress polling.
    """
    import os
    from numasec.config import Config

    _cleanup_sessions()

    # ── API Key check ──
    config = Config()
    has_key = any([
        config.get("DEEPSEEK_API_KEY"),
        config.get("ANTHROPIC_API_KEY"),
        config.get("OPENAI_API_KEY"),
        os.environ.get("DEEPSEEK_API_KEY"),
        os.environ.get("ANTHROPIC_API_KEY"),
        os.environ.get("OPENAI_API_KEY"),
    ])
    if not has_key:
        return (
            "## ⚡ No API Key\n\n"
            "`numasec_assess_start` requires an LLM API key (DeepSeek recommended, $0.12/scan).\n\n"
            "Set `DEEPSEEK_API_KEY` in your environment or MCP config.\n\n"
            "**Tools that work without any key:**\n"
            f"- `numasec_quick_check` — instant scan of {target}\n"
            "- `numasec_http` / `numasec_browser` / `numasec_recon`\n"
        )

    # ── Concurrency check ──
    running = sum(
        1 for s in _active_sessions.values()
        if s.status in (_SessionStatus.STARTING, _SessionStatus.RUNNING)
    )
    if running >= _MAX_CONCURRENT:
        active_lines = "\n".join(
            f"- `{s.session_id}` — {s.target} ({s.progress_pct}%)"
            for s in _active_sessions.values()
            if s.status == _SessionStatus.RUNNING
        )
        return (
            f"## ⚠️ Max Concurrent Assessments ({_MAX_CONCURRENT})\n\n"
            f"**Running:**\n{active_lines}\n\n"
            "Wait for completion or cancel one with `numasec_assess_cancel`."
        )

    # ── Create session ──
    # max_iterations = LLM turns (each turn yields 5-10 events)
    depth_iters = {"quick": 30, "standard": 80, "deep": 150}
    # estimated duration in seconds — used for progress bar
    depth_est_secs = {"quick": 180, "standard": 600, "deep": 1800}
    session_id = uuid.uuid4().hex[:12]
    session = _AssessmentSession(
        session_id=session_id,
        target=target,
        depth=depth,
        start_time=time.time(),
        max_iterations=depth_iters.get(depth, 80),
    )
    session._est_duration = depth_est_secs.get(depth, 600)
    _active_sessions[session_id] = session
    # ── Launch background task with done callback ──
    task = asyncio.create_task(
        _run_assess_background(session, target, scope, budget, depth)
    )
    task.add_done_callback(_task_done_callback)
    session._task = task

    est = {"quick": "2-5", "standard": "5-15", "deep": "10-30"}

    return (
        f"## ✅ Assessment Started\n\n"
        f"| | |\n|---|---|\n"
        f"| **Session** | `{session_id}` |\n"
        f"| **Target** | {target} |\n"
        f"| **Depth** | {depth} |\n"
        f"| **Est. Duration** | {est.get(depth, '5-15')} minutes |\n"
        f"| **Budget** | ${budget:.2f} |\n\n"
        f"**→ Now call `numasec_assess_status(session_id=\"{session_id}\")` "
        f"to monitor progress.**\n\n"
        f"⚠️ You MUST keep calling `numasec_assess_status` in a loop until "
        f"the response says **COMPLETED**. The scan takes {est.get(depth, '5-15')} "
        f"minutes and needs ~5-15 status calls. Do NOT stop early or present "
        f"partial results as a final report."
    )


async def _run_assess_background(
    session: _AssessmentSession,
    target: str,
    scope: str,
    budget: float,
    depth: str,
) -> None:
    """Background coroutine that runs the full agent assessment."""
    agent = None
    try:
        session.status = _SessionStatus.RUNNING
        session._update_event.set()

        from numasec.agent import Agent
        from numasec.router import LLMRouter, Provider
        from numasec.cost_tracker import CostTracker
        from numasec.tools import check_tool_availability

        router = LLMRouter(primary=Provider.DEEPSEEK)
        agent = Agent(router=router, max_iterations=session.max_iterations)

        scope_targets = (
            [t.strip() for t in scope.split(",") if t.strip()]
            if scope else [target]
        )
        agent.tools.set_scope(scope_targets)

        availability = check_tool_availability()
        has_external = any(
            availability.get(t, False)
            for t in ("nmap", "nuclei", "sqlmap", "httpx", "ffuf")
        )

        cost_tracker = CostTracker(budget_limit=budget)
        depth_timeout = {"quick": 300, "standard": 900, "deep": 2400}
        timeout = depth_timeout.get(depth, 900)

        tool_guidance = ""
        if not has_external:
            tool_guidance = (
                "\n\nIMPORTANT: Only `http` and `browser_*` tools are available. "
                "nmap, nuclei, sqlmap, httpx, ffuf, subfinder are NOT installed. "
                "DO NOT try to call them. "
                "Use `http` for all HTTP testing. "
                "Use `browser_navigate`/`browser_fill`/`browser_click` for JS-heavy apps."
            )

        prompt = (
            f"Run a {'quick' if depth == 'quick' else 'thorough'} security assessment "
            f"on {target}. Find real vulnerabilities, not theoretical ones. "
            f"Use create_finding for every confirmed vulnerability."
            f"{tool_guidance}"
        )

        async for event in agent.run(prompt):
            session.step += 1
            # Progress based on elapsed time vs estimated duration
            # (step count is unreliable — each LLM turn yields 5-10 events)
            elapsed = time.time() - session.start_time
            est = getattr(session, '_est_duration', 600)
            session.progress_pct = min(95, int(elapsed / est * 100))

            if event.type == "tool_start":
                session.current_tool = event.tool_name
                session.tools_used += 1
                session._update_event.set()
            elif event.type == "finding" and event.finding:
                session.findings.append(event.finding.to_dict())
                session._update_event.set()
            elif event.type == "phase_complete":
                session.current_phase = event.data.get("phase_name", "")
                session._update_event.set()
            elif event.type == "usage":
                cost_tracker.add_tokens(
                    session.provider,
                    event.data.get("input_tokens", 0),
                    event.data.get("output_tokens", 0),
                )
                session.cost = cost_tracker.get_total_cost()

            # Hard timeout
            if time.time() - session.start_time > timeout:
                logger.warning(
                    f"[{session.session_id}] Timeout after {timeout}s"
                )
                break

            # Budget
            if cost_tracker.is_over_budget():
                logger.warning(
                    f"[{session.session_id}] Over budget ${session.cost:.2f}"
                )
                break

        # Only set COMPLETED if not already cancelled
        if session.status != _SessionStatus.CANCELLED:
            session.status = _SessionStatus.COMPLETED
            session.progress_pct = 100
            session._update_event.set()

    except asyncio.CancelledError:
        # cancel_assess is the authoritative setter — only set if not already done
        if session.status != _SessionStatus.CANCELLED:
            session.status = _SessionStatus.CANCELLED
        session._update_event.set()
        logger.info(f"[{session.session_id}] Cancelled")
    except Exception as e:
        session.status = _SessionStatus.FAILED
        session.error = str(e)
        session._update_event.set()
        logger.error(f"[{session.session_id}] Failed: {e}", exc_info=True)
    finally:
        if agent:
            try:
                await agent.close()
            except Exception:
                pass


def get_assess_status(session_id: str) -> str:
    """Return current status — synchronous snapshot (used internally)."""
    return _format_status(session_id)


async def get_assess_status_longpoll(
    session_id: str,
    wait: int = 60,
) -> str:
    """Wait up to *wait* seconds for something new, then return status.

    "Something new" means:
    - A new finding appeared
    - The session completed / failed / was cancelled
    - The progress jumped ≥ 10 %

    If nothing new by the timeout, returns the current status anyway.
    This dramatically reduces the number of visible tool calls.
    """
    _cleanup_sessions()

    session = _active_sessions.get(session_id)
    if not session:
        return _format_status(session_id)

    # If already terminal, return immediately
    terminal = {
        _SessionStatus.COMPLETED,
        _SessionStatus.FAILED,
        _SessionStatus.CANCELLED,
    }
    if session.status in terminal:
        return _format_status(session_id)

    # Snapshot what we know right now
    baseline_findings = len(session.findings)
    baseline_pct = session.progress_pct

    # Wait for the update event or timeout (efficient, no busy-wait)
    session._update_event.clear()
    try:
        await asyncio.wait_for(session._update_event.wait(), timeout=wait)
    except asyncio.TimeoutError:
        pass

    return _format_status(session_id)


def _format_status(session_id: str) -> str:
    """Return current status of an async assessment as Markdown.

    - **Running**: progress bar, step count, tools used, live findings
    - **Completed**: full formatted report (same as numasec_assess)
    - **Failed/Cancelled**: error + partial findings
    """
    _cleanup_sessions()

    session = _active_sessions.get(session_id)
    if not session:
        active = [
            f"- `{s.session_id}` ({s.target}, {s.status.value})"
            for s in _active_sessions.values()
        ]
        return (
            f"## ❌ Session Not Found\n\n"
            f"No assessment with ID `{session_id}`.\n\n"
            f"**Active sessions:** {', '.join(active) if active else 'none'}"
        )

    elapsed = time.time() - session.start_time

    # ── Completed → full report ──
    if session.status == _SessionStatus.COMPLETED:
        return format_assessment_markdown(
            target=session.target,
            findings=session.findings,
            cost=session.cost,
            duration=elapsed,
            provider=session.provider,
            tools_used=session.tools_used,
        )

    # ── Failed ──
    if session.status == _SessionStatus.FAILED:
        partial = _format_partial_findings(session.findings)
        return (
            f"## ❌ Assessment Failed\n\n"
            f"**Target:** {session.target}\n"
            f"**Error:** {session.error}\n"
            f"**Duration:** {elapsed:.0f}s | **Tools:** {session.tools_used}"
            f"{partial}"
        )

    # ── Cancelled ──
    if session.status == _SessionStatus.CANCELLED:
        if session.findings:
            return (
                format_assessment_markdown(
                    target=session.target,
                    findings=session.findings,
                    cost=session.cost,
                    duration=elapsed,
                    provider=session.provider,
                    tools_used=session.tools_used,
                )
                + "\n\n*⏹ Assessment was cancelled. Results may be partial.*"
            )
        return (
            f"## ⏹ Assessment Cancelled\n\n"
            f"**Target:** {session.target} | {elapsed:.0f}s\n\n"
            f"No findings before cancellation."
        )

    # ── Running / Starting ──
    bar = _text_progress_bar(session.progress_pct)
    lines = [
        f"## ⏳ Assessment In Progress — NOT COMPLETE\n",
        f"| | |",
        f"|---|---|",
        f"| **Progress** | {bar} **{session.progress_pct}%** |",
        f"| **Duration** | {elapsed:.0f}s |",
        f"| **Tools Used** | {session.tools_used} |",
        f"| **Cost** | ${session.cost:.3f} |",
    ]
    if session.current_phase:
        lines.append(f"| **Phase** | {session.current_phase} |")
    if session.current_tool:
        lines.append(f"| **Running** | `{session.current_tool}` |")

    if session.findings:
        lines.append(f"\n### 🔍 Findings So Far ({len(session.findings)})\n")
        for f in session.findings:
            sev = f.get("severity", "info")
            icon = SEVERITY_ICONS.get(sev, "⚪")
            title = f.get("title", "Unknown")
            lines.append(f"{icon} **{sev.upper()}:** {title}")
            desc = f.get("description", "")
            if desc:
                lines.append(f"> {desc[:150]}{'…' if len(desc) > 150 else ''}\n")
    else:
        lines.append("\n*No findings yet — still scanning…*")

    lines.append(
        f"\n---\n"
        f"⚠️ **ACTION REQUIRED**: The assessment is still running ({session.progress_pct}%). "
        f"You MUST call `numasec_assess_status` again with session `{session.session_id}` "
        f"to get the complete report. DO NOT present these partial results as a final report. "
        f"The scan will find more vulnerabilities as it continues."
    )
    return "\n".join(lines)


def cancel_assess(session_id: str) -> str:
    """Cancel a running assessment and return partial results."""
    session = _active_sessions.get(session_id)
    if not session:
        return f"## ❌ Session Not Found\n\nNo assessment with ID `{session_id}`."

    if session.status not in (_SessionStatus.STARTING, _SessionStatus.RUNNING):
        return (
            f"## Assessment Already {session.status.value.title()}\n\n"
            f"Session `{session_id}` is {session.status.value}. "
            f"Use `numasec_assess_status` to see results."
        )

    # Cancel the asyncio task — set status FIRST (authoritative)
    session.status = _SessionStatus.CANCELLED
    if session._task and not session._task.done():
        session._task.cancel()
    session._update_event.set()

    elapsed = time.time() - session.start_time
    partial = _format_partial_findings(session.findings)

    return (
        f"## ⏹ Assessment Cancelled\n\n"
        f"**Target:** {session.target}\n"
        f"**Duration:** {elapsed:.0f}s | **Cost:** ${session.cost:.3f}\n"
        f"**Progress:** {session.progress_pct}%"
        f"{partial}"
    )


def _format_partial_findings(findings: list[dict]) -> str:
    """Format partial findings list for status/cancel messages."""
    if not findings:
        return "\n\nNo findings were discovered."
    lines = [f"\n\n### Findings ({len(findings)})\n"]
    for f in findings:
        sev = f.get("severity", "info")
        icon = SEVERITY_ICONS.get(sev, "⚪")
        lines.append(f"- {icon} **{sev.upper()}:** {f.get('title', '?')}")
    return "\n".join(lines)


def format_assessment_markdown(
    target: str,
    findings: list[dict[str, Any]],
    cost: float,
    duration: float,
    provider: str,
    tools_used: int,
) -> str:
    """Format assessment results as Markdown for screenshot virality."""
    lines = [f"# 🛡️ NumaSec Assessment — {target}\n"]

    if findings:
        lines.append(
            f"**{len(findings)} vulnerabilities** found | "
            f"**${cost:.2f}** | {duration:.0f}s | {provider}\n"
        )
        # Sort by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.index(f.get("severity", "info"))
            if f.get("severity", "info") in SEVERITY_ORDER else 99,
        )
        for f in sorted_findings:
            sev = f.get("severity", "info")
            icon = SEVERITY_ICONS.get(sev, "⚪")
            lines.append(f"## {icon} {sev.upper()}: {f.get('title', 'Unknown')}\n")
            if f.get("description"):
                lines.append(f"{f['description']}\n")
            if f.get("evidence"):
                ev = f["evidence"][:300]
                lines.append(f"**Evidence:** `{ev}`\n")
    else:
        lines.append(
            f"**No vulnerabilities found** | **${cost:.2f}** | {duration:.0f}s | {provider}\n"
        )
        lines.append(
            "The target appears secure against automated testing. "
            "Consider manual review for business logic vulnerabilities.\n"
        )

    lines.append(f"\n---\n*Powered by [NumaSec](https://github.com/FrancescoStabile/numasec) | ${cost:.2f} with {provider}*")
    return "\n".join(lines)


def format_quick_check_markdown(
    target: str,
    tech_info: str,
    port_info: str,
    vuln_info: str,
    cost: float,
    duration: float,
) -> str:
    """Format quick check results as Markdown."""
    lines = [f"# ⚡ Quick Check — {target}\n"]

    # Technology detection
    if tech_info and "error" not in tech_info.lower():
        lines.append("## Technologies Detected\n")
        lines.append(f"{_extract_tech_summary(tech_info)}\n")

    # Port scan
    if port_info and "error" not in port_info.lower():
        lines.append("## Open Ports\n")
        lines.append(f"{_extract_port_summary(port_info)}\n")

    # Vulnerabilities
    if vuln_info and "error" not in vuln_info.lower():
        vuln_summary = _extract_vuln_summary(vuln_info)
        if vuln_summary:
            lines.append("## Findings\n")
            lines.append(f"{vuln_summary}\n")

    lines.append(
        "\n**Want deeper testing?** → Use `numasec_assess` for full "
        "assessment with exploitation.\n"
    )
    lines.append(f"*Quick check: ${cost:.2f} | {duration:.0f}s*")
    return "\n".join(lines)


def _extract_tech_summary(raw: str) -> str:
    """Extract technology info from httpx output."""
    try:
        data = json.loads(raw)
        parts = []
        if data.get("status_code"):
            parts.append(f"**Status:** {data['status_code']}")
        if data.get("title"):
            parts.append(f"**Title:** {data['title']}")
        if data.get("tech"):
            parts.append(f"**Stack:** {', '.join(data['tech'])}")
        if data.get("webserver"):
            parts.append(f"**Server:** {data['webserver']}")
        return "\n".join(parts) if parts else raw[:500]
    except (json.JSONDecodeError, TypeError):
        return raw[:500]


def _extract_port_summary(raw: str) -> str:
    """Extract port info from nmap output."""
    try:
        data = json.loads(raw)
        ports = data.get("ports", [])
        if ports:
            lines = []
            for p in ports[:20]:
                port_num = p.get("port", "?")
                state = p.get("state", "?")
                service = p.get("service", "?")
                version = p.get("version", "")
                line = f"- **{port_num}** ({state}) — {service}"
                if version:
                    line += f" {version}"
                lines.append(line)
            return "\n".join(lines)
        return raw[:500]
    except (json.JSONDecodeError, TypeError):
        # Fallback: show raw nmap output
        return f"```\n{raw[:800]}\n```"


def _extract_vuln_summary(raw: str) -> str:
    """Extract vulnerability info from nuclei output."""
    try:
        data = json.loads(raw)
        findings = data.get("findings", [])
        if not findings:
            return ""
        lines = []
        for f in findings[:10]:
            sev = f.get("severity", "info")
            icon = SEVERITY_ICONS.get(sev, "⚪")
            name = f.get("name", f.get("template", "Unknown"))
            lines.append(f"{icon} **{sev.upper()}**: {name}")
        return "\n".join(lines)
    except (json.JSONDecodeError, TypeError):
        return raw[:500]


# ═══════════════════════════════════════════════════════════════════════════
# High-Level Tools
# ═══════════════════════════════════════════════════════════════════════════


async def run_assess(
    target: str,
    scope: str = "",
    budget: float = 5.0,
    depth: str = "standard",
    progress_callback=None,
) -> str:
    """Run a full autonomous security assessment.

    Creates an Agent, runs the full ReAct loop, collects findings,
    returns formatted Markdown.

    If no LLM API key is configured, returns a graceful fallback message
    guiding the user to the 6 tools that work without any key.

    Args:
        target: Target URL with protocol
        scope: Comma-separated allowed targets (default: same as target)
        budget: Max cost in USD
        depth: 'quick', 'standard', or 'deep'
        progress_callback: async callable(step, total, message) for progress updates

    Returns:
        Markdown-formatted assessment results
    """
    import os
    from numasec.config import Config

    # ── Zero-Friction Check: graceful fallback when no API key ──
    config = Config()
    has_key = any([
        config.get("DEEPSEEK_API_KEY"),
        config.get("ANTHROPIC_API_KEY"),
        config.get("OPENAI_API_KEY"),
        os.environ.get("DEEPSEEK_API_KEY"),
        os.environ.get("ANTHROPIC_API_KEY"),
        os.environ.get("OPENAI_API_KEY"),
    ])

    if not has_key:
        return (
            "## ⚡ No API Key — Use NumaSec Tools Directly\n\n"
            "`numasec_assess` requires an LLM API key (DeepSeek recommended, $0.12/scan).\n\n"
            "**But you can start testing RIGHT NOW without any key:**\n\n"
            f"1. **Quick security check**: Call `numasec_quick_check` with target `{target}` "
            "— instant results, zero cost\n"
            f"2. **HTTP requests**: Call `numasec_http` to probe `{target}` endpoints\n"
            f"3. **Browser testing**: Call `numasec_browser` to test JavaScript-heavy pages\n"
            f"4. **Reconnaissance**: Call `numasec_recon` to scan ports and services\n"
            "5. **Knowledge base**: Call `numasec_get_knowledge` for attack cheatsheets\n\n"
            "The host AI (Claude/GPT in your coding tool) handles the reasoning. "
            "NumaSec handles the execution.\n\n"
            "**To unlock the full autonomous agent:**\n"
            "```\n"
            "# Get a key at platform.deepseek.com ($0.12 per full assessment)\n"
            "# Then add to your MCP config:\n"
            "#   \"env\": { \"DEEPSEEK_API_KEY\": \"sk-...\" }\n"
            "# Or set it globally:\n"
            "#   export DEEPSEEK_API_KEY=sk-...\n"
            "```"
        )

    from numasec.agent import Agent
    from numasec.router import LLMRouter, Provider
    from numasec.cost_tracker import CostTracker
    from numasec.tools import check_tool_availability

    # Determine max iterations from depth
    depth_map = {"quick": 15, "standard": 30, "deep": 50}
    max_iterations = depth_map.get(depth, 30)

    # Session timeout (prevents runaway executions)
    depth_timeout = {"quick": 120, "standard": 300, "deep": 600}
    session_timeout = depth_timeout.get(depth, 300)

    # Create agent
    router = LLMRouter(primary=Provider.DEEPSEEK)
    agent = Agent(router=router, max_iterations=max_iterations)

    # Set scope
    scope_targets = [t.strip() for t in scope.split(",") if t.strip()] if scope else [target]
    agent.tools.set_scope(scope_targets)

    # Check what tools are actually available
    availability = check_tool_availability()
    has_external = any(
        availability.get(t, False)
        for t in ("nmap", "nuclei", "sqlmap", "httpx", "ffuf")
    )

    # Cost tracker
    cost_tracker = CostTracker(budget_limit=budget)

    # Collect findings
    findings: list[dict] = []
    step = 0
    start_time = time.time()
    provider_name = "deepseek"
    tools_used = 0

    try:
        # Build prompt — adapt based on available tools
        if has_external:
            tool_guidance = ""
        else:
            tool_guidance = (
                "\n\nIMPORTANT: Only `http` and `browser_*` tools are available. "
                "nmap, nuclei, sqlmap, httpx, ffuf, subfinder are NOT installed. "
                "DO NOT try to call them — they will error. "
                "Use `http` for all HTTP testing (injection, headers, auth bypass). "
                "Use `browser_navigate`/`browser_fill`/`browser_click` for JS-heavy apps. "
                "Focus on: header analysis, auth testing, injection via HTTP requests, "
                "exposed sensitive paths, information disclosure."
            )

        prompt = (
            f"Run a {'quick' if depth == 'quick' else 'thorough'} security assessment "
            f"on {target}. Find real vulnerabilities, not theoretical ones. "
            f"Use create_finding for every confirmed vulnerability."
            f"{tool_guidance}"
        )

        async for event in agent.run(prompt):
            step += 1

            # Hard session timeout — prevent runaway execution
            elapsed = time.time() - start_time
            if elapsed > session_timeout:
                logger.warning(f"Session timeout after {elapsed:.0f}s (limit: {session_timeout}s)")
                break

            # Progress callback for MCP ctx.report_progress()
            if progress_callback:
                msg = ""
                if event.type == "tool_start":
                    msg = f"Running {event.tool_name}..."
                    tools_used += 1
                elif event.type == "finding":
                    f = event.finding
                    msg = f"{SEVERITY_ICONS.get(f.severity, '⚪')} Found: {f.title} ({f.severity})"
                elif event.type == "phase_complete":
                    msg = f"Phase complete: {event.data.get('phase_name', '')}"
                elif event.type == "done":
                    msg = "Assessment complete"

                if msg:
                    try:
                        await progress_callback(step, max_iterations, msg)
                    except Exception:
                        pass  # Don't crash on progress reporting failure

            # Collect findings
            if event.type == "finding" and event.finding:
                findings.append(event.finding.to_dict())

            # Track usage
            if event.type == "usage":
                cost_tracker.add_tokens(
                    provider_name,
                    event.data.get("input_tokens", 0),
                    event.data.get("output_tokens", 0),
                )

            # Budget check
            if cost_tracker.is_over_budget():
                logger.warning(f"Budget exceeded: ${cost_tracker.get_total_cost():.2f} > ${budget:.2f}")
                break

    except Exception as e:
        logger.error(f"Assessment error: {e}", exc_info=True)
        return f"# Assessment Error\n\nFailed to complete assessment of {target}.\n\n**Error:** {str(e)}"

    finally:
        try:
            await agent.close()
        except Exception:
            pass

    duration = time.time() - start_time
    cost = cost_tracker.get_total_cost()

    return format_assessment_markdown(
        target=target,
        findings=findings,
        cost=cost,
        duration=duration,
        provider=provider_name,
        tools_used=tools_used,
    )


async def run_quick_check(
    target: str,
    progress_callback=None,
) -> str:
    """Run a 30-second quick security check using ONLY Python-native tools.

    No external binaries required (no nmap, nuclei, httpx CLI).
    Uses the httpx Python library directly for all checks:
    1. HTTP response analysis (status, headers, server)
    2. Security headers audit
    3. Common misconfigurations check

    Args:
        target: Target URL with protocol
        progress_callback: async callable(step, total, message) for progress

    Returns:
        Markdown-formatted quick check results
    """
    from urllib.parse import urlparse

    parsed = urlparse(target)
    if not parsed.scheme:
        target = "http://" + target
        parsed = urlparse(target)

    start_time = time.time()
    total_steps = 3
    lines = [f"# ⚡ Quick Check — {target}\n"]

    # ── 1. HTTP Response Analysis ──
    resp = None
    try:
        if progress_callback:
            await progress_callback(1, total_steps, "Connecting & detecting technologies...")

        async with httpx_lib.AsyncClient(
            timeout=15, follow_redirects=True, verify=False
        ) as client:
            logger.debug(f"Quick check: TLS verification disabled for {target}")
            resp = await client.get(target)

        lines.append("## Server & Technology\n")
        lines.append(f"**Status:** {resp.status_code}")
        server = resp.headers.get("server", "Not disclosed")
        lines.append(f"**Server:** {server}")
        powered = resp.headers.get("x-powered-by")
        if powered:
            lines.append(f"**X-Powered-By:** {powered}")
        ct = resp.headers.get("content-type", "")
        lines.append(f"**Content-Type:** {ct}")

        # Extract title from HTML
        body_text = resp.text[:5000]
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
        if title_match:
            lines.append(f"**Page Title:** {title_match.group(1).strip()}")

        # Detect common frameworks from headers + body
        techs = []
        body_lower = body_text.lower()
        if "express" in server.lower():
            techs.append("Express.js")
        if "nginx" in server.lower():
            techs.append("Nginx")
        if "apache" in server.lower():
            techs.append("Apache")
        if "angular" in body_lower or "ng-app" in body_lower:
            techs.append("Angular")
        if "react" in body_lower or "__next" in body_lower:
            techs.append("React/Next.js")
        if "vue" in body_lower:
            techs.append("Vue.js")
        if "jquery" in body_lower:
            techs.append("jQuery")
        if resp.headers.get("x-aspnet-version") or "asp.net" in body_lower:
            techs.append("ASP.NET")
        if resp.headers.get("x-drupal-cache"):
            techs.append("Drupal")
        if "wp-content" in body_lower:
            techs.append("WordPress")
        if techs:
            lines.append(f"**Detected Stack:** {', '.join(techs)}")
        lines.append("")
    except Exception as e:
        lines.append(f"## Server & Technology\n\n⚠️ Connection failed: {e}\n")

    # ── 2. Security Headers Audit ──
    if resp is not None:
        try:
            if progress_callback:
                await progress_callback(2, total_steps, "Auditing security headers...")

            lines.append("## Security Headers\n")

            security_headers = {
                "Strict-Transport-Security": ("HSTS — protects against downgrade attacks", "critical"),
                "Content-Security-Policy": ("CSP — prevents XSS and injection", "high"),
                "X-Content-Type-Options": ("Prevents MIME-type sniffing", "medium"),
                "X-Frame-Options": ("Prevents clickjacking", "medium"),
                "X-XSS-Protection": ("Legacy XSS filter (deprecated but still checked)", "low"),
                "Referrer-Policy": ("Controls referrer information leaking", "low"),
                "Permissions-Policy": ("Controls browser feature access", "low"),
            }

            missing_critical = []
            missing_other = []
            present = []

            for header, (desc, severity) in security_headers.items():
                val = resp.headers.get(header.lower())
                if val:
                    present.append(f"- ✅ **{header}:** `{val}`")
                elif severity in ("critical", "high"):
                    missing_critical.append(f"- 🔴 **{header}** — MISSING ({desc})")
                else:
                    missing_other.append(f"- 🟡 **{header}** — missing ({desc})")

            if present:
                lines.append("**Present:**")
                lines.extend(present)
            if missing_critical:
                lines.append("\n**Missing (important):**")
                lines.extend(missing_critical)
            if missing_other:
                lines.append("\n**Missing (recommended):**")
                lines.extend(missing_other)

            # CORS check
            cors = resp.headers.get("access-control-allow-origin")
            if cors:
                if cors == "*":
                    lines.append(f"\n- 🔴 **CORS:** Wildcard `*` — allows any origin")
                else:
                    lines.append(f"\n- ⚪ **CORS:** `{cors}`")

            # Cookie security
            set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
            if not set_cookies:
                # httpx uses multi_items()
                set_cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
            if set_cookies:
                lines.append("\n**Cookies:**")
                for cookie in set_cookies[:5]:
                    issues = []
                    cl = cookie.lower()
                    if "secure" not in cl:
                        issues.append("no Secure flag")
                    if "httponly" not in cl:
                        issues.append("no HttpOnly flag")
                    if "samesite" not in cl:
                        issues.append("no SameSite")
                    name_part = cookie.split("=")[0].strip()
                    if issues:
                        lines.append(f"- 🟡 `{name_part}` — {', '.join(issues)}")
                    else:
                        lines.append(f"- ✅ `{name_part}` — properly secured")

            lines.append("")
        except Exception as e:
            lines.append(f"\n⚠️ Header analysis error: {e}\n")

    # ── 3. Common Misconfiguration Checks ──
    if resp is not None:
        try:
            if progress_callback:
                await progress_callback(3, total_steps, "Checking common misconfigurations...")

            lines.append("## Quick Vulnerability Checks\n")
            findings = []

            async with httpx_lib.AsyncClient(
                timeout=10, follow_redirects=False, verify=False
            ) as client:
                # Check common sensitive paths
                sensitive_paths = [
                    ("/.env", "Environment file exposed"),
                    ("/.git/config", "Git repository exposed"),
                    ("/robots.txt", "Robots.txt (informational)"),
                    ("/api/", "API endpoint discovered"),
                    ("/admin", "Admin panel"),
                    ("/swagger-ui.html", "Swagger docs exposed"),
                    ("/api-docs", "API docs exposed"),
                    ("/.well-known/security.txt", "Security.txt"),
                ]

                for path, desc in sensitive_paths:
                    try:
                        check_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                        r = await asyncio.wait_for(
                            client.get(check_url),
                            timeout=5,
                        )
                        if r.status_code == 200:
                            body_preview = r.text[:200].strip()
                            is_vuln = path in ("/.env", "/.git/config", "/swagger-ui.html", "/api-docs")
                            icon = "🔴" if is_vuln else "⚪"
                            severity = "HIGH" if is_vuln else "INFO"
                            findings.append(f"- {icon} **{severity}:** {desc} — `{path}` (200 OK)")
                        elif r.status_code in (301, 302, 308):
                            if path == "/admin":
                                findings.append(f"- ⚪ **INFO:** {desc} — `{path}` redirects to `{r.headers.get('location', '?')}`")
                    except Exception:
                        pass

                # Check for verbose error pages
                try:
                    r = await client.get(f"{target}/nonexistent_path_404_test")
                    if r.status_code >= 400:
                        body = r.text.lower()
                        if any(kw in body for kw in ["stack trace", "traceback", "exception", "debug"]):
                            findings.append("- 🟠 **MEDIUM:** Verbose error pages — stack traces exposed")
                except Exception:
                    pass

            if findings:
                lines.extend(findings)
            else:
                lines.append("- ✅ No obvious misconfigurations found in quick scan")

            lines.append("")
        except Exception as e:
            lines.append(f"\n⚠️ Misconfiguration check error: {e}\n")

    duration = time.time() - start_time
    lines.append(
        "\n**Want deeper testing?** → Use `numasec_assess` for full "
        "assessment with exploitation.\n"
    )
    lines.append(f"*Quick check completed in {duration:.1f}s — no external tools required, $0.00 LLM cost*")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# Mid-Level Tools
# ═══════════════════════════════════════════════════════════════════════════


async def run_recon(target: str, scan_type: str = "full") -> str:
    """Run reconnaissance on a target.

    Uses external tools if available (nmap, httpx CLI), falls back to
    Python-native HTTP probing if not installed.
    """
    from numasec.tools import create_tool_registry
    from urllib.parse import urlparse

    parsed = urlparse(target)
    host = parsed.hostname or target

    results = []

    has_nmap = shutil.which("nmap") is not None
    has_httpx_cli = shutil.which("httpx") is not None

    if has_nmap or has_httpx_cli:
        # External tools available — use registry
        registry = create_tool_registry()
        registry.set_scope([target])

        if has_httpx_cli:
            try:
                tech = await asyncio.wait_for(
                    registry.call("httpx", {"url": target}),
                    timeout=15,
                )
                results.append(f"## Technology Detection\n\n{_extract_tech_summary(tech)}")
            except Exception as e:
                results.append(f"## Technology Detection\n\nError: {e}")

        if has_nmap:
            nmap_opts = "-T4 --top-ports 1000 -sV" if scan_type == "full" else "-T4 --top-ports 100"
            try:
                ports = await asyncio.wait_for(
                    registry.call("nmap", {"target": host, "options": nmap_opts}),
                    timeout=120,
                )
                results.append(f"## Port Scan\n\n{_extract_port_summary(ports)}")
            except Exception as e:
                results.append(f"## Port Scan\n\nError: {e}")

        try:
            await registry.close()
        except Exception:
            pass
    else:
        # Fallback: Python-native recon via httpx library
        results.append("*Note: External tools (nmap, httpx CLI) not installed. Using Python-native recon.*\n")

        try:
            async with httpx_lib.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
                resp = await client.get(target)
                parts = []
                parts.append(f"**Status:** {resp.status_code}")
                parts.append(f"**Server:** {resp.headers.get('server', 'N/A')}")
                powered = resp.headers.get("x-powered-by")
                if powered:
                    parts.append(f"**X-Powered-By:** {powered}")
                parts.append(f"**Content-Type:** {resp.headers.get('content-type', 'N/A')}")

                title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:3000], re.IGNORECASE | re.DOTALL)
                if title_match:
                    parts.append(f"**Title:** {title_match.group(1).strip()}")

                results.append("## Technology Detection\n\n" + "\n".join(parts))
        except Exception as e:
            results.append(f"## Technology Detection\n\nError: {e}")

        # Quick port probe on common ports
        common_ports = [21, 22, 25, 53, 80, 443, 3000, 3306, 5432, 8080, 8443, 8888, 9090]
        open_ports = []
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((host, port)) == 0:
                        open_ports.append(str(port))
            except Exception:
                pass
        if open_ports:
            results.append(f"## Open Ports (quick probe)\n\n**Open:** {', '.join(open_ports)}")
        else:
            results.append("## Open Ports\n\nNo common ports open (quick probe only)")

    return f"# 🔍 Recon — {target}\n\n" + "\n\n".join(results)


async def run_http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    data: str = "",
) -> str:
    """Make an HTTP request with security context."""
    from numasec.tools import create_tool_registry

    registry = create_tool_registry()
    registry.set_scope([url])

    args: dict[str, Any] = {"url": url, "method": method}
    if headers:
        args["headers"] = headers
    if data:
        args["data"] = data

    try:
        result = await asyncio.wait_for(
            registry.call("http", args),
            timeout=30,
        )
    except Exception as e:
        result = json.dumps({"error": str(e)})
    finally:
        try:
            await registry.close()
        except Exception:
            pass

    # Format as Markdown
    try:
        resp = json.loads(result)
        lines = [f"## HTTP {method} {url}\n"]
        lines.append(f"**Status:** {resp.get('status_code', '?')}\n")
        h = resp.get("headers", {})
        if h:
            interesting = {k: v for k, v in h.items()
                          if k.lower() in ("server", "x-powered-by", "content-type",
                                           "set-cookie", "x-frame-options",
                                           "content-security-policy", "access-control-allow-origin")}
            if interesting:
                lines.append("**Interesting Headers:**")
                for k, v in interesting.items():
                    lines.append(f"- `{k}: {v}`")
                lines.append("")
        body = resp.get("body", "")
        if body:
            preview = body[:2000]
            lines.append(f"**Body** ({len(body)} chars):\n```\n{preview}\n```")
        return "\n".join(lines)
    except (json.JSONDecodeError, TypeError):
        return f"## HTTP {method} {url}\n\n```\n{result[:3000]}\n```"


async def run_browser_action(
    url: str,
    action: str = "navigate",
    selector: str = "",
    value: str = "",
) -> str:
    """Run a browser automation action.

    Actions: navigate, fill, click, screenshot, login
    """
    from numasec.tools import create_tool_registry

    registry = create_tool_registry()
    registry.set_scope([url])

    action_map = {
        "navigate": ("browser_navigate", {"url": url}),
        "screenshot": ("browser_screenshot", {"url": url}),
        "fill": ("browser_fill", {"url": url, "selector": selector, "value": value}),
        "click": ("browser_click", {"url": url, "selector": selector}),
    }

    tool_name, args = action_map.get(action, ("browser_navigate", {"url": url}))

    try:
        result = await asyncio.wait_for(
            registry.call(tool_name, args),
            timeout=60,
        )
    except Exception as e:
        result = json.dumps({"error": str(e)})
    finally:
        try:
            await registry.close()
        except Exception:
            pass

    return f"## Browser: {action} on {url}\n\n```\n{result[:5000]}\n```"


async def run_create_finding(
    title: str,
    severity: str,
    description: str,
    evidence: str = "",
) -> str:
    """Register a security finding with auto-enrichment (CWE, CVSS, OWASP)."""
    from numasec.state import Finding
    from numasec.standards import enrich_finding

    # Create a proper Finding model for validation + enrichment
    try:
        finding = Finding(
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
        )
        enrich_finding(finding)
    except Exception:
        # Fallback: format without enrichment
        finding = None

    # Build enrichment section if available
    standards_lines = ""
    if finding:
        parts = []
        if finding.cwe_id:
            parts.append(f"**CWE:** {finding.cwe_id}")
        if finding.cvss_score is not None:
            parts.append(f"**CVSS:** {finding.cvss_score}")
        if finding.owasp_category:
            parts.append(f"**OWASP:** {finding.owasp_category}")
        if parts:
            standards_lines = " | ".join(parts) + "\n\n"
        # Use validated severity from Finding model
        severity = finding.severity

    return (
        f"{SEVERITY_ICONS.get(severity, '⚪')} **{severity.upper()}: {title}**\n\n"
        f"{standards_lines}"
        f"{description}\n\n"
        f"{'**Evidence:** `' + evidence[:300] + '`' if evidence else ''}\n\n"
        f"*Finding registered.*"
    )
