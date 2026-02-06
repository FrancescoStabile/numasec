"""
NumaSec v3 — CLI

The Vibe Security Experience.
Continuous scroll, real-time streaming, hacker aesthetics.

Architecture:
  - StreamRenderer for all display (no Live, no Panel, no Tree)
  - Agent events → renderer methods (stream_text, tool_start, etc.)
  - Everything scrolls down naturally like Claude Code
  - ANSI direct writes for zero-latency text streaming
"""

import asyncio
import logging
import os
import re
import time
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.key_binding import KeyBindings
from rich.console import Console
from rich.text import Text


try:
    from numasec.theme import (
        CYBERPUNK_THEME,
        MATRIX_GREEN,
        CYBER_PURPLE,
        ELECTRIC_CYAN,
        DIM_GRAY,
        GHOST_GRAY,
        HACK_RED,
        NEON_GREEN,
        GOLD,
    )
except ImportError:
    CYBERPUNK_THEME = None
    MATRIX_GREEN = "green"
    CYBER_PURPLE = "magenta"
    ELECTRIC_CYAN = "cyan"
    DIM_GRAY = "dim"
    GHOST_GRAY = "bright_black"
    HACK_RED = "red"
    NEON_GREEN = "green"
    GOLD = "yellow"

from numasec.agent import Agent
from numasec.renderer import StreamRenderer

from numasec.session import SessionManager
from numasec.cost_tracker import CostTracker
from numasec.config import ensure_config, Config

logger = logging.getLogger("numasec.cli")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════


class NumaSecCLI:
    """
    NumaSec CLI — continuous scroll, real-time streaming.

    No TUI, no fixed views, no boxes.
    Everything flows down like a hacker's terminal.
    """

    def __init__(self, resume_session_id: str = None, show_browser: bool = False):
        if show_browser:
            os.environ["NUMASEC_SHOW_BROWSER"] = "1"

        self.console = Console(theme=CYBERPUNK_THEME if CYBERPUNK_THEME else None)
        self.agent: Agent | None = None
        self.session: PromptSession | None = None
        self.config: Config | None = None

        # Session persistence
        self.session_manager = SessionManager()
        self.current_session_id = None
        self.resume_id = resume_session_id

        # Cost tracking
        self.cost_tracker = CostTracker(budget_limit=10.0)

        # Target tracking
        self.current_target = None

    # ──────────────────────────────────────────────────────────
    # Main loop
    # ──────────────────────────────────────────────────────────

    async def run(self):
        """Main CLI loop."""
        # Load config
        self.config = ensure_config()

        if not self.config.has_api_key():
            self.console.print(f"[{HACK_RED}]No API keys configured. Run setup again or edit ~/.numasec/config.yaml[/]")
            return

        # Set API keys in environment
        for key, value in self.config.get_api_keys().items():
            os.environ[key] = value

        # Resume session if requested
        if self.resume_id:
            session_data = self.session_manager.resume_session(self.resume_id)
            if session_data:
                self.current_session_id = self.resume_id
                self.console.print(f"[{MATRIX_GREEN}]Resumed session {self.resume_id[:8]}...[/]")
                self.console.print(f"[{GHOST_GRAY}]Target: {session_data.target}[/]")
                self.console.print(f"[{GHOST_GRAY}]Findings: {len(session_data.findings)} | Messages: {len(session_data.messages)}[/]\n")
            else:
                self.console.print(f"[{HACK_RED}]Session {self.resume_id} not found[/]")
                return

        # Create agent
        try:
            self.agent = Agent()
        except Exception as e:
            self.console.print(f"[{HACK_RED}]Failed to initialize agent: {e}[/]")
            return

        # Banner
        self._print_banner()

        # Input session
        kb = self._create_keybindings()
        self.session = PromptSession(key_bindings=kb)

        # Main loop
        while True:
            try:
                # Prompt with optional cost display
                cost_suffix = ""
                total_cost = self.cost_tracker.get_total_cost()
                if total_cost > 0:
                    pct = self.cost_tracker.get_budget_percentage()
                    color = "ansired" if pct > 75 else "ansibrightyellow" if pct > 50 else "ansibrightblack"
                    cost_suffix = f" <{color}>${total_cost:.3f}</{color}>"

                user_input = await self.session.prompt_async(
                    HTML(f"<ansibrightgreen>\u03bb</ansibrightgreen>{cost_suffix} ")
                )

                if not user_input.strip():
                    continue

                # Commands
                if user_input.startswith("/"):
                    await self._handle_command(user_input)
                    continue

                # Create session on first message
                if not self.current_session_id:
                    target = user_input[:50] if len(user_input) <= 50 else user_input[:47] + "..."
                    session = self.session_manager.create_session(target=target)
                    self.current_session_id = session.id
                    self.console.print(f"[{GHOST_GRAY}]Session: {self.current_session_id[:8]}...[/]")
                    self.current_target = self._extract_target(user_input)

                # Run agent
                await self._run_agent(user_input)

            except (KeyboardInterrupt, asyncio.CancelledError):
                if self.agent and self.agent.is_running:
                    self.console.print(f"\n[{CYBER_PURPLE}]Agent paused[/]")
                    self.agent.pause()
                    if self.current_session_id:
                        self.session_manager.mark_paused()
                else:
                    self.console.print(f"\n[{GHOST_GRAY}]Use /quit to exit[/]")
            except EOFError:
                break

        self.console.print(f"\n[{GHOST_GRAY}]Disconnected. Stay safe.[/]")
        if self.agent:
            await self.agent.close()

    # ──────────────────────────────────────────────────────────
    # Agent execution — the core
    # ──────────────────────────────────────────────────────────

    async def _run_agent(self, user_input: str):
        """
        Run agent with real-time streaming output.

        Uses StreamRenderer for continuous scroll display.
        No Live(), no fixed views — everything flows down.

        Ctrl+C during execution pauses the agent and returns to
        the prompt so the user can inspect findings or export a
        report.  The key mechanism: asyncio delivers SIGINT as
        CancelledError (not KeyboardInterrupt) inside a running
        coroutine, so we catch both.
        """
        renderer = StreamRenderer(self.console)
        current_args = {}
        assessment_start = time.monotonic()
        interrupted = False
        tool_call_number = 0
        target_banner_shown = False

        try:
            async for event in self.agent.run(user_input):
                if event.type == "text":
                    renderer.stream_text(event.content)

                elif event.type == "tool_start":
                    # Show target acquired banner before first tool call
                    if not target_banner_shown:
                        target_display = self.current_target or self._extract_target(user_input)
                        if target_display:
                            renderer.target_acquired(target_display)
                        target_banner_shown = True

                    tool_call_number += 1
                    current_args = event.data.get("arguments", {})
                    renderer.tool_start(event.tool_name, current_args, tool_number=tool_call_number)
                    self.cost_tracker.add_tool_call()

                elif event.type == "tool_end":
                    renderer.tool_result(event.tool_name, event.tool_result, current_args)
                    current_args = {}

                elif event.type == "finding":
                    renderer.finding(event.finding)
                    # Auto-save session
                    self._save_current_state()

                elif event.type == "usage":
                    input_tok = event.data.get("input_tokens", 0)
                    output_tok = event.data.get("output_tokens", 0)
                    cache_read = event.data.get("cache_read_tokens", 0)
                    renderer.usage(input_tok, output_tok, cache_read)
                    # Track costs
                    provider = "deepseek"
                    if hasattr(self.agent, 'router') and hasattr(self.agent.router, 'current_provider'):
                        provider = self.agent.router.current_provider.value
                    self.cost_tracker.add_tokens(provider, input_tok, output_tok)

                elif event.type == "error":
                    renderer.error(event.data.get("message", "Unknown error"))
                    break

                elif event.type == "plan_generated":
                    plan_text = event.data.get("plan", "")
                    if plan_text:
                        self.console.print(f"\n  [{CYBER_PURPLE}]◆ ATTACK PLAN[/]")
                        for raw_line in plan_text.split("\n"):
                            line = raw_line.strip()
                            if not line:
                                continue
                            # Strip markdown artifacts
                            line = line.lstrip("# ").strip()
                            line = line.replace("**", "")
                            # Render checkboxes as icons
                            if line.startswith("[ ] "):
                                self.console.print(f"    [{ELECTRIC_CYAN}]○ {line[4:]}[/]")
                            elif line.startswith("[x] ") or line.startswith("[X] "):
                                self.console.print(f"    [{MATRIX_GREEN}]✓ {line[4:]}[/]")
                            elif line.lower().startswith("objective:"):
                                self.console.print(f"        [{GHOST_GRAY}]{line}[/]")
                            elif "attack plan" in line.lower():
                                self.console.print(f"    [{GHOST_GRAY}]{line}[/]")
                            else:
                                self.console.print(f"    [{GHOST_GRAY}]{line}[/]")
                        self.console.print()

                elif event.type == "phase_complete":
                    phase_name = event.data.get("phase_name", "")
                    next_phase = event.data.get("next_phase", "")
                    renderer.phase_transition(phase_name, next_phase)

                elif event.type == "reflection":
                    # Recovery guidance is injected into the agent context.
                    # Don't dump it to the user — it's noise.
                    pass

                elif event.type == "done":
                    break

        except (KeyboardInterrupt, asyncio.CancelledError):
            interrupted = True
            if self.agent:
                self.agent.pause()
            self.console.print(f"\n\n  [{CYBER_PURPLE}]Agent paused[/]")

        renderer.end_stream()

        if interrupted:
            # ── Interrupted: save progress and hint at report ──
            self._save_current_state()
            findings = self.agent.state.findings if self.agent else []
            if findings:
                self.console.print(
                    f"  [{MATRIX_GREEN}]{len(findings)} finding(s) collected[/]"
                )
            self.console.print(
                f"  [{GHOST_GRAY}]Use /report, /findings or /export to see results[/]\n"
            )
        else:
            # ── Normal completion: assessment card ──
            self._save_current_state()
            total = self.cost_tracker.get_total_cost()
            duration = time.monotonic() - assessment_start
            findings = self.agent.state.findings if self.agent else []

            if findings:
                target_display = self.current_target or "unknown"
                renderer.assessment_complete(
                    target=target_display,
                    duration_s=duration,
                    cost=total,
                    findings=findings,
                    tools_used=self.cost_tracker.tool_calls,
                )
            elif total > 0.01:
                # No findings but cost incurred — show cost summary
                self.console.print()
                summary = self.cost_tracker.format_summary()
                self.console.print(f"[{GHOST_GRAY}]{summary}[/]")

        # Iteration divider
        renderer.divider()

    # ──────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────

    def _extract_target(self, user_input: str) -> str:
        """Extract target (URL, IP, hostname) from user input."""
        url_match = re.search(
            r'https?://[^\s]+|[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?',
            user_input
        )
        if url_match:
            return url_match.group().rstrip(".,;:)")

        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', user_input)
        if ip_match:
            return ip_match.group()

        local_match = re.search(r'\blocalhost(?::\d+)?\b', user_input)
        if local_match:
            return local_match.group()

        return user_input[:30] + "..." if len(user_input) > 30 else user_input

    def _create_keybindings(self) -> KeyBindings:
        """Keyboard shortcuts."""
        kb = KeyBindings()

        @kb.add("c-c")
        def _(event):
            if self.agent and self.agent.is_running:
                self.console.print(f"\n[{CYBER_PURPLE}]Pausing agent...[/]")
                self.agent.pause()
                if self.current_session_id:
                    self.session_manager.mark_paused()
            else:
                self.console.print(f"\n[{GHOST_GRAY}]Use /quit to exit[/]")

        @kb.add("c-d")
        def _(event):
            self.console.print(f"\n[{GHOST_GRAY}]Ciao![/]")
            if self.current_session_id:
                self.session_manager.mark_complete()
            raise EOFError

        @kb.add("c-l")
        def _(event):
            self.console.clear()

        return kb

    # ──────────────────────────────────────────────────────────
    # Commands
    # ──────────────────────────────────────────────────────────

    async def _handle_command(self, command: str):
        """Handle slash commands."""
        cmd = command.lower().strip()
        parts = cmd.split()
        base = parts[0] if parts else cmd

        if base == "/help":
            self._print_help()

        elif base == "/demo":
            from numasec.demo import run_demo
            await run_demo(self.console)

        elif base == "/clear":
            self.console.clear()
            if self.agent:
                self.agent.reset()
            self.console.print(f"[{MATRIX_GREEN}]Session cleared[/]")

        elif base == "/findings":
            if not self.agent or not self.agent.state.findings:
                self.console.print(f"[{GHOST_GRAY}]No findings yet[/]")
            else:
                findings = self.agent.state.findings
                # Header
                self.console.print()
                hdr = Text()
                hdr.append("  Security Findings", style=f"bold {MATRIX_GREEN}")
                hdr.append(f"  ({len(findings)})", style=GHOST_GRAY)
                self.console.print(hdr)
                # Individual findings
                renderer = StreamRenderer(self.console)
                for f in findings:
                    renderer.finding(f)
                # Severity summary
                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                for f in findings:
                    sev = f.severity if hasattr(f, "severity") else "info"
                    if sev in counts:
                        counts[sev] += 1
                parts = []
                if counts["critical"]:
                    parts.append(f"[{HACK_RED}]{counts['critical']} critical[/]")
                if counts["high"]:
                    parts.append(f"[{HACK_RED}]{counts['high']} high[/]")
                if counts["medium"]:
                    parts.append(f"[{GOLD}]{counts['medium']} medium[/]")
                if counts["low"]:
                    parts.append(f"[{ELECTRIC_CYAN}]{counts['low']} low[/]")
                if counts["info"]:
                    parts.append(f"[{MATRIX_GREEN}]{counts['info']} info[/]")
                self.console.print(f"  [{GHOST_GRAY}]{' / '.join(parts)}[/]")
                self.console.print()

        elif base == "/report":
            fmt = parts[1] if len(parts) > 1 else "html"
            await self._generate_report(fmt)

        elif base == "/export":
            fmt = parts[1] if len(parts) > 1 else "md"
            await self._generate_report(fmt)

        elif base == "/plan":
            self._print_plan()

        elif base == "/stats":
            self._print_stats()

        elif base == "/cost":
            self._print_cost()

        elif base == "/history":
            self._print_history()

        elif base == "/resume":
            if len(parts) < 2:
                self.console.print(f"[{HACK_RED}]Usage: /resume <session_id>[/]")
            else:
                sid = parts[1]
                session_data = self.session_manager.resume_session(sid)
                if session_data:
                    self.current_session_id = sid
                    self.console.print(f"[{MATRIX_GREEN}]Resumed session {sid[:8]}...[/]")
                else:
                    self.console.print(f"[{HACK_RED}]Session not found: {sid}[/]")

        elif base == "/reset":
            if self.agent:
                self.agent.reset()
            self.cost_tracker.reset()
            if self.current_session_id:
                self.session_manager.mark_complete()
            self.current_session_id = None
            self.console.print(f"[{MATRIX_GREEN}]Session reset[/]")

        elif cmd in ("/quit", "/exit", "/q"):
            if self.current_session_id:
                self.session_manager.mark_complete()
            raise EOFError

        else:
            self.console.print(f"[{HACK_RED}]Unknown command: {command}[/]")
            self.console.print(f"[{GHOST_GRAY}]Type /help for commands[/]")

    # ──────────────────────────────────────────────────────────
    # Display methods — clean, no boxes
    # ──────────────────────────────────────────────────────────

    def _print_banner(self):
        """Print startup banner — ASCII art + status, no panels."""
        from numasec.theme import CyberpunkAssets

        self.console.clear()

        # ASCII art
        self.console.print(CyberpunkAssets.MATRIX_BANNER)

        # System status — clean lines, no panel
        tools_count = len(self.agent.tools.tools) if self.agent else "?"

        # Detect active provider
        provider_name = "DeepSeek/Claude/OpenAI"
        if self.agent and hasattr(self.agent, 'router'):
            try:
                p = self.agent.router.primary.value
                provider_name = p[0].upper() + p[1:] if p else provider_name
            except Exception:
                pass

        self.console.print(f"  [{MATRIX_GREEN}]● SYSTEM READY[/]")
        self.console.print(f"  [{GHOST_GRAY}]● LLM: {provider_name}[/]")
        self.console.print(f"  [{GHOST_GRAY}]● Tools: {tools_count} integrated[/]")
        self.console.print(f"  [{CYBER_PURPLE}]● Mode: AUTONOMOUS PENTESTING[/]")
        if os.environ.get("NUMASEC_SHOW_BROWSER"):
            self.console.print(f"  [{ELECTRIC_CYAN}]● Browser: VISIBLE MODE[/]")
        self.console.print()
        self.console.print(f"  [{GHOST_GRAY}]Describe your target or type /help[/]")
        self.console.print()

    def _print_help(self):
        """Print help — clean text, no panels."""
        self.console.print()
        self.console.print(f"  [{ELECTRIC_CYAN}]commands[/]")
        self.console.print()

        cmds = [
            ("/clear",        "clear session and reset"),
            ("/findings",     "show all findings"),
            ("/plan",         "show current attack plan"),
            ("/report [fmt]", "generate full report (html|md|json)"),
            ("/export [fmt]", "export report (md|json|html)"),
            ("/stats",        "session statistics"),
            ("/cost",         "cost breakdown"),
            ("/history",      "recent sessions"),
            ("/resume <id>",  "resume a session"),
            ("/demo",         "run mocked demo assessment"),
            ("/reset",        "reset session and cost tracker"),
            ("/quit",         "exit"),
        ]

        for cmd_name, desc in cmds:
            c = Text()
            c.append(f"  {cmd_name:<16}", style=MATRIX_GREEN)
            c.append(desc, style=GHOST_GRAY)
            self.console.print(c)

        self.console.print()
        shortcuts = Text()
        shortcuts.append("  ", style="")
        shortcuts.append("ctrl-c", style=DIM_GRAY)
        shortcuts.append(" pause  ", style=GHOST_GRAY)
        shortcuts.append("ctrl-d", style=DIM_GRAY)
        shortcuts.append(" exit  ", style=GHOST_GRAY)
        shortcuts.append("ctrl-l", style=DIM_GRAY)
        shortcuts.append(" clear", style=GHOST_GRAY)
        self.console.print(shortcuts)
        self.console.print()

    def _print_cost(self):
        """Print cost breakdown — clean lines."""
        self.console.print()

        for provider, tokens in self.cost_tracker.tokens_by_provider.items():
            cost = self.cost_tracker.get_provider_cost(provider)
            if cost > 0:
                line = Text()
                line.append(f"  {provider:<12}", style=ELECTRIC_CYAN)
                line.append(f"${cost:.4f}", style=MATRIX_GREEN)
                line.append(f"  ({tokens['input']:,} in / {tokens['output']:,} out)", style=GHOST_GRAY)
                self.console.print(line)

        total_cost = self.cost_tracker.get_total_cost()
        total_in, total_out = self.cost_tracker.get_total_tokens()

        self.console.print()
        total_line = Text()
        total_line.append("  total       ", style=GHOST_GRAY)
        total_line.append(f"${total_cost:.4f}", style=f"bold {MATRIX_GREEN}")
        total_line.append(f"  ({total_in + total_out:,} tokens, {self.cost_tracker.tool_calls} tool calls)", style=GHOST_GRAY)
        self.console.print(total_line)

        pct = self.cost_tracker.get_budget_percentage()
        if self.cost_tracker.is_over_budget():
            self.console.print(f"  [{HACK_RED}]over budget (${total_cost:.3f} / ${self.cost_tracker.budget_limit:.2f})[/]")
        elif pct > 75:
            self.console.print(f"  [{GOLD}]{pct:.0f}% of budget used[/]")

        self.console.print()

    def _print_history(self):
        """Print session history — clean lines."""
        sessions = self.session_manager.list_sessions(limit=10)

        if not sessions:
            self.console.print(f"  [{GHOST_GRAY}]No sessions found[/]")
            return

        self.console.print()
        for s in sessions:
            status_icon = {"active": "\u25cf", "paused": "\u25c9", "complete": "\u25cb"}.get(s.status, "\u00b7")
            color = {"active": MATRIX_GREEN, "paused": GOLD, "complete": GHOST_GRAY}.get(s.status, GHOST_GRAY)

            line = Text()
            line.append(f"  {status_icon} ", style=color)
            line.append(f"{s.id[:8]}", style=ELECTRIC_CYAN)
            target_display = s.target[:35] if len(s.target) <= 35 else s.target[:32] + "..."
            line.append(f"  {target_display:<35}", style=GHOST_GRAY)
            line.append(f"  {len(s.findings)} findings", style=MATRIX_GREEN if s.findings else GHOST_GRAY)
            if s.cost > 0:
                line.append(f"  ${s.cost:.3f}", style=GHOST_GRAY)
            self.console.print(line)

        self.console.print()
        self.console.print(f"  [{GHOST_GRAY}]Use /resume <id> to continue a session[/]")
        self.console.print()

    def _print_plan(self):
        """Print current attack plan — clean lines."""
        if not self.agent or not self.agent.state.plan or not self.agent.state.plan.objective:
            self.console.print(f"  [{GHOST_GRAY}]No attack plan yet. Start a scan first.[/]")
            return

        plan = self.agent.state.plan
        self.console.print()
        self.console.print(f"  [{ELECTRIC_CYAN}]Attack Plan: {plan.objective}[/]")
        self.console.print()

        for phase in plan.phases:
            status_icon = {
                "pending": "○",
                "active": "●",
                "complete": "✓",
                "skipped": "⊘",
            }.get(phase.status.value, "·")
            color = {
                "pending": GHOST_GRAY,
                "active": MATRIX_GREEN,
                "complete": ELECTRIC_CYAN,
                "skipped": DIM_GRAY,
            }.get(phase.status.value, GHOST_GRAY)

            self.console.print(f"  [{color}]{status_icon} {phase.name}[/]")
            for step in phase.steps:
                step_icon = "✓" if step.status.value in ("complete", "skipped") else "·"
                step_color = MATRIX_GREEN if step.status.value == "complete" else GHOST_GRAY
                self.console.print(f"    [{step_color}]{step_icon} {step.tool_hint or 'manual'}: {step.description}[/]")

        self.console.print()

    def _print_stats(self):
        """Print session stats — clean lines."""
        if not self.agent:
            return

        state = self.agent.state
        self.console.print()
        self.console.print(f"  [{GHOST_GRAY}]iterations[/]  [{MATRIX_GREEN}]{state.iteration}[/]")
        self.console.print(
            f"  [{GHOST_GRAY}]findings[/]    [{MATRIX_GREEN}]{len(state.findings)}[/]"
            f"  [{GHOST_GRAY}](critical: {state.critical_count}, high: {state.high_count})[/]"
        )
        self.console.print(f"  [{GHOST_GRAY}]messages[/]    [{MATRIX_GREEN}]{len(state.messages)}[/]")
        self.console.print()

    def _save_current_state(self):
        """Persist current agent state to the session file."""
        if not self.current_session_id or not self.agent:
            return
        try:
            cost = self.cost_tracker.get_total_cost()
            tokens_in, tokens_out = self.cost_tracker.get_total_tokens()
            self.session_manager.save_state(
                self.agent.state, cost, tokens_in, tokens_out
            )
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")

    async def _generate_report(self, format: str = "html"):
        """Generate professional pentest report from current agent state."""
        if not self.agent:
            self.console.print(f"[{GHOST_GRAY}]No active session[/]")
            return

        # Generate report even without findings — profile/plan data is valuable
        state = self.agent.state
        has_data = (
            state.findings
            or state.profile.ports
            or state.profile.endpoints
            or state.profile.technologies
            or (state.plan and state.plan.objective)
        )
        if not has_data:
            self.console.print(f"[{GHOST_GRAY}]No data to report yet — run a scan first[/]")
            return

        from numasec.report import write_report

        output_dir = Path("~/.numasec/reports").expanduser()
        target = self.current_target or "unknown"
        session_id = self.current_session_id or ""
        cost = self.cost_tracker.get_total_cost()

        try:
            filepath = write_report(
                self.agent.state,
                output_dir,
                format=format,
                target=target,
                session_id=session_id,
                cost=cost,
            )
            self.console.print(f"\n  [{MATRIX_GREEN}]Report saved: {filepath}[/]")
            self.console.print(f"  [{GHOST_GRAY}]Format: {format.upper()}[/]\n")
        except Exception as e:
            logger.error(f"Report generation failed: {e}", exc_info=True)
            self.console.print(f"[{HACK_RED}]Report failed: {e}[/]")

    def _load_env(self):
        """Load .env file if exists."""
        check = Path.cwd()
        for _ in range(5):
            env_file = check / ".env"
            if env_file.exists():
                for line in env_file.read_text().splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, _, v = line.partition("=")
                        os.environ.setdefault(k.strip(), v.strip())
                return
            check = check.parent

    def _check_api_keys(self) -> bool:
        """Check if at least one API key is available."""
        return any([
            os.environ.get("DEEPSEEK_API_KEY"),
            os.environ.get("ANTHROPIC_API_KEY"),
            os.environ.get("OPENAI_API_KEY"),
        ])
