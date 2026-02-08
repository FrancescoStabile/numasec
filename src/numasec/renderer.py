"""
NumaSec Stream Renderer
=======================

Continuous scroll renderer inspired by Claude Code CLI.
Hacker aesthetics, real-time streaming, zero-latency.

Architecture:
  - Agent text → ANSI direct writes (bypasses Rich for speed)
  - Tool calls → Rich console.print with clean formatting
  - Findings → severity-colored flowing sections
  - Everything scrolls down naturally. No Live(), no Panel(), no Tree().

Design principles:
  1. Continuous scroll only — never lock the viewport
  2. Stream text character-by-character via raw ANSI
  3. Format tool output intelligently (no raw JSON dumps)
  4. Minimal chrome — no boxes, no borders on regular content
  5. Matrix/hacker aesthetic through color, not decoration
"""

import json
import re
import sys
import time
import asyncio
import threading

from rich.console import Console
from rich.text import Text


# ═══════════════════════════════════════════════════════════════════════════
# ANSI Direct Output
# ═══════════════════════════════════════════════════════════════════════════
# Bypasses Rich for zero-latency character streaming.
# Uses 24-bit color matching the theme palette exactly.

class _ANSI:
    """ANSI escape sequences for direct terminal output."""
    # Colors (24-bit, matches theme.py palette)
    GREEN       = "\033[38;2;0;255;65m"
    BRIGHT_GREEN= "\033[38;2;0;255;65m"   # Same as GREEN — unified
    CYAN        = "\033[38;2;125;207;255m"   # Softer sky blue
    PURPLE      = "\033[38;2;185;104;255m"
    RED         = "\033[38;2;255;85;85m"     # Warm red
    GOLD        = "\033[38;2;229;192;123m"   # Warm amber
    GRAY        = "\033[38;2;212;212;212m"   # Bright — agent text is the star
    DIM_GRAY    = "\033[38;2;110;110;110m"   # Subtle secondary
    # Modifiers
    BOLD        = "\033[1m"
    DIM         = "\033[2m"
    ITALIC      = "\033[3m"
    RESET       = "\033[0m"

ANSI = _ANSI()

# Rich color aliases (for console.print calls)
# 3-tier visual hierarchy: content (_TEXT) > labels (_DIM) > structure (_BORDER)
_GREEN   = "#00ff41"
_CYAN    = "#7dcfff"    # Softer sky blue — readable, not blinding
_PURPLE  = "#b968ff"
_RED     = "#ff5555"    # Warm red — critical findings, errors
_GOLD    = "#e5c07b"    # Warm amber — medium findings, warnings
_TEXT    = "#d4d4d4"    # Bright content — the star of every line
_DIM     = "#6e6e6e"    # Labels, counters, secondary info
_BORDER  = "#444444"    # Structural chrome — pipes, dashes, connectors
_GRAY    = "#555555"    # Fallback, unknown severity


# ═══════════════════════════════════════════════════════════════════════════
# Matrix Spinner — Shows during LLM thinking
# ═══════════════════════════════════════════════════════════════════════════


class MatrixSpinner:
    """
    Non-blocking matrix-style spinner for LLM thinking periods.
    
    Uses ANSI direct writes (no Rich) for zero-flicker updates.
    Automatically disappears when text arrives.
    Thread-based so it doesn't block the async event loop.
    """
    
    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    _GLITCH = ["░", "▒", "▓", "█", "▓", "▒"]
    
    def __init__(self, out=None):
        self._out = out or sys.stdout
        self._running = False
        self._thread: threading.Thread | None = None
        self._frame = 0
    
    def start(self, label: str = "thinking"):
        """Start the spinner in a background thread."""
        if self._running:
            return
        self._running = True
        self._frame = 0
        self._label = label
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop the spinner and clear the line."""
        if not self._running:
            return
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.2)
            self._thread = None
        # Clear the spinner line
        self._out.write(f"\r\033[2K")
        self._out.flush()
    
    def _spin(self):
        """Background spin loop."""
        while self._running:
            frame = self._FRAMES[self._frame % len(self._FRAMES)]
            glitch = self._GLITCH[self._frame % len(self._GLITCH)]
            self._out.write(
                f"\r  {ANSI.GREEN}{glitch} {frame} {self._label}{ANSI.RESET}\033[K"
            )
            self._out.flush()
            self._frame += 1
            time.sleep(0.08)


def matrix_rain(console: Console, duration: float = 1.2, width: int = 60):
    """
    Brief matrix rain effect for startup. Pure ANSI, <2 seconds.
    
    Creates falling green characters that resolve into the brand.
    """
    import random
    out = console.file or sys.stdout
    chars = "0123456789abcdef#@$!>|{}[]<>=+-~:.%&*^"
    rows = 8
    
    # Build the rain
    grid = [[" "] * width for _ in range(rows)]
    drops = [random.randint(-rows, 0) for _ in range(width)]
    
    frames = int(duration / 0.06)
    for frame_idx in range(frames):
        # Update drops
        for col in range(width):
            drops[col] += 1
            if drops[col] >= 0 and drops[col] < rows:
                grid[drops[col]][col] = random.choice(chars)
            # Fade old chars
            if drops[col] - 3 >= 0 and drops[col] - 3 < rows:
                grid[drops[col] - 3][col] = " "
            # Reset drops that fell off
            if drops[col] > rows + 3:
                drops[col] = random.randint(-4, -1)
        
        # Render
        out.write(f"\033[{rows}A" if frame_idx > 0 else "")
        for row in range(rows):
            line = ""
            for col in range(width):
                c = grid[row][col]
                if c != " ":
                    # Bold at drop head for visual depth
                    if any(drops[col] == row + offset for offset in range(2)):
                        line += f"\033[1m{ANSI.GREEN}{c}\033[22m"
                    else:
                        line += f"{ANSI.GREEN}{c}"
                else:
                    line += " "
            out.write(f"  {line}{ANSI.RESET}\n")
        out.flush()
        time.sleep(0.06)
    
    # Clear rain area
    out.write(f"\033[{rows}A")
    for _ in range(rows):
        out.write(f"\033[2K\n")
    out.write(f"\033[{rows}A")
    out.flush()


def startup_animation(console: Console, provider: str = "AI",
                      tools_count: int = 19, knowledge_count: int = 46):
    """
    Dramatic startup sequence — animated system initialization.
    
    Each check appears with a brief spinner then resolves to ✓.
    Creates the feeling of a powerful system booting up.
    """
    out = console.file or sys.stdout
    
    checks = [
        (f"AI engine ready ({provider})", 0.3),
        (f"{tools_count} security tools loaded", 0.25),
        (f"{knowledge_count} knowledge modules active", 0.2),
        ("Browser automation ready", 0.15),
    ]
    
    spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    console.print()
    console.print(f"  [{_DIM}]Initializing...[/]")
    console.print()
    
    for label, duration in checks:
        # Spinner phase
        frames = int(duration / 0.06)
        for i in range(frames):
            frame = spinner_frames[i % len(spinner_frames)]
            out.write(f"\r  {ANSI.DIM_GRAY}{frame} {label}{ANSI.RESET}\033[K")
            out.flush()
            time.sleep(0.06)
        # Resolve to checkmark
        out.write(f"\r  {ANSI.GREEN}✓ {label}{ANSI.RESET}\033[K\n")
        out.flush()
    
    console.print()
    ready = Text()
    ready.append("  ◉ ", style=f"bold {_GREEN}")
    ready.append("READY", style=f"bold {_GREEN}")
    ready.append(" — Paste a URL or describe your target.", style=_DIM)
    console.print(ready)
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
# Stream Renderer
# ═══════════════════════════════════════════════════════════════════════════


class StreamRenderer:
    """
    Continuous scroll renderer for NumaSec.

    Text streams in real-time via direct ANSI writes.
    Tools and findings use Rich for clean formatting.
    No Live(), no Panel(), no fixed views — everything scrolls.
    """

    def __init__(self, console: Console):
        self.console = console
        self._out = console.file or sys.stdout
        # Streaming state
        self._streaming = False
        self._in_tag = False
        self._tag_buffer = ""
        self._needs_newline = False
        self._suppressing = False  # True while inside <thinking>...</thinking>
        # Matrix spinner
        self._spinner = MatrixSpinner(self._out)

    # ──────────────────────────────────────────────────────────
    # Spinner control
    # ──────────────────────────────────────────────────────────

    def spinner_start(self, label: str = "thinking"):
        """Show matrix spinner during LLM waits."""
        self._spinner.start(label)
    
    def spinner_stop(self):
        """Stop the spinner (called automatically when text arrives)."""
        self._spinner.stop()

    # ──────────────────────────────────────────────────────────
    # Agent text streaming
    # ──────────────────────────────────────────────────────────

    def start_stream(self):
        """Begin a new text streaming section."""
        self._streaming = True
        self._out.write(f"\n  {ANSI.GRAY}")
        self._out.flush()

    def stream_text(self, chunk: str):
        """
        Stream agent text in real-time.

        Strips <thinking> tags and markdown formatting artifacts.
        Writes directly to stdout for zero-latency display.
        """
        if not self._streaming:
            self.start_stream()

        cleaned = self._clean_stream(chunk)
        if cleaned:
            # Maintain left gutter: indent after every explicit newline
            indented = cleaned.replace("\n", "\n  ")
            self._out.write(indented)
            self._out.flush()
            self._needs_newline = not cleaned.endswith("\n")

    def end_stream(self):
        """End text streaming, reset ANSI state."""
        if self._streaming:
            self._out.write(ANSI.RESET)
            if self._needs_newline:
                self._out.write("\n")
            self._out.flush()
            self._streaming = False
            self._needs_newline = False
            # Flush any partial tag buffer as-is
            if self._tag_buffer:
                self._tag_buffer = ""
            self._in_tag = False

    def _clean_stream(self, chunk: str) -> str:
        """
        Clean streaming text: strip thinking tags, markdown artifacts.
        Uses a state machine to handle tags spanning multiple chunks.
        """
        _SUPPRESSED_TAGS = ("thinking", "thought", "reflection", "antthinking")
        result = []

        for char in chunk:
            if self._in_tag:
                self._tag_buffer += char
                if char == ">":
                    self._in_tag = False
                    tag_lower = self._tag_buffer.lower()
                    # Check if this is a suppressed tag (thinking, etc.)
                    is_suppressed = any(t in tag_lower for t in _SUPPRESSED_TAGS)
                    if is_suppressed:
                        # Opening tag → start suppressing content
                        if not tag_lower.startswith("</"):
                            self._suppressing = True
                        else:
                            # Closing tag → stop suppressing
                            self._suppressing = False
                        self._tag_buffer = ""
                        continue
                    # Not a tag we strip — output it (if not suppressed)
                    if not self._suppressing:
                        result.append(self._tag_buffer)
                    self._tag_buffer = ""
                elif len(self._tag_buffer) > 60:
                    # Too long to be a real tag — flush
                    self._in_tag = False
                    if not self._suppressing:
                        result.append(self._tag_buffer)
                    self._tag_buffer = ""
            elif char == "<":
                self._in_tag = True
                self._tag_buffer = char
            else:
                if not self._suppressing:
                    result.append(char)

        text = "".join(result)

        # Strip markdown bold/italic artifacts
        text = text.replace("**", "")
        text = text.replace("__", "")

        return text

    # ──────────────────────────────────────────────────────────
    # Tool display
    # ──────────────────────────────────────────────────────────

    # ──────────────────────────────────────────────────────────
    # Target acquired & phase transitions
    # ──────────────────────────────────────────────────────────

    def target_acquired(self, target: str):
        """Print target lock-on banner — dramatic opening of every assessment."""
        self.end_stream()
        tw = max((self.console.width or 80) - 6, 50)

        # Animated lock-on effect via ANSI direct writes
        lock_frames = ["◎", "◉", "●", "◉", "◎", "◉", "●"]
        for i, frame in enumerate(lock_frames):
            self._out.write(f"\r  {ANSI.GREEN}{frame} TARGET LOCK{ANSI.RESET}\033[K")
            self._out.flush()
            time.sleep(0.06)
        self._out.write("\r\033[2K")  # clear the animation line
        self._out.flush()

        self.console.print()

        border = "─" * tw
        self.console.print(f"  [{_GREEN}]┌{border}┐[/]")
        
        title_str = "◉ TARGET ACQUIRED"
        title_pad = " " * (tw - len(title_str) - 1)
        self.console.print(f"  [{_GREEN}]│[/] [bold {_GREEN}]{title_str}{title_pad}[/][{_GREEN}]│[/]")

        tgt = target[:tw - 3] if len(target) <= tw - 3 else target[:tw - 6] + "..."
        url_pad = " " * (tw - len(tgt) - 1)
        self.console.print(f"  [{_GREEN}]│[/] [bold {_GREEN}]{tgt}{url_pad}[/][{_GREEN}]│[/]")

        self.console.print(f"  [{_GREEN}]└{border}┘[/]")
        self.console.print()

    def phase_transition(self, completed_phase: str, next_phase: str = "",
                         phase_num: int = 0, total_phases: int = 0):
        """Print cinematic phase transition with progress — key moment in demo."""
        self.end_stream()
        tw = max((self.console.width or 80) - 4, 50)

        self.console.print()

        rule = Text()
        rule.append("  " + "━" * tw, style=f"bold {_GREEN}")
        self.console.print(rule)

        self.console.print()

        # Completed phase with checkmark
        line = Text()
        line.append("  ✓ ", style=f"bold {_GREEN}")
        line.append(completed_phase.upper(), style=f"bold {_GREEN}")
        line.append(" COMPLETE", style=f"bold {_GREEN}")
        self.console.print(line)

        # Progress bar if we have phase counts
        if total_phases > 0 and phase_num > 0:
            filled = int((phase_num / total_phases) * 20)
            empty = 20 - filled
            pbar = Text()
            pbar.append("  ", style="")
            pbar.append("▰" * filled, style=f"bold {_GREEN}")
            pbar.append("▱" * empty, style=_BORDER)
            pbar.append(f"  {phase_num}/{total_phases}", style=_DIM)
            self.console.print(pbar)

        # Next phase arrow
        if next_phase:
            self.console.print()
            nxt = Text()
            nxt.append("  →  ", style=_BORDER)
            nxt.append(next_phase.upper(), style=f"bold {_CYAN}")
            self.console.print(nxt)

        self.console.print()

        rule2 = Text()
        rule2.append("  " + "━" * tw, style=f"bold {_GREEN}")
        self.console.print(rule2)
        self.console.print()

    # ──────────────────────────────────────────────────────────
    # Tool display
    # ──────────────────────────────────────────────────────────

    def tool_start(self, name: str, args: dict, tool_number: int = 0):
        """Print tool execution header — clean single line with counter and action verb."""
        self.end_stream()

        desc = self._describe_tool(name, args)
        action = self._tool_action_verb(name)
        self._tool_start_time = time.monotonic()

        header = Text()
        header.append("\n  ── ", style=_BORDER)
        if tool_number > 0:
            header.append(f"[{tool_number}] ", style=_DIM)
        header.append(name, style=f"bold {_CYAN}")
        if action:
            header.append(f" {action}", style=_DIM)
        if desc:
            header.append(" → ", style=_BORDER)
            header.append(desc, style=_TEXT)

        self.console.print(header)

    def tool_result(self, name: str, result: str, args: dict | None = None):
        """Print formatted tool result with smart per-line coloring."""
        # Calculate elapsed time
        elapsed_str = ""
        if hasattr(self, "_tool_start_time") and self._tool_start_time:
            elapsed = time.monotonic() - self._tool_start_time
            if elapsed < 1:
                elapsed_str = f"{elapsed*1000:.0f}ms"
            else:
                elapsed_str = f"{elapsed:.1f}s"
            self._tool_start_time = None

        formatted = self._format_result(name, result, args)
        is_failure = self._is_tool_failure(result)

        lines = formatted.split("\n")
        for line in lines:
            if not line.strip():
                continue
            row = Text()
            row.append("  │ ", style=_BORDER)
            stripped = line.strip()

            if is_failure:
                # Actual tool crash/timeout — gold warning, not red
                row.append(line, style=_GOLD)
            elif stripped.isdigit() and len(stripped) <= 3:
                # HTTP status code — colored by range
                row.append(stripped, style=f"bold {self._status_style(int(stripped))}")
            elif stripped.startswith("... (") and stripped.endswith(")"):
                # Truncation indicator
                row.append(line, style=_DIM)
            elif stripped.lower().startswith("error:"):
                # Error label — gold accent, readable message
                idx = stripped.index(":") + 1
                row.append(stripped[:idx], style=_GOLD)
                row.append(stripped[idx:], style=_TEXT)
            elif ": " in stripped[:40]:
                # Header-like (key: value)
                key, _, val = stripped.partition(": ")
                row.append(key + ": ", style=_DIM)
                row.append(val, style=_TEXT)
            else:
                row.append(line, style=_TEXT)

            self.console.print(row)

        # Close bracket with elapsed time
        close = Text()
        close.append("  └─", style=_BORDER)
        if elapsed_str:
            close.append(f" {elapsed_str}", style=_DIM)
        self.console.print(close)

    # ──────────────────────────────────────────────────────────
    # Security findings
    # ──────────────────────────────────────────────────────────

    def finding(self, finding):
        """Print security finding — cinematic, screenshot-worthy, unmissable."""
        self.end_stream()

        severity_map = {
            "critical": (_RED,  "▲▲", "CRITICAL"),
            "high":     (_RED,  "▲",  "HIGH"),
            "medium":   (_GOLD, "■",  "MEDIUM"),
            "low":      (_CYAN, "●",  "LOW"),
            "info":     (_GREEN,"○",  "INFO"),
        }

        color, icon, label = severity_map.get(
            finding.severity, (_GRAY, "·", "UNKNOWN")
        )

        is_critical = finding.severity == "critical"
        is_high = finding.severity == "high"
        is_critical_or_high = is_critical or is_high
        is_medium = finding.severity == "medium"

        # Terminal bell for critical/high — audible "something happened"
        if is_critical_or_high:
            self._out.write("\a")
            self._out.flush()

        # Full-width bars for maximum visual impact
        tw = max((self.console.width or 80) - 4, 50)

        self.console.print()

        # ── TOP BAR ──
        if is_critical:
            # Solid block wall — impossible to miss in any video
            bar = Text()
            bar.append("  " + "█" * tw, style=f"bold {color}")
            self.console.print(bar)
            self.console.print()
        elif is_high:
            bar = Text()
            bar.append("  " + "━" * tw, style=f"bold {color}")
            self.console.print(bar)
            self.console.print()
        elif is_medium:
            bar = Text()
            bar.append("  " + "─" * tw, style=color)
            self.console.print(bar)

        # ── SEVERITY + TITLE ──
        h = Text()
        h.append(f"  {icon} ", style=f"bold {color}")
        h.append(label, style=f"bold {color}")
        h.append("  ", style="")
        h.append(finding.title, style=f"bold {color}")
        self.console.print(h)

        # Separator after title for critical/high
        if is_critical_or_high:
            sep = Text()
            sep.append("  " + "━" * tw, style=color)
            self.console.print(sep)

        self.console.print()

        # Get available width for text wrapping
        wrap_w = max(tw - 2, 40)

        # ── DESCRIPTION ──
        if finding.description and finding.description != finding.title:
            desc = " ".join(
                l.strip() for l in finding.description.split("\n")[:8] if l.strip()
            )
            gutter = "  │ "
            avail = wrap_w - len(gutter)
            for wl in self._textwrap(desc, avail):
                d = Text()
                d.append(gutter, style=color)
                d.append(wl, style=_TEXT)
                self.console.print(d)
            self.console.print()

        # ── EVIDENCE ── the proof
        if finding.evidence:
            ev = " ".join(
                l.strip() for l in finding.evidence.split("\n")[:8] if l.strip()
            )
            gutter      = "  │ "
            ev_label    = "Evidence:  "
            pad         = " " * len(ev_label)
            avail       = wrap_w - len(gutter) - len(ev_label)
            for i, wl in enumerate(self._textwrap(ev, avail)):
                e = Text()
                e.append(gutter, style=color)
                if i == 0:
                    e.append(ev_label, style=f"bold {color}")
                else:
                    e.append(pad, style="")
                e.append(wl, style=_TEXT)
                self.console.print(e)

        # ── PAYLOAD ── the money shot for screenshots
        payload = self._extract_payload(finding)
        if payload:
            p = Text()
            p.append("  │ ", style=color)
            p.append("Payload:   ", style=f"bold {color}")
            p.append(payload, style=f"bold {_TEXT}")
            self.console.print(p)

        # ── IMPACT ── why this matters
        if is_critical_or_high and finding.description:
            impact = self._extract_impact(finding)
            if impact:
                il = Text()
                il.append("  │ ", style=color)
                il.append("Impact:    ", style=f"bold {color}")
                il.append(impact, style=_TEXT)
                self.console.print(il)

        # ── METADATA ── CVE, CVSS
        meta = []
        if hasattr(finding, "cve") and finding.cve:
            meta.append(finding.cve)
        if hasattr(finding, "cvss_score") and finding.cvss_score:
            meta.append(f"CVSS {finding.cvss_score}")
        if meta:
            m = Text()
            m.append("  │ ", style=color)
            m.append(" │ ".join(meta), style=f"bold {_DIM}")
            self.console.print(m)

        # ── BOTTOM BAR ── matches top for visual symmetry
        if is_critical:
            self.console.print()
            bar = Text()
            bar.append("  " + "█" * tw, style=f"bold {color}")
            self.console.print(bar)
        elif is_high:
            self.console.print()
            bar = Text()
            bar.append("  " + "━" * tw, style=f"bold {color}")
            self.console.print(bar)
        elif is_medium:
            bar = Text()
            bar.append("  " + "─" * tw, style=color)
            self.console.print(bar)
        else:
            close = Text()
            close.append("  └─", style=color)
            self.console.print(close)

        self.console.print()

    # ──────────────────────────────────────────────────────────
    # Errors & status
    # ──────────────────────────────────────────────────────────

    def error(self, message: str):
        """Print error message."""
        self.end_stream()
        self.console.print()
        e = Text()
        e.append("  ✗ ", style=f"bold {_RED}")
        e.append(str(message)[:500], style=_RED)
        self.console.print(e)

    def info(self, message: str):
        """Print subtle info message."""
        self.end_stream()
        i = Text()
        i.append(f"  {message}", style=_DIM)
        self.console.print(i)

    def usage(self, input_tokens: int, output_tokens: int,
              cache_read: int = 0, **kwargs):
        """Print token usage stats on one line."""
        parts = [f"{input_tokens:,} in", f"{output_tokens:,} out"]
        if cache_read > 0 and (input_tokens + cache_read) > 0:
            pct = (cache_read / (input_tokens + cache_read)) * 100
            parts.append(f"cache {pct:.0f}%")

        u = Text()
        u.append("  tokens: ", style=_DIM)
        u.append(" │ ".join(parts), style=_DIM)
        self.console.print(u)

    # ──────────────────────────────────────────────────────────
    # Tool description generator
    # ──────────────────────────────────────────────────────────

    def _describe_tool(self, name: str, args: dict) -> str:
        """Generate human-readable one-line description."""
        try:
            if name == "http":
                method = args.get("method", "GET")
                url = args.get("url", "")
                return f"{method} {url}"
            elif name == "nmap":
                target = args.get("target", "")
                ports = args.get("ports", "")
                return f"{target}" + (f" -p {ports}" if ports else "")
            elif name == "nuclei":
                target = args.get("target", args.get("url", ""))
                templates = args.get("templates", "")
                return f"{target}" + (f" [{templates}]" if templates else "")
            elif name == "sqlmap":
                return args.get("url", "")
            elif name == "browser_navigate":
                return args.get("url", "")
            elif name == "browser_fill":
                sel = args.get("selector", "?")
                val = args.get("value", "")
                if len(val) > 50:
                    val = val[:50] + "..."
                return f'{sel} ← "{val}"'
            elif name == "browser_click":
                return args.get("selector", "?")
            elif name == "browser_screenshot":
                return "capture"
            elif name == "browser_login":
                return args.get("url", "")
            elif name in ("httpx", "httpx_probe"):
                return args.get("target", args.get("url", ""))
            elif name == "ffuf":
                url = args.get("url", "")
                return url
            elif name == "subfinder":
                return args.get("domain", "")
            else:
                for v in args.values():
                    if isinstance(v, str) and v and len(v) < 80:
                        return v
                return ""
        except Exception:
            return ""

    @staticmethod
    def _tool_action_verb(name: str) -> str:
        """Return contextual action verb for tool — shows intelligence, not just name."""
        verbs = {
            "nmap": "scanning ports",
            "nuclei": "testing vulnerabilities",
            "sqlmap": "testing SQL injection",
            "ffuf": "brute-forcing paths",
            "subfinder": "discovering subdomains",
            "httpx": "probing endpoints",
            "http": "requesting",
            "browser_navigate": "navigating",
            "browser_fill": "injecting payload",
            "browser_click": "clicking",
            "browser_screenshot": "capturing evidence",
            "browser_login": "testing authentication",
            "browser_get_cookies": "extracting cookies",
            "browser_set_cookies": "planting cookies",
            "browser_clear_session": "resetting session",
            "run_command": "executing",
            "run_exploit": "exploiting",
            "read_file": "reading",
            "write_file": "writing",
            "create_finding": "registering finding",
        }
        return verbs.get(name, "")

    # ──────────────────────────────────────────────────────────
    # Result formatters
    # ──────────────────────────────────────────────────────────

    def _format_result(self, name: str, result: str, args: dict | None = None) -> str:
        """Format tool result intelligently."""
        if not result or result == "None" or result == "null":
            return "ok"

        # Try JSON parse
        data = None
        if isinstance(result, str):
            try:
                data = json.loads(result)
            except (json.JSONDecodeError, TypeError):
                pass
        elif isinstance(result, dict):
            data = result

        if data and isinstance(data, dict):
            if "status_code" in data or name == "http":
                return self._fmt_http(data)
            if name.startswith("browser_"):
                return self._fmt_browser(data)
            if name == "nmap" and "hosts" in data:
                return self._fmt_nmap(data)
            if "error" in data:
                return self._fmt_error_dict(data)
            return self._fmt_dict(data)

        # Plain text
        text = str(result).strip()

        # Truncate sanely — keep output compact
        lines = text.split("\n")
        if len(lines) > 25:
            head = "\n".join(lines[:15])
            tail = "\n".join(lines[-5:])
            return f"{head}\n... ({len(lines) - 20} more lines)\n{tail}"
        elif len(text) > 1500:
            return text[:1500] + f"\n... ({len(text) - 1500} more chars)"

        return text

    def _fmt_http(self, data: dict) -> str:
        """Format HTTP response: status + key headers + clean body preview."""
        parts = []

        # Status line
        status = data.get("status_code", "?")
        parts.append(f"{status}")

        # Interesting headers only
        headers = data.get("headers", {})
        h_lower = {k.lower(): v for k, v in headers.items()} if headers else {}
        interesting = [
            "content-type", "server", "x-powered-by", "location",
            "set-cookie", "x-frame-options", "access-control-allow-origin",
            "content-security-policy", "www-authenticate",
        ]
        for h in interesting:
            val = h_lower.get(h)
            if val:
                sv = str(val)
                if len(sv) > 100:
                    sv = sv[:100] + "..."
                parts.append(f"{h}: {sv}")

        # Body preview — strip HTML, keep it short
        body = data.get("body", data.get("response_text", ""))
        if body:
            body_str = str(body).strip()
            total_len = len(body_str)

            # Check if HTML
            if "<html" in body_str.lower() or "<!doctype" in body_str.lower():
                clean = self._strip_html(body_str)
                if clean:
                    # For error pages (5xx), truncate stack traces aggressively
                    status = data.get("status_code", 0)
                    if status >= 500 and " at " in clean:
                        # Keep only the error message, drop the call stack
                        cut = clean.find(" at ")
                        clean = clean[:cut].strip()
                    # Show just the meaningful text, max 300 chars
                    if len(clean) > 300:
                        parts.append(clean[:300])
                        parts.append(f"... ({total_len} chars total)")
                    else:
                        parts.append(clean)
                else:
                    parts.append(f"({total_len} chars HTML)")
            elif self._is_binary_like(body_str):
                # Binary, encoded, or gibberish content — don't dump it
                parts.append(f"({total_len} chars binary/encoded data)")
            elif total_len > 500:
                parts.append(body_str[:500])
                parts.append(f"... ({total_len} chars total)")
            elif body_str:
                parts.append(body_str)

        return "\n".join(parts)

    def _fmt_browser(self, data: dict) -> str:
        """Format browser tool result — compact."""
        parts = []

        # Status code first if present
        if "status_code" in data:
            parts.append(str(data["status_code"]))

        for k, v in data.items():
            if k in ("screenshot", "status_code"):
                continue
            sv = str(v)
            if len(sv) > 200:
                sv = sv[:200] + "..."
            parts.append(f"{k}: {sv}")

        return "\n".join(parts) if parts else "ok"

    def _fmt_error_dict(self, data: dict) -> str:
        """Format error dict."""
        err = data.get("error", "")
        rest = {k: v for k, v in data.items() if k != "error"}
        lines = [f"error: {err}"]
        for k, v in list(rest.items())[:5]:
            lines.append(f"{k}: {str(v)[:200]}")
        return "\n".join(lines)

    def _fmt_nmap(self, data: dict) -> str:
        """Format nmap result — clean port table like nmap output."""
        parts = []
        target = data.get("target", "")
        if target:
            parts.append(f"target: {target}")

        hosts = data.get("hosts", [])
        if not isinstance(hosts, list):
            return self._fmt_dict(data)

        for host in hosts:
            if not isinstance(host, dict):
                continue
            ip = host.get("ip", "?")
            state = host.get("state", "?")
            parts.append(f"{ip}  {state}")
            for port in host.get("ports", []):
                if not isinstance(port, dict):
                    continue
                p = port.get("port", "?")
                proto = port.get("protocol", "tcp")
                service = port.get("service", "")
                product = port.get("product", "")
                version = port.get("version", "")
                detail = f"  {product}" if product else ""
                detail += f" {version}" if version else ""
                parts.append(f"  {p}/{proto}  open  {service}{detail}")

        return "\n".join(parts) if parts else self._fmt_dict(data)

    def _fmt_dict(self, data: dict) -> str:
        """Format generic dict result."""
        parts = []
        for k, v in list(data.items())[:25]:
            sv = str(v)
            if len(sv) > 200:
                sv = sv[:200] + "..."
            parts.append(f"{k}: {sv}")
        if len(data) > 25:
            parts.append(f"... ({len(data) - 25} more fields)")
        return "\n".join(parts)

    def _is_tool_failure(self, result: str) -> bool:
        """Check for actual tool crash — not HTTP error responses."""
        if not result:
            return False
        r = str(result)
        # JSON with status_code = HTTP response, never a tool failure
        try:
            data = json.loads(r) if isinstance(r, str) else r
            if isinstance(data, dict) and "status_code" in data:
                return False
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
        head = r[:200].lower()
        return any(w in head for w in (
            "timeout", "traceback", "exception",
            "command failed", "no such file", "connection refused",
        ))

    @staticmethod
    def _status_style(code: int) -> str:
        """Color for HTTP status code — pentesting perspective."""
        if code < 300:
            return _GREEN
        elif code < 400:
            return _CYAN
        elif code < 500:
            return _GOLD
        else:
            return _PURPLE  # 5xx = interesting, not error

    def status_bar(self, phase_name: str = "", phase_num: int = 0,
                   total_phases: int = 0, finding_counts: dict | None = None,
                   tool_count: int = 0, cost: float = 0.0, elapsed_s: float = 0.0):
        """
        Compact attack progress line — the ambient heartbeat of the assessment.
        
        Printed periodically to show the viewer "this is alive and progressing."
        The single most important element for demo video pacing.
        """
        self.end_stream()
        fc = finding_counts or {}

        # Phase progress
        parts = []
        if phase_name:
            if total_phases > 0:
                filled = int((phase_num / total_phases) * 10)
                empty = 10 - filled
                bar = "▰" * filled + "▱" * empty
                parts.append(f"{bar} {phase_name.upper()}")
            else:
                parts.append(phase_name.upper())

        # Finding severity pills
        sev_parts = []
        crit = fc.get("critical", 0)
        high = fc.get("high", 0)
        med = fc.get("medium", 0)
        low = fc.get("low", 0)
        if crit:
            sev_parts.append(f"▲▲{crit}")
        if high:
            sev_parts.append(f"▲{high}")
        if med:
            sev_parts.append(f"■{med}")
        if low:
            sev_parts.append(f"●{low}")
        if sev_parts:
            parts.append(" ".join(sev_parts))
        
        # Tool count
        if tool_count:
            parts.append(f"{tool_count} ops")

        # Cost
        if cost > 0.001:
            parts.append(f"${cost:.2f}")

        # Elapsed
        if elapsed_s > 0:
            if elapsed_s < 60:
                parts.append(f"{elapsed_s:.0f}s")
            else:
                m, s = divmod(int(elapsed_s), 60)
                parts.append(f"{m}:{s:02d}")

        if not parts:
            return

        line = Text()
        line.append("  ═══ ", style=_GREEN)
        line.append(" │ ".join(parts), style=_DIM)
        self.console.print(line)

    def intel_update(self, new_ports: int = 0, new_endpoints: int = 0,
                     new_techs: int = 0, new_creds: int = 0,
                     new_hypotheses: int = 0):
        """
        Brief intelligence discovery line — shows the AI learning in real-time.
        
        Printed after tool execution when new data is extracted.
        Makes the viewer see: "it's not just running tools, it's UNDERSTANDING."
        """
        self.end_stream()
        parts = []
        if new_ports > 0:
            parts.append(f"+{new_ports} port{'s' if new_ports > 1 else ''}")
        if new_endpoints > 0:
            parts.append(f"+{new_endpoints} endpoint{'s' if new_endpoints > 1 else ''}")
        if new_techs > 0:
            parts.append(f"+{new_techs} tech{'s' if new_techs > 1 else ''}")
        if new_creds > 0:
            parts.append(f"+{new_creds} credential{'s' if new_creds > 1 else ''}")
        if new_hypotheses > 0:
            parts.append(f"+{new_hypotheses} hypothesis")

        if not parts:
            return

        line = Text()
        line.append("  ◆ INTEL  ", style=f"bold {_PURPLE}")
        line.append("  ".join(parts), style=_TEXT)
        self.console.print(line)

    def divider(self):
        """Subtle iteration divider."""
        self.end_stream()
        self.console.print()
        d = Text()
        d.append("  · · · · · · · · · · · · · · ·", style=_BORDER)
        self.console.print(d)

    def assessment_complete(
        self,
        target: str,
        duration_s: float,
        cost: float,
        findings: list,
        tools_used: int,
    ):
        """
        Print the assessment complete summary card.
        
        This is the FINAL FRAME — the screenshot-worthy finale
        that ends every demo video. Must be perfect.
        """
        self.end_stream()

        # Count severities
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity if hasattr(f, "severity") else "info"
            if sev in counts:
                counts[sev] += 1

        total_findings = len(findings)

        # Determine risk level
        if counts["critical"] > 0:
            risk = "CRITICAL"
            risk_color = _RED
        elif counts["high"] > 0:
            risk = "HIGH"
            risk_color = _RED
        elif counts["medium"] > 0:
            risk = "MEDIUM"
            risk_color = _GOLD
        elif counts["low"] > 0:
            risk = "LOW"
            risk_color = _CYAN
        else:
            risk = "CLEAN"
            risk_color = _GREEN

        # Format duration
        if duration_s < 60:
            dur = f"{duration_s:.0f}s"
        else:
            m, s = divmod(int(duration_s), 60)
            dur = f"{m}m {s:02d}s"

        # Dynamic width — use terminal width for maximum impact
        tw = min(max((self.console.width or 80) - 4, 50), 72)
        w = tw  # inner width
        border = _GREEN if total_findings == 0 else risk_color

        self.console.print()

        # ═══ TOP BORDER (double line for emphasis) ═══
        top = Text()
        top.append(f"  ╔{'═' * w}╗", style=f"bold {border}")
        self.console.print(top)

        # Empty line
        self.console.print(Text(f"  ║{' ' * w}║", style=f"bold {border}"))

        # Title — centered, bold
        title = "ASSESSMENT COMPLETE"
        pad = (w - len(title)) // 2
        t = Text()
        t.append("  ║", style=f"bold {border}")
        t.append(f"{' ' * pad}{title}{' ' * (w - pad - len(title))}", style=f"bold {_GREEN}")
        t.append("║", style=f"bold {border}")
        self.console.print(t)

        # Empty line
        self.console.print(Text(f"  ║{' ' * w}║", style=f"bold {border}"))

        # Separator
        sep = Text()
        sep.append(f"  ╟{'─' * w}╢", style=f"bold {border}")
        self.console.print(sep)

        # Empty line
        self.console.print(Text(f"  ║{' ' * w}║", style=f"bold {border}"))

        # Target
        tgt_display = target[:w - 14] if len(target) <= w - 14 else target[:w - 17] + "..."
        self._card_line_v2(f"  Target:    {tgt_display}", w, border, _TEXT)

        # Duration + Cost on same line
        dur_cost = f"  Duration:  {dur}        Cost: ${cost:.2f}"
        self._card_line_v2(dur_cost, w, border, _TEXT)

        # Tools used
        if tools_used > 0:
            self._card_line_v2(f"  Tools:     {tools_used} operations", w, border, _DIM)

        # Empty line
        self.console.print(Text(f"  ║{' ' * w}║", style=f"bold {border}"))

        # Separator
        sep2 = Text()
        sep2.append(f"  ╟{'─' * w}╢", style=f"bold {border}")
        self.console.print(sep2)

        # Empty line
        self.console.print(Text(f"  ║{' ' * w}║", style=f"bold {border}"))

        # Visual severity breakdown with bar chart
        max_count = max(counts.values()) if any(counts.values()) else 1
        sev_config = [
            ("critical", "▲▲", _RED),
            ("high",     "▲ ", _RED),
            ("medium",   "■ ", _GOLD),
            ("low",      "● ", _CYAN),
        ]
        for sev_name, sev_icon, sev_color in sev_config:
            count = counts[sev_name]
            if count > 0 or sev_name in ("critical", "high"):
                bar_len = int((count / max_count) * 15) if count > 0 else 0
                bar = "█" * bar_len + "░" * (15 - bar_len)
                label = f"  {sev_icon} {sev_name.upper():<10} {count}  {bar}"
                row = Text()
                row.append("  ║", style=f"bold {border}")
                padded = label + " " * max(0, w - len(label))
                # Color the severity part
                row.append(padded[:w], style=sev_color if count > 0 else _DIM)
                row.append("║", style=f"bold {border}")
                self.console.print(row)

        # Empty line
        self.console.print(Text(f"  ║{' ' * w}║", style=f"bold {border}"))

        # Risk level — large and bold
        risk_row = Text()
        risk_row.append("  ║", style=f"bold {border}")
        risk_label = f"  RISK LEVEL: {risk}"
        remaining = w - len(risk_label)
        risk_row.append(risk_label, style=f"bold {risk_color}")
        risk_row.append(" " * remaining, style="")
        risk_row.append("║", style=f"bold {border}")
        self.console.print(risk_row)

        # Empty line
        self.console.print(Text(f"  ║{' ' * w}║", style=f"bold {border}"))

        # What This Means
        summary = self._human_risk_summary(risk, counts, total_findings)
        if summary:
            for sline in self._textwrap(summary, w - 4):
                self._card_line_v2(f"  {sline}", w, border, _TEXT)
            self.console.print(Text(f"  ║{' ' * w}║", style=f"bold {border}"))

        # Separator
        sep3 = Text()
        sep3.append(f"  ╟{'─' * w}╢", style=f"bold {border}")
        self.console.print(sep3)

        self.console.print(Text(f"  ║{' ' * w}║", style=f"bold {border}"))

        # Hints
        self._card_line_v2("  /report       →  Full HTML report", w, border, _DIM)
        self._card_line_v2("  /findings     →  All issues found", w, border, _DIM)

        # Empty line
        self.console.print(Text(f"  ║{' ' * w}║", style=f"bold {border}"))

        # Branding footer
        footer_text = "numasec.com — Vibe Security"
        fpad = (w - len(footer_text)) // 2
        fl = Text()
        fl.append("  ║", style=f"bold {border}")
        fl.append(f"{' ' * fpad}{footer_text}{' ' * (w - fpad - len(footer_text))}", style=_DIM)
        fl.append("║", style=f"bold {border}")
        self.console.print(fl)

        # Empty line
        self.console.print(Text(f"  ║{' ' * w}║", style=f"bold {border}"))

        # ═══ BOTTOM BORDER ═══
        bot = Text()
        bot.append(f"  ╚{'═' * w}╝", style=f"bold {border}")
        self.console.print(bot)
        self.console.print()

    def _card_line_v2(self, content: str, width: int, border_color: str, text_color: str):
        """Helper: render one line inside the assessment card (double-border version)."""
        row = Text()
        row.append("  ║", style=f"bold {border_color}")
        padded = content + " " * max(0, width - len(content))
        row.append(padded[:width], style=text_color)
        row.append("║", style=f"bold {border_color}")
        self.console.print(row)

    def _card_line(self, content: str, width: int, border_color: str, text_color: str):
        """Helper: render one line inside the assessment card."""
        row = Text()
        row.append("  │", style=border_color)
        # Pad content to width
        padded = content + " " * max(0, width - len(content))
        row.append(padded[:width], style=text_color)
        row.append("│", style=border_color)
        self.console.print(row)

    @staticmethod
    def _human_risk_summary(risk: str, counts: dict, total: int) -> str:
        """Generate a plain-language 'What This Means' summary — impersonal, tool-like."""
        if total == 0:
            return "No security issues identified during this assessment."
        
        if risk == "CRITICAL":
            return (
                f"Critical security issues detected — immediate action required. "
                f"Potential full system compromise or complete data breach. "
                f"Prioritize critical findings first."
            )
        elif risk == "HIGH":
            return (
                f"{total} issue{'s' if total != 1 else ''} identified, including "
                f"high-severity vulnerabilities. User accounts and private data "
                f"are at risk. Address these before going live."
            )
        elif risk == "MEDIUM":
            return (
                f"{total} issue{'s' if total != 1 else ''} identified. No critical "
                f"flaws, but misconfigurations and information leaks increase "
                f"the attack surface. Worth addressing."
            )
        elif risk == "LOW":
            return (
                f"Only minor issues found — mostly missing security headers "
                f"and minor information leaks. Good to fix when possible, "
                f"not urgent."
            )
        return f"{total} issue{'s' if total != 1 else ''} identified — review recommended."

    @staticmethod
    def _extract_payload(finding) -> str:
        """Extract exploit payload from finding evidence for display."""
        evidence = finding.evidence or ""
        desc = finding.description or ""
        combined = f"{evidence} {desc}"

        # Look for common payload patterns
        import re
        # Script tags
        m = re.search(r'(<script[^>]*>.*?</script>)', combined, re.IGNORECASE)
        if m:
            return m.group(1)[:120]
        # SQL injection patterns
        m = re.search(r"(['\"]\s*(?:OR|AND|UNION)\s+.{5,60})", combined, re.IGNORECASE)
        if m:
            return m.group(1)[:120]
        # URL with payload parameters
        m = re.search(r'((?:id|q|search|query|user|name|input)=[^\s&]{5,80})', combined, re.IGNORECASE)
        if m:
            return m.group(1)[:120]
        # Curl command
        m = re.search(r'(curl\s+.{10,100})', combined, re.IGNORECASE)
        if m:
            return m.group(1)[:120]
        return ""

    @staticmethod
    def _extract_impact(finding) -> str:
        """Extract impact summary from finding description."""
        desc = finding.description or ""
        # Look for impact-related sentences
        import re
        m = re.search(
            r'(?:impact|allows?|enables?|leads? to|results? in|grants?)[:\s]+([^.]{10,100})',
            desc, re.IGNORECASE
        )
        if m:
            return m.group(1).strip()[:100]
        # For SQLi
        lower = desc.lower()
        if 'database' in lower or 'data' in lower:
            return "Full database access"
        if 'admin' in lower:
            return "Administrative access"
        if 'session' in lower or 'cookie' in lower:
            return "Session hijacking"
        if 'execute' in lower or 'rce' in lower:
            return "Remote code execution"
        return ""

    @staticmethod
    def _textwrap(text: str, width: int) -> list[str]:
        """Wrap text to fit within width, breaking at word boundaries."""
        if width < 20:
            width = 20
        words = text.split()
        lines: list[str] = []
        current: list[str] = []
        length = 0
        for w in words:
            needed = len(w) if not current else length + 1 + len(w)
            if current and needed > width:
                lines.append(" ".join(current))
                current = [w]
                length = len(w)
            else:
                current.append(w)
                length = needed
        if current:
            lines.append(" ".join(current))
        return lines or [""]

    # ──────────────────────────────────────────────────────────
    # Content detection utilities
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _is_binary_like(text: str) -> bool:
        """Detect binary, encoded, or gibberish content (not useful to display)."""
        if len(text) < 100:
            return False
        # Sample the first 200 chars
        sample = text[:200]
        # High ratio of digits/hex with no spaces = binary/encoded
        alphanum = sum(1 for c in sample if c.isalnum())
        spaces = sum(1 for c in sample if c == ' ')
        if len(sample) > 0 and spaces / len(sample) < 0.02 and alphanum / len(sample) > 0.9:
            return True
        return False

    @staticmethod
    def _strip_html(html: str) -> str:
        """Strip HTML to meaningful text. Remove scripts, styles, tags."""
        # Remove <script>...</script> and <style>...</style>
        text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        # Remove HTML comments
        text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
        # Remove all tags
        text = re.sub(r'<[^>]+>', ' ', text)
        # Decode common entities
        text = text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
        text = text.replace('&nbsp;', ' ').replace('&quot;', '"')
        # Collapse whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text
