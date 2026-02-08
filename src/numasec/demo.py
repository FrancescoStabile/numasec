"""
NumaSec v3 — Demo Mode

Cinematic replay of a realistic security assessment.
Showcases every visual feature for maximum demo impact.
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

from numasec.renderer import StreamRenderer, matrix_rain, startup_animation
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
# Demo Script — a realistic web app assessment
# ═══════════════════════════════════════════════════════════════════════════

TARGET = "http://localhost:3000"

# Each step: (type, delay_before, **kwargs)
# Types: text, tool_start, tool_end, finding, usage, phase, plan, intel, status

DEMO_SCRIPT: list[dict] = [
    # ── Opening analysis ──
    {"type": "text", "delay": 0.02, "content": "I'll analyze "},
    {"type": "text", "delay": 0.02, "content": TARGET},
    {"type": "text", "delay": 0.02, "content": " for security vulnerabilities. Starting with reconnaissance to map the attack surface, then testing for exploitable flaws.\n\n"},

    # ── Phase: DISCOVERY ──
    {"type": "plan", "delay": 0.3, "content": (
        "Testing Plan\n"
        "[ ] Phase 1: RECONNAISSANCE — Map the attack surface\n"
        "    Objective: Discover open ports, endpoints, and technologies\n"
        "[ ] Phase 2: VULNERABILITY TESTING — Find exploitable flaws\n"
        "    Objective: Test inputs, authentication, and access controls\n"
        "[ ] Phase 3: EXPLOITATION — Prove impact\n"
        "    Objective: Demonstrate real-world attack scenarios\n"
        "[ ] Phase 4: REPORTING — Actionable results\n"
        "    Objective: Generate prioritized findings with fixes"
    )},

    # Tool 1: HTTP probe
    {"type": "tool_start", "delay": 0.4, "name": "http",
     "args": {"method": "GET", "url": f"{TARGET}/"}},
    {"type": "tool_end", "delay": 0.8, "name": "http",
     "result": '{"status_code": 200, "headers": {"server": "Express", "x-powered-by": "Express", "content-type": "text/html; charset=utf-8"}, "body": "<html><head><title>My Vibe App</title></head><body>..."}'},

    # Intel feed — AI learned something
    {"type": "intel", "delay": 0.1, "ports": 1, "endpoints": 1, "techs": 2},

    {"type": "text", "delay": 0.02, "content": "Node.js Express app detected. The `X-Powered-By: Express` header reveals the framework — removing it is a quick win. Let me check for exposed sensitive files.\n\n"},

    # Tool 2: Check exposed files
    {"type": "tool_start", "delay": 0.3, "name": "http",
     "args": {"method": "GET", "url": f"{TARGET}/.env"}},
    {"type": "tool_end", "delay": 0.6, "name": "http",
     "result": '{"status_code": 200, "body": "DATABASE_URL=postgresql://admin:supersecret123@db:5432/myapp\\nJWT_SECRET=mysecretkey123\\nSTRIPE_SECRET_KEY=sk_live_abc123def456\\nAWS_ACCESS_KEY=AKIA..."}'},

    # Intel — credentials discovered
    {"type": "intel", "delay": 0.1, "creds": 4, "hypotheses": 2},

    {"type": "text", "delay": 0.02, "content": "The .env file is publicly accessible. It contains database credentials, JWT secret, Stripe live key, and AWS access key. "},
    {"type": "text", "delay": 0.02, "content": "This is a complete infrastructure compromise — anyone on the internet can read this file.\n\n"},

    # Finding 1 — CRITICAL (the big moment)
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Environment File Exposed — Database, API Keys & Secrets Leaked",
        severity="critical",
        description="The .env file at /.env is accessible without authentication, exposing: database credentials (admin:supersecret123), JWT signing secret (allows token forgery), live Stripe API key (enables fraudulent charges), and AWS access key (potential full cloud compromise).\n\nFix: Block /.env in Express static file config or reverse proxy. Rotate ALL exposed credentials immediately — they are already compromised.",
        evidence=f"GET {TARGET}/.env → 200 OK — DATABASE_URL, JWT_SECRET, STRIPE_SECRET_KEY, AWS_ACCESS_KEY all exposed",
    )},

    # Usage after first batch
    {"type": "usage", "delay": 0.1, "input_tokens": 2847, "output_tokens": 412},

    # Status bar — show progress
    {"type": "status", "delay": 0.2, "phase": "RECONNAISSANCE", "phase_num": 1, "total": 4,
     "findings": {"critical": 1}, "tools": 2, "cost": 0.02, "elapsed": 28},

    # Tool 3: Port scan
    {"type": "tool_start", "delay": 0.3, "name": "nmap",
     "args": {"target": "localhost", "ports": "1-1024"}},
    {"type": "tool_end", "delay": 1.2, "name": "nmap",
     "result": '{"target": "localhost", "hosts": [{"ip": "127.0.0.1", "state": "up", "ports": [{"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.9"}, {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.24"}, {"port": 3000, "protocol": "tcp", "service": "http", "product": "Node.js Express"}, {"port": 5432, "protocol": "tcp", "service": "postgresql", "product": "PostgreSQL", "version": "15.2"}]}]}'},

    # Intel — ports discovered
    {"type": "intel", "delay": 0.1, "ports": 4, "techs": 2},

    {"type": "text", "delay": 0.02, "content": "Four services exposed: SSH, nginx reverse proxy, Express app on 3000, and PostgreSQL on 5432. The database port is directly accessible — combined with the leaked credentials, this means direct database access from the internet.\n\n"},

    # ── Phase transition ──
    {"type": "phase", "delay": 0.5, "completed": "RECONNAISSANCE", "next": "VULNERABILITY TESTING",
     "phase_num": 1, "total": 4},

    # Tool 4: Test login for SQLi
    {"type": "text", "delay": 0.02, "content": "Testing the login endpoint for SQL injection — injecting database commands through form fields.\n\n"},

    {"type": "tool_start", "delay": 0.3, "name": "http",
     "args": {"method": "POST", "url": f"{TARGET}/api/auth/login", "data": "{\"email\": \"' OR '1'='1\", \"password\": \"anything\"}"}},
    {"type": "tool_end", "delay": 0.7, "name": "http",
     "result": '{"status_code": 200, "body": "{\\"token\\": \\"eyJhbGciOiJIUzI1NiIs...\\", \\"user\\": {\\"id\\": 1, \\"email\\": \\"admin@myvibeapp.com\\", \\"role\\": \\"admin\\"}}"}'},

    {"type": "text", "delay": 0.02, "content": "SQL injection confirmed — authentication completely bypassed. Logged in as admin without knowing the password. "},
    {"type": "text", "delay": 0.02, "content": "Any account is accessible, including admin. Full database can be dumped.\n\n"},

    # Finding 2 — CRITICAL
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="SQL Injection — Complete Authentication Bypass",
        severity="critical",
        description="The login endpoint /api/auth/login does not sanitize input. Injecting ' OR '1'='1 in the email field bypasses authentication entirely, granting admin access. An attacker can access any account, dump the database, or modify records.\n\nFix: Use parameterized queries (prepared statements). If using Sequelize/Prisma/Drizzle, use query builders — never raw SQL with string concatenation.",
        evidence=f"POST {TARGET}/api/auth/login — email: ' OR '1'='1 → 200 OK with admin JWT token",
    )},

    # Usage
    {"type": "usage", "delay": 0.1, "input_tokens": 4621, "output_tokens": 583},

    # Status bar
    {"type": "status", "delay": 0.2, "phase": "VULNERABILITY TESTING", "phase_num": 2, "total": 4,
     "findings": {"critical": 2}, "tools": 4, "cost": 0.05, "elapsed": 67},

    # Tool 5: XSS in search
    {"type": "text", "delay": 0.02, "content": "Testing the search feature for cross-site scripting (XSS) — injecting JavaScript through user input.\n\n"},

    {"type": "tool_start", "delay": 0.3, "name": "browser_navigate",
     "args": {"url": f"{TARGET}/search"}},
    {"type": "tool_end", "delay": 0.5, "name": "browser_navigate",
     "result": '{"status_code": 200, "title": "Search — My Vibe App", "url": "http://localhost:3000/search"}'},

    {"type": "tool_start", "delay": 0.2, "name": "browser_fill",
     "args": {"selector": "input[name='q']", "value": "<img src=x onerror=alert(document.cookie)>"}},
    {"type": "tool_end", "delay": 0.4, "name": "browser_fill",
     "result": '{"success": true, "filled": "input[name=\'q\']"}'},

    {"type": "tool_start", "delay": 0.2, "name": "browser_screenshot",
     "args": {"filename": "xss_proof.png"}},
    {"type": "tool_end", "delay": 0.4, "name": "browser_screenshot",
     "result": '{"screenshot": "evidence/xss_proof.png", "title": "Search Results — alert box visible", "dialog_detected": "alert: session cookie displayed"}'},

    # Intel
    {"type": "intel", "delay": 0.1, "endpoints": 2, "hypotheses": 1},

    {"type": "text", "delay": 0.02, "content": "XSS confirmed. The search page renders user input without sanitization — the injected script executed and displayed the session cookie. "},
    {"type": "text", "delay": 0.02, "content": "An attacker can craft a link that steals any user's session when clicked.\n\n"},

    # Finding 3 — HIGH
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Reflected XSS — Session Theft via Search",
        severity="high",
        description="The search feature at /search renders user input directly into the HTML without escaping. Injecting <img src=x onerror=alert(document.cookie)> executes JavaScript in the victim's browser, exposing session cookies and enabling full account takeover.\n\nFix: Escape all user input before rendering in HTML. In React, JSX does this automatically — check for dangerouslySetInnerHTML. Add Content-Security-Policy header.",
        evidence=f"Payload: <img src=x onerror=alert(document.cookie)> → JavaScript executed, cookie displayed",
    )},

    # Tool 6: IDOR check
    {"type": "text", "delay": 0.02, "content": "Testing for Insecure Direct Object Reference (IDOR) — checking if user data can be accessed by changing the ID parameter.\n\n"},

    {"type": "tool_start", "delay": 0.3, "name": "http",
     "args": {"method": "GET", "url": f"{TARGET}/api/users/2"}},
    {"type": "tool_end", "delay": 0.5, "name": "http",
     "result": '{"status_code": 200, "body": "{\\"id\\": 2, \\"email\\": \\"jane@company.com\\", \\"role\\": \\"user\\", \\"ssn\\": \\"123-45-6789\\", \\"address\\": \\"123 Main St\\"}"}'},

    {"type": "text", "delay": 0.02, "content": "IDOR confirmed — accessing /api/users/2 returns another user's full profile including SSN and address. No authorization check.\n\n"},

    # Finding 4 — HIGH
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="IDOR — Any User's Personal Data Accessible",
        severity="high",
        description="The /api/users/:id endpoint returns full user profiles without verifying the requester's identity. Incrementing the ID exposes all users' data including SSN, address, and email. This is a mass data breach waiting to happen.\n\nFix: Add authorization middleware — verify the authenticated user matches the requested user ID, or has admin role.",
        evidence=f"GET {TARGET}/api/users/2 → 200 OK with SSN, address, email of another user",
    )},

    # Usage
    {"type": "usage", "delay": 0.1, "input_tokens": 7842, "output_tokens": 1053},

    # ── Phase transition ──
    {"type": "phase", "delay": 0.5, "completed": "VULNERABILITY TESTING", "next": "EXPLOITATION",
     "phase_num": 2, "total": 4},

    # Status bar — big update
    {"type": "status", "delay": 0.2, "phase": "EXPLOITATION", "phase_num": 3, "total": 4,
     "findings": {"critical": 2, "high": 2}, "tools": 8, "cost": 0.08, "elapsed": 112},

    # Tool 7: Missing security headers
    {"type": "tool_start", "delay": 0.3, "name": "http",
     "args": {"method": "GET", "url": f"{TARGET}/"}},
    {"type": "tool_end", "delay": 0.4, "name": "http",
     "result": '{"status_code": 200, "headers": {"server": "Express", "x-powered-by": "Express"}, "body": "..."}'},

    {"type": "text", "delay": 0.02, "content": "Several important security headers are missing. No Content-Security-Policy, no X-Frame-Options, no Strict-Transport-Security. "},
    {"type": "text", "delay": 0.02, "content": "These are quick wins — a single line of code with the `helmet` middleware fixes all of them.\n\n"},

    # Finding 5 — MEDIUM
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Missing Security Headers — CSP, HSTS, X-Frame-Options",
        severity="medium",
        description="The application lacks critical security headers: Content-Security-Policy (prevents XSS), X-Frame-Options (prevents clickjacking), Strict-Transport-Security (forces HTTPS), X-Content-Type-Options (prevents MIME sniffing). These are industry-standard protections.\n\nFix: npm install helmet && app.use(helmet()) — one line, all headers set automatically.",
        evidence=f"GET {TARGET}/ → Missing: CSP, X-Frame-Options, HSTS, X-Content-Type-Options",
    )},

    # Finding 6 — LOW
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Technology Fingerprinting via X-Powered-By Header",
        severity="low",
        description="The X-Powered-By: Express header is present, revealing the server framework. This information helps attackers identify framework-specific exploits and reduces their reconnaissance time.\n\nFix: app.disable('x-powered-by') or use the helmet package which removes it automatically.",
        evidence=f"GET {TARGET}/ → X-Powered-By: Express",
    )},

    # Final usage
    {"type": "usage", "delay": 0.1, "input_tokens": 9847, "output_tokens": 1421},

    # ── Phase transition: done ──
    {"type": "phase", "delay": 0.5, "completed": "EXPLOITATION", "next": "REPORTING",
     "phase_num": 3, "total": 4},

    {"type": "text", "delay": 0.02, "content": "Assessment complete. Here's the priority breakdown:\n\n"},
    {"type": "text", "delay": 0.02, "content": "1. Rotate ALL credentials from .env immediately — they're already compromised\n"},
    {"type": "text", "delay": 0.02, "content": "2. Fix SQL injection in /api/auth/login — use parameterized queries\n"},
    {"type": "text", "delay": 0.02, "content": "3. Add authorization checks to /api/users/:id\n"},
    {"type": "text", "delay": 0.02, "content": "4. Escape user input in search to prevent XSS\n"},
    {"type": "text", "delay": 0.02, "content": "5. Install helmet for security headers — one-line fix\n\n"},
]


# ═══════════════════════════════════════════════════════════════════════════
# Demo Runner
# ═══════════════════════════════════════════════════════════════════════════


async def run_demo(console: Console | None = None):
    """
    Run the full NumaSec demo.

    Cinematic replay with all visual features active.
    No API keys, no Docker, no real target needed.
    """
    if console is None:
        console = Console(
            theme=CYBERPUNK_THEME if CYBERPUNK_THEME else None,
            color_system="truecolor",
        )

    renderer = StreamRenderer(console)
    tool_number = 0
    current_args = {}
    findings: list[Finding] = []
    demo_start = time.monotonic()

    # ── Banner ──
    if CyberpunkAssets:
        console.clear()

        # Matrix rain intro — brief, cinematic, matches CLI experience
        try:
            term_width = console.width or 80
            rain_width = min(term_width - 4, 70)
            console.print()  # breathing room
            matrix_rain(console, duration=1.0, width=rain_width)
        except Exception:
            pass

        console.print(CyberpunkAssets.MATRIX_BANNER)

    # ── Startup animation ──
    try:
        startup_animation(console, provider="DeepSeek", tools_count=19, knowledge_count=46)
    except Exception:
        pass

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
            renderer.phase_transition(
                step["completed"],
                step.get("next", ""),
                phase_num=step.get("phase_num", 0),
                total_phases=step.get("total", 0),
            )

        elif step["type"] == "intel":
            renderer.intel_update(
                new_ports=step.get("ports", 0),
                new_endpoints=step.get("endpoints", 0),
                new_techs=step.get("techs", 0),
                new_creds=step.get("creds", 0),
                new_hypotheses=step.get("hypotheses", 0),
            )

        elif step["type"] == "status":
            renderer.status_bar(
                phase_name=step.get("phase", ""),
                phase_num=step.get("phase_num", 0),
                total_phases=step.get("total", 0),
                finding_counts=step.get("findings", {}),
                tool_count=step.get("tools", 0),
                cost=step.get("cost", 0),
                elapsed_s=step.get("elapsed", 0),
            )

        elif step["type"] == "plan":
            content = step["content"]
            console.print(f"\n  [{CYBER_PURPLE}]◆ TESTING PLAN[/]")
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

    # ── Assessment complete card — THE money shot ──
    duration = time.monotonic() - demo_start
    total_cost = 0.11  # Simulated cost matching real-world DeepSeek pricing

    renderer.assessment_complete(
        target=TARGET,
        duration_s=duration,
        cost=total_cost,
        findings=findings,
        tools_used=tool_number,
    )

    # ── Demo outro ──
    finding_count = len(findings)
    crit_count = sum(1 for f in findings if f.severity.lower() == "critical")
    high_count = sum(1 for f in findings if f.severity.lower() == "high")
    console.print()
    console.print(f"  [{MATRIX_GREEN}]NumaSec found {finding_count} vulnerabilities ({crit_count} critical, {high_count} high) in {duration:.0f} seconds.[/]")
    console.print(f"  [{MATRIX_GREEN}]Cost: $0.11. Imagine what it finds on your app.[/]")
    console.print()
    console.print(f"  [{GHOST_GRAY}]Get started:[/]")
    console.print(f"  [{MATRIX_GREEN}]  export DEEPSEEK_API_KEY=\"sk-...\"[/]")
    console.print(f"  [{MATRIX_GREEN}]  numasec[/]")
    console.print()


def main_demo():
    """Sync entry point for `numasec --demo`."""
    try:
        asyncio.run(run_demo())
    except KeyboardInterrupt:
        print("\n\nDemo interrupted.")
