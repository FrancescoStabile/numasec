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
# Demo Script — a realistic web app assessment
# ═══════════════════════════════════════════════════════════════════════════

TARGET = "http://localhost:3000"

# Each step: (type, delay_before, **kwargs)
# Types: text, tool_start, tool_end, finding, usage, phase, plan

DEMO_SCRIPT: list[dict] = [
    # ── Opening analysis ──
    {"type": "text", "delay": 0.02, "content": "I'll check "},
    {"type": "text", "delay": 0.02, "content": TARGET},
    {"type": "text", "delay": 0.02, "content": " for security issues. Let me start by seeing what's running and looking for common problems.\n\n"},

    # ── Phase: DISCOVERY ──
    {"type": "plan", "delay": 0.3, "content": (
        "Testing Plan\n"
        "[ ] Phase 1: DISCOVERY — See what's running\n"
        "    Objective: Find open ports, pages, and technologies\n"
        "[ ] Phase 2: SECURITY TESTING — Check for vulnerabilities\n"
        "    Objective: Test inputs, forms, and endpoints\n"
        "[ ] Phase 3: RESULTS — Summarize findings\n"
        "    Objective: Explain what's wrong and how to fix it"
    )},

    # Tool 1: HTTP probe
    {"type": "tool_start", "delay": 0.4, "name": "http",
     "args": {"method": "GET", "url": f"{TARGET}/"}},
    {"type": "tool_end", "delay": 0.8, "name": "http",
     "result": '{"status_code": 200, "headers": {"server": "Express", "x-powered-by": "Express"}, "body": "<html><title>My Vibe App</title>..."}'},

    {"type": "text", "delay": 0.02, "content": "Node.js Express app detected. The `X-Powered-By: Express` header is exposed — "},
    {"type": "text", "delay": 0.02, "content": "this reveals the exact framework to potential attackers. Checking for exposed files.\n\n"},

    # Tool 2: Check exposed files
    {"type": "tool_start", "delay": 0.3, "name": "http",
     "args": {"method": "GET", "url": f"{TARGET}/.env"}},
    {"type": "tool_end", "delay": 0.6, "name": "http",
     "result": '{"status_code": 200, "body": "DATABASE_URL=postgresql://admin:supersecret123@db:5432/myapp\\nJWT_SECRET=mysecretkey123\\nSTRIPE_SECRET_KEY=sk_live_abc123..."}'},

    {"type": "text", "delay": 0.02, "content": "**The .env file is publicly accessible.** It contains database credentials, the JWT secret, and a live Stripe API key. "},
    {"type": "text", "delay": 0.02, "content": "Anyone on the internet can read this. Critical severity.\n\n"},

    # Finding 1
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Environment File Exposed — Database & API Keys Leaked",
        severity="critical",
        description="The .env file is accessible at /.env without authentication. It exposes database credentials (admin:supersecret123), the JWT signing secret, and a live Stripe API key. An attacker can use these to access the database directly, forge authentication tokens, and make charges on the Stripe account.\n\nFix: Block .env in the Express static file config or add a deny rule in the reverse proxy (nginx/Apache). Rotate ALL exposed credentials immediately.",
        evidence=f"GET {TARGET}/.env → 200 OK with DATABASE_URL, JWT_SECRET, STRIPE_SECRET_KEY",
    )},

    # Usage after first batch
    {"type": "usage", "delay": 0.1, "input_tokens": 2847, "output_tokens": 412},

    # ── Phase transition ──
    {"type": "phase", "delay": 0.5, "completed": "DISCOVERY", "next": "SECURITY TESTING"},

    # Tool 3: Test login for SQLi
    {"type": "text", "delay": 0.02, "content": "Testing the login form for SQL injection (injecting database commands through input fields).\n\n"},

    {"type": "tool_start", "delay": 0.3, "name": "http",
     "args": {"method": "POST", "url": f"{TARGET}/api/auth/login", "data": "{\"email\": \"' OR '1'='1\", \"password\": \"anything\"}"}},
    {"type": "tool_end", "delay": 0.7, "name": "http",
     "result": '{"status_code": 200, "body": "{\\"token\\": \\"eyJhbGciOiJIUzI1NiIs...\\", \\"user\\": {\\"id\\": 1, \\"email\\": \\"admin@myvibeapp.com\\", \\"role\\": \\"admin\\"}}"}'},

    {"type": "text", "delay": 0.02, "content": "SQL injection confirmed. Authentication bypass achieved — logged in as admin without knowing the password. "},
    {"type": "text", "delay": 0.02, "content": "Any account on the application is accessible with this technique.\n\n"},

    # Finding 2
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="SQL Injection in Login — Any Account Accessible",
        severity="critical",
        description="The login endpoint at /api/auth/login does not sanitize input. Special characters in the email field bypass authentication, granting access as any user — including admin. Full application access and all user data are exposed.\n\nFix: Use parameterized queries instead of string concatenation. If using Prisma, Sequelize, or Drizzle, ensure query builders are used — not raw SQL.",
        evidence=f"POST {TARGET}/api/auth/login with email: ' OR '1'='1 → 200 OK with admin token",
    )},

    # Tool 4: XSS in search
    {"type": "text", "delay": 0.02, "content": "Checking the search feature for XSS (cross-site scripting — injecting code into pages).\n\n"},

    {"type": "tool_start", "delay": 0.3, "name": "browser_fill",
     "args": {"selector": "input[name='q']", "value": "<script>alert('hacked')</script>"}},
    {"type": "tool_end", "delay": 0.5, "name": "browser_fill",
     "result": '{"success": true, "filled": "input[name=\'q\']"}'},

    {"type": "tool_start", "delay": 0.2, "name": "browser_screenshot",
     "args": {"filename": "xss_proof.png"}},
    {"type": "tool_end", "delay": 0.4, "name": "browser_screenshot",
     "result": '{"screenshot": "evidence/xss_proof.png", "title": "Search Results - My Vibe App"}'},

    {"type": "text", "delay": 0.02, "content": "XSS confirmed — the search page renders user input without sanitizing it. "},
    {"type": "text", "delay": 0.02, "content": "An attacker could use this to steal user sessions or redirect users to phishing pages.\n\n"},

    # Finding 3
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Cross-Site Scripting (XSS) in Search",
        severity="high",
        description="The search feature renders user input directly on the page without sanitization. A crafted link containing JavaScript will execute in any user's browser when clicked — enabling session theft and account hijacking.\n\nFix: Escape all user input before rendering in HTML. In React, JSX handles this automatically — but check for dangerouslySetInnerHTML usage. Add a Content-Security-Policy header.",
        evidence=f"Payload: <script>alert('hacked')</script> → rendered and executed in search results",
    )},

    # Usage
    {"type": "usage", "delay": 0.1, "input_tokens": 5193, "output_tokens": 687},

    # Tool 5: Missing security headers
    {"type": "tool_start", "delay": 0.3, "name": "http",
     "args": {"method": "GET", "url": f"{TARGET}/"}},
    {"type": "tool_end", "delay": 0.4, "name": "http",
     "result": '{"status_code": 200, "headers": {"server": "Express", "x-powered-by": "Express"}, "body": "..."}'},

    {"type": "text", "delay": 0.02, "content": "Several important security headers are missing: no Content-Security-Policy, no X-Frame-Options, no Strict-Transport-Security. "},
    {"type": "text", "delay": 0.02, "content": "Easy wins — one line of code to fix.\n\n"},

    # Finding 4
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Missing Security Headers",
        severity="medium",
        description="The application does not set several important security headers: Content-Security-Policy (prevents XSS), X-Frame-Options (prevents clickjacking), Strict-Transport-Security (forces HTTPS). These are simple to add and significantly improve security.\n\nFix: Install the `helmet` npm package and add `app.use(helmet())` to the Express app. This sets all headers automatically in one line.",
        evidence=f"GET {TARGET}/ → Missing: CSP, X-Frame-Options, HSTS, X-Content-Type-Options",
    )},

    # Finding 5
    {"type": "finding", "delay": 0.1, "finding": Finding(
        title="Technology Fingerprinting — X-Powered-By Header",
        severity="low",
        description="The X-Powered-By: Express header is present, revealing the exact framework in use. This information helps attackers identify framework-specific exploits.\n\nFix: Add `app.disable('x-powered-by')` or use the helmet package.",
        evidence=f"GET {TARGET}/ → X-Powered-By: Express",
    )},

    # Final usage
    {"type": "usage", "delay": 0.1, "input_tokens": 8421, "output_tokens": 1253},

    # ── Phase transition: done ──
    {"type": "phase", "delay": 0.5, "completed": "SECURITY TESTING", "next": "RESULTS"},

    {"type": "text", "delay": 0.02, "content": "Assessment complete. Summary of findings:\n"},
    {"type": "text", "delay": 0.02, "content": "1. .env file publicly accessible — credentials exposed (critical, rotate keys immediately)\n"},
    {"type": "text", "delay": 0.02, "content": "2. SQL injection in login — full authentication bypass (critical)\n"},
    {"type": "text", "delay": 0.02, "content": "3. XSS in search — session theft possible (high)\n"},
    {"type": "text", "delay": 0.02, "content": "4. Missing security headers — one-line fix with helmet (medium)\n\n"},
    {"type": "text", "delay": 0.02, "content": "Priority: fix .env exposure and SQL injection first — highest impact.\n\n"},
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

    # ── Assessment complete card ──
    duration = time.monotonic() - demo_start
    total_cost = 0.12  # Simulated cost matching real-world DeepSeek pricing

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
    console.print()
    console.print(f"  [{MATRIX_GREEN}]NumaSec found {finding_count} vulnerabilities ({crit_count} critical) in under 5 minutes.[/]")
    console.print(f"  [{MATRIX_GREEN}]Imagine what it finds on your app.[/]")
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
