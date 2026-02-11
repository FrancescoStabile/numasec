"""
NumaSec — MCP Server

THE integration point for Claude Desktop, Cursor, VS Code Copilot,
and any MCP-compliant host.

Exposes NumaSec as:
    - 10 Tools (3 assessment + 4 mid-level + 1 utility + 2 async session)
    - 46+ Resources (knowledge base as numasec://kb/*)
    - 2 Prompts (assessment workflow, quick check)

Transports:
    - stdio (default): For local MCP hosts (Claude Desktop)
    - streamable-http: For remote/multi-session clients

Usage:
    numasec --mcp              # stdio transport
    numasec --mcp-http         # HTTP transport (default port from FastMCP)

Architecture:
    FastMCP framework — zero boilerplate, type annotations → schemas.
    Tools call into mcp_tools.py which wraps the Agent engine.
    Resources call into mcp_resources.py which reads knowledge/.
    The Agent core (agent.py, tools/, extractors, planner, etc.)
    is UNTOUCHED — MCP is a thin skin, not a rewrite.
"""

import json
import logging
import platform
import sys
from pathlib import Path
from typing import Annotated

logger = logging.getLogger("numasec.mcp")


def create_mcp_server():
    """Create and configure the NumaSec MCP server.

    Returns:
        FastMCP server instance with all tools, resources, and prompts registered.

    Raises:
        ImportError: If mcp package is not installed (pip install 'numasec[mcp]')
    """
    try:
        from mcp.server.fastmcp import FastMCP, Context
    except ImportError:
        raise ImportError(
            "MCP support requires the 'mcp' package.\n"
            "Install it with: pip install 'numasec[mcp]'\n"
            "Or: pip install 'mcp[cli]>=1.26.0'"
        )

    from numasec.mcp_resources import (
        discover_knowledge_files,
        read_knowledge,
        list_knowledge_topics,
    )
    from numasec.mcp_tools import (
        run_assess,
        run_quick_check,
        run_recon,
        run_http_request,
        run_browser_action,
        run_create_finding,
        start_assess_async,
        get_assess_status_longpoll,
        cancel_assess,
        SEVERITY_ICONS,
    )

    mcp = FastMCP(
        "numasec",
        instructions=(
            "AI security testing for your apps. "
            "Find vulnerabilities, get remediation guidance, "
            "all for $0.12 per scan with DeepSeek."
        ),
    )

    # ═════════════════════════════════════════════════════════════════════
    # Tool 1: numasec_assess — THE viral hook
    # ═════════════════════════════════════════════════════════════════════

    @mcp.tool(annotations={
        "title": "Full Security Assessment (blocking)",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    })
    async def numasec_assess(
        target: Annotated[str, "Target URL with protocol (e.g. 'http://localhost:3000', 'https://app.example.com'). Must include http:// or https://."],
        scope: Annotated[str, "Comma-separated allowed targets for scope control. Default: same as target. Example: 'localhost:3000,localhost:8080'"] = "",
        budget: Annotated[float, "Maximum cost in USD. Default $5.00. With DeepSeek: ~$0.12/scan. With Claude: ~$2-5/scan."] = 5.0,
        depth: Annotated[str, "Assessment depth: 'quick' (5min, top vulns only), 'standard' (15min, comprehensive), 'deep' (30min+, with exploitation). Default: 'standard'."] = "standard",
        ctx: Context = None,
    ) -> str:
        """⚠️ BLOCKING — prefer `numasec_assess_start` for a better experience.

        This tool blocks for 5-20 minutes with NO progress updates.
        The user will see nothing until the full assessment completes.

        **USE THIS ONLY** for `depth='quick'` scans (< 5 minutes).

        **FOR ALL OTHER ASSESSMENTS, use this workflow instead:**
        1. Call `numasec_assess_start` → returns a session ID immediately
        2. Tell the user the assessment has started
        3. Call `numasec_assess_status` — it waits for new findings automatically
        4. Share new findings with the user, then call status again
        5. When status is "completed", present the full report

        The async workflow gives the user live progress, live findings,
        and the ability to cancel — a much better experience.

        If you still choose to use this tool, it runs an autonomous AI agent
        that plans attack strategy, runs 20+ security tools (nmap, nuclei,
        sqlmap, browser automation), and documents every vulnerability.

        **Output**: Markdown report with findings, cost, and duration.
        **Cost**: ~$0.12 with DeepSeek, ~$2-5 with Claude/GPT-4.
        """
        async def _progress(step, total, message):
            if ctx:
                await ctx.report_progress(step, total)
                await ctx.info(message)

        return await run_assess(
            target=target,
            scope=scope,
            budget=budget,
            depth=depth,
            progress_callback=_progress,
        )

    # ═════════════════════════════════════════════════════════════════════
    # Tool 2a: numasec_assess_start — Non-blocking async assessment
    # ═════════════════════════════════════════════════════════════════════

    @mcp.tool(annotations={
        "title": "Start Security Assessment",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    })
    async def numasec_assess_start(
        target: Annotated[str, "Target URL with protocol (e.g. 'http://localhost:3000')"],
        scope: Annotated[str, "Comma-separated allowed targets. Default: same as target."] = "",
        budget: Annotated[float, "Maximum cost in USD. Default $5.00."] = 5.0,
        depth: Annotated[str, "Assessment depth: 'quick', 'standard', 'deep'. Default: 'standard'."] = "standard",
    ) -> str:
        """🚀 PRIMARY TOOL — Start a security assessment and return immediately.

        This is the **recommended** way to run security assessments. It launches
        the assessment in the background and returns a session ID within seconds.
        You then poll for live progress — the user sees findings as they appear.

        **Workflow (ALWAYS follow ALL steps — do NOT stop early):**
        1. Call this tool → receive a session_id
        2. Tell the user: "Assessment started, I'll monitor progress..."
        3. Call `numasec_assess_status(session_id)` — it waits internally for news
        4. When it returns, share any new findings briefly with the user
        5. **If status ≠ COMPLETED → call `numasec_assess_status` again (MANDATORY)**
        6. Keep looping step 3-5 until the response says status is **COMPLETED**
        7. Only then present the full final report to the user

        ⚠️ **IMPORTANT**: A typical assessment needs 5-15 status calls over
        5-20 minutes. Do NOT stop polling after a few calls — the scan is
        still finding vulnerabilities. Partial results are NOT a valid report.

        **Use this tool whenever the user asks to**:
        - "Run a security assessment on ..."
        - "Test my app for vulnerabilities"
        - "Hack / pentest / scan ..."
        - Any security testing request

        The only exception is `numasec_quick_check` for 30-second checks.

        **Cost**: ~$0.12 with DeepSeek, ~$2-5 with Claude/GPT-4.
        **Duration**: 5-20 min depending on depth and target complexity.
        """
        return await start_assess_async(
            target=target, scope=scope, budget=budget, depth=depth,
        )

    # ═════════════════════════════════════════════════════════════════════
    # Tool 2b: numasec_assess_status — Live progress + findings
    # ═════════════════════════════════════════════════════════════════════

    @mcp.tool(annotations={
        "title": "Assessment Status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    })
    async def numasec_assess_status(
        session_id: Annotated[str, "Session ID returned by numasec_assess_start"],
    ) -> str:
        """Check assessment progress — KEEP CALLING until status is COMPLETED.

        This tool uses **long-polling**: it waits up to 60 seconds internally
        for something interesting (new findings, completion, or significant
        progress) before returning. Just call it and wait — no rapid polling.

        ⚠️ **CRITICAL**: If the response says "NOT COMPLETE", you MUST call
        this tool again. Do NOT summarize partial results as a final report.
        The assessment discovers more vulnerabilities as it runs longer.
        Presenting incomplete results would mislead the user.

        **Workflow:**
        1. Call this tool → it waits internally, then returns with news
        2. Share any new findings briefly with the user
        3. **If status ≠ COMPLETED → call this tool again immediately**
        4. Only when status = COMPLETED → present the full final report

        Returns:
        - **Running** (status ≠ COMPLETED): partial progress — MUST call again
        - **Completed**: full assessment report with all findings — you can stop
        - **Failed/Cancelled**: error + partial findings — you can stop
        """
        return await get_assess_status_longpoll(session_id)

    # ═════════════════════════════════════════════════════════════════════
    # Tool 2c: numasec_assess_cancel — Stop a running assessment
    # ═════════════════════════════════════════════════════════════════════

    @mcp.tool(annotations={
        "title": "Cancel Assessment",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    })
    async def numasec_assess_cancel(
        session_id: Annotated[str, "Session ID returned by numasec_assess_start"],
    ) -> str:
        """Cancel a running assessment and get partial results.

        Use when:
        - The user wants to stop the assessment early
        - Enough findings have been discovered
        - The assessment is taking too long

        Returns any findings collected before cancellation.
        """
        return cancel_assess(session_id)

    # ═════════════════════════════════════════════════════════════════════
    # Tool 3: numasec_quick_check — 30-second first impression
    # ═════════════════════════════════════════════════════════════════════

    @mcp.tool(annotations={
        "title": "Quick Security Check",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    })
    async def numasec_quick_check(
        target: Annotated[str, "Target URL with protocol (e.g. http://localhost:3000)"],
        ctx: Context = None,
    ) -> str:
        """30-second security spot check. Fast, cheap, instant value.

        Runs 3 fast checks WITHOUT the full AI agent loop:
        1. Technology detection (httpx) — what's running?
        2. Port scan (nmap top 100) — what's exposed?
        3. Known vulnerabilities (nuclei critical+high) — any CVEs?

        **When to use**:
        - First time trying NumaSec — see results in 30 seconds
        - Quick sanity check before deploying
        - Checking if a target is worth a full assessment
        - When you need speed over thoroughness

        **When NOT to use**:
        - When you need comprehensive testing (use numasec_assess)
        - For business logic vulnerabilities (requires full agent)
        - For authenticated testing (requires numasec_assess with browser)

        **Speed**: ~30 seconds | **Cost**: ~$0.01

        **Output**: Markdown with detected technologies, open ports, and
        any critical/high vulnerabilities found. Suggests full assessment
        if issues are detected.
        """
        async def _progress(step, total, message):
            if ctx:
                await ctx.report_progress(step, total)
                await ctx.info(message)

        return await run_quick_check(
            target=target,
            progress_callback=_progress,
        )

    # ═════════════════════════════════════════════════════════════════════
    # Tool 4: numasec_recon — Mid-level reconnaissance
    # ═════════════════════════════════════════════════════════════════════

    @mcp.tool(annotations={
        "title": "Reconnaissance Scan",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    })
    async def numasec_recon(
        target: Annotated[str, "Target URL or hostname (e.g. 'http://10.0.0.1', '192.168.1.0/24')"],
        scan_type: Annotated[str, "'full' (top 1000 ports + version detection) or 'quick' (top 100 ports). Default: 'full'."] = "full",
    ) -> str:
        """Run reconnaissance: port scanning + technology detection.

        Combines nmap and httpx for a complete recon view of the target.

        **When to use**:
        - Mapping open ports and services on a target
        - Identifying web server technology stack
        - Starting point before targeted vulnerability testing
        - Scanning network ranges (CIDR notation supported)

        **When NOT to use**:
        - For full vulnerability assessment (use numasec_assess)
        - For a single HTTP request (use numasec_http)
        """
        return await run_recon(target=target, scan_type=scan_type)

    # ═════════════════════════════════════════════════════════════════════
    # Tool 4: numasec_http — Mid-level HTTP requests
    # ═════════════════════════════════════════════════════════════════════

    @mcp.tool(annotations={
        "title": "HTTP Request",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    })
    async def numasec_http(
        url: Annotated[str, "Target URL with protocol (e.g. 'http://localhost:3000/api/users')"],
        method: Annotated[str, "HTTP method: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD. Default: GET."] = "GET",
        headers: Annotated[str, "JSON string of HTTP headers (e.g. '{\"Authorization\": \"Bearer token123\"}'). Default: none."] = "",
        data: Annotated[str, "Request body. For JSON: '{\"key\": \"value\"}'. For form: 'user=test&pass=test'. Default: none."] = "",
    ) -> str:
        """Make an HTTP request with security-focused analysis.

        **When to use**:
        - Testing specific API endpoints for injection
        - Checking response headers for security misconfigurations
        - Sending crafted payloads (SQLi, XSS, SSRF probes)
        - Authenticated requests with custom headers/cookies

        **When NOT to use**:
        - For comprehensive automated testing (use numasec_assess)
        - For browser-rendered pages (use numasec_browser)
        """
        parsed_headers = None
        if headers:
            if len(headers) > 32768:
                return "**Error:** Headers JSON exceeds 32KB size limit."
            try:
                parsed_headers = json.loads(headers)
            except json.JSONDecodeError:
                return f"**Error:** Invalid JSON in headers: `{headers[:200]}`"

        return await run_http_request(
            url=url,
            method=method,
            headers=parsed_headers,
            data=data,
        )

    # ═════════════════════════════════════════════════════════════════════
    # Tool 5: numasec_browser — Mid-level browser automation
    # ═════════════════════════════════════════════════════════════════════

    @mcp.tool(annotations={
        "title": "Browser Automation",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    })
    async def numasec_browser(
        url: Annotated[str, "Target URL to interact with"],
        action: Annotated[str, "Browser action: 'navigate' (load page), 'screenshot' (capture page), 'fill' (fill form field), 'click' (click element). Default: 'navigate'."] = "navigate",
        selector: Annotated[str, "CSS selector for fill/click actions (e.g. '#username', 'button[type=submit]'). Required for fill and click actions."] = "",
        value: Annotated[str, "Value to fill in form fields. Required for fill action."] = "",
    ) -> str:
        """Browser automation for testing JavaScript-heavy apps.

        Uses a real browser (Playwright) with stealth mode for realistic testing.
        Handles SPAs, JavaScript-rendered content, cookies, and form interactions.

        **When to use**:
        - Testing XSS in JavaScript-rendered pages
        - Filling and submitting login forms
        - Interacting with single-page applications (React, Vue, Angular)
        - Taking screenshots for evidence

        **When NOT to use**:
        - For simple HTTP requests (use numasec_http — it's faster)
        - For API endpoints that don't need rendering (use numasec_http)
        """
        return await run_browser_action(
            url=url, action=action, selector=selector, value=value,
        )

    # ═════════════════════════════════════════════════════════════════════
    # Tool 6: numasec_get_knowledge — Knowledge base access
    # ═════════════════════════════════════════════════════════════════════

    @mcp.tool(annotations={
        "title": "Security Knowledge Base",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    })
    async def numasec_get_knowledge(
        topic: Annotated[str, "Knowledge topic to retrieve. Examples: 'web-cheatsheet', 'sqli-to-rce', 'linux-cheatsheet', 'payloads/command-injection'. Use hyphens, not underscores."],
    ) -> str:
        """Access NumaSec's security knowledge base — cheatsheets, payloads, attack chains.

        46+ curated security documents covering:
        - Web vulnerabilities (SQLi, XSS, SSRF, SSTI, file upload, etc.)
        - Attack chains (SQLi→RCE, LFI→RCE, SSTI→RCE, Upload→RCE)
        - OS cheatsheets (Linux, Windows, Active Directory)
        - Cloud security (AWS, Azure, GCP exploitation)
        - Payloads (command injection, PHP RCE, Python sandbox escape)
        - Binary exploitation (heap, ROP, reversing)
        - Crypto, OSINT, blockchain cheatsheets

        **When to use**:
        - After finding a vulnerability — get exploitation techniques
        - Understanding remediation strategies for specific vuln types
        - Getting payload lists for manual testing
        - Learning attack chain escalation paths

        **When NOT to use**:
        - For running actual security tests (use numasec_assess or other tools)

        **Example topics**: 'web-cheatsheet', 'linux-cheatsheet', 'attack-chains/sqli-to-rce',
        'payloads/command-injection', 'cloud/cloud-exploitation', 'quick-wins'
        """
        return read_knowledge(topic)

    # ═════════════════════════════════════════════════════════════════════
    # Tool 7: create_finding — Register a vulnerability
    # ═════════════════════════════════════════════════════════════════════

    @mcp.tool(annotations={
        "title": "Register Finding",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    })
    async def create_finding(
        title: Annotated[str, "Short finding title (e.g. 'SQL Injection in /api/users')"],
        severity: Annotated[str, "Severity: 'critical', 'high', 'medium', 'low', or 'info'. Guide: critical=RCE/auth bypass, high=SQLi/XSS/SSRF, medium=misconfig/info disclosure, low=missing headers, info=version disclosure"],
        description: Annotated[str, "Detailed description of the vulnerability and its impact"],
        evidence: Annotated[str, "Proof: HTTP request/response, payload used, command output, screenshot path"] = "",
    ) -> str:
        """Register a security finding/vulnerability.

        Use this to document any vulnerability you discover during testing.
        Findings are collected and included in the assessment report.

        **When to use**: Every time you confirm a vulnerability, misconfiguration,
        or information disclosure. It's better to over-report than to miss something.
        """
        return await run_create_finding(
            title=title, severity=severity, description=description, evidence=evidence,
        )

    # ═════════════════════════════════════════════════════════════════════
    # MCP Resources — Knowledge Base (46+ files)
    # ═════════════════════════════════════════════════════════════════════

    @mcp.resource("numasec://kb/{path}")
    async def kb_resource(path: str) -> str:
        """Security knowledge base — cheatsheets, payloads, attack chains.

        Read any of 46+ curated security documents directly.
        """
        return read_knowledge(path)

    # Also register a resource listing
    @mcp.resource("numasec://kb")
    async def kb_index() -> str:
        """List all available knowledge base topics."""
        topics = list_knowledge_topics()
        lines = ["# NumaSec Knowledge Base\n", f"**{len(topics)} topics available**\n"]
        for t in topics:
            lines.append(f"- [{t['name']}]({t['uri']}) — {t['description'][:80]}")
        return "\n".join(lines)

    # ═════════════════════════════════════════════════════════════════════
    # MCP Prompts — Workflow Templates
    # ═════════════════════════════════════════════════════════════════════

    @mcp.prompt()
    def security_assessment(target: str) -> str:
        """Complete security assessment workflow for a web application."""
        return (
            f"Run a thorough security assessment on {target}.\n\n"
            "Recommended workflow (non-blocking, with live progress):\n"
            "1. Call numasec_quick_check for a fast initial scan (30 seconds)\n"
            "2. Review quick check results — note technologies and open ports\n"
            "3. Call numasec_assess_start for the full autonomous assessment\n"
            "4. Tell the user the assessment has started\n"
            "5. Call numasec_assess_status — it waits for new findings automatically\n"
            "6. Share NEW findings briefly with the user\n"
            "7. ⚠️ If status ≠ COMPLETED → call numasec_assess_status AGAIN\n"
            "8. Keep looping steps 5-7 — expect 5-15 calls over 5-20 minutes\n"
            "9. ONLY when status = COMPLETED → present the full final report\n"
            "10. For each CRITICAL/HIGH finding, read relevant knowledge:\n"
            "   - SQL Injection → numasec://kb/web-cheatsheet\n"
            "   - XSS → numasec://kb/web-cheatsheet\n"
            "   - File Upload → numasec://kb/payloads/file-upload\n"
            "   - SSTI → numasec://kb/ssti-advanced-bypasses\n"
            "11. Provide remediation recommendations\n\n"
            "⚠️ IMPORTANT: Do NOT present partial findings as a final report.\n"
            "The assessment discovers more vulnerabilities over time. Wait for COMPLETED."
        )

    @mcp.prompt()
    def quick_security_check(target: str) -> str:
        """Quick 30-second security spot check."""
        return (
            f"Quick security check on {target}.\n\n"
            "Use numasec_quick_check for rapid vulnerability detection.\n"
            "Report findings and suggest immediate fixes.\n"
            "If critical issues are found, recommend running numasec_assess for deeper testing."
        )

    return mcp


# ═══════════════════════════════════════════════════════════════════════════
# Server Runner
# ═══════════════════════════════════════════════════════════════════════════


async def run_mcp_server(transport: str = "stdio"):
    """Start the MCP server with the specified transport.

    Args:
        transport: 'stdio' for local clients, 'http' for remote/multi-session
    """
    mcp = create_mcp_server()

    logger.info(f"NumaSec MCP server starting (transport={transport})")

    if transport == "http":
        await mcp.run_streamable_http_async()
    else:
        await mcp.run_stdio_async()


# ═══════════════════════════════════════════════════════════════════════════
# Claude Desktop Auto-Setup
# ═══════════════════════════════════════════════════════════════════════════


def setup_claude_desktop():
    """Auto-configure Claude Desktop to use NumaSec.

    Detects OS, finds the Claude Desktop config file, and adds NumaSec
    as an MCP server. Idempotent — safe to run multiple times.
    """
    system = platform.system()

    if system == "Darwin":
        config_path = Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif system == "Linux":
        config_path = Path.home() / ".config" / "Claude" / "claude_desktop_config.json"
    elif system == "Windows":
        config_path = Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    else:
        print(f"Unsupported OS: {system}")
        print("Manually add NumaSec to your MCP client configuration.")
        return

    # Load existing config or create new
    config: dict = {}
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            config = {}

    # Find the numasec executable
    numasec_cmd = _find_numasec_executable()

    # Add/update NumaSec server config
    config.setdefault("mcpServers", {})
    # If fallback to python executable, use -m numasec invocation
    if numasec_cmd == sys.executable:
        config["mcpServers"]["numasec"] = {
            "command": numasec_cmd,
            "args": ["-m", "numasec", "--mcp"],
        }
    else:
        config["mcpServers"]["numasec"] = {
            "command": numasec_cmd,
            "args": ["--mcp"],
        }

    # Write config
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    print("✅ NumaSec configured for Claude Desktop!")
    print(f"   Config: {config_path}")
    print(f"   Command: {numasec_cmd} --mcp")
    print()
    print("   Restart Claude Desktop to see NumaSec tools.")
    print()
    print("   6 of 7 tools work WITHOUT any API key (zero friction).")
    print("   To unlock the full autonomous agent (numasec_assess):")
    print("     export DEEPSEEK_API_KEY=sk-...  ($0.12 per scan)")
    print()
    print("   Try asking Claude: 'Run a security check on http://localhost:3000'")


def _find_numasec_executable() -> str:
    """Find the numasec executable path."""
    import shutil

    # Check if numasec is in PATH
    which = shutil.which("numasec")
    if which:
        return which

    # Check common locations
    candidates = [
        Path(sys.executable).parent / "numasec",
        Path.home() / ".local" / "bin" / "numasec",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    # Fallback: use the python module invocation (split for MCP hosts)
    return sys.executable
