# security-mcp

MCP server that gives your AI assistant (Claude Code, Copilot, Cursor) a full appsec toolkit: vulnerability scanners, session management, and reporting. Point it at a web target, it runs a PTES assessment and produces findings with CWE, CVSS, and OWASP classification.

> **Quick setup:** paste this README into Claude Code, GitHub Copilot Chat, or Claude Desktop and ask *"Install and configure security-mcp as MCP server"*, the AI will handle the rest.

---

## Install

```bash
git clone
cd security-mcp
pip install -e ".[mcp]"
playwright install chromium
```

Verify:
```bash
security-mcp --version
```

---

## Setup: Claude Code

Add to your project's `.mcp.json` or global `~/.claude.json`:

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "security-mcp",
      "args": ["--mcp"],
      "env": {
        "SECMCP_ALLOW_INTERNAL": "1"
      }
    }
  }
}
```

Restart Claude Code. The 47 tools appear automatically.

## Setup: GitHub Copilot (VS Code)

Create `.vscode/mcp.json` in your project root:

```json
{
  "servers": {
    "security-mcp": {
      "command": "security-mcp",
      "args": ["--mcp"],
      "env": {
        "SECMCP_ALLOW_INTERNAL": "1"
      }
    }
  }
}
```

Reload VS Code (Ctrl+Shift+P → "Developer: Reload Window"). In Copilot Chat, switch to **Agent** mode — the tools appear in the 🔧 menu.

Requires VS Code 1.99+ and GitHub Copilot Chat extension.

## Setup: Claude Desktop

Edit `claude_desktop_config.json` (`%APPDATA%\Claude\` on Windows, `~/Library/Application Support/Claude/` on macOS):

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "security-mcp",
      "args": ["--mcp"],
      "env": {
        "SECMCP_ALLOW_INTERNAL": "1"
      }
    }
  }
}
```

Restart Claude Desktop.

## Setup: Cursor

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "security-mcp",
      "args": ["--mcp-http"]
    }
  }
}
```

Cursor uses HTTP transport (`--mcp-http`), not stdio.

---

## Environment variables

security-mcp does not read `.env` files. Variables are passed via the `"env"` block in the MCP config above.

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECMCP_ALLOW_INTERNAL` | `0` | Set to `1` to scan localhost/private IPs (lab targets) |
| `MCP_TRANSPORT` | `stdio` | Transport override: `stdio` or `http` |
| `SECMCP_RATE_PER_MINUTE` | `60` | Per-session rate limit (calls/min) |
| `SECMCP_RATE_CONCURRENT` | `5` | Per-session max concurrent tool calls |
| `SECMCP_RATE_GLOBAL_PER_MINUTE` | `120` | Global rate limit across all sessions |
| `SECMCP_RATE_GLOBAL_CONCURRENT` | `10` | Global max concurrent tool calls |

---

## Quick start

Once connected, ask your AI assistant:

> "Run a security assessment on http://localhost:3000"

Or step by step:

1. **"Create a session for http://localhost:3000"** → `create_session`
2. **"Get a scan plan for this target"** → `get_scan_plan`
3. **"Run the mandatory tests"** → `get_mandatory_tests` → individual scanner tools
4. **"Check OWASP coverage gaps"** → `get_coverage_gaps`
5. **"Generate a SARIF report"** → `generate_report`

Every finding saved via `save_finding` is auto-enriched with CVSS v3.1 score, CWE, OWASP Top 10 category, and MITRE ATT&CK technique.

---

## What's included

- **36 atomic security tools** — port scan, HTTP requests, browser automation, 22 vulnerability scanners
- **7 intelligence tools** — KB search, CWE info, PTES scan planning, OWASP coverage tracking
- **4 session tools** — create session, save findings, get findings, generate reports (SARIF, HTML, Markdown, JSON)
- **3 prompt templates** — `security_assessment` (full PTES workflow), `threat_model` (STRIDE), `code_review` (OWASP/CWE)

## Responsible use

This tool is for authorized testing only:
- Pentest sessions on **authorized** test/staging environments
- Internal security reviews before deployment
- Security training labs (DVWA, Juice Shop, WebGoat)
