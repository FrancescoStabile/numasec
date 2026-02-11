<div align="center">

# NumaSec

### AI security testing for your apps. One command, real vulnerabilities, full report.

Works inside **Claude Desktop**, **Cursor**, **VS Code** — or standalone as CLI.
$0.12 per scan with DeepSeek. MIT license.

<img src="docs/assets/demo.gif" alt="NumaSec Demo" width="700">

*NumaSec autonomously finding 8 vulnerabilities in [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — a deliberately insecure web app used as a security training benchmark.*

[![$0.12/scan](https://img.shields.io/badge/cost-$0.12%2Fscan-58a6ff?style=flat-square&labelColor=0d1117)](#quick-start)
[![MCP Native](https://img.shields.io/badge/MCP-native-10b981?style=flat-square&labelColor=0d1117)](#mcp-integration)
[![20 Tools](https://img.shields.io/badge/tools-20_security_tools-f59e0b?style=flat-square&labelColor=0d1117)](#how-it-works)
[![Autonomous Agent](https://img.shields.io/badge/agent-fully_autonomous-8b5cf6?style=flat-square&labelColor=0d1117)](#how-it-works)
[![MIT License](https://img.shields.io/badge/license-MIT-6b7280?style=flat-square&labelColor=0d1117)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/FrancescoStabile/numasec/ci.yml?branch=main&style=flat-square&labelColor=0d1117&label=CI)](https://github.com/FrancescoStabile/numasec/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/numasec?style=flat-square&labelColor=0d1117&color=3b82f6)](https://pypi.org/project/numasec/)

</div>

---

You describe the target. NumaSec figures out how to break in — planning the attack, picking techniques, adapting on the fly, and writing the report. No security expertise. No config files. No $10K consultant.

```bash
# MCP — use from Claude Desktop, Cursor, or any MCP client
pip install 'numasec[mcp]' && numasec setup-claude

# CLI — interactive terminal
pip install numasec && numasec check http://localhost:3000
```

---

## MCP Integration — Find Vulnerabilities *and* Fix Them

NumaSec is a native [Model Context Protocol](https://modelcontextprotocol.io) server. This isn't just scanning — it's a complete **find → understand → fix** workflow inside your IDE.

**Setup (30 seconds):**

```bash
pip install 'numasec[mcp]'
numasec setup-claude    # Auto-configures Claude Desktop
```

Restart Claude Desktop. Done.

### Find vulnerabilities

> "Hey Claude, test my app at localhost:3000 for security issues"

NumaSec runs a full autonomous pentest — port scanning, tech fingerprinting, SQLi/XSS testing, directory fuzzing — and reports back with findings, evidence, and CVSS scores.

### Understand the root cause

> "Explain the SQL injection you found and show me the vulnerable code"

Claude reads NumaSec's 46+ security knowledge resources (`numasec://kb/*`) to explain *why* the vulnerability exists, what the impact is, and references the relevant CWE/OWASP classification.

### Fix the code in your IDE

> "Fix the SQL injection in routes/search.ts"

With your project open in Cursor or VS Code, Claude can **apply the fix directly** — replacing string concatenation with parameterized queries, adding missing security headers, escaping user input. You go from vulnerability to remediation without leaving your editor.

**This is the key difference**: traditional scanners give you a PDF and walk away. NumaSec + MCP gives you a pentester *and* a security engineer, integrated into your development workflow.

### What you get

| MCP Feature | What It Does |
|---|---|
| **10 Tools** | `numasec_assess`, `numasec_assess_start`, `numasec_assess_status`, `numasec_assess_cancel`, `numasec_quick_check`, `numasec_recon`, `numasec_http`, `numasec_browser`, `numasec_get_knowledge`, `create_finding` |
| **46+ Resources** | Security knowledge base — cheatsheets, attack chains, payloads, remediation guides |
| **2 Prompts** | `security_assessment` (full workflow), `quick_security_check` (30-second check) |
| **Standards** | Every finding enriched with CVSS v3.1, CWE-ID, OWASP Top 10 category |

<details>
<summary><b>Client configuration: Claude Desktop, Cursor, VS Code</b></summary>

**Claude Desktop** (automatic):
```bash
numasec setup-claude  # writes ~/.config/Claude/claude_desktop_config.json
```

**Cursor** — add to Settings → MCP Servers:
```json
{
  "numasec": {
    "command": "numasec",
    "args": ["--mcp"],
    "env": { "DEEPSEEK_API_KEY": "sk-..." }
  }
}
```

**VS Code** — add to `.vscode/mcp.json`:
```json
{
  "servers": {
    "numasec": {
      "command": "numasec",
      "args": ["--mcp"],
      "env": { "DEEPSEEK_API_KEY": "sk-..." }
    }
  }
}
```

**Transports:**
```bash
numasec --mcp                   # stdio (Claude Desktop, Cursor — default)
numasec --mcp-http              # HTTP (remote clients, web UIs)
numasec --mcp-http --port 9090  # custom port
```

Full setup guide: [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md)

</details>

---

## What It Finds

NumaSec doesn't just scan — it thinks. It plans an attack strategy, picks the right tools, adapts based on what it discovers, and escalates when it finds something real.

| What it tests | How |
|--------------|-----|
| **Exposed secrets** — .env files, API keys, credentials in source | HTTP probing, directory fuzzing |
| **SQL injection** — auth bypass, data extraction, blind injection | Manual payloads → sqlmap escalation |
| **XSS** — reflected, stored, DOM-based in forms and search fields | Playwright browser automation with screenshots |
| **Misconfigurations** — missing headers, debug mode, stack traces | Response analysis, technology fingerprinting |
| **Known CVEs** — outdated frameworks, vulnerable dependencies | Nuclei templates, version detection |
| **Auth flaws** — default creds, IDOR, broken access controls | Login testing, session analysis |

Every finding comes with evidence and a fix — not just "vulnerability found", but *what's wrong*, *why it matters*, and *exactly how to fix it*.

<details>
<summary><b>Example output</b></summary>

```
λ check http://localhost:3000 for security issues

  ◉ SCANNING
  http://localhost:3000

  ── [1] http → GET http://localhost:3000/
  │ 200
  │ server: Express
  │ x-powered-by: Express
  └─ 0.1s

  ── [2] http → GET http://localhost:3000/.env
  │ 200
  │ DATABASE_URL=postgresql://admin:supersecret@db:5432/myapp
  │ JWT_SECRET=mysecretkey123
  └─ 0.2s

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ▲▲ CRITICAL — Environment File Exposed
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  │ The .env file is publicly accessible. It contains the
  │ database password, JWT secret, and API keys. Anyone can
  │ read them.
  │
  │ Evidence:   GET /.env → 200 OK with credentials
  │ Fix:        Block .env in Express static config
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ▲▲ CRITICAL — SQL Injection in Login
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  │ The login endpoint doesn't sanitize input. A single
  │ payload bypasses authentication and grants admin access
  │ to any account.
  │
  │ Payload:    ' OR '1'='1
  │ Evidence:   POST /api/auth/login → 200 OK with admin token
  │ Fix:        Use parameterized queries (Prisma/Sequelize)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ┌──────────────────────────────────────────────────────┐
  │              ASSESSMENT COMPLETE                     │
  │                                                      │
  │  Target:    http://localhost:3000                    │
  │  Duration:  4m 23s                                   │
  │  Cost:      $0.12                                    │
  │                                                      │
  │  ▲▲ 2 CRITICAL   ▲ 1 HIGH                            │
  │  ■  1 MEDIUM     ● 1 LOW                             │
  │                                                      │
  │  Risk Level: CRITICAL                                │
  │                                                      │
  │  Critical security issues detected — immediate       │
  │  action required. Fix critical findings first.       │
  └──────────────────────────────────────────────────────┘
```

</details>

---

## Quick Start

```bash
pip install numasec
```

**See it work instantly** — no API key, no target, no setup:

```bash
numasec --demo
```

**Run it for real** — set one API key and go:

```bash
export DEEPSEEK_API_KEY="sk-..."    # ~$0.12/scan, 1M free tokens for new accounts
numasec
```

That's it. Paste a URL, describe what to test, and NumaSec handles the rest.

<details>
<summary><b>More options</b> — Claude, OpenAI, Ollama, browser mode, security tools</summary>

```bash
# AI providers (set any combination — automatic fallback)
export DEEPSEEK_API_KEY="sk-..."          # Cheapest (~$0.12/scan)
export ANTHROPIC_API_KEY="sk-ant-..."     # Best reasoning
export OPENAI_API_KEY="sk-..."            # General purpose
# Ollama detected automatically if running locally (free)

# Browser automation — XSS testing, form filling, visual evidence
playwright install chromium

# Security scanners — advanced vulnerability detection
sudo apt install nmap sqlmap
# nuclei: https://github.com/projectdiscovery/nuclei

# Usage
numasec                              # Interactive mode
numasec check http://localhost:3000  # One-shot check
numasec --show-browser               # Watch the browser in real-time
numasec --budget 5.0                 # Set cost limit
numasec --resume <session-id>        # Resume a previous session
```

</details>

---

## The Report

Every assessment produces a professional report — **PDF** (branded cover page, severity donut charts, CVSS/CWE/OWASP metadata) or **HTML** (dark theme, interactive). Share it with your team, attach it to a ticket, or hand it to an AI to fix the code.

<div align="center">
<img src="docs/assets/report.gif" alt="NumaSec Security Report" width="700">
</div>

---

## How It Works

```
You describe the target
  → AI plans the attack (discovery → mapping → testing → exploitation → results)
  → Picks the right tool for each step (20 tools: nmap, sqlmap, Playwright, nuclei...)
  → Analyzes results, generates hypotheses, adapts the plan
  → Confirmed findings documented with evidence and fixes
  → Professional report generated automatically
```

It's not a scanner. It's not a ChatGPT wrapper. It's an autonomous agent with structured memory, attack planning, 14 result extractors, 14 escalation chains, and a 46-file knowledge base — all orchestrated by a ReAct loop that thinks before it acts.

Every finding is automatically enriched with CVSS v3.1 scores, CWE identifiers, and OWASP Top 10 categories. Use it as a CLI pentester, or plug it into your IDE via MCP and fix vulnerabilities as they're found.

<details>
<summary><b>Architecture deep dive</b></summary>

```
cli.py          → Interactive REPL with real-time streaming
agent.py        → ReAct loop (50 iterations, loop detection, circuit breaker)
router.py       → Multi-provider LLM routing (DeepSeek → Claude → OpenAI → Ollama)
planner.py      → 5-phase attack plan (discovery → mapping → testing → analysis → results)
state.py        → Structured memory (TargetProfile with ports, endpoints, technologies)
extractors.py   → 14 extractors parse tool output into structured data automatically
reflection.py   → 7 tool-specific analyzers guide what to check next
chains.py       → 14 escalation chains (SQLi→RCE, LFI→RCE, SSTI→RCE, XSS→session theft...)
knowledge/      → 46 attack patterns, cheatsheets, and payload references
report.py       → Reports in Markdown, HTML, and JSON
plugins.py      → Extend with custom tools, chains, and extractors
renderer.py     → Terminal UI with character-by-character streaming
mcp_server.py   → FastMCP server (10 tools, 46+ resources, 2 prompts)
mcp_tools.py    → MCP tool implementations bridging to the engine
mcp_resources.py→ Knowledge base exposed as MCP Resources
```

17,800+ lines of Python. 388 tests. MIT license.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full technical breakdown.

</details>

<details>
<summary><b>Python API</b></summary>

```python
from numasec.agent import Agent
from numasec.router import LLMRouter, Provider
from numasec.tools import create_tool_registry
from numasec.state import State

router = LLMRouter(primary=Provider.DEEPSEEK)
tools = create_tool_registry()
state = State()
agent = Agent(router=router, tools=tools, state=state)

async for event in agent.run("find SQLi in localhost:3000"):
    if event.type == "text":
        print(event.content, end="")
    elif event.type == "finding":
        print(f"Found: {event.finding.title}")
```

</details>

<details>
<summary><b>MCP Resources — 46+ security knowledge files</b></summary>

NumaSec's entire knowledge base is exposed as MCP Resources. Any MCP client can read them:

```
numasec://kb/web-cheatsheet          → OWASP Top 10, XSS/SQLi/SSTI payloads
numasec://kb/linux-cheatsheet        → Privilege escalation, enumeration
numasec://kb/attack-decision-matrix  → Automated attack path selection
numasec://kb/blind-injection         → Boolean/time-based blind SQLi techniques
numasec://kb/ssti-advanced-bypasses  → Jinja2/Twig/Freemarker SSTI chains
numasec://kb/crypto-cheatsheet       → TLS, JWT, hash cracking
numasec://kb/osint-cheatsheet        → Reconnaissance, subdomain enum
numasec://kb/quick-wins              → Fast checks that find real bugs
... and 38 more
```

Claude reads these automatically during assessments to suggest accurate fixes.

</details>

---

## Legal

**Only test apps you own or have explicit permission to test.** NumaSec is a security tool — use it responsibly.

**Yes:** Your own apps, staging/production environments, bug bounty targets, practice labs (DVWA, Juice Shop, HackTheBox)

**No:** Other people's apps without written authorization

---

## Roadmap

- [x] MCP integration (Claude Desktop, Cursor, VS Code)
- [x] 46-file knowledge base as MCP Resources
- [x] Browser automation (8 Playwright tools)
- [x] Standards engine (CVSS v3.1, CWE, OWASP Top 10 auto-enrichment)
- [x] Attack graph (multi-stage exploitation chains)
- [x] PDF reports (professional pentest reports with severity charts)
- [x] Pydantic-validated findings with auto-enrichment
- [ ] Parallel tool execution (asyncio.gather for independent scans)
- [ ] CI/CD integration (security gates in deployment pipelines)
- [ ] Plugin marketplace (community tools, chains, extractors)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues, PRs, and feedback welcome.

---

**Built by [Francesco Stabile](https://www.linkedin.com/in/francesco-stabile-dev)** — making security accessible to every developer.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/francesco-stabile-dev)
[![X](https://img.shields.io/badge/X-000000?style=flat-square&logo=x&logoColor=white)](https://x.com/Francesco_Sta)

[MIT License](LICENSE)
