<div align="center">

# NumaSec

### Vibe coding changed how we build. NumaSec changes how we secure it.

One command. Real vulnerabilities. Full report. **$0.12.**

<img src="docs/assets/demo.gif" alt="NumaSec Demo" width="700">

[![$0.12/scan](https://img.shields.io/badge/cost-$0.12%2Fscan-00ff41?style=flat-square&labelColor=0d1117)](#quick-start)
[![20 Security Tools](https://img.shields.io/badge/tools-20_security_scanners-00ff41?style=flat-square&labelColor=0d1117)](#what-it-finds)
[![Bring Your Own LLM](https://img.shields.io/badge/LLM-bring_your_own-00ff41?style=flat-square&labelColor=0d1117)](#quick-start)
[![MIT License](https://img.shields.io/badge/license-MIT-00ff41?style=flat-square&labelColor=0d1117)](LICENSE)

</div>

---

You describe the target. NumaSec runs 19 security tools, finds real vulnerabilities, and writes the report. No security expertise. No config files. No $10K consultant.

```bash
pip install numasec && numasec --demo
```

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

Every assessment produces a professional HTML report — dark theme, severity donut chart, evidence blocks, remediation steps. Share it with your team, attach it to a ticket, or hand it to an AI to fix the code.

<div align="center">
<img src="docs/assets/report.gif" alt="NumaSec Security Report" width="700">
</div>

---

## How It Works

```
You describe the target
  → AI plans the attack (discovery → mapping → testing → exploitation → results)
  → Picks the right tool for each step (19 tools: nmap, sqlmap, Playwright, nuclei...)
  → Analyzes results, generates hypotheses, adapts the plan
  → Confirmed findings documented with evidence and fixes
  → Professional report generated automatically
```

It's not a scanner. It's not a ChatGPT wrapper. It's an autonomous agent with structured memory, attack planning, 14 result extractors, 14 escalation chains, and a 46-file knowledge base — all orchestrated by a ReAct loop that thinks before it acts.

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
```

12,000+ lines of Python. 170+ tests. 5 core dependencies.

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

---

## Legal

**Only test apps you own or have explicit permission to test.** NumaSec is a security tool — use it responsibly.

✅ Your own apps, staging/production environments, bug bounty targets, practice labs (DVWA, Juice Shop, HackTheBox)

❌ Other people's apps without written authorization

---

## Roadmap

- Parallel tool execution (asyncio.gather for independent scans)
- LLM-powered planning (adaptive strategies based on target type)
- Benchmark suite (automated scoring against DVWA, Juice Shop, WebGoat)
- CI/CD integration (security gates in deployment pipelines)
- MCP integration (Model Context Protocol for tool interoperability)

See [VISION.md](docs/notes/VISION.md) for the full technical blueprint.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues, PRs, and feedback welcome.

---

**Built by [Francesco Stabile](https://www.linkedin.com/in/francesco-stabile-dev)** — making security accessible to every developer.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/francesco-stabile-dev)
[![X](https://img.shields.io/badge/X-000000?style=flat-square&logo=x&logoColor=white)](https://x.com/Francesco_Sta)

[MIT License](LICENSE)
