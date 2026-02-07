<div align="center">

# NumaSec

**AI security testing for your apps.**

Paste a URL. Get a security report. Fix what matters.

<img src="docs/assets/demo.gif" alt="NumaSec Demo" width="700">

[Get Started](#quick-start) · [How It Works](#how-it-works) · [Architecture](#architecture) · [Docs](docs/)

[![MIT License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue?style=flat-square)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-184_passed-green?style=flat-square)](#)

</div>

---

**Vibe coding gave everyone the power to build. NumaSec gives everyone the power to secure what they build.**

NumaSec is an open-source CLI that checks your app for security vulnerabilities — automatically. You tell it what to test, it figures out the rest: finds open ports, checks for SQL injection, tests your forms, and generates a report explaining what's wrong and how to fix it.

No security expertise required. Average cost: **$0.12** with DeepSeek. Average time: **5 minutes**.

```
You: check http://localhost:3000 for security issues

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

## Quick Start

### Install

```bash
pip install numasec
```

### See it in action (no API key needed)

```bash
numasec --demo
```

### Configure

```bash
# DeepSeek (cheapest — ~$0.12/scan, 1M free tokens for new accounts)
export DEEPSEEK_API_KEY="sk-..."

# Or Claude / OpenAI (automatic fallback)
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

### Check your app

```bash
numasec                              # Interactive mode
numasec check http://localhost:3000  # Quick one-shot check
```

That's it. Describe what you want to test and NumaSec handles the rest.

### Optional: Full Power

```bash
# Browser automation (XSS testing, form filling, screenshots)
playwright install chromium

# Security tools (advanced scanning)
sudo apt install nmap sqlmap
# nuclei: https://github.com/projectdiscovery/nuclei
```

---

## How It Works

NumaSec is an AI agent that thinks like a security tester. It plans what to check, uses real security tools, analyzes the results, and adapts — just like a human would, but faster and cheaper.

```
Your app URL
  → AI plans the assessment (discovery → testing → results)
  → For each step:
      → AI picks the right tool + arguments
      → Tool runs (http requests, browser tests, scanners)
      → Results are analyzed automatically
      → AI decides what to check next
  → Security issues documented with evidence
  → Report generated with fixes
```

The agent adapts in real-time. If it finds a suspicious endpoint, it tests it. If SQL injection is confirmed, it digs deeper. If a tool isn't installed, it falls back to HTTP requests and browser automation.

---

## Tools

19 integrated security tools, all orchestrated by the agent:

| Category | Tools |
|----------|-------|
| **Recon** | `nmap` · `httpx` · `subfinder` · `ffuf` |
| **Web Testing** | `http` · `browser_navigate` · `browser_fill` · `browser_click` · `browser_screenshot` · `browser_login` · `browser_get_cookies` · `browser_set_cookies` · `browser_clear_session` |
| **Exploitation** | `nuclei` · `sqlmap` · `run_exploit` |
| **Utility** | `read_file` · `write_file` · `run_command` |

The browser tools use Playwright for full JavaScript rendering — SPAs, form interactions, authenticated sessions, and visual evidence capture.

```bash
# Watch the browser in real-time during assessments
numasec --show-browser
```

---

## Architecture

```
cli.py          → Interactive REPL with streaming output
agent.py        → AI loop (max 50 iterations, loop detection, circuit breaker)
router.py       → Multi-provider AI routing (DeepSeek → Claude → OpenAI → Ollama)
planner.py      → 5-phase testing plan (discovery → mapping → testing → analysis → results)
state.py        → Structured memory (what's been found so far)
extractors.py   → 14 extractors parse tool output into structured data
reflection.py   → 7 tool-specific analyzers guide what to check next
chains.py       → 14 escalation chains (SQLi→RCE, LFI→RCE, SSTI→RCE, etc.)
knowledge/      → 46 attack patterns, cheatsheets, and payload references
report.py       → Reports in Markdown, HTML, and JSON
plugins.py      → Extend with custom tools, chains, and extractors
renderer.py     → Terminal UI with real-time streaming
```

**11,800+ lines of Python. 184 tests. 5 core dependencies.**

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical details.

---

## Usage

### CLI

```bash
numasec                              # Interactive mode
numasec check http://localhost:3000  # Quick one-shot check
numasec --demo                       # See it in action (no API key)
numasec --show-browser               # Watch the browser testing in real-time
numasec --verbose                    # Debug logging
numasec --budget 5.0                 # Set cost limit
numasec --resume <session-id>        # Resume a previous session
```

### Commands

```
/plan          Show testing progress
/findings      List discovered security issues
/report html   Generate full HTML report
/export md     Export Markdown report
/export json   Export JSON report
/cost          Show cost breakdown by provider
/stats         Session statistics
/history       Recent sessions
/resume <id>   Resume a session
/demo          Run demo assessment
/clear         Reset session
/quit          Exit
```

### Python API

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

---

## LLM Providers

NumaSec supports multiple LLM providers with automatic fallback:

| Provider | Avg. Cost | Best For |
|----------|-----------|----------|
| **DeepSeek** | $0.12/assessment | Default — best cost/performance ratio |
| **Claude** | $0.50–0.80/assessment | Complex reasoning, report writing |
| **OpenAI** | $0.40–0.70/assessment | General purpose |
| **Ollama** | Free (local) | Offline use, privacy-sensitive targets |

Set any combination of API keys. NumaSec routes to the cheapest available provider and falls back automatically on failure.

---

## Cost

| Approach | Cost | Time |
|----------|------|------|
| Hiring a security consultant | $2,000–10,000 | 1–2 weeks |
| Learning security yourself | Free | Months |
| NumaSec + DeepSeek | **$0.10–0.15** | 5–15 minutes |
| NumaSec + Claude | $0.30–0.80 | 5–15 minutes |

---

## Legal & Ethics

**Only test apps you own or have permission to test.**

✅ OK to test:
- Your own apps (localhost, staging, production)
- Bug bounty targets (HackerOne, Bugcrowd)
- Practice environments (DVWA, Juice Shop, HackTheBox)
- Systems with written authorization

❌ Not OK:
- Other people's apps without permission
- Random websites on the internet

---

## Roadmap

See [VISION.md](docs/notes/VISION.md) for the full technical blueprint.

**Next up:**
- Parallel tool execution (asyncio.gather for independent calls)
- LLM-powered planning (adaptive plans based on target type)
- Benchmark suite (automated scoring against DVWA, Juice Shop, WebGoat)
- CI/CD integration (security gates in deployment pipelines)
- MCP integration (Model Context Protocol for tool interoperability)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues, PRs, and feedback are welcome.

---

## Author

**Francesco Stabile** — Making security accessible to every developer.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/francesco-stabile-dev)
[![X](https://img.shields.io/badge/X-000000?style=flat-square&logo=x&logoColor=white)](https://x.com/Francesco_Sta)

---

## License

[MIT](LICENSE)
