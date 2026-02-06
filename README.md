<div align="center">

# NumaSec

**Autonomous AI agent for penetration testing.**

Describe a target in natural language. Get real vulnerabilities, evidence, and professional reports.

<img src="docs/assets/demo.gif" alt="NumaSec Demo" width="700">

[Get Started](#quick-start) · [How It Works](#how-it-works) · [Architecture](#architecture) · [Docs](docs/)

[![MIT License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue?style=flat-square)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-184_passed-green?style=flat-square)](#)

</div>

---

NumaSec is an open-source CLI agent that runs security assessments autonomously. You type what you want to test — it plans the attack, executes 19 integrated tools, extracts findings with evidence, and generates a professional report.

Average cost per assessment: **$0.12** with DeepSeek. Average time: **5 minutes**.

```
You: test http://localhost:3000 for vulnerabilities

  ◉ TARGET ACQUIRED
  http://localhost:3000

  ── [1] nmap → localhost -sV -sC
  │ 22/tcp   open  ssh      OpenSSH 8.2p1
  │ 80/tcp   open  http     Apache 2.4.41
  │ 3000/tcp open  http     Node.js Express
  └─ 1.2s

  ── [2] ffuf → http://localhost:3000/FUZZ
  │ 200  /api
  │ 200  /admin
  │ 200  /ftp
  │ 301  /login
  └─ 3.4s

  ── [3] http → GET http://localhost:3000/ftp
  │ 200
  │ content-type: text/html
  │ confidential.md, package.json.bak, coupons_2026.md
  └─ 0.2s

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ▲ HIGH — Directory Listing Exposes Sensitive Files
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  │ The /ftp endpoint lists files publicly, exposing
  │ backup archives and internal documentation.
  │
  │ Evidence:   GET /ftp → 200 OK, 7 files listed
  │ Impact:     Sensitive data exposure
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ┌──────────────────────────────────────────────────────┐
  │              ASSESSMENT COMPLETE                     │
  │                                                      │
  │  Target:    http://localhost:3000                    │
  │  Duration:  4m 23s                                   │
  │  Cost:      $0.12                                    │
  │                                                      │
  │  ▲▲ 0 CRITICAL   ▲ 2 HIGH                            │
  │  ■  3 MEDIUM     ● 1 LOW                             │
  │                                                      │
  │  Risk Level: HIGH                                    │
  └──────────────────────────────────────────────────────┘
```

---

## Quick Start

### Install

```bash
pip install numasec
```

### Configure

```bash
# DeepSeek (cheapest — ~$0.12/assessment, 1M free tokens for new accounts)
export DEEPSEEK_API_KEY="sk-..."

# Or Claude / OpenAI (automatic fallback)
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

### Run

```bash
numasec
```

That's it. Describe what you want to test and the agent handles the rest.

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

NumaSec is a **ReAct agent** — it reasons about what to do, acts by calling security tools, observes the results, and repeats until the assessment is complete.

```
User prompt
  → LLM generates attack plan (recon → exploit → post-exploit)
  → For each step:
      → LLM selects tool + arguments
      → Tool executes (nmap, sqlmap, browser, etc.)
      → Extractors parse output → structured TargetProfile
      → Reflection engine analyzes results → next action
  → Findings registered with evidence
  → Professional report generated
```

The agent adapts in real-time. If it discovers a new endpoint during recon, it tests it. If a SQL injection is confirmed, it escalates through a pre-built attack chain. If it gets stuck, the reflection engine suggests a different approach.

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
agent.py        → ReAct loop (max 50 iterations, loop detection, circuit breaker)
router.py       → Multi-provider LLM routing (DeepSeek → Claude → OpenAI → Ollama)
planner.py      → 5-phase attack plan (recon → enum → exploit → post-exploit → report)
state.py        → Structured memory (TargetProfile: ports, endpoints, techs, creds, vulns)
extractors.py   → 14 extractors parse tool output into structured data
reflection.py   → 7 tool-specific reflectors guide the agent's next action
chains.py       → 14 escalation chains (SQLi→RCE, LFI→RCE, SSTI→RCE, etc.)
knowledge/      → 46 attack patterns, cheatsheets, and payload references
report.py       → Professional reports in Markdown, HTML, and JSON
plugins.py      → Extend with custom tools, chains, and extractors
renderer.py     → Continuous-scroll terminal UI with real-time streaming
```

**11,400 lines of Python. 184 tests. 5 core dependencies.**

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical details.

---

## Usage

### CLI

```bash
numasec                        # Interactive mode
numasec --demo                 # Mocked demo (no API key needed)
numasec --show-browser         # See browser in real-time
numasec --verbose              # Debug logging
numasec --budget 5.0           # Set cost limit
numasec --resume <session-id>  # Resume a previous session
```

### Commands

```
/plan          Show current attack plan and progress
/findings      List all discovered vulnerabilities
/report html   Generate full HTML report (dark theme)
/export md     Export Markdown report
/export json   Export JSON report
/cost          Show cost breakdown by provider
/stats         Session statistics
/history       Recent sessions
/resume <id>   Resume a session
/demo          Run mocked demo assessment
/clear         Clear screen and reset
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
| Security consultant | $2,000–10,000 | 1–2 weeks |
| Manual testing | Free | 4–8 hours |
| NumaSec + DeepSeek | **$0.10–0.15** | 5–15 minutes |
| NumaSec + Claude | $0.30–0.80 | 5–15 minutes |

---

## Legal & Ethics

**NumaSec is for authorized testing only.**

Authorized use:
- Systems you own or operate
- Bug bounty programs (HackerOne, Bugcrowd)
- Penetration tests with written authorization
- Practice environments (DVWA, Juice Shop, HackTheBox)

Unauthorized access to computer systems is illegal. You are responsible for how you use this tool.

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

**Francesco Stabile** — Building the future of AI security testing.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/francesco-stabile-dev)
[![X](https://img.shields.io/badge/X-000000?style=flat-square&logo=x&logoColor=white)](https://x.com/Francesco_Sta)

---

## License

[MIT](LICENSE)
