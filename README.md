<h1 align="center">numasec</h1>
<h3 align="center">AI pentester that actually finds vulnerabilities. Open source. Runs in your terminal.</h3>

<p align="center">
  <img src="docs/readmeimage.png" alt="numasec running a pentest against OWASP Juice Shop" width="900" />
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+" /></a>
  <a href="https://github.com/FrancescoStabile/numasec/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/FrancescoStabile/numasec/ci.yml?branch=main&style=flat-square&label=build" alt="Build" /></a>
  <a href="https://github.com/FrancescoStabile/numasec/releases/latest"><img src="https://img.shields.io/github/v/release/FrancescoStabile/numasec?style=flat-square&label=release" alt="Release" /></a>
  <a href="https://pypi.org/project/numasec/"><img src="https://img.shields.io/pypi/v/numasec?style=flat-square&label=pypi" alt="PyPI" /></a>
</p>

<p align="center">
  <b>96% vulnerability recall on OWASP Juice Shop</b> · 10 specialized agents · 21 security tools · PTES methodology
</p>

---

## Quickstart

```bash
pip install numasec
numasec
```

Or with Docker:
```bash
docker run -it francescosta/numasec
```

Or from source:
```bash
curl -fsSL https://numasec.dev/install | bash
```

Type `/target https://yourapp.com` and watch it work. The AI scans, finds vulnerabilities, chains attacks together, and writes the report. You watch, approve, and steer.

Works with **Claude, GPT-4, Gemini, DeepSeek, Mistral**, or any OpenAI-compatible model.

---

## Why numasec

Most "AI security tools" wrap a single scanner and call it AI. numasec is different — it's a **team of 10 specialized agents** running **21 offensive security tools** through an actual penetration testing methodology.

It doesn't just find vulnerabilities. It **chains them**: a leaked API key in JavaScript → SSRF → cloud metadata → account takeover. Then it writes a professional report with CVSS scores, CWE IDs, OWASP categories, and remediation guidance.

**Benchmarked against real targets:**

| Target | Vulnerabilities Found | Coverage |
|---|---|---|
| OWASP Juice Shop v17 | 25/26 ground-truth vulns | **96% recall** |
| DVWA | 7/7 vulnerability categories | **100%** |
| WebGoat | 20+ vulnerabilities across all modules | **Full coverage** |

---

## What it finds

<table>
<tr>
<td width="33%">

**Injection**
- SQL injection (blind, time-based, union, error-based)
- NoSQL injection
- OS command injection
- Server-Side Template Injection
- XXE injection
- GraphQL introspection & injection

</td>
<td width="33%">

**Authentication & Access**
- JWT attacks (alg:none, weak HS256, kid traversal)
- OAuth misconfiguration
- Default credentials & password spray
- IDOR
- CSRF
- Privilege escalation

</td>
<td width="33%">

**Client & Server Side**
- XSS (reflected, stored, DOM)
- SSRF with cloud metadata detection
- CORS misconfiguration
- Path traversal / LFI
- Open redirect
- HTTP request smuggling
- Race conditions
- File upload bypass

</td>
</tr>
</table>

Every finding is auto-enriched with **CWE ID**, **CVSS 3.1 score**, **OWASP Top 10 category**, **MITRE ATT&CK technique**, and actionable **remediation guidance**.

---

## Multi-Agent Architecture

numasec isn't a single bot — it's a coordinated team of specialized agents, each with distinct roles and permissions:

### Primary Agents

| Agent | Role | What it does |
|---|---|---|
| 🔴 **pentest** | Full PTES methodology | Recon → Discovery → Vuln Assessment → Exploitation → Reporting |
| 🔵 **recon** | Intelligence gathering | Port scanning, fingerprinting, subdomain enum, service probing — no exploitation |
| 🟠 **hunt** | OWASP Top 10 hunter | Systematic, aggressive testing across all 10 OWASP categories |
| 🟡 **review** | Secure code review | Static analysis of source code, diffs, commits, PRs |
| 🟢 **report** | Report & findings | Finding management, severity validation, report generation |

### Subagents

| Agent | Role |
|---|---|
| **scanner** | Executes automated vulnerability scans (passive → semi-active → active) |
| **analyst** | Validates results, eliminates false positives, correlates attack chains |
| **reporter** | Generates SARIF / Markdown / HTML / JSON reports |
| **explore** | CVE research, exploit documentation, knowledge base queries |

Each agent has **tailored permissions** — the recon agent can't run exploits, the review agent can't launch scanners. The analyst agent filters false positives using strict evidence criteria before any finding enters the report.

---

## Security Tooling

21 purpose-built security tools and 38 async scanners under the hood — covering reconnaissance, injection testing, authentication attacks, access control, file upload bypass, race conditions, request smuggling, out-of-band detection, and more. The AI selects and orchestrates them automatically based on what it discovers about your target.

A built-in **knowledge base of 34 templates** covers detection patterns, exploitation techniques, payloads, and remediation — so the AI doesn't hallucinate attack methodology, it looks it up. Extensible with your own templates and plugins.

---

## Reports

Four output formats, all auto-generated:

| Format | Use case |
|---|---|
| **SARIF** | Drop into GitHub Code Scanning, GitLab SAST, or any SARIF viewer |
| **HTML** | Self-contained report to share with your team |
| **Markdown** | Paste into tickets, docs, or wikis |
| **JSON** | Feed into your pipeline or dashboard |

Every report includes an executive summary with risk score (0-100), severity breakdown, OWASP coverage matrix, attack chain documentation, and per-finding remediation.

---

## OWASP Top 10 Coverage

The TUI header tracks real-time testing coverage across all 10 OWASP categories as the pentest progresses. Each category is automatically mapped to the relevant tools — so you always know what's been tested and what's left.

---

## Installation

### pip (recommended)

```bash
pip install numasec
numasec
```

Downloads the TUI binary automatically on first run. No Bun, Node, or other runtime needed.

### Docker

```bash
docker run -it francescosta/numasec
```

Full TUI + all 21 security tools. Multi-arch (amd64, arm64).

### From source

```bash
curl -fsSL https://numasec.dev/install | bash
```

Or manually:
```bash
git clone https://github.com/FrancescoStabile/numasec.git
cd numasec
pip install -e ".[all]"    # Python backend
cd agent && bun install && bun run build  # TUI
```

---

## Usage

```bash
numasec                  # Start interactive TUI
```

### Slash Commands

| Command | Description |
|---|---|
| `/target <url>` | Set target and begin reconnaissance |
| `/findings` | List all discovered vulnerabilities |
| `/report <format>` | Generate report (markdown, html, sarif, json) |
| `/coverage` | Show OWASP Top 10 coverage matrix |
| `/creds` | List discovered credentials |
| `/evidence <id>` | Show evidence for a specific finding |
| `/review` | Security review of code changes |
| `/init` | Analyze app and create security profile |

### Agent Modes

Switch between agents for different tasks:
- **pentest** — full methodology, default
- **recon** — reconnaissance only, no exploitation
- **hunt** — aggressive OWASP Top 10 testing
- **review** — secure code review (no network scanning)
- **report** — finding management and deliverables

---

## LLM Providers

| Provider | Models |
|---|---|
| Anthropic | Claude Opus, Sonnet, Haiku |
| OpenAI | GPT-4o, GPT-4, o1 |
| Google | Gemini Pro, Flash |
| AWS Bedrock | Claude, Llama |
| Azure OpenAI | GPT-4, GPT-4o |
| Mistral | Large, Medium |
| DeepSeek | V2, Coder |
| OpenRouter | Any model via aggregation |
| GitHub Copilot | Copilot models |
| Google Vertex | Gemini via Vertex |
| GitLab | GitLab models |

---

## Development

```bash
pip install -e ".[all]"

# Tests (1273 unit + 3 benchmark suites)
pytest tests/ -v
pytest tests/ -m "not slow and not benchmark"   # fast run

# Lint & type check
ruff check numasec/
ruff format numasec/
mypy numasec/

# TypeScript TUI
cd agent && bun install
cd packages/numasec && bun run typecheck
cd packages/numasec && bun test
```

### Benchmarks

```bash
# Juice Shop (96% recall)
JUICE_SHOP_URL=http://localhost:3000 pytest tests/benchmarks/test_juice_shop.py -v

# DVWA (100% coverage)
DVWA_TARGET=http://localhost:8080 pytest tests/benchmarks/test_dvwa.py -v

# WebGoat
WEBGOAT_TARGET=http://localhost:8081/WebGoat pytest tests/benchmarks/test_webgoat.py -v
```

### Extend with plugins

Drop a Python file with a `register(registry)` function into `~/.numasec/plugins/` or a YAML scanner template into `~/.numasec/templates/`.

---

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│                        Terminal TUI                         │
│  (TypeScript/Bun • SolidJS reactive UI • 5 agent modes)     │
└────────────────────────────┬────────────────────────────────┘
                             │ 
┌────────────────────────────▼────────────────────────────────┐
│                    Security Engine                          │
│  ┌─────────────┐  ┌───────────────┐  ┌───────────────────┐  │
│  │ 21 Security │  │ 34 Knowledge  │  │  Session Store    │  │
│  │ Tools       │  │ Base Templates│  │                   │  │
│  └──────┬──────┘  └───────────────┘  └───────────────────┘  │
│         │                                                   │
│  ┌──────▼──────────────────────────────────────────────┐    │
│  │            38 Skills                                │    │
│  │  Injection · Auth · Access · Recon · Fuzzing        │    │
│  │  Client-side · Server-side · Out-of-band · ...      │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

The TUI drives the AI conversation. The AI calls security tools. Each tool orchestrates one or more async scanners. Findings are auto-enriched (CWE → CVSS → OWASP → MITRE ATT&CK), deduplicated, and grouped into attack chains. Reports are generated from the session store.

**No hallucinated methodology.** The knowledge base provides real detection patterns, exploitation techniques, and payloads. The deterministic planner (based on the CHECKMATE paper) selects tests based on detected technologies — no LLM involved in test selection.

---

**Built by [Francesco Stabile](https://www.linkedin.com/in/francesco-stabile-dev).**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/francesco-stabile-dev)
[![X](https://img.shields.io/badge/X-000000?style=flat-square&logo=x&logoColor=white)](https://x.com/Francesco_Sta)

[MIT License](LICENSE)
