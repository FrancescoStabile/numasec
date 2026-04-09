<h1 align="center">numasec</h1>
<h3 align="center">The AI agent for security. Like Claude Code, but for pentesting.</h3>

<p align="center">
  <img src="docs/readmeimage.png" alt="numasec running a pentest against OWASP Juice Shop" width="900" />
</p>

<p align="center">
  <a href="#why-numasec"><img src="https://img.shields.io/badge/AI%20Pentesting-Platform-DC143C?style=flat-square" alt="AI Pentesting Platform" /></a>
  <a href="https://hub.docker.com/r/francescosta/numasec"><img src="https://img.shields.io/docker/pulls/francescosta/numasec?style=flat-square" alt="Docker Pulls" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License" /></a>
  <a href="https://github.com/FrancescoStabile/numasec/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/FrancescoStabile/numasec/ci.yml?branch=main&style=flat-square&label=build" alt="Build" /></a>
  <a href="https://github.com/FrancescoStabile/numasec/releases/latest"><img src="https://img.shields.io/github/v/release/FrancescoStabile/numasec?style=flat-square&label=release" alt="Release" /></a>
</p>

<p align="center">
  <b>96% recall on Juice Shop</b> · <b>100% on DVWA</b> · 21+ security tools · MCP-native · open source
</p>

---

## Quickstart

```bash
git clone https://github.com/FrancescoStabile/numasec.git
cd numasec && pip install -e ".[all]"
cd agent && bun install && bun run build
numasec
```

Or with Docker:
```bash
docker run -it francescosta/numasec
```

Pick your LLM provider, type `pentest https://yourapp.com`, and it starts. Automated penetration testing against any web application. Works with any model: DeepSeek, Claude, GPT, Ollama, or any OpenAI-compatible endpoint.

---

## Why numasec

Claude Code writes code. Copilot reviews it. Cursor helps you navigate it. But when it comes to web application security, finding vulnerabilities, testing authentication, chaining exploits, there's no AI agent built for that.

numasec is that agent.

- **Built for security from the ground up.** Not a wrapper around ChatGPT. 21+ security tools, 34 attack templates, a deterministic planner based on the [CHECKMATE](https://arxiv.org/abs/2512.11143) paper. The AI coordinates and analyzes. It doesn't hallucinate the methodology.
- **MCP-native.** Ships with 21+ built-in security tools and connects to any MCP server. Add your own tools, same protocol Claude Code and Cursor use for extensibility.
- **Attack chains, not isolated findings.** Leaked API key in JS → SSRF → cloud metadata → account takeover. Documented with full evidence.
- **Benchmarked and reproducible.** 96% recall on Juice Shop. 100% on DVWA. Full coverage on WebGoat. Better than most manual security assessments. [Run them yourself.](tests/benchmarks/)

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
- CRLF injection

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
- Host header injection

</td>
</tr>
</table>

Every finding includes **CWE ID**, **CVSS 3.1 score**, **OWASP Top 10 category**, **MITRE ATT&CK technique**, and **remediation steps**. Auto-generated, validated by the analyst agent before entering the report. Built for bug bounty hunters, security engineers, and red teams.

---

## How it works

```
pentest https://app.com
        │
        ▼
┌───────────────────────────────────────────────┐
│  Deterministic Planner                        │
│  34 templates · PTES methodology              │
│  Selects tests based on fingerprinted tech    │
└───────────────────┬───────────────────────────┘
                    ▼
┌───────────────────────────────────────────────┐
│  21+ Security Tools                           │
│  SQLi · XSS · SSRF · Auth · IDOR · CSRF       │
│  Smuggling · Race · Upload · SSTI · ...       │
└───────────────────┬───────────────────────────┘
                    ▼
┌───────────────────────────────────────────────┐
│  Findings                                     │
│  Auto-enriched: CWE → CVSS → OWASP → ATT&CK   │
│  Deduplicated · Chained · Scored              │
└───────────────────┬───────────────────────────┘
                    ▼
┌───────────────────────────────────────────────┐
│  Report                                       │
│  SARIF · HTML · Markdown · JSON               │
└───────────────────────────────────────────────┘
```

Reports include executive summary, risk score (0-100), OWASP coverage matrix, attack chain documentation, and per-finding remediation. SARIF plugs into GitHub Code Scanning and GitLab SAST. Use it as a DAST step in your CI/CD pipeline.

---

## LLM Providers

All 21+ tools run locally. You bring any LLM. Pick your provider from the TUI.

| Provider | Cost per pentest | Why |
|---|---|---|
| **DeepSeek** | **~$0.07** | Best value. [Free tier available](https://platform.deepseek.com/) |
| GPT-4.1 | ~$1 | Higher quality analysis |
| Claude Sonnet 4 | ~$1.50 | Best reasoning for complex chains |
| **Ollama (local)** | **$0** | Run locally. Full privacy |
| AWS Bedrock / Azure | Varies | Enterprise compliance |

<details>
<summary><b>All 60+ supported providers</b></summary>
<br>
Anthropic · OpenAI · Google Gemini · AWS Bedrock · Azure OpenAI · Mistral · DeepSeek · Ollama Cloud · OpenRouter · GitHub Copilot · GitHub Models · Google Vertex · Groq · Fireworks AI · Together AI · Cohere · Cerebras · Nvidia · Perplexity · xAI · Hugging Face · LM Studio · and 40+ more via OpenAI-compatible endpoints.
</details>

---

## Installation

### From source (recommended)

```bash
git clone https://github.com/FrancescoStabile/numasec.git
cd numasec
pip install -e ".[all]"    # Python backend
cd agent && bun install && bun run build  # TUI
```

### Docker

```bash
docker run -it francescosta/numasec
```

Full TUI + all security tools. Multi-arch (amd64, arm64).

### pip

```bash
pip install numasec
numasec
```

Downloads the TUI binary on first run. No Bun, Node, or other runtime needed.

---

## Usage

```bash
numasec                  # Launch the TUI
```

### Slash commands

| Command | Description |
|---|---|
| `/target <url>` | Set target and start scanning |
| `/findings` | List discovered vulnerabilities |
| `/report <format>` | Generate report (markdown, html, sarif, json) |
| `/coverage` | OWASP Top 10 coverage matrix |
| `/creds` | Discovered credentials |
| `/evidence <id>` | Evidence for a specific finding |
| `/review` | Security review of code changes |
| `/init` | Analyze app and create security profile |

### Agent modes

| Mode | What it does |
|---|---|
| 🔴 **pentest** | Full PTES methodology: recon → vuln testing → exploitation → report (default) |
| 🔵 **recon** | Reconnaissance only, no exploitation |
| 🟠 **hunt** | Systematic OWASP Top 10 sweep |
| 🟡 **review** | Secure code review, no network scanning |
| 🟢 **report** | Finding management and deliverables |

---

## Development

```bash
pip install -e ".[all]"

# Tests
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

---

## Contributing

Issues, PRs, and tool templates are welcome.

- **Found a bug?** Open an issue with steps to reproduce.
- **Want to add a tool?** Check `community-templates/` for the YAML template format. No Python required.
- **Want to contribute code?** Fork, branch from `main`, open a PR. Tests: `pytest tests/ -v`.

---

<p align="center">
  Built by <a href="https://www.linkedin.com/in/francesco-stabile-dev">Francesco Stabile</a>.
</p>

<p align="center">
  <a href="https://www.linkedin.com/in/francesco-stabile-dev"><img src="https://img.shields.io/badge/LinkedIn-0077B5?style=flat-square&logo=linkedin&logoColor=white" alt="LinkedIn" /></a>
  <a href="https://x.com/Francesco_Sta"><img src="https://img.shields.io/badge/X-000000?style=flat-square&logo=x&logoColor=white" alt="X" /></a>
</p>

<p align="center"><a href="LICENSE">MIT License</a></p>
