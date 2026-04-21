<h1 align="center">numasec</h1>
<h3 align="center">The AI agent for cyber security. Like Claude Code, but for cyber security.</h3>

<p align="center">
  <img src="docs/readmeimage.png" alt="numasec running a pentest against OWASP Juice Shop" width="900" />
</p>

<p align="center">
  <a href="https://github.com/FrancescoStabile/numasec/stargazers"><img src="https://img.shields.io/github/stars/FrancescoStabile/numasec?style=flat-square&color=DC143C" alt="GitHub Stars" /></a>
  <a href="#why-numasec"><img src="https://img.shields.io/badge/AI%20Cyber%20Security-Agent-DC143C?style=flat-square" alt="AI Cyber Security Agent" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License" /></a>
  <a href="https://github.com/FrancescoStabile/numasec/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/FrancescoStabile/numasec/ci.yml?branch=dev&style=flat-square&label=build" alt="Build" /></a>
  <a href="https://github.com/FrancescoStabile/numasec/releases/latest"><img src="https://img.shields.io/github/v/release/FrancescoStabile/numasec?style=flat-square&label=release" alt="Release" /></a>
</p>

<p align="center">
  37 native security tools · 48 templates, payload packs, and playbooks · evidence graph + attack paths
</p>

## Table of Contents

- [Quickstart](#quickstart)
- [Why numasec](#why-numasec)
- [What it finds](#what-it-finds)
- [How it works](#how-it-works)
- [LLM Providers](#llm-providers)
- [Installation](#installation)
- [Usage](#usage)
- [Development](#development)
- [Contributing](#contributing)

## Quickstart

```bash
npm install -g numasec
numasec
```

Connect a provider, choose a model, type `pentest https://yourapp.com`, and it starts.

## Why numasec

Coding has Claude Code, Copilot, Cursor.
Cyber security has nothing.

Until now.

<p align="center">
  <img src="docs/pentest-demo.gif" alt="numasec running a pentest" width="900" />
</p>

- **Built for cyber security from the ground up.** Not a wrapper around ChatGPT. 37 native security tools, 48 templates, payload packs, and playbooks, a stateful browser runtime, and an evidence graph that turns proof into attack paths.
- **Recon. Exploit. Chain vulnerabilities. Generate reports.** Default credentials → admin access → user enumeration. SQLi → token issuance → account takeover. IDOR → data exposure → business impact.
- **Single binary, no Python tax.** Pure TypeScript. No Docker required. `bun build` produces a single executable.
- **Attack paths, not isolated findings.** Every serious run becomes graph nodes and edges — evidence, hypotheses, findings, resources, attack paths — not a pile of disconnected scanner output.
- **Works with hosted and local LLM providers.** Use the provider you already trust for reasoning and orchestration; numasec still executes the scanning, evidence capture, chaining, and reporting locally.

<p align="center">
  <a href="https://github.com/FrancescoStabile/numasec/stargazers">
    <img src="https://img.shields.io/github/stars/FrancescoStabile/numasec?style=social" alt="GitHub Stars" />
  </a>
  <br/>
  <sub>If numasec is useful to you, a star helps more people find it.</sub>
</p>

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
- Race conditions
- File upload bypass
- Mass assignment

</td>
</tr>
</table>

Every finding includes **CWE ID**, **CVSS 3.1 score**, **OWASP Top 10 category**, **MITRE ATT&CK technique**, and **remediation steps**.

<p align="center">
  <img src="docs/attack-chain.gif" alt="numasec attack chain findings" width="900" />
</p>

## How it works

```mermaid
graph TD
    A["pentest https://app.com"] --> B

    B["🗺️ Planner + Playbooks\n48 templates, payload packs, and playbooks\nChooses what to hit next from the live surface"]
    B --> C

    C["⚔️ Stateful Runtime\nBrowser actors · shared auth · working memory\nRecovery, replay, resource inventory"]
    C --> D

    D["🔧 37 Native Security Tools\nRecon · auth · injection · browser · replay\nBuilt to keep pushing, not just probe once"]
    D --> E

    E["🧠 Evidence Graph\nNodes + edges for evidence, hypotheses,\nfindings, resources, and attack paths"]
    E --> F

    F["📄 Report\nSARIF · HTML · Markdown"]

    style B fill:#1a1a2e,color:#e0e0e0,stroke:#DC143C
    style C fill:#1a1a2e,color:#e0e0e0,stroke:#DC143C
    style D fill:#1a1a2e,color:#e0e0e0,stroke:#DC143C
    style E fill:#1a1a2e,color:#e0e0e0,stroke:#DC143C
    style F fill:#1a1a2e,color:#e0e0e0,stroke:#DC143C
```

Every serious run now leaves behind graph nodes and edges — evidence, hypotheses, findings, resources, attack paths — so numasec remembers what it proved instead of rediscovering the same app every turn.

Reports include executive summary, risk score, OWASP coverage matrix, attack paths, and per-finding remediation. SARIF plugs into GitHub Code Scanning and GitLab SAST.

<p align="center">
  <img src="docs/report-demo.gif" alt="numasec report output" width="900" />
</p>

## LLM Providers

All 37 tools execute inside numasec. The model decides what to do next; numasec performs the recon, testing, evidence capture, and reporting.

| Use case | Provider examples | Notes |
|---|---|---|
| Hosted reasoning | Anthropic, OpenAI, xAI, Google, OpenRouter, Bedrock, GitHub Models | Best when you want stronger reasoning on harder chains and longer investigations |
| Local / private | Ollama | Best when you want local execution and no external model API spend |

## Installation

### npm (recommended)

```bash
npm install -g numasec
numasec
```

For browser automation, install Chromium once:

```bash
npx playwright install chromium
```

### From source (local build)

```bash
git clone https://github.com/FrancescoStabile/numasec.git
cd numasec
bash install.sh
```

This installs a **local** build from your current checkout. Pull updates in the repo, then rerun `bash install.sh` to refresh it.

Or manually:

```bash
cd numasec/agent
bun install
cd packages/numasec
NUMASEC_CHANNEL=local NUMASEC_VERSION=local bun run build
# Binary at dist/numasec-<platform>-<arch>/bin/numasec
```

### Optional: external tools

numasec works standalone, but external probes get much better with this setup:

```bash
# Recommended
apt install nmap

# Optional
apt install sqlmap
apt install ffuf
```

Chromium is what unlocks the full browser side of numasec: login flows, SPA work, authenticated replay, and browser-driven attack paths.

## Usage

```bash
numasec                  # Launch the TUI
```

### Agent modes

| Mode | What it does |
|---|---|
| 🔴 **pentest** | Full PTES methodology: recon → vuln testing → exploitation → report |
| 🔵 **recon** | Reconnaissance only, no exploitation |
| 🟠 **hunt** | Systematic OWASP-style vulnerability hunting |
| 🟡 **review** | Secure code review, no network scanning |
| 🟢 **report** | Findings, attack paths, and deliverables |

### Canonical workflow commands

| Command | Description |
|---|---|
| `/scope set <target>` | Set engagement scope and begin reconnaissance |
| `/scope show` | Show current scope and latest observed surface |
| `/hypothesis list` | List evidence-graph hypotheses |
| `/verify next` | Plan the next verification primitive |
| `/evidence list` | List findings with available evidence |
| `/evidence show <id-or-title>` | Show full evidence for one finding |
| `/chains list` | List derived attack paths |
| `/finding list` | List findings by severity |
| `/finding finalize <id-or-title>` | Finalize one provisional finding through the closure path |
| `/remediation plan` | Generate prioritized remediation actions |
| `/retest run [filter]` | Replay and retest saved findings |
| `/report status` | Show report readiness, blockers, and whether final export is currently possible |
| `/report generate [format] [--out <path>] [--final] [--note <text>]` | Generate report (`markdown`, `html`, `sarif`); default is a working report, `--final` enforces readiness |
| `/report finalize [format] [--out <path>] [--working] [--note <text>]` | Run the closure-aware report path; blocks with exact blocker commands instead of drifting |

Legacy aliases still supported in v1.x:

| Legacy command | Current replacement |
|---|---|
| `/target <url>` | `/scope set <url>` |
| `/findings` | `/finding list` |
| `/report <format>` | `/report generate <format>` |
| `/evidence` | `/evidence list` |
| `/evidence <id-or-title>` | `/evidence show <id-or-title>` |

## Development

> [!IMPORTANT]  
> Bun MUST be version `1.3.11`. I'm not sure why but other versions often corrupt upon building.


```bash
cd agent
bun install

# Type check
bun typecheck

# Tests
cd packages/numasec && bun test --timeout 30000

# Runtime validation
cd packages/numasec && bun run test:runtime

# Benchmark proof pack (runtime eval + live fixture + optional local Juice Shop)
cd packages/numasec && bun run test:benchmark-proof

# Build
cd packages/numasec && bun run build
```

## Contributing

Issues, PRs, and ideas are welcome.

- **Found a bug?** Open an issue with steps to reproduce.
- **Want to contribute code?** Fork, branch from `dev`, open a PR.

<p align="center">
  Built by <a href="https://www.linkedin.com/in/francesco-stabile-dev">Francesco Stabile</a>.
</p>

<p align="center">
  <a href="https://www.linkedin.com/in/francesco-stabile-dev"><img src="https://img.shields.io/badge/LinkedIn-0077B5?style=flat-square&logo=linkedin&logoColor=white" alt="LinkedIn" /></a>
  <a href="https://x.com/Francesco_Sta"><img src="https://img.shields.io/badge/X-000000?style=flat-square&logo=x&logoColor=white" alt="X" /></a>
</p>

<p align="center"><a href="LICENSE">MIT License</a></p>
