<p align="center">
  <img src="assets/readmeimage.png" alt="numasec" width="720" />
</p>

<h1 align="center">numasec</h1>

<p align="center"><b>AI-native security workbench for operators, builders, and hackers.</b></p>

<p align="center">
  <a href="https://github.com/FrancescoStabile/numasec/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/FrancescoStabile/numasec/ci.yml?branch=develop&style=for-the-badge&label=CI&logo=github" alt="CI"></a>
  <a href="https://github.com/FrancescoStabile/numasec/releases"><img src="https://img.shields.io/github/v/release/FrancescoStabile/numasec?include_prereleases&style=for-the-badge&color=00ff41&label=release" alt="release"></a>
  <a href="https://www.npmjs.com/package/numasec"><img src="https://img.shields.io/npm/v/numasec?style=for-the-badge&color=00ff41&logo=npm" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="MIT"></a>
  <a href="https://github.com/FrancescoStabile/numasec/stargazers"><img src="https://img.shields.io/github/stars/FrancescoStabile/numasec?style=for-the-badge&color=yellow&logo=starship" alt="stars"></a>
</p>

<p align="center">
  <a href="#why-numasec">Why</a> |
  <a href="#what-it-can-do">Capabilities</a> |
  <a href="#plays">Plays</a> |
  <a href="#operations">Operations</a> |
  <a href="#install">Install</a> |
  <a href="#community">Community</a>
</p>

<p align="center">
  <img src="assets/demo-pentest.gif" alt="numasec running a pentest against OWASP Juice Shop" width="900" />
</p>

## Why numasec

Security work is not a single prompt.

It is scope, recon, browser state, raw requests, screenshots, notes, payloads, dead ends, local tools, findings, retests, and a report that still makes sense next week.

numasec is a terminal-native AI workbench built around that reality. It gives you specialist security agents, durable operation memory, a real browser, raw HTTP, local tool execution, reusable plays, plugin hooks, and adapter-driven workflows for web, code, cloud, containers, IaC, and binaries.

If a coding agent is an engineer, **numasec is an operator**.

<p align="center"><sub>5 primary agents | 7 operation kinds | 11 built-in plays | 30+ built-in tools | embedded skills | plugin API</sub></p>

## What it can do

numasec sits between a chat agent and a security distribution. It can reason like an assistant, but it can also act through the tools that matter during an assessment.

| Area | What numasec brings |
|---|---|
| Web application testing | Browser automation, raw HTTP, crawling, JavaScript inspection, authenticated request replay, scanner orchestration, `/pwn`, `/play web-surface`, `/play auth-surface`, `/play api-surface` |
| Network recon | Port and service discovery, banner collection, scanner-backed pipelines, methodology guidance, scoped execution |
| AppSec review | Repository triage, source search, sink discovery, dependency/CVE context, remediation guidance, code-aware subagents |
| OSINT | Passive target profiling, subdomain and archive workflows, source notes, confidence and provenance discipline |
| Cloud posture | Adapter-backed checks for cloud accounts using the tools you already trust locally |
| Container security | Image surface triage with package, layer, exposed-port, and vulnerability signals when adapters are available |
| IaC triage | Terraform, Kubernetes, and infrastructure config review with adapter output normalized for the agent |
| Binary and CTF work | Artifact-first warmups, strings/metadata enrichment, reverse-engineering handoff, forensics skill support |
| Reporting | Operation notes, scoped findings, remediation advice, redacted share archives, signed handoffs |

## The operator model

numasec is organized around security modes instead of one generic assistant voice.

| Mode | Use it for |
|---|---|
| `security` | General security help, logs, tooling, quick research, setup, explanation |
| `pentest` | Authorized recon, exploitation workflow, evidence, findings, report-ready notes |
| `appsec` | Code review, authz bugs, dependency risk, secure design, patch advice |
| `osint` | Passive intelligence, attribution-safe research, provenance-heavy investigation |
| `hacking` | CTFs, exploit dev, reversing, shells, quick-and-dirty lab work |

Subagents let numasec go wide without losing the main thread:

| Subagent | Use it for |
|---|---|
| `explore` | Fast codebase scouting and "where does this live?" questions |
| `general` | Parallel research or multi-step work that should not pollute the main context |

## Plays

A play is a reusable security workflow: more structured than "ask the model", more flexible than a scanner preset.

Plays declare inputs, required capabilities, tool steps, skipped/degraded states, and the final evidence shape. That makes them testable, reviewable, and easy to extend without turning the agent into a pile of prompt soup.

Built-in plays in 1.1.7:

| Play | Purpose |
|---|---|
| `web-surface` | Crawl, inspect JavaScript, map routes, and collect web surface evidence |
| `api-surface` | Probe API shape, endpoints, auth assumptions, and request/response behavior |
| `auth-surface` | Inspect login, session, token, CSRF, and authorization boundaries |
| `network-surface` | Port scan, service probe, and banner collection |
| `appsec-triage` | Repository-first security triage for patterns, sinks, and risky areas |
| `osint-target` | Passive profile for domains, emails, handles, and public footprint |
| `ctf-warmup` | Artifact-first CTF and forensics warmup with optional local enrichment |
| `cloud-posture` | Cloud account posture checks through local security adapters |
| `container-surface` | Container image surface and vulnerability triage |
| `iac-triage` | Infrastructure-as-code checks for Terraform, Kubernetes, and config risk |
| `binary-triage` | Binary metadata, strings, and quick reverse-engineering triage |

Run one directly:

```text
/play web-surface http://localhost:3000
/play container-surface bkimminich/juice-shop
/play iac-triage ./infra
/play binary-triage ./challenge
```

Or let `/pwn` classify the target, create an operation, choose the best play, and start with the right specialist.

## Tools that actually do work

The built-in palette includes normal agent tools and security-specific primitives:

```text
bash, read, write, edit, grep, glob, task, fetch, search, code, skill,
httprequest, browser, scanner, crypto, net, vault, interact, methodology,
cve, play, pwn_bootstrap, doctor, opsec, share, remediate,
cloud_posture, container_surface, iac_triage, binary_triage
```

If `nmap`, `ffuf`, `gobuster`, `sqlmap`, `nuclei`, `prowler`, `trivy`, `checkov`, `checksec`, or your own tooling is on `PATH`, numasec can use it through scoped shell/tool flows. If an adapter is missing, plays report that honestly instead of pretending the scan happened.

## Operations

Every real engagement becomes an operation.

An operation is a durable notebook at:

```text
.numasec/operation/<slug>/numasec.md
```

numasec reloads that file into the active system context. Scope, target details, assumptions, findings, attempted payloads, rejected hypotheses, screenshots, and next steps stay with the engagement instead of disappearing into chat history.

<p align="center">
  <img src="assets/demo-operations.gif" alt="creating an operation in numasec" width="900" />
</p>

The TUI keeps the work readable while the agent is acting:

| Panel | What it shows |
|---|---|
| Pulse | Current target, operation state, and mode |
| Plan | Live todo list even when the selected model has no native planning UI |
| Activity | Tool calls, adapter runs, browser/HTTP activity, and evidence flow |

`/opsec strict` turns scope into a guardrail. Out-of-scope browser, HTTP, and shell actions are blocked before they leave the tool.

## Commands worth remembering

```text
/pwn https://target           classify target, create operation, choose play, begin
/play                         list reusable workflows
/play web-surface https://x   run a specific play
/operations                   switch between saved engagements
/agents                       choose a specialist agent
/mode appsec                  switch mode directly
/doctor                       inspect runtime, tools, vault, and CVE bundle
/opsec strict                 enforce declared scope
/teach                        narrate tool use for demos and learning
/share --sign                 create a redacted, optionally signed handoff archive
/remediate OBS-001            turn an observation into patch guidance
/models                       switch model/provider inside the TUI
```

## Install

```bash
npm install -g numasec
numasec
```

The npm package is intentionally small: it installs a JavaScript wrapper plus the matching platform binary package. Seeing only a handful of packages added is normal.

Docker:

```bash
docker run -it --rm -v "$PWD:/work" -w /work numasec/numasec:latest
```

From source:

```bash
git clone https://github.com/FrancescoStabile/numasec.git
cd numasec
bun install
cd packages/numasec
bun run build
```

## Recommended local toolkit

numasec works out of the box, then gets sharper as your machine gains security tools.

```bash
# Debian / Kali / Ubuntu
apt install nmap sqlmap ffuf gobuster nikto

# macOS
brew install nmap sqlmap ffuf gobuster nikto

# Browser support
npx playwright install chromium
```

Useful optional adapters:

| Workflow | Tools that unlock more signal |
|---|---|
| Cloud posture | `prowler` |
| Container surface | `trivy`, `docker` |
| IaC triage | `checkov` |
| Binary triage | `checksec` |

Run `/doctor` any time to inspect the core runtime and common local tooling. Adapter-backed plays also report missing adapter tools directly in their own output.

## Models and providers

numasec works with the model stack you already use: Anthropic, OpenAI, Google, xAI, Bedrock, GitHub Models, OpenRouter, Ollama, Vercel AI Gateway, and OpenAI-compatible endpoints.

Most newly released model IDs do not require a numasec release if your provider accepts custom model strings. Provider package updates still matter when the SDK needs new API features, metadata, transport behavior, or capability flags.

## First run

```bash
numasec
```

Then try:

```text
/pwn http://localhost:3000
```

numasec classifies the target, creates an operation, loads the right security mode, and starts from the best available play.

For persistent project instructions outside a specific operation, add `numasec.md` or `.numasec.md` at the project root:

```markdown
# Target: internal-api.corp.com
- Base: https://internal-api.corp.com/v2
- Auth: Bearer token in `Authorization`
- Test account: seeded local test user
- Focus: IDOR, privilege escalation, JWT/session handling
- Out of scope: DoS, brute force, social engineering
```

## Extending numasec

The project is designed to grow by contribution instead of by one giant prompt.

| Extension point | What you can add |
|---|---|
| Skills | `SKILL.md` workflows for repeatable domain knowledge |
| Plugins | Tools, commands, TUI surfaces, and SDK-backed integrations |
| Plays | Deterministic security workflows with capability checks and tests |
| Adapters | Thin wrappers around best-of-breed local security tools |
| Docs | Operator playbooks, methodology notes, examples, and lab recipes |

The cleanest community contribution is often a play: pick one repeatable workflow, define the inputs, wire the tools, describe degraded behavior, and add tests. Users get something practical immediately, and maintainers get a small reviewable unit.

## Docs

| Doc | What it covers |
|---|---|
| [`AGENTS.md`](./AGENTS.md) | Agent behavior, prompts, conventions |
| [`docs/MANIFESTO.md`](./docs/MANIFESTO.md) | Product philosophy and boundaries |
| [`docs/OPERATIONS.md`](./docs/OPERATIONS.md) | Operation memory, scope, workflow |
| [`docs/TOOLS.md`](./docs/TOOLS.md) | The tool palette |
| [`docs/PROMPTS.md`](./docs/PROMPTS.md) | Prompting model by model |
| [`docs/PLUGINS.md`](./docs/PLUGINS.md) | Extensibility and plugin hooks |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | How to contribute |
| [`SECURITY.md`](./SECURITY.md) | Responsible disclosure |

## FAQ

**Is numasec only for red teams?**

No. It is useful for authorized pentesting, AppSec review, secure design, OSINT, research, CTFs, and training.

**Is it a scanner?**

No. It can drive scanners, but the product is the workflow around them: scope, context, evidence, decisions, and handoff.

**Can it run without external tools?**

Yes. Built-in browser, HTTP, code, methodology, CVE, and file tools work immediately. External adapters unlock deeper checks.

**Can I use new models as they come out?**

Usually yes through provider configuration/model IDs. SDK upgrades are needed when providers add new APIs or capability semantics, not for every string-only model release.

**Can I extend it?**

Yes. Skills, plugins, adapters, and plays are first-class extension points.

## Development

Use Bun `1.3.11`, matching the repository `packageManager` field.

```bash
bun install
bun dev
cd packages/numasec
bun typecheck
bun test --timeout 30000
bun run build
```

Do not run `bun test` from the repository root; package tests run from their package directories.

## License

[MIT](./LICENSE). Use it for authorized work, research, education, and defense.

<p align="center">
  Built by <a href="https://www.linkedin.com/in/francesco-stabile-dev">Francesco Stabile</a>
  | <a href="https://x.com/Francesco_Sta">@Francesco_Sta</a>
  <br/><sub>If numasec helps you, <a href="https://github.com/FrancescoStabile/numasec/stargazers">drop a star</a>. Thanks for the support.</sub>
</p>
