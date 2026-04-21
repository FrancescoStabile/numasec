<p align="center">
  <img src="assets/readmeimage.png" alt="numasec" width="720" />
</p>

<h1 align="center">numasec</h1>

<p align="center"><b>Terminal native AI for real security work.</b></p>

<p align="center">
  <a href="https://github.com/FrancescoStabile/numasec/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/FrancescoStabile/numasec/ci.yml?branch=develop&style=for-the-badge&label=CI&logo=github" alt="CI"></a>
  <a href="https://github.com/FrancescoStabile/numasec/releases"><img src="https://img.shields.io/github/v/release/FrancescoStabile/numasec?include_prereleases&style=for-the-badge&color=00ff41&label=release" alt="release"></a>
  <a href="https://www.npmjs.com/package/numasec"><img src="https://img.shields.io/npm/v/numasec?style=for-the-badge&color=00ff41&logo=npm" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="MIT"></a>
  <a href="https://github.com/FrancescoStabile/numasec/stargazers"><img src="https://img.shields.io/github/stars/FrancescoStabile/numasec?style=for-the-badge&color=yellow&logo=starship" alt="stars"></a>
</p>

<p align="center">
  <a href="#what-numasec-is">What it is</a> |
  <a href="#what-ships">What ships</a> |
  <a href="#operations-are-the-product">Operations</a> |
  <a href="#what-you-actually-type">Commands</a> |
  <a href="#install">Install</a> |
  <a href="#docs">Docs</a>
</p>

<p align="center">
  <img src="assets/demo-pentest.gif" alt="numasec running a pentest against OWASP Juice Shop" width="900" />
</p>

## What numasec is

Most AI security tools still feel like one of two bad ideas.

The first is a scanner that dumps 500 findings and walks away.

The second is a chat wrapper that sounds confident and cannot actually do the work.

numasec is the third thing.

It is a security focused agent environment for the terminal. It can switch between specialist agents, keep engagement memory on disk, drive a real browser, send raw HTTP, run the tools already on your machine, and hand you back a scoped engagement instead of a pile of vibes.

Open numasec, run `/pwn https://target`, let it create the operation, pick the right play, route to the right agent, keep notes in `numasec.md`, and package the result when you are done.

> If Claude Code is an engineer, **numasec is an operator.**

<p align="center"><sub>5 primary agents | 2 user facing subagents | 30 built in tools | 5 built in plays | 2 embedded skills | 7 operation kinds</sub></p>

## What ships

This is the shape of numasec right now: a terminal-native security stack with real agents, real workflows, and enough built-in machinery to feel like a small operating environment instead of a prompt wrapper.

| Layer | What is actually there |
|---|---|
| Primary agents | `security`, `pentest`, `appsec`, `osint`, `hacking` |
| Subagents | `general`, `explore` |
| Internal helpers | `compaction`, `title`, `summary` |
| Operation kinds | `pentest`, `appsec`, `osint`, `hacking`, `bughunt`, `ctf`, `research` |
| Built in plays | `web-surface`, `network-surface`, `appsec-triage`, `osint-target`, `ctf-warmup` |
| Built in skills | `passive-osint`, `forensics-kit` |
| Core palette | 30 built in tools spanning shell, files, browser, HTTP, scanner, crypto, net, methodology, CVE, remediation, and sharing |

That is the part people immediately get when they see numasec for the first time: it is not one prompt with a terminal attached. It is a small security operating system.

### The agents

`security` is the generalist. `pentest` is the engagement driver for recon, exploitation, and reporting. `appsec` is for code review and application assessment. `osint` is for intelligence gathering and forensics. `hacking` is for CTFs, exploit development, and reverse engineering.

Kinds and agents are intentionally not the same thing. A `bughunt` operation boots into `pentest`. A `ctf` operation boots into `hacking`. A `research` operation boots into `security`. That lets the workflow feel natural without multiplying agents just for branding.

### The subagents

`general` is the parallel worker. Hand it a noisy or multi step task and let it go wide without trashing the main thread.

`explore` is the fast codebase scout. It is tuned for finding files, tracing patterns, and answering "where does this live?" questions quickly.

Under the hood, numasec also uses helper agents for compaction, title generation, and summaries so long sessions stay usable.

### The plays

The built in plays are not marketing props. They are actual reusable pipelines:

- `web-surface`: crawl, inspect JavaScript, light dir fuzz, passive subdomain enumeration
- `network-surface`: port scan, service probe, banner collection
- `appsec-triage`: repository triage for vuln patterns and focus areas
- `osint-target`: passive target profiling for domains, emails, or handles
- `ctf-warmup`: quick artifact triage using the forensics skill

### The skills

The two embedded skills ship in the binary and are always available:

- `passive-osint`: subdomains, wayback, email and account enumeration without touching the target
- `forensics-kit`: incident triage workflow for suspicious files or challenge artifacts

You can add more with your own `SKILL.md` files. numasec discovers them from skill directories and folds them into the agent context when needed.

### The tools

The core palette is where numasec stops feeling like a demo.

It has normal file and code tools, but also the security primitives you actually want: `bash`, `httprequest`, `browser`, `scanner`, `crypto`, `net`, `vault`, `interact`, `methodology`, `cve`, `play`, `pwn_bootstrap`, `doctor`, `opsec`, `share`, `remediate`.

That means the agent can reason and act in the same place. Open Chromium. Replay an authenticated request. Crawl an app. Parse scope. Look up ATT&CK or PTES offline. Generate a handoff archive. Move from finding to patch.

If you already have `nmap`, `sqlmap`, `ffuf`, `nuclei`, `gobuster`, Burp, or your own binaries on `PATH`, numasec can drive those too through the shell.

## Operations are the product

Every real engagement in numasec becomes an Operation.

An operation is a real file on disk at `.numasec/operation/<slug>/numasec.md`. It is auto loaded as system instruction every time that engagement is active. Scope, target, findings, attempts, dead ends, todo items: the running agent reads the same notebook you do.

That one design choice changes the product completely. Close the laptop on Friday, come back on Monday, reopen the operation, and the agent is still standing in the same room.

<p align="center">
  <img src="assets/demo-operations.gif" alt="creating an operation in numasec" width="900" />
</p>

The sidebar keeps the run readable while work is happening:

- **Pulse**: current target and engagement state
- **Plan**: live todo list, even on models that do not natively expose planning
- **Activity**: tool calls as they happen

`/opsec strict` turns scope into an actual guardrail. HTTP, browser, and shell activity that falls outside declared scope gets blocked before it leaves the tool.

## What you actually type

```text
/pwn https://target           classify target, create operation, pick play, start work
/operations                   switch between saved engagements
/agents                       open the agent picker
/mode pentest                 jump straight into a specialist
/play web-surface https://x   run a reusable pipeline
/teach                        turn on narrated, tutorial style tool use
/doctor                       audit your local setup
/opsec strict                 lock the engagement to declared scope
/share --sign                 create a redacted handoff archive, optionally signed
/remediate OBS-001            turn an observation into patch advice
/review                       review the current repo like an appsec engineer
/models                       switch model without leaving the TUI
```

There is a lot more in the TUI, but those are the commands that tell the story fast.

## Why numasec feels different

It keeps memory on disk instead of pretending the context window is enough.

It separates specialist agents from operation kinds instead of forcing everything into one assistant voice.

It treats tools as first class primitives instead of accessories.

It can teach while it works. `/teach` turns the whole session into narrated operator mode, which is perfect for demos, live training, or recorded walkthroughs.

It works with the models you already use. Anthropic, OpenAI, Google, xAI, Bedrock, GitHub Models, OpenRouter, Ollama, and any OpenAI compatible endpoint can sit behind the same TUI.

## Install

```bash
npm i -g numasec
numasec
```

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

## Recommended toolkit

numasec has its own browser, HTTP, scanner, crypto, net, CVE, and methodology tooling built in. It still gets better when your machine already has the usual security binaries installed.

```bash
# Debian / Kali / Ubuntu
apt install nmap sqlmap ffuf gobuster nikto

# macOS
brew install nmap sqlmap ffuf gobuster nikto

# Headless browser for the built in browser tool
npx playwright install chromium
```

Run `/doctor` any time. It checks runtime, workspace, vault mode, CVE bundle, and which external tools are present or missing.

## First run

```bash
numasec
```

Then:

```text
/pwn http://localhost:3000
```

numasec classifies the target, creates and activates an operation, picks the matching play, and starts with the right default agent.

If you want persistent project context outside a specific operation, drop a `numasec.md` or `.numasec.md` file in the project root. numasec loads it automatically next time.

Example:

```markdown
# Target: internal-api.corp.com
- Base: https://internal-api.corp.com/v2
- Auth: Bearer in `Authorization`
- Creds: testuser / testpass123
- Focus: IDOR, privesc, JWT tampering
- Out of scope: DoS, social engineering, brute force
```

## Docs

| Doc | What it covers |
|---|---|
| [`AGENTS.md`](./AGENTS.md) | Agent behavior, prompts, conventions |
| [`docs/MANIFESTO.md`](./docs/MANIFESTO.md) | What numasec is for, and what it refuses to be |
| [`docs/OPERATIONS.md`](./docs/OPERATIONS.md) | Operation memory, scope, workflow |
| [`docs/TOOLS.md`](./docs/TOOLS.md) | The tool palette |
| [`docs/PROMPTS.md`](./docs/PROMPTS.md) | Prompting model by model |
| [`docs/PLUGINS.md`](./docs/PLUGINS.md) | Extensibility and plugin hooks |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | How to contribute |
| [`SECURITY.md`](./SECURITY.md) | Responsible disclosure |

## FAQ

**Is numasec only for red team work?**  
No. `appsec`, `osint`, and `security` are just as useful for code review, secure design review, triage, and research.

**How is this different from Claude Code or opencode?**  
They are general coding agents. numasec is specialized for security workflows, security tooling, scoped engagements, and operation memory.

**Can I extend it?**  
Yes. Skills are discoverable, plugins can extend the system, and the agent already knows how to work with tools on your own machine.

## Development

> [!IMPORTANT]  
> Bun MUST be version `1.3.11`. I'm not sure why but other versions often corrupt upon building.


```bash
bun install
bun dev
cd packages/numasec
bun typecheck
bun test --timeout 30000
bun run build
```

## License

[MIT](./LICENSE). Do what you want. Do not do crimes.

<p align="center">
  Built by <a href="https://www.linkedin.com/in/francesco-stabile-dev">Francesco Stabile</a>
  | <a href="https://x.com/Francesco_Sta">@Francesco_Sta</a>
  <br/><sub>If numasec saved you a shift, <a href="https://github.com/FrancescoStabile/numasec/stargazers">drop a star</a>. It helps more than you think.</sub>
</p>
