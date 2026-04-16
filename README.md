<p align="center">
  <img src="assets/readmeimage.png" alt="numasec" width="720" />
</p>

<p align="center">
  <strong>AI cybersecurity agent. In your terminal.</strong>
</p>

<p align="center">
  <a href="https://github.com/FrancescoStabile/numasec/stargazers"><img src="https://img.shields.io/github/stars/FrancescoStabile/numasec?style=flat-square&color=00ff41" alt="Stars" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-00ff41?style=flat-square" alt="MIT" /></a>
  <a href="https://github.com/FrancescoStabile/numasec/actions"><img src="https://img.shields.io/github/actions/workflow/status/FrancescoStabile/numasec/ci.yml?branch=develop&style=flat-square&label=CI" alt="CI" /></a>
</p>

---

numasec is an open-source AI agent for cybersecurity that lives in your terminal.

It is not a scanner. It is not a wrapper around ChatGPT. It is a conversational operator — you talk to it, it reasons about what to do, and then it does it. Shell commands, HTTP requests, browser automation, recon, exploitation, reporting. Whatever the job requires.

Think of what Claude Code did for software engineering. numasec does that for security.

<p align="center">
  <img src="assets/pentest-demo.gif" alt="numasec pentest demo" width="720" />
</p>

## Why

AI-powered coding tools changed how people write software. Security has nothing equivalent. There are scanners that dump 500 findings and leave you to figure it out. There are ChatGPT wrappers that can't actually run anything. There is no tool where you can sit in a terminal, describe what you need, and watch an AI agent actually do security work.

numasec fills that gap. It has:

- **Shell access.** Full bash. nmap, sqlmap, nuclei, gobuster, ffuf, burp, wireshark — whatever is installed on your system, numasec can use it. Run it inside Kali and it has access to everything.
- **Native security tools.** Built-in HTTP client, Playwright browser automation, attack surface recon, web crawling. No external dependencies needed for the basics.
- **5 specialized agents.** Each one has deep methodology prompts — not generic "be a hacker" instructions, but structured operational knowledge encoding how experienced practitioners actually work.
- **Any LLM provider.** Anthropic, OpenAI, Google, xAI, OpenRouter, Ollama, Bedrock, GitHub Models. You pick the brain; numasec provides the hands.
- **Single binary.** TypeScript on Bun. Builds to a standalone executable for macOS, Linux, and Windows. No Python, no pip, no virtualenvs.

## Install

```bash
git clone https://github.com/FrancescoStabile/numasec.git
cd numasec && bun install
cd packages/numasec && bun run build
```

The binary lands in `dist/numasec-<platform>/bin/numasec`. Add it to your PATH or run it directly.

**Required for browser tool** — numasec uses Playwright for browser automation:

```bash
npx playwright install chromium
```

Optional but recommended — install external tools to extend what numasec can do:

```bash
apt install nmap sqlmap ffuf gobuster    # or your package manager
```

## Quick start

```bash
numasec
```

That's it. You're in the TUI. Start talking.

```
> Pentest http://localhost:3000 — it's a Juice Shop instance, focus on injection and broken access control
```

numasec will map the attack surface, test endpoints, chain findings, and produce a report. You can interrupt, redirect, ask questions, or take over at any point. It's conversational — not fire-and-forget.

Switch agents with `/mode` or TAB:

```
/mode pentest    # penetration testing
/mode appsec     # code review, SAST, dependency analysis
/mode osint      # open-source intelligence, recon, forensics
/mode hacking    # CTF, exploit dev, reverse engineering
/mode security   # general purpose (default)
```

## What it looks like

<p align="center">
  <img src="assets/attack-chain.gif" alt="attack chain visualization" width="720" />
</p>

<p align="center">
  <img src="assets/report-demo.gif" alt="report generation" width="720" />
</p>

## Agents

| Agent | What it does |
|---|---|
| **security** | General-purpose security operator. Default mode. Ask it anything — threat modeling, architecture review, incident response, whatever. |
| **pentest** | PTES/OWASP methodology. Systematic recon → exploitation → chaining → reporting. |
| **appsec** | Secure code review, SAST, dependency auditing, security architecture analysis. Thinks like a developer who became an attacker. |
| **osint** | Intelligence collection, digital forensics, threat intel. Sources everything, confidence-levels assessments, full provenance chains. |
| **hacking** | CTF, exploit development, reverse engineering, crypto, binary exploitation. Creative problem-solving mode. |

Every agent has a full operational prompt encoding methodology, decision frameworks, and domain expertise. They are not "you are a hacker" one-liners — they are structured operational knowledge built from real-world practice.

## Tools

### Security

| Tool | Description |
|---|---|
| `bash` | Full shell. Run anything — nmap, sqlmap, nuclei, gobuster, metasploit, whatever is on the system. |
| `http_request` | Raw HTTP client with auth, cookies, redirect control, response parsing, curl replay. |
| `browser` | Playwright-based. Navigate, click, fill forms, screenshot, evaluate JS, extract cookies, intercept requests. |
| `observe_surface` | Attack surface recon — crawl, directory fuzz, JavaScript analysis, port scanning, service fingerprinting. |

### Platform

File read/write/edit, grep, glob, git operations, code search, web search, web fetch, multi-file edit, apply patch, task delegation, LSP integration, planning, and more. 20+ tools total.

## .numasec.md

Drop a `.numasec.md` file in any directory to give the agent persistent context for that target:

```markdown
# Target: internal-api.corp.com
- Base URL: https://internal-api.corp.com/v2
- Auth: Bearer token in Authorization header (get from /auth/login)
- Test credentials: testuser / testpass123
- Focus areas: IDOR, privilege escalation, JWT manipulation
- Out of scope: DoS, rate limiting, social engineering
```

numasec loads this automatically when you launch from that directory.

## Providers

numasec is multi-provider. The model handles reasoning; numasec handles execution locally on your machine.

| Category | Providers |
|---|---|
| Cloud | Anthropic, OpenAI, Google, xAI, OpenRouter, AWS Bedrock, GitHub Models |
| Local | Ollama, any OpenAI-compatible endpoint |

Configure with `numasec --provider <name>` or set it in the TUI.

## Development

```bash
bun install              # from repo root
bun dev                  # launch dev mode
bun typecheck            # type check workspace
cd packages/numasec
bun test --timeout 30000 # run tests
bun run build            # build binary
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

[MIT](./LICENSE)

---

<p align="center">
  Built by <a href="https://www.linkedin.com/in/francesco-stabile-dev">Francesco Stabile</a>
  · <a href="https://x.com/Francesco_Sta">@Francesco_Sta</a>
</p>
