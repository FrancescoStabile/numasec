# numasec — Product Requirements Document

**Version**: 2.0  
**Date**: July 2026  
**Status**: Active — this is the guiding document for all development decisions.

---

## 1. What numasec IS

numasec is an adversarial intelligence that lives in the terminal. You point it at an application, and it thinks like a hacker, attacks like a pentester, and reports like a consultant — in real time, in front of you.

```
$ numasec https://target.com
```

One command. The AI takes over. It maps the attack surface, finds vulnerabilities, chains them into attack paths, proves impact, and generates a professional report. You watch the whole thing unfold.

**numasec is NOT:**
- An MCP server for other AI tools to consume
- A library of security scanners
- A wrapper around existing tools
- A chatbot that talks about security

**numasec IS:**
- A single integrated product: TUI + tools + intelligence
- Installed with one command: `pip install numasec` (today), single binary (future)
- The Claude Code of cybersecurity: an AI agent you watch work in your terminal

The product is the **experience**. Not the scanners. Not the API. The experience of watching artificial intelligence do something genuinely dangerous and useful. That experience — screenshotted, GIF'd, shared — is what drives adoption.

---

## 2. Vision — The Inevitable Product

### The Viral Moment

A GIF where numasec:
1. Gets pointed at a real (intentionally vulnerable) application
2. In 3-5 minutes, finds a chain of vulnerabilities
3. Exploits them step by step, showing its reasoning
4. Achieves real impact: admin takeover, data extraction, privilege escalation
5. Generates a professional report

That GIF, posted on Reddit/HN/Twitter, is the "ChatGPT moment" for security. It's the first time people watch an AI think like a hacker.

### Why It's Inevitable

**Timing.** AI agents are exploding. Claude Code proved terminal AI agents are a category. No one has done this for security. numasec is first.

**Fear factor.** Security is different from coding. When Claude Code writes bad code, you reject it. When numasec finds a vulnerability in your app, you feel fear. Fear drives sharing.

**Economics.** A real pentest costs €20K-100K and takes weeks. numasec does it in minutes for API costs. This is a category shift, not an incremental improvement.

### The Experience Target

```
$ numasec https://target.com

🧠 Analyzing target...
   Flask 2.3.2 | React 18 | PostgreSQL | JWT auth
   3 open ports | 47 endpoints | GraphQL detected

🎯 Strategy: "REST API with JWT — testing token security first,
    then injection points, then access controls."

⚡ Phase 1: Reconnaissance                           45s
   [sidebar fills with endpoints, tech stack, hidden paths]

⚡ Phase 2: Vulnerability Assessment                  4m
   🔴 SQL Injection in /api/users?id=
   → "Extracting data..." → "Got admin credentials"
   → "Logging in as admin..." → "Admin panel accessible"
   🔴 IDOR in /api/orders/{id}
   → "Can enumerate all orders with admin token"
   🟡 JWT secret cracked in 2.3s
   → "Forging admin token as alternative path..."

⛓ CHAIN: SQLi → Admin Creds → Admin Panel → User Export
   Impact: Full database compromise (10,000 records)

⛓ CHAIN: Weak JWT → Forged Token → Admin Access
   Impact: Authentication bypass without credentials

📊 Coverage: OWASP 7/10 | Findings: 5 | Chains: 2 | Critical: 2
📄 Report: numasec-report.html
⏱  Duration: 6m 12s | Cost: $0.43
```

Not a table of CVEs. A **story** of how an attacker breaks in.

---

## 3. Architecture

### 3.1 Product Architecture

```
numasec = ONE PRODUCT
├── Install: pip install numasec (now) → single binary (future)
├── Run: numasec https://target.com
├── Experience: TUI with real-time findings, chains, OWASP, report
└── Intelligence: Reasons like a pentester, adapts to the environment
```

### 3.2 Technical Architecture (Current — v4.x)

```
┌──────────────────────────────────────────────────────────┐
│  TUI (TypeScript / Bun / SolidJS)                        │
│  ~63K LOC — forked from OpenCode                         │
│                                                          │
│  ┌─────────────────────┐  ┌───────────────────────────┐  │
│  │ STRATEGIC INTELLIGENCE│  │ EXPERIENCE               │  │
│  │ • System prompts     │  │ • Real-time message view  │  │
│  │ • Agent selection    │  │ • Sidebar: findings,      │  │
│  │ • Subagent delegation│  │   chains, OWASP matrix    │  │
│  │ • LLM reasoning loop │  │ • Header: cost, model     │  │
│  │ • Permission model   │  │ • Report viewer           │  │
│  └─────────────────────┘  └───────────────────────────┘  │
│                    │ JSON-RPC over stdio                  │
│                    │ (worker.py bridge)                   │
├────────────────────┼─────────────────────────────────────┤
│  Python Backend    ▼                                     │
│  ~31K LOC                                                │
│                                                          │
│  ┌─────────────────────┐  ┌───────────────────────────┐  │
│  │ TACTICAL INTELLIGENCE│  │ EXECUTION                 │  │
│  │ • Knowledge base    │  │ • 38 security scanners    │  │
│  │ • BM25 retriever    │  │ • External tool wrappers  │  │
│  │ • Tool output enrich│  │ • Session / checkpoint    │  │
│  │ • Planner (PTES)    │  │ • Report generation       │  │
│  └─────────────────────┘  └───────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### 3.3 Technical Architecture (Target — v6.0)

The Python backend is eliminated. All tools become native TypeScript, integrated directly into the TUI codebase.

```
┌──────────────────────────────────────────────────────────┐
│  numasec (TypeScript / Bun / SolidJS)                    │
│  Single codebase, single runtime                         │
│                                                          │
│  ┌─────────────────────┐  ┌───────────────────────────┐  │
│  │ INTELLIGENCE         │  │ TOOLS                     │  │
│  │ • System prompts     │  │ • http_request (fetch)    │  │
│  │ • Agent reasoning    │  │ • shell (Bun.spawn)       │  │
│  │ • Knowledge base     │  │ • browser (Playwright)    │  │
│  │ • Planner (PTES)     │  │ • test_payloads (generic) │  │
│  │ • Environment aware  │  │ • Specialized scanners    │  │
│  └─────────────────────┘  │   (JWT, race, upload)     │  │
│                           │ • Session / checkpoint     │  │
│  ┌─────────────────────┐  │ • Report generation       │  │
│  │ EXPERIENCE           │  └───────────────────────────┘  │
│  │ • Real-time TUI     │                                 │
│  │ • Sidebar: findings │  ┌───────────────────────────┐  │
│  │ • Attack narratives │  │ KNOWLEDGE BASE            │  │
│  │ • Report viewer     │  │ • Methodology playbooks   │  │
│  └─────────────────────┘  │ • External tool guides    │  │
│                           │ • Attack chain patterns   │  │
│                           │ • Tech-specific guides    │  │
│                           │ • Payload libraries (YAML)│  │
│                           └───────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

**No worker.py.** No JSON-RPC bridge. No PythonBridge. No serialization gotchas. No dual runtime. One codebase. One binary.

### 3.4 Intelligence Architecture

Intelligence is split between two layers:

**Strategic intelligence** (system prompts — the agent's personality):
- WHO the agent is: a senior penetration tester
- HOW it thinks: adversarially, always chaining, always proving impact
- WHEN to follow through vs move on
- WHEN to use external tools vs built-in

**Tactical intelligence** (knowledge base — the agent's expertise):
- WHAT techniques exist for each vulnerability class
- WHAT tools to use and how (external tool guides)
- WHAT patterns indicate chaining opportunities
- WHAT technology-specific attacks to try

This separation is natural and already exists. Prompts live in the TUI (`agent/prompt/*.txt`). Knowledge base lives in `knowledge/templates/` (currently Python, will be TypeScript-loaded YAML).

---

## 4. Tools — The Final Set

### 4.1 Design Philosophy

The tools are the agent's hands. They should be:
- **Few enough** that the LLM can reason about which to use (< 25)
- **Powerful enough** that the agent can accomplish any testing task
- **Transparent enough** that the agent understands what they do
- **Enriched** — every tool response includes context for next steps

### 4.2 The Tool Map (v4.2 target — 21 tools)

#### Primitives (3)

These are the foundation. Like Claude Code's `bash` + `read` + `write`.

| # | Tool | Description | Notes |
|---|------|-------------|-------|
| 1 | `http_request` | Send any HTTP request with full control | Already exists |
| 2 | `shell` | Execute any shell command | Merge of run_command + security_shell |
| 3 | `browser` | Headless browser for SPA/JS | Already exists |

**`shell` is the gateway to external tools.** When nmap, sqlmap, nuclei, ffuf are installed, the agent calls them directly via shell. The knowledge base tells it how.

#### Reconnaissance (4)

| # | Tool | Description | Notes |
|---|------|-------------|-------|
| 4 | `recon` | Port scan + tech fingerprint + service probe | Already exists |
| 5 | `crawl` | Spider + sitemap + OpenAPI discovery | Already exists |
| 6 | `dir_fuzz` | Directory/file brute force | Already exists |
| 7 | `js_analyze` | JS endpoint/secret/route extraction | Already exists |

#### Testing (8)

| # | Tool | Description | Notes |
|---|------|-------------|-------|
| 8 | `injection_test` | SQL, NoSQL, SSTI, CMDI, GraphQL, CRLF, LFI | Absorbs crlf_test + path_test |
| 9 | `xss_test` | Cross-site scripting | Stays separate (different methodology) |
| 10 | `auth_test` | JWT, auth bypass, credential testing | Already exists |
| 11 | `access_control_test` | IDOR, CSRF, CORS, mass assignment | Absorbs mass_assignment_test |
| 12 | `ssrf_test` | Server-side request forgery | Already exists |
| 13 | `upload_test` | File upload abuse | Already exists |
| 14 | `race_test` | Race conditions | Already exists |
| 15 | `vuln_scan` | CVE/template scanning | Already exists |

#### Session (4)

| # | Tool | Description | Notes |
|---|------|-------------|-------|
| 16 | `create_session` | Initialize assessment session | Via worker special method |
| 17 | `save_finding` | Persist a finding | Via worker special method |
| 18 | `build_chains` | Group findings into attack chains | Via worker special method |
| 19 | `generate_report` | Create report | Via worker special method |

#### Utility (2)

| # | Tool | Description | Notes |
|---|------|-------------|-------|
| 20 | `oob` | Out-of-band callback server | Already exists |
| 21 | `poc_validate` | Proof of concept validation | Already exists |

### 4.3 Tools Removed / Consolidated

| Tool | Action | Rationale |
|------|--------|-----------|
| `crlf_test` | → `injection_test` | CRLF is an injection — no separate tool needed |
| `path_test` | → `injection_test` (LFI) + `recon` (host header) | Absorbed into related tools |
| `smuggling_test` | → `shell` + KB entry | Too niche for a dedicated tool. Agent uses shell with KB guidance when needed |
| `burp_bridge` | → optional plugin | Niche user base. Not core product |
| `sqlmap_scan` | → `shell` + KB | Redundant when agent can call `sqlmap` directly via shell |
| `nuclei_scan` | → `shell` + KB | Redundant when agent can call `nuclei` directly via shell |
| `security_shell` | → `shell` | Merged into unified shell tool |
| `run_command` | → `shell` | Merged into unified shell tool |
| `mass_assignment_test` | → `access_control_test` | Mass assignment is an access control issue |
| Duplicate `dir_fuzz` | → fix | Registration bug, remove duplicate |

### 4.4 The `shell` Tool (Critical Design)

`shell` replaces three existing tools (`run_command`, `security_shell`, `sqlmap_scan`, `nuclei_scan`) with a single, powerful primitive.

```
shell(command: str, timeout: int = 300) → {stdout, stderr, exit_code}
```

The agent decides what to run. The knowledge base tells it how. Examples:
- `shell("nmap -sV -sC -p- --min-rate=5000 target.com")`
- `shell("sqlmap -u 'http://target.com/api?id=1' --batch --dump")`
- `shell("nuclei -u target.com -severity high,critical")`
- `shell("ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ")`

Security model: sandboxed execution with allowlisted commands (already exists in the TUI permission system — see `agent.ts` where `nmap *: allow`, `sqlmap *: ask`, etc.).

### 4.5 The `test_payloads` Tool (v6.0 — TypeScript rewrite)

When the Python backend is eliminated, most vulnerability-class-specific scanners become a single generic tool:

```typescript
test_payloads({
  url: string,
  method: "GET" | "POST" | "PUT" | "DELETE",
  parameter: string,
  position: "query" | "body" | "header" | "cookie" | "path",
  payloads: string[],           // from KB YAML
  success_indicators: string[], // from KB YAML
  failure_indicators: string[], // from KB YAML
  timeout_ms: number,
  concurrent: number,           // parallel requests
}) → {
  vulnerable: boolean,
  matched_payload: string,
  evidence: string,
  response_status: number,
  response_body_snippet: string,
}
```

The knowledge base provides payloads and indicators per vulnerability class:

```yaml
# knowledge/payloads/sqli.yaml
payloads:
  error_based: ["' OR 1=1--", "1' UNION SELECT NULL--", ...]
  blind_boolean: ["1' AND 1=1--", "1' AND 1=2--", ...]
  time_based: ["1' AND SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--", ...]
success_indicators:
  error_based: ["error in your SQL syntax", "Warning: mysql_", "ORA-", ...]
  blind_boolean: [] # compare response length/content
  time_based: [] # compare response time
```

This ONE tool replaces ~10 Python scanners for "payload → response check" vulnerability classes: SQLi, XSS, CRLF, open redirect, basic SSTI, basic CMDI, basic LFI.

Scanners that require specialized logic remain as dedicated TypeScript tools:
- JWT analysis (cryptographic operations)
- Race condition testing (precise concurrent timing)
- File upload testing (multipart form handling)
- Browser-based testing (DOM XSS, SPA interaction)
- NoSQL injection (JSON structure manipulation)

### 4.6 Tool Output Enrichment

Every tool response includes context for the LLM. Not just "what happened" but "what to do next."

**Current** (raw results):
```json
{"vulnerable": true, "type": "sqli", "payload": "' OR 1=1--", "url": "/api/users?id=1"}
```

**Target** (enriched results):
```json
{
  "vulnerable": true,
  "type": "sqli",
  "payload": "' OR 1=1--",
  "url": "/api/users?id=1",
  "next_steps": [
    "Use sqlmap via shell for deep exploitation: sqlmap -u 'http://target/api/users?id=1' --batch --dump",
    "Test other endpoints with similar parameter patterns: /api/orders?id=, /api/products?id=",
    "Check if extracted data includes credentials that can be used for auth_test"
  ],
  "chain_potential": "SQLi on data endpoints often chains with IDOR — if you can extract user IDs, test access controls"
}
```

This was started in v4.1.4 (the "agent intelligence rewrite"). The v4.2 release doubles down on it for every tool.

---

## 5. Knowledge Base

### 5.1 Philosophy

The knowledge base fills the gap between "LLM that can execute commands" and "LLM that thinks like a pentester." LLMs are trained on millions of code files but far less security content. The KB is what makes numasec's reasoning security-specific.

**Principles:**
- **Methodology over payloads.** Not "try these 30 SQL strings" but "when you see a numeric parameter on a data endpoint, suspect SQLi because..."
- **Quality over quantity.** 50 excellent playbooks > 100 mediocre templates
- **Actionable.** Every KB entry should be directly usable by the agent in the current assessment
- **Two retrieval modes:** pre-loaded (technology-specific guides in system prompt) and on-demand (agent explicitly queries KB)

### 5.2 Structure

```
knowledge/
├── methodology/                      # HOW TO THINK (highest priority)
│   ├── web_app_assessment.yaml       # Complete playbook for web applications
│   ├── api_assessment.yaml           # REST/GraphQL API testing methodology
│   ├── auth_assessment.yaml          # Authentication testing playbook
│   ├── chain_building.yaml           # How to identify and build attack chains
│   └── follow_through.yaml           # From detection to exploitation to impact proof
│
├── tools/                            # HOW TO USE EXTERNAL TOOLS
│   ├── nmap.yaml                     # When to use, which flags, output interpretation
│   ├── sqlmap.yaml                   # SQLi exploitation workflow
│   ├── nuclei.yaml                   # CVE/template scanning workflow
│   ├── ffuf.yaml                     # Directory fuzzing workflow
│   ├── hydra.yaml                    # Brute force workflow
│   ├── nikto.yaml                    # Web server scanning
│   ├── wpscan.yaml                   # WordPress-specific testing
│   └── gobuster.yaml                 # Directory enumeration
│
├── targets/                          # TECHNOLOGY-SPECIFIC GUIDES
│   ├── jwt.yaml                      # JWT attack vectors, tools, bypass techniques
│   ├── graphql.yaml                  # Introspection, injection, DoS, batching attacks
│   ├── rest_api.yaml                 # IDOR, mass assignment, rate limiting, API versioning
│   ├── oauth.yaml                    # Redirect attacks, token theft, scope escalation
│   ├── websocket.yaml                # Injection, hijacking, origin validation
│   └── spa_react.yaml               # DOM XSS, source maps, API key exposure
│
├── chains/                           # ATTACK CHAIN PATTERNS
│   ├── sqli_to_takeover.yaml         # SQLi → credential extraction → admin access → data theft
│   ├── auth_bypass_chain.yaml        # JWT crack → token forge → admin → panel access
│   ├── ssrf_to_internal.yaml         # SSRF → internal API → cloud metadata → keys
│   ├── idor_to_data_theft.yaml       # IDOR → enumeration → mass scraping
│   └── upload_to_rce.yaml            # File upload → webshell → command execution
│
├── detection/                        # (existing, maintained)
├── exploitation/                     # (existing, expanded with follow-through steps)
├── payloads/                         # (existing, becomes KB-driven for scanners)
├── remediation/                      # (existing)
└── reference/                        # (existing)
```

### 5.3 KB-Driven Payloads

**Today:** Payloads are hardcoded in Python scanner files.
```python
# sqli_tester.py — hardcoded
PAYLOADS = ["' OR 1=1--", "1' UNION SELECT...", ...]
```

**Target:** Scanners read payloads from KB YAML at runtime.
```python
# sqli_tester.py — KB-driven
payloads = self.kb.get_payloads("sqli/error_based")
```

```yaml
# knowledge/payloads/sqli-payloads.yaml
error_based:
  - "' OR 1=1--"
  - "1' UNION SELECT NULL,NULL--"
  - "1' AND 1=CONVERT(int, (SELECT @@version))--"
```

This means:
- Updating payloads = editing a YAML file (no Python code changes)
- Community can contribute payloads via PR (like nuclei templates)
- Scanner logic (how to send, how to evaluate) stays in code
- Payload content (what to send, what to look for) lives in YAML

### 5.4 Retrieval Architecture

**Pre-loaded retrieval:** At session start, the agent's target technology is identified (via recon). Relevant KB entries are injected into the system prompt:
- Flask app → load `targets/rest_api.yaml` + `methodology/web_app_assessment.yaml`
- GraphQL detected → load `targets/graphql.yaml`
- JWT auth → load `targets/jwt.yaml` + `methodology/auth_assessment.yaml`

**On-demand retrieval:** The agent explicitly queries the KB mid-assessment:
- "I found SQLi, how do I exploit it?" → retriever returns `exploitation/exploit-injection-methodology.yaml`
- "What sqlmap flags should I use?" → retriever returns `tools/sqlmap.yaml`
- "What chains from SQLi?" → retriever returns `chains/sqli_to_takeover.yaml`

The retriever uses BM25 (keyword matching) with optional semantic reranking (60% BM25, 40% cosine similarity). This already exists and works.

---

## 6. System Prompts — The Agent's Personality

### 6.1 Current State

11 prompt files totaling 516 lines across 5 primary agents (pentest, recon, hunt, review, report), 4 subagents (scanner, analyst, reporter, explore), and 3 utility agents (compaction, title, summary).

The prompts are **good but procedural.** They tell the agent what to DO ("run recon, then test injection, then test auth"). They should teach the agent how to THINK.

### 6.2 Target State — Reasoning-Based Prompts

The system prompts should encode adversarial thinking patterns, not step-by-step procedures.

**Core principles to embed in prompts:**

1. **Every finding is a starting point.** When you find something, don't move on. Ask: "Can I use this to go deeper? Does this combine with something else? What's the real-world impact?"

2. **Chains are the goal.** Individual vulnerabilities are interesting. Attack chains are devastating. Always look for: vulnerability A → escalation B → impact C.

3. **Prove impact.** "SQL injection exists" is boring. "Extracted 10,000 user records via SQL injection" is terrifying. Go from detection → exploitation → concrete impact.

4. **Adapt to tools.** When external tools are available, use them — they're more thorough than built-in scanners. When they're not, the built-in scanners work fine.

5. **Tell the story.** Your output isn't a list of CVEs. It's a narrative: "Starting from X, I discovered Y, which led to Z, with the final impact being..."

### 6.3 Prompt Changes

The pentest prompt already contains good reasoning patterns (see "CROSS-FINDING INTELLIGENCE" section and "QUALITY STANDARDS" section in current `pentest.txt`). The changes for v4.2 are:

1. **Add follow-through instructions.** After each finding, the agent should attempt exploitation and impact proof before moving on.

2. **Add environment adaptation.** Inject available tools into the prompt; teach the agent when to prefer shell(nmap) over built-in recon.

3. **Expand chain-building guidance.** Specific chain patterns: "SQLi + credential extraction → auth_test with stolen creds" etc.

4. **Shorten the procedural parts.** The current "TESTING STRATEGY" section is a priority list. It should be a reasoning framework.

---

## 7. Environment Adaptation

### 7.1 Philosophy

numasec adapts to whatever tools are available. No setup required. No configuration ceremony. The Claude Code approach: try the best tool, fall back if not available.

### 7.2 Detection

At session start (< 0.5 seconds), check PATH for known security tools:

```
nmap, sqlmap, nuclei, ffuf, gobuster, nikto, hydra, amass, wpscan,
subfinder, feroxbuster, dirsearch, whatweb, wafw00f, john, hashcat
```

Also detect:
- OS: `uname -s` → Linux/Darwin, plus `/etc/os-release` for distro (Kali detection)
- Shell: `$SHELL`
- Python: `python3 --version` (for Python-based tools)

### 7.3 Injection

The result is injected as a single block into the system prompt:

```
# Environment
OS: Kali Linux 2025.1
Security tools: nmap (7.94), sqlmap (1.8), nuclei (3.2.4), ffuf (2.1.0), hydra (9.5)
Not installed: amass, wpscan, nikto, subfinder
```

Or for a macOS developer:

```
# Environment
OS: macOS 15.1
Security tools: nmap (7.94)
Not installed: sqlmap, nuclei, ffuf, hydra, amass, wpscan, nikto
```

**No tier system.** No capability classes. No consent dialog. Just facts. The agent reads the facts and adapts its strategy. This is how Claude Code handles tool availability — organically, not through formal configuration.

### 7.4 Agent Behavior by Environment

The agent's behavior naturally adapts:

**Kali (full toolset):** Agent uses nmap for recon, sqlmap for SQLi exploitation, nuclei for CVE scanning, ffuf for directory fuzzing, hydra for brute force. Built-in scanners become secondary.

**Linux with some tools:** Agent uses nmap where available, falls back to built-in for unavailable tools. Transparent — the user sees "Using nmap for port scanning" or "Using built-in scanner (nmap not installed)."

**macOS/Windows (minimal tools):** Agent uses built-in scanners for everything. Experience is still good — the scanners work. But depth is limited compared to a full toolset.

**The user never sees an error.** If sqlmap isn't installed, the agent uses the built-in SQLi scanner. If nmap isn't available, it uses the Python port scanner. The experience degrades gracefully, never breaks.

---

## 8. Report Format

### 8.1 Current State

Reports are tables of findings with severity, URL, description, and remediation. Functional but not compelling.

### 8.2 Target State — Attack Narratives

The report tells a **story**, not a list. It's structured as:

**1. Executive Summary** (1 paragraph)
> "We identified 2 attack paths that lead to complete application compromise. An attacker starting from the public login page can gain full admin access and extract the entire user database within 5 minutes."

**2. Attack Paths** (one section per chain)
> "**Path 1: SQL Injection → Admin Takeover**
> Starting from the `/api/users` endpoint, we discovered a SQL injection vulnerability in the `id` parameter. By exploiting this, we extracted admin credentials from the database. Using these credentials, we accessed the admin panel at `/admin/`, which exposed a user export function containing 10,000 records including names, emails, and hashed passwords.
>
> **Impact:** Full database compromise. 10,000 users affected.
> **Time to exploit:** 3 minutes from initial discovery."

**3. All Findings** (detailed table with remediation per finding)

**4. Remediation Roadmap** (prioritized by chain impact)
> "Priority 1: Fix SQL injection (blocks Attack Path 1)
> Priority 2: Rotate JWT secret (blocks Attack Path 2)
> Priority 3: Implement IDOR protection (reduces blast radius)"

The same information as today, but formatted as a narrative that a CEO understands, a CISO brings to the board, and a developer fixes in a day.

### 8.3 Implementation

The report generator takes findings + chains and produces the narrative. The LLM generates the narrative text (executive summary, attack path descriptions). The structure (finding details, remediation, OWASP coverage) is deterministic.

---

## 9. Finding Model

### 9.1 Current Model

```python
class Finding:
    title, description, severity, url, method, parameter
    evidence, remediation, cwe_id, cvss_score, cvss_vector
    owasp_category, confidence, chain_id, related_finding_ids
    timestamp, id (auto-generated)
```

### 9.2 Changes

One field added:

```python
next_actions: list[str]  # Deterministic suggestions for what to try next
```

Populated by tool output enrichment logic (not by the LLM). When a finding is saved:
- SQLi finding → `["Use sqlmap for deep exploitation", "Test related endpoints", "Check for credential extraction"]`
- JWT weakness → `["Forge admin token", "Test protected endpoints with forged token"]`
- IDOR → `["Enumerate sequential IDs", "Test with different auth levels"]`

**Not added:** `exploitation_steps`, `impact_proof`, `chain_narrative`. These belong in the **report**, not in individual findings. Reports are generated from findings + chains; the narrative is produced at report time by the LLM.

---

## 10. OpenCode Fork Strategy

### 10.1 Decision

**Cherry-pick selective.** Accept divergence. Monitor upstream releases. Cherry-pick specific commits that add value (new providers, SDK improvements, bug fixes). Never merge wholesale.

### 10.2 Rationale

The parts of OpenCode that numasec uses most (rendering, message handling, agent loop) are the parts most heavily customized (sidebar, header, findings panel, OWASP matrix). Upstream changes to these areas would conflict with and potentially break numasec-specific features.

The parts useful from upstream (new LLM providers, MCP SDK updates, rendering performance) tend to be isolated in `packages/sdk/`, `src/provider/`, `src/mcp/`. These are easier to cherry-pick.

### 10.3 Process

`UPSTREAM_LOG.md` already tracks upstream releases. The workflow:
1. Monitor OpenCode releases (weekly review)
2. For each release, scan changelog for relevant changes
3. If a change is relevant: cherry-pick the specific commit(s)
4. If a change conflicts with numasec customizations: skip or adapt manually
5. Document in `UPSTREAM_LOG.md`

---

## 11. The Python → TypeScript Rewrite

### 11.1 Decision

Eliminate the Python backend entirely. All tools become native TypeScript, built into the TUI codebase. A clean branch (`typescript-rewrite`), done all at once.

### 11.2 Why

| Benefit | Impact |
|---------|--------|
| No worker.py bridge | Eliminates the #1 documented gotcha and fragility source |
| One language, one runtime | Halves cognitive load for a solo founder |
| Simpler distribution | Single binary install instead of Python + Bun |
| Direct function calls | No JSON-RPC overhead, no serialization bugs |
| OpenCode alignment | Tools are native, not foreign Python behind MCP |

### 11.3 What Gets Rewritten

| Component | Python LOC | TypeScript approach |
|-----------|-----------|-------------------|
| Scanners (payload → response) | ~10K | `test_payloads` generic tool + KB YAML |
| Scanners (specialized logic) | ~5K | Dedicated TypeScript tools (JWT, race, upload, NoSQL, browser) |
| Knowledge base loader/retriever | ~1K | YAML loader + BM25 in TypeScript |
| Session store | ~1.5K | Already has Drizzle ORM + SQLite in TUI |
| Composites | ~2K | Agent decides directly; thin TypeScript wrappers if needed |
| Tool registry | ~1K | Native OpenCode tool system |
| Report generation | ~2K | TypeScript, possibly shared with existing TUI report viewer |
| Finding model | ~500 | TypeScript types/zod schemas |
| Planner | ~800 | TypeScript |
| Worker/MCP server | ~2K | **DELETED** |

**Total: ~26K LOC Python → estimated ~12K LOC TypeScript** (due to `test_payloads` genericizing 10+ scanners, and elimination of bridge/MCP code).

### 11.4 What Gets Deleted

- `numasec/worker.py` — the bridge (DELETED)
- `numasec/mcp/` — MCP server infrastructure (DELETED)
- `numasec/tools/_base.py` — ToolRegistry (DELETED, replaced by native OpenCode tools)
- `agent/packages/numasec/src/bridge/` — PythonBridge, internal.ts, setup.ts (DELETED)
- `pyproject.toml` — Python package config (DELETED or reduced to legacy)

### 11.5 What Stays

- `knowledge/templates/*.yaml` — KB content (format unchanged, loader rewritten)
- `community-templates/*.yaml` — community scanner templates (loaded by TypeScript)
- Agent prompts (`agent/prompt/*.txt`) — unchanged
- TUI code (`agent/packages/numasec/src/cli/`) — unchanged
- Session persistence (Drizzle ORM + SQLite) — already TypeScript

### 11.6 Migration Architecture

**`test_payloads`** is the key innovation. It replaces ~10 Python scanners with ONE TypeScript tool:

```typescript
// One tool to rule them all
async function testPayloads(args: {
  url: string
  method: string
  parameter: string
  position: "query" | "body" | "header" | "cookie" | "path"
  payloads: string[]
  successIndicators: string[]
  failureIndicators: string[]
  timeoutMs?: number
  concurrent?: number
}): Promise<TestResult> {
  // Send each payload, check for indicators, return first match
}
```

The KB provides payloads and indicators per vulnerability class. The agent reads the KB, chooses the right payloads, calls `test_payloads`. This replaces:
- `sqli_tester.py` (error-based, UNION-based)
- `xss_tester.py` (reflected, stored)
- `crlf_tester.py`
- `open_redirect_tester.py`
- `lfi_tester.py` (basic path traversal)
- `host_header_tester.py`
- `ssti_tester.py` (basic expression evaluation)
- `command_injection_tester.py` (basic command injection)

Scanners that require specialized logic become dedicated TypeScript tools:
- `jwt_analyzer.ts` — token decode, secret cracking, algorithm confusion
- `race_tester.ts` — concurrent request timing
- `upload_tester.ts` — multipart form construction, type bypass
- `nosql_tester.ts` — JSON structure manipulation, operator injection
- `browser_tester.ts` — DOM interaction, SPA testing
- `graphql_tester.ts` — introspection, query depth, batching

### 11.7 Timing

The rewrite happens AFTER v4.3 (the "GIF release"). The intelligence improvements in v4.2 and v4.3 work with the current Python backend. The rewrite is a v5.0 or v6.0 milestone that improves maintainability and distribution without changing the user experience.

However, if the decision is to do it sooner (which is Francesco's prerogative), the clean-branch approach is correct: create `typescript-rewrite`, migrate everything, test thoroughly, merge when complete.

---

## 12. Migration Path — Release Plan

### v4.2 — The Intelligence Release

**Theme:** Make the agent smarter with what it already has.

**Changes:**
1. System prompt rewrite — reasoning-based, not procedural
2. Knowledge base expansion — +15 new templates (methodology, tools, targets, chains)
3. Environment detection — inject available tools into system prompt
4. Tool output enrichment — next-step suggestions in every tool response
5. Tool consolidation — crlf_test + path_test → injection_test
6. Shell unification — merge run_command + security_shell + sqlmap_scan + nuclei_scan into `shell`
7. Finding model — add `next_actions` field

**Metric:** crAPI recall from 33% → 55%+, with same or better precision.

### v4.3 — The Follow-Through Release

**Theme:** The agent doesn't stop at detection. It proves impact.

**Changes:**
1. Follow-through behavior — agent exploits findings and demonstrates impact
2. Report narratives — attack path stories instead of finding tables
3. KB-driven payloads — scanners read from YAML instead of hardcoded Python
4. Tool cleanup — remove burp_bridge (plugin), mass_assignment → access_control
5. Enhanced chain visualization in TUI sidebar

**Metric:** crAPI recall 55%+ with exploitation proof for every confirmed critical/high. Report includes attack path narratives.

**This is the "GIF release"** — the release that produces the demo that goes viral.

### v5.0 — The TypeScript Release

**Theme:** Kill Python. One codebase. One binary.

**Changes:**
1. `test_payloads` generic tool replaces payload-based scanners
2. Specialized TypeScript tools for JWT, race, upload, NoSQL, GraphQL, browser
3. KB loader and BM25 retriever in TypeScript
4. Session store on Drizzle ORM + bun:sqlite (already exists)
5. Delete: worker.py, PythonBridge, MCP server infrastructure
6. Distribution: single binary via npm

**Metric:** Feature parity with v4.3. All tests green. Distribution simplified.

### v6.0 — The Jarvis Release

**Theme:** Full external tool orchestration. Community flywheel.

**Changes:**
1. Deep integration with 20+ external security tools via shell + KB
2. Community contribution system for payloads (PR on YAML = new attacks)
3. Assessment memory — agent remembers what worked on similar targets
4. Adaptive strategy based on available tools and target type

**Metric:** Professional pentester on Kali achieves 80%+ recall on benchmark targets. Community contributors actively submitting KB content.

---

## 13. Decisions Log

Decisions made during the strategic discussion, recorded for reference.

| # | Decision | Rationale | Date |
|---|----------|-----------|------|
| 1 | numasec is ONE product (TUI + tools), not an MCP server for others | Product dilution. Using numasec tools in Claude Desktop removes the experience. The TUI IS the product. | Jul 2026 |
| 2 | Target user: both security professionals and developers, priority security professional | Pros have existing tools and methodology. numasec adds AI reasoning on top. Developers get a working scanner. | Jul 2026 |
| 3 | OpenCode fork: cherry-pick selective | Customizations are deep (sidebar, findings, OWASP). Wholesale merging would break them. Cherry-pick isolated improvements (providers, SDK). | Jul 2026 |
| 4 | Python elimination: full rewrite on clean branch | No gradual migration. Clean break. One codebase, one runtime, one binary. | Jul 2026 |
| 5 | Environment detection: minimal PATH check, no formal ToolProfile | Claude Code approach — organic discovery, no ceremony. Inject tool list into prompt. Agent adapts. | Jul 2026 |
| 6 | Investment priority: intelligence layer (80%) over tools (20%) | Model quality matters more than tool count (3x recall difference between models on same tools). The brain is the moat. | Jul 2026 |
| 7 | KB philosophy: methodology > payloads, quality > quantity | 50 excellent playbooks beat 100 mediocre templates. Teach HOW to think, not just WHAT to send. | Jul 2026 |
| 8 | Freeze scanner enhancement, invest in intelligence | Don't compete with sqlmap on SQLi payloads. Compete on reasoning, chaining, and follow-through. | Jul 2026 |
| 9 | Report format: attack narratives, not finding tables | A story a CEO understands beats a table a developer skims. Same data, better format. | Jul 2026 |
| 10 | `test_payloads` replaces ~10 scanners in TypeScript rewrite | Generic tool + KB YAML is more maintainable than 10 dedicated scanner files. | Jul 2026 |
| 11 | `shell` as unified external tool gateway | One tool replaces run_command + security_shell + sqlmap_scan + nuclei_scan. Agent decides what to run. | Jul 2026 |
| 12 | No AdversarialReasoner component | The LLM is the reasoner. Tool output enrichment guides next steps. System prompt teaches adversarial thinking. | Jul 2026 |
| 13 | No directory restructuring | Conceptual layers, not physical reorganization. Current structure works. Don't break imports for architectural purity. | Jul 2026 |

---

## 14. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| TypeScript rewrite introduces bugs | High | Medium | Comprehensive test suite. Field testing against crAPI, DVWA, Juice Shop, WebGoat before merge. |
| Intelligence improvements don't translate to better recall | Medium | High | Field test every prompt change against benchmark targets. Measure before/after. |
| OpenCode diverges in a direction that makes cherry-picking hard | Medium | Low | Accept divergence. numasec is its own project. Only cherry-pick isolated improvements. |
| Token costs for enriched prompts become prohibitive | Low | Medium | Monitor cost per assessment. Offer quick/standard/deep modes. Keep prompts dense, not verbose. |
| External tool availability varies too much across environments | Medium | Low | Built-in scanners always work. External tools are enhancement, not requirement. |
| Solo founder bottleneck | High | High | Prioritize ruthlessly. Ship v4.2 and v4.3 before attempting the TypeScript rewrite. |

---

## 15. Success Criteria

### v4.2 success = intelligence measurably improves results
- crAPI recall: 33% → 55%+ (same model, same target)
- Agent uses available external tools without errors
- Tool output includes actionable next-step suggestions
- No regression in precision (maintain 100% or near)

### v4.3 success = the demo that sells itself
- A 90-second GIF of numasec finding and chaining vulnerabilities on a real target
- Report includes attack path narratives, not just finding tables
- At least one chain where the agent follows through: detection → exploitation → impact proof
- Posted on Reddit/HN, reaches front page

### v5.0 success = one codebase, one binary
- `npm install -g numasec` works on macOS, Linux
- No Python runtime required
- Feature parity with v4.3
- All existing tests ported and passing

### v6.0 success = community flywheel
- 10+ community-contributed KB entries (payload files, methodology guides)
- 80%+ recall on benchmark targets with full Kali toolset
- Professional pentesters using numasec in real engagements
