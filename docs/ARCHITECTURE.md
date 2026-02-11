# NumaSec Architecture

> Technical documentation for NumaSec v3.2.0 — AI-driven security testing with multi-stage attack reasoning.

---

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [System Overview](#system-overview)
3. [Core Components](#core-components)
4. [Intelligence Engine (v3.2)](#intelligence-engine)
5. [Standards Engine](#standards-engine)
6. [MCP Integration](#mcp-integration)
7. [SOTA Prompt Engineering](#sota-prompt-engineering)
8. [Tool System](#tool-system)
9. [Context Management](#context-management)
10. [Error Recovery](#error-recovery)
11. [LLM Router](#llm-router)
12. [Report Generation](#report-generation)
13. [File Structure](#file-structure)
14. [Technical Decisions](#technical-decisions)

---

## Design Philosophy

### Single-Agent Architecture

NumaSec implements a unified agent architecture rather than a multi-agent system:

| Approach | Advantages | Trade-offs |
|----------|-----------|------------|
| **Multi-Agent** | Specialized roles, parallel execution | Higher coordination overhead, increased costs |
| **Single-Agent** | Simplified execution, lower latency | Requires sophisticated prompting |

NumaSec compensates for single-agent constraints through advanced prompt engineering, an intelligence engine (attack graph + LLM planner + standards), and intelligent tool orchestration — achieving comparable accuracy at significantly reduced operational cost.

### Core Principles

1. **Chain Exploitation, Not Just Discovery**: The attack graph connects individual findings into multi-stage attack paths — this is what separates a pentest from a vuln scan
2. **Standards-First Reporting**: Every finding is automatically enriched with CVSS v3.1 score, CWE ID, and OWASP Top 10 classification
3. **Dual Interface**: Same engine accessible via interactive CLI (Rich TUI) or programmatic MCP protocol
4. **Tool Integration**: Leverage specialized security tools with guided usage patterns
5. **Resilient Execution**: Implement systematic error recovery (23 patterns)
6. **Context Preservation**: Maintain conversation continuity through group-based trimming
7. **Evidence Collection**: Capture verifiable proof for all findings

---

## System Overview

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             NUMASEC v3.2.0                                       │
│                                                                                  │
│  ┌──────────┐   ┌──────────────────────────────────────────────────────────┐     │
│  │          │   │                     AGENT CORE                           │     │
│  │   CLI    │   │  ┌──────────┐  ┌──────────┐  ┌───────────────────────┐   │     │
│  │ (cli.py) │◄─►│  │ Agent    │  │ Router   │  │ State (Pydantic)      │   │     │
│  │          │   │  │ • ReAct  │◄►│ • DeepSk │  │ • Finding (validated) │   │     │
│  │ • Rich   │   │  │ • CoT    │  │ • Claude │  │ • Severity enum       │   │     │
│  │ • TUI    │   │  │ • Plan   │  │ • GPT-4  │  │ • Auto-enrichment     │   │     │
│  │ • /cmds  │   │  │ • Graph  │  │ • Ollama │  │ • Session persist     │   │     │
│  │          │   │  └────┬─────┘  └──────────┘  └───────────────────────┘   │     │
│  └──────────┘   │       │                                                  │     │
│                 │       ▼                                                  │     │
│  ┌──────────┐   │  ┌──────────────────────────────────────────────────┐    │     │
│  │          │   │  │              INTELLIGENCE ENGINE                 │    │     │
│  │   MCP    │   │  │                                                  │    │     │
│  │ (server) │◄─►│  │  ┌──────────────┐  ┌─────────────────────────┐   │    │     │
│  │          │   │  │  │ Attack Graph │  │ LLM Planner             │   │    │     |
│  │ • 7 tools│   │  │  │              │  │                         │   │    │     │
│  │ • 46 res │   │  │  │ 31 nodes     │  │ 5 target templates      │   │    │     │
│  │ • 2 prmp │   │  │  │ 25+ edges    │  │ + LLM refinement        │   │    │     │
│  │ • stdio  │   │  │  │ 12 chains    │  │ • web_standard          │   │    │     │
│  │ • http   │   │  │  │              │  │ • wordpress             │   │    │     │
│  │          │   │  │  │ sqli→db→cred │  │ • api_rest              │   │    │     │
│  │ Annotated│   │  │  │ →admin→rce   │  │ • spa_javascript        │   │    │     │
│  │ Tools    │   │  │  │              │  │ • network               │   │    │     │
│  └──────────┘   │  │  └──────────────┘  └─────────────────────────┘   │    │     │
│                 │  │                                                  │    │     │
│                 │  │  ┌──────────────────────────────────────────┐    │    │     │
│                 │  │  │ Standards Engine                         │    │    │     │
│                 │  │  │ CVSS v3.1 │ CWE (40+) │ OWASP Top 10     │    │    │     │
│                 │  │  │ auto-enrich on every add_finding()       │    │    │     │
│                 │  │  └──────────────────────────────────────────┘    │    │     │
│                 │  └──────────────────────────────────────────────────┘    │     │
│                 │                                                          │     │
│                 │       ▼                                                  │     │
│                 │  ┌──────────────────────────────────────────────────┐    │     │
│                 │  │                  TOOL REGISTRY                   │    │     │
│                 │  │                                                  │    │     │
│                 │  │  ┌──────┐ ┌──────┐ ┌────────┐ ┌───────┐          │    │     │
│                 │  │  │ nmap │ │ http │ │browser │ │nuclei │          │    │     │
│                 │  │  │      │ │      │ │(8 acts)│ │       │          │    │     │
│                 │  │  └──────┘ └──────┘ └────────┘ └───────┘          │    │     │
│                 │  │  ┌──────┐ ┌──────┐ ┌────────┐ ┌───────┐          │    │     │
│                 │  │  │sqlmap│ │ ffuf │ │ file   │ │command│          │    │     │
│                 │  │  │      │ │      │ │  ops   │ │       │          │    │     │
│                 │  │  └──────┘ └──────┘ └────────┘ └───────┘          │    │     │
│                 │  │                                                  │    │     │
│                 │  │  tools/__init__.py → Central registry + schemas  │    │     │
│                 │  └──────────────────────────────────────────────────┘    │     │
│                 │                                                          │     │
│                 │       ▼                                                  │     │
│                 │  ┌──────────────────────────────────────────────────┐    │     │
│                 │  │              REPORT PIPELINE                     │    │     │
│                 │  │                                                  │    │     │
│                 │  │  Markdown │ HTML (themed) │ JSON │ PDF           │    │     │
│                 │  │  ─────────────────────────────────               │    │     │
│                 │  │  Cover • Executive Summary • Severity Chart      │    │     │
│                 │  │  CVSS/CWE/OWASP per finding • Remediation table  │    │     │
│                 │  └──────────────────────────────────────────────────┘    │     │
│                 └──────────────────────────────────────────────────────────┘     │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow — One Assessment Cycle

```
User Request
     │
     ▼
┌─────────────┐   detect_target_type()    ┌─────────────────┐
│  Agent.run() │ ───────────────────────► │ LLM Planner     │
│              │                          │ template + LLM  │
│              │ ◄─────────────────────── │ → AttackPlan    │
│              │        plan              └─────────────────┘
│              │
│  for phase   │   execute tool   ┌───────────────────┐
│  in plan:    │ ────────────────►│ Tool Registry     │
│              │                  │ nmap/http/browser │
│              │ ◄────────────────│ → raw output      │
│              │     result       └───────────────────┘
│              │
│  extractors  │   update profile  ┌─────────────────┐
│  run on      │ ─────────────────►│ TargetProfile   │
│  every       │                   │ ports, techs,   │
│  result      │                   │ endpoints, vulns│
│              │                   └─────────────────┘
│              │
│  if finding  │   add_finding()   ┌───────────────────┐
│  detected:   │ ─────────────────►│ State             │
│              │                   │ → Pydantic valid. │
│              │   auto-enrich     │ → CWE/CVSS/OWASP  │
│              │                   └────────┬──────────┘
│              │                            │
│              │   mark_discovered()        ▼
│              │ ─────────────────►┌─────────────────┐
│              │                   │ Attack Graph    │
│              │ ◄─────────────────│ → next steps    │
│              │   available paths │ → chain context │
│              │                   └─────────────────┘
│              │
│  inject      │   graph context added to system prompt
│  graph ctx   │   → agent sees: "SQLi confirmed → try DB dump next"
│              │
│  reflect     │   reflect_on_result() → strategic insight
│              │
└──────┬───────┘
       │
       ▼
  Report (MD / HTML / PDF / JSON)
  with CVSS, CWE, OWASP per finding
```

---

## Core Components

### agent.py — Core Agent (760 LOC)

The agent implements a continuous reasoning loop:

1. **Plan Generation**: `generate_plan_with_llm()` detects target type, selects template, refines via LLM (falls back to sync `generate_plan()`)
2. **Dynamic System Prompt**: Built per-iteration with base prompt + target profile + plan status + **attack graph context** + escalation chains + knowledge
3. **Tool Execution**: Execute tools, run extractors, reflect on results
4. **Finding Pipeline**: `create_finding` → Pydantic validation → auto-enrichment (CWE/CVSS/OWASP) → attack graph `mark_discovered()` → downstream chain activation
5. **Attack Graph Injection**: `self.attack_graph.to_prompt_context()` tells the LLM what chains are now available: "SQLi confirmed → try DB dump → credential extraction → admin access"
6. **Loop Detection**: Hash-based dedup prevents infinite tool cycles

```python
# The key integration points in agent.py:
self.attack_graph = AttackGraph()  # 31 nodes, 25+ edges, 12 chains

# In _build_dynamic_system_prompt():
graph_ctx = self.attack_graph.to_prompt_context()  # injected every iteration

# In run():
plan = await generate_plan_with_llm(objective, profile, self.router)  # LLM-refined

# On every finding:
self.attack_graph.mark_discovered(finding.title)  # activates downstream paths
```

### router.py — Multi-Provider LLM (641 LOC)

**LLMRouter** manages provider selection, failover, and task-aware routing:

- **Initialization**: Defines priority order (default: DeepSeek → Claude → OpenAI)
- **Task Types**: `TaskType` enum routes different workloads (ASSESSMENT, PLANNING, REFLECTION, etc.) to optimal providers
- **Failover Strategy**: On rate limit errors, automatically tries next provider
- **Error Handling**: Propagates non-recoverable errors
- **Provider Exhaustion**: Raises exception if all providers fail

### state.py — Pydantic State (175 LOC)

**State** manages session data with validated findings:

- **Finding (Pydantic BaseModel)**: Title validation (>= 10 chars, no generic titles), `Severity` enum with fuzzy normalization, auto-timestamp, CWE/CVSS/OWASP fields
- **Auto-enrichment**: `add_finding()` calls `enrich_finding()` — every finding gets standards metadata automatically
- **Session Persistence**: `~/.numasec/sessions/{id}.json` with full context restoration

---

## Intelligence Engine

> **v3.2.0 — The core differentiator.** Other tools find individual vulnerabilities; NumaSec chains them into multi-stage attacks.

### Attack Graph (689 LOC)

A directed exploitation graph that reasons about attack chains:

```
             ┌─────────────────────────────────────────────────────┐
             │              ATTACK GRAPH                           │
             │                                                     │
             │   31 Capability Nodes:                              │
             │   sqli, sqli_blind, xss_stored, xss_reflected,      │
             │   lfi, rfi, ssrf, ssti, cmdi, file_upload,          │
             │   file_write, auth_bypass, idor, default_creds,     │
             │   db_access, credential_dump, admin_access, rce,    │
             │   session_hijack, account_takeover, data_exfil,     │
             │   internal_access, log_poisoning, webshell,         │
             │   token_forgery, jwt_vuln, dir_listing,             │ 
             │   config_exposure, info_disclosure, pii_leak,       │
             │   secrets_found                                     │
             │                                                     │
             │   25+ Directed Edges (exploitation techniques)      │
             │   12 Pre-built Exploitation Chains                  │
             └─────────────────────────────────────────────────────┘

Chain Examples:
  Chain 1: SQLi → DB Dump → Credential Extraction → Admin Access → RCE
  Chain 2: LFI → Log Poisoning → RCE
  Chain 3: SSRF → Internal Access → Config Exposure → Credential Dump
  Chain 4: File Upload → Web Shell → RCE
  Chain 5: XSS → Session Hijacking → Account Takeover
  Chain 6: SSTI → RCE (direct)
  Chain 7: Auth Bypass → Admin Access → RCE
  Chain 8: Default Creds → Admin Access → File Write → Web Shell → RCE
  ...
```

**How it works:**

1. Agent discovers a vulnerability (e.g., SQL Injection in `/api/users`)
2. `mark_discovered("SQL Injection in /api/users")` activates the "sqli" node
3. 3-tier fuzzy matching: exact ID → label substring → keyword aliases (15+ mappings)
4. Returns available exploitation paths: "SQLi confirmed → try DB dump next"
5. `to_prompt_context()` injects chain state into next LLM call
6. Agent sees downstream steps and automatically pursues escalation

**Serialization**: Full `to_dict()` / `from_dict()` for session persistence — attack graph state survives session pause/resume.

### LLM-Powered Planner (743 LOC)

Intelligent plan generation with target-type awareness:

| Target Type | Detection | Template Phases |
|------------|-----------|-----------------|
| `web_standard` | Default (HTTP ports detected) | Recon → Mapping → Injection → Access → Post-Exploit |
| `wordpress` | "wordpress" in technologies | Recon → WP Enum → Plugin Exploit → Privilege Esc → Post-Exploit |
| `api_rest` | FastAPI/Express/Flask in techs | Recon → API Mapping → Auth Testing → Injection → Data Extract |
| `spa_javascript` | React/Vue/Angular or SPA flag | Recon → JS Analysis → API Audit → Client-Side → Post-Exploit |
| `network` | No web ports open | Host Discovery → Port Scan → Service Exploit → Pivot → Post-Exploit |

**Flow:**

1. `detect_target_type(profile)` analyzes technologies and ports
2. Select matching template (5 phases each, with specific tools/techniques per step)
3. Serialize profile + template to LLM via `router.stream(task_type=TaskType.PLANNING)`
4. LLM refines plan: adjusts phases, adds target-specific steps, reorders priorities
5. Parse JSON response → `AttackPlan` object
6. Fallback: On LLM failure, use raw template (zero dependency on LLM availability)

---

## Standards Engine

> `src/numasec/standards/` — Every finding speaks the language of compliance.

### CVSS v3.1 Calculator (203 LOC)

- `calculate_cvss_score(vector)` → Full base-score computation per CVSS v3.1 spec
- 17+ pre-built vectors for common vulnerability types (SQLi, XSS, RCE, LFI, etc.)
- `cvss_from_severity(severity)` → Quick mapping for when vector isn't available
- `cvss_from_vuln_type(vuln_type)` → Best-effort vector selection from title keywords

### CWE Mapping (360 LOC)

- 40+ CWE entries with keyword-based matching
- `map_to_cwe(text)` → Analyzes finding title/description text, returns CWE ID + name
- Each entry cross-references OWASP category
- `get_cwe_by_id("CWE-89")` → Direct lookup

### OWASP Top 10 2021 (194 LOC)

- Full 10-category taxonomy (A01:2021 through A10:2021)
- `map_cwe_to_owasp(cwe_id)` → CWE → OWASP resolution via CWE database cross-ref
- `get_owasp_category("A03:2021")` → Direct category lookup with descriptions

### Auto-Enrichment Pipeline

```python
# In state.py add_finding():
def add_finding(self, finding: Finding):
    enrich_finding(finding)  # ← automatic, every time
    self.findings.append(finding)

# enrich_finding() fills ONLY empty fields:
#   title → map_to_cwe() → CWE-89
#   CWE-89 → map_cwe_to_owasp() → A03:2021 - Injection
#   severity → cvss_from_severity() → 7.5
```

---

## MCP Integration

> NumaSec as a native MCP server — usable from Claude Desktop, Cursor, VS Code, any MCP host.

### Architecture: "Engine-In-Place, MCP-as-Skin"

```
┌───────────────────┐     stdio / HTTP     ┌───────────────────────────┐
│  MCP Client       │ ◄──────────────────► │  NumaSec MCP Server       │
│                   │                      │  (mcp_server.py)          │
│  • Claude Desktop │     MCP Protocol     │                           │
│  • Cursor         │                      │  7 Tools (annotated)      │
│  • VS Code        │                      │  46+ Resources            │
│  • Any MCP host   │                      │  2 Prompts                │
└───────────────────┘                      └──────────┬────────────────┘
                                                      │
                                                      ▼
                                           ┌───────────────────────┐
                                           │  mcp_tools.py         │
                                           │  (bridge layer)       │
                                           │                       │
                                           │  Wraps Agent engine   │
                                           │  with graceful        │
                                           │  fallback on missing  │
                                           │  tools                │
                                           └───────────┬───────────┘
                                                       │
                                                       ▼
                                           ┌───────────────────────┐
                                           │  Agent Core           │
                                           │  (completely          │
                                           │   untouched)          │
                                           └───────────────────────┘
```

### MCP Tools (with ToolAnnotations)

| Tool | Purpose | Annotations |
|------|---------|-------------|
| `numasec_assess` | Full security assessment | `destructiveHint=True`, `openWorldHint=True` |
| `numasec_quick_check` | Headers/CORS/cookies audit | `readOnlyHint=True`, `openWorldHint=True` |
| `numasec_recon` | Port scanning + HTTP probing | `readOnlyHint=True`, `openWorldHint=True` |
| `numasec_http` | HTTP requests with security focus | `openWorldHint=True` |
| `numasec_browser` | Playwright browser automation | `openWorldHint=True` |
| `numasec_get_knowledge` | Knowledge base lookup | `readOnlyHint=True` |
| `create_finding` | Log a security finding | `readOnlyHint=True` |

### MCP Resources

- `numasec://kb/{topic}` — 46+ knowledge base articles (cheatsheets, attack chains, payloads)
- Entire knowledge directory exposed as structured resources for LLM consumption

---

## SOTA Prompt Engineering

NumaSec implements five research-backed optimization techniques:

### 1. Few-Shot Examples (+55% accuracy)

Each tool has 2-3 example interactions showing scenario → thinking → tool call → result → follow-up. Integrated into system prompt.

### 2. Chain-of-Thought (CoT)

Mandatory `<thinking>` tags before every action: goal identification → context assessment → tool selection → risk analysis.

### 3. Self-Correction (Reflexion)

On tool failure: failure analysis → target validation → parameter review → alternative strategies. Agent adjusts autonomously.

### 4. Error Recovery (23 Patterns)

Regex-matched recovery strategies per tool (nmap, sqlmap, browser). Pattern match → guidance hint → LLM adjusts next attempt.

### 5. Context Management (Group-Based Trimming)

Bundle assistant messages with tool results as atomic units. Delete oldest complete groups (never split mid-sequence). Zero API errors.

### 6. Attack Graph Context Injection (NEW in v3.2)

The dynamic system prompt now includes real-time attack graph state:

```
## Attack Graph Status
Confirmed: sqli, lfi
Available chains:
  - SQLi → DB Dump → Credential Extraction (priority: 1)
  - LFI → Log Poisoning → RCE (priority: 2)
Next recommended steps:
  1. Use sqlmap --dump to extract database contents
  2. Read /var/log/apache2/access.log via LFI for log poisoning
```

This gives the LLM strategic direction — not just "what to test" but "where to escalate."

---

## Tool System

### Tool Registration

**TOOL_REGISTRY** (700 LOC): JSON Schema per tool with types, descriptions, validation, enums. 20 tools total.

### Browser Tools Architecture (1,608 LOC)

**BrowserContextPool**: Up to 3 concurrent Playwright contexts with 5-minute TTL, session persistence (cookies/localStorage), lazy initialization.

### Browser vs HTTP

| Use Case | Tool |
|----------|------|
| API testing, header manipulation, response inspection | `http` |
| JavaScript-rendered pages (SPAs), XSS proof screenshots | `browser_*` |
| Form interactions, login flows, cookie testing | `browser_*` |

---

## Context Management

### Group-Based Trimming (261 LOC)

**Problem**: LLM APIs require tool results immediately after tool calls. Naive trimming orphans tool results → 400 errors.

**Solution**:
1. Build groups: assistant message + its tool results = atomic unit
2. Token accounting per group
3. Delete oldest complete groups (never split mid-sequence)
4. Always preserve system prompt + recent context

**Result**: Zero API errors from context issues across 128k token window.

---

## Error Recovery

### 23 Patterns (443 LOC)

**Nmap**: Root privileges → TCP connect scan, host down → skip ping, unreachable → verify target

**SQLmap**: Parameter detection → explicit param, connection → retry with different method

**Browser**: Timeout → increase wait, element not found → alternative selectors, navigation → validate URL

**Integration**: Error text → regex match → recovery strategy → hint appended to tool output → LLM adjusts.

---

## LLM Router

### Provider Configuration

| Provider | Model | Cost/Test | Max Tokens | Task Routing |
|----------|-------|-----------|------------|--------------|
| DeepSeek | deepseek-chat | $0.12 | 128k | Default for assessment |
| Claude | claude-sonnet-4 | $0.50 | 200k | Complex reasoning |
| OpenAI | gpt-4 | $0.80 | 128k | Fallback |
| Ollama | Local | Free | Varies | Air-gapped environments |

### Task-Aware Routing

`TaskType` enum routes workloads to optimal providers:
- `ASSESSMENT` → DeepSeek (cost-efficient for tool-heavy work)
- `PLANNING` → Can use any provider (plan generation via `generate_plan_with_llm`)
- `REFLECTION` → Strategic analysis of tool results

### Message Normalization

Converts NumaSec's internal format to provider-specific schemas (DeepSeek tool roles, Claude content blocks, OpenAI function_call). Transparent provider switching.

---

## Report Generation

### Four Output Formats

| Format | Module | Features |
|--------|--------|----------|
| **Markdown** | `report.py` | Structured sections, severity tables, remediation |
| **HTML** | `report.py` + `renderer.py` | Themed (cyberpunk), styled, interactive |
| **JSON** | `report.py` | Machine-readable, all metadata preserved |
| **PDF** | `pdf_report.py` | Professional pentest report (reportlab) |

### PDF Report Structure (613 LOC)

1. **Cover Page**: Target, date, session ID, branding
2. **Executive Summary**: Risk score (0-100), severity donut chart, summary statistics
3. **Target Profile**: Ports table, technologies, WAF detection, OS fingerprint
4. **Findings**: Sorted by severity, each with CVSS/CWE/OWASP metadata, evidence in code blocks
5. **Attack Timeline**: Plan phases and execution status
6. **Remediation Summary**: Priority table (Critical → Info)
7. **Methodology Appendix**: Tools used, approach documentation

---

## File Structure

```
src/numasec/                          # 17,878 LOC across 39 files
├── __init__.py              # Package exports, __version__
├── __main__.py              # Entry point (python -m numasec)
│
├── agent.py                 # 🧠 Core agent loop (760 LOC)
│   ├── Agent class          #    ReAct loop + intelligence engine integration
│   ├── run()                #    LLM planner → tool execution → graph update
│   ├── execute_tool()       #    Tool dispatch + error recovery
│   ├── _build_dynamic_system_prompt()  # Profile + plan + attack graph context
│   └── TOOL_TIMEOUTS        #    Adaptive per-tool timeouts
│
├── attack_graph.py          # 📊 Multi-stage exploitation graph (689 LOC)
│   ├── AttackGraph          #    31 nodes, 25+ edges, 12 chains
│   ├── mark_discovered()    #    3-tier fuzzy matching + alias dict
│   ├── get_available_paths()#    Chain activation after discovery
│   ├── to_prompt_context()  #    LLM-readable graph state
│   └── to_dict/from_dict()  #    Session persistence
│
├── planner.py               # 📋 LLM-powered planner (743 LOC)
│   ├── PLAN_TEMPLATES       #    5 target types × 5 phases
│   ├── detect_target_type() #    Profile → target classification
│   ├── generate_plan_with_llm()  # Async: template + LLM refinement
│   ├── generate_plan()      #    Sync fallback
│   └── AttackPlan           #    Plan state management
│
├── standards/               # 📐 Security standards engine
│   ├── __init__.py          #    enrich_finding() — auto-enrichment
│   ├── cvss.py              #    CVSS v3.1 calculator (203 LOC)
│   ├── cwe_mapping.py       #    40+ CWE entries (360 LOC)
│   └── owasp.py             #    OWASP Top 10 2021 (194 LOC)
│
├── router.py                # 🔀 Multi-LLM routing (641 LOC)
│   ├── LLMRouter            #    Provider selection + failover
│   ├── TaskType enum        #    Task-aware routing
│   └── normalize_messages() #    Provider format conversion
│
├── state.py                 # 💾 Session state (175 LOC)
│   ├── Finding (Pydantic)   #    Validated model with auto-enrichment
│   ├── Severity enum        #    critical/high/medium/low/info
│   └── State                #    Findings + messages + session
│
├── report.py                # 📄 Report generation (1,055 LOC)
│   └── write_report()       #    MD / HTML / JSON / PDF dispatch
│
├── pdf_report.py            # 📑 PDF report (613 LOC)
│   ├── generate_pdf_report()#    Professional pentest report
│   ├── _severity_chart()    #    Donut chart via reportlab
│   └── Custom styles        #    CoverTitle, SeverityBadge, etc.
│
├── renderer.py              # 🎨 HTML renderer (1,435 LOC)
├── cli.py                   # 💻 Rich TUI CLI (921 LOC)
├── config.py                # ⚙️ Configuration (208 LOC)
│
├── mcp_server.py            # 🔌 MCP server (527 LOC)
│   ├── 7 tools (annotated)  #    ToolAnnotations on all tools
│   ├── 46+ resources        #    numasec://kb/* URIs
│   └── 2 prompts            #    Assessment + quick check workflows
│
├── mcp_tools.py             # 🔧 MCP tool bridge (819 LOC)
│   └── Graceful fallback    #    Works even without external tools
│
├── mcp_resources.py         # 📚 Knowledge as MCP resources (160 LOC)
│
├── context.py               # 📊 Context trimming (261 LOC)
├── cost_tracker.py          # 💰 Cost tracking (148 LOC)
├── error_recovery.py        # 🛡️ 23 recovery patterns (443 LOC)
├── few_shot_examples.py     # 🎯 Tool examples (505 LOC)
├── extractors.py            # 🔍 Output extractors (534 LOC)
├── reflection.py            # 🪞 Result reflection (179 LOC)
├── chains.py                # ⛓️ Escalation chains (162 LOC)
├── target_profile.py        # 🎯 Target model (354 LOC)
├── knowledge_loader.py      # 📖 Knowledge loading (391 LOC)
├── session.py               # 💿 Session management (284 LOC)
├── plugins.py               # 🔌 Plugin system (553 LOC)
├── demo.py                  # 🎬 Demo mode (422 LOC)
├── theme.py                 # 🎨 Theme definitions
├── logging_config.py        # 📝 Logging setup
│
├── tools/                   # 🛠️ Tool implementations
│   ├── __init__.py          #    Central registry (700 LOC)
│   ├── recon.py             #    nmap, httpx, subfinder (664 LOC)
│   ├── exploit.py           #    nuclei, sqlmap (473 LOC)
│   ├── browser.py           #    Playwright 8-action suite (1,608 LOC)
│   └── browser_fallback.py  #    Fallback logic (239 LOC)
│
├── prompts/                 # 📜 System prompts
│   └── system.md
│
└── knowledge/               # 📚 Attack patterns & cheatsheets
    ├── web_cheatsheet.md
    ├── linux_cheatsheet.md
    ├── attack_chains/       #    Multi-stage attack references
    ├── binary/              #    Binary exploitation
    ├── cloud/               #    Cloud security
    └── ...                  #    30+ knowledge files
```

### Test Suite

```
tests/                               # 3,913 LOC, 320 tests
├── conftest.py                      # Shared fixtures
├── test_agent.py                    # Agent loop tests
├── test_attack_graph.py             # 20+ tests: nodes, edges, discovery, paths, serialization
├── test_chains.py                   # Escalation chain tests
├── test_context.py                  # Context trimming tests
├── test_cost_tracker.py             # Cost tracking tests
├── test_extractors.py               # Extractor tests
├── test_knowledge.py                # Knowledge loading tests
├── test_pdf_report.py               # 6 tests: PDF generation, magic bytes, severity chart
├── test_planner.py                  # Plan generation + 5 template tests + target detection
├── test_plugins.py                  # Plugin system tests
├── test_recon_tools.py              # Recon tool tests
├── test_reflection.py               # Reflection tests
├── test_report.py                   # MD/HTML/JSON report tests
├── test_session.py                  # Session persistence tests
├── test_standards.py                # 30 tests: CVSS, CWE, OWASP, enrichment
├── test_target_profile.py           # Target model tests
└── benchmarks/                      # Integration benchmarks (DVWA, Juice Shop)
    ├── ground_truth.py              # Expected vulnerability definitions
    ├── scorer.py                    # F1/precision/recall scoring
    ├── test_dvwa.py                 # DVWA benchmark suite
    └── test_juice_shop.py           # Juice Shop benchmark suite
```

---

## Technical Decisions

### Primary Provider Selection

| Factor | DeepSeek | Claude | GPT-4 |
|--------|----------|--------|-------|
| Cost | $0.12/pentest | $0.50 | $0.80 |
| Tool calling | Excellent | Excellent | Good |
| Context window | 128k | 200k | 128k |
| Reliability | 99%+ | 99%+ | 99%+ |

DeepSeek offers optimal cost-performance ratio for security testing workloads.

### Pydantic for Finding Validation

- **Type safety**: Catches invalid severity values, generic titles at creation time
- **Auto-enrichment hook**: `add_finding()` calls `enrich_finding()` — zero manual effort
- **Serialization**: Native JSON export for report pipeline and session persistence

### Attack Graph as Differentiator

- **Why**: PentestGPT/Shannon find individual vulns. NumaSec chains them: SQLi → DB dump → credential extraction → admin access → RCE
- **31 nodes cover**: The complete exploitation taxonomy from info disclosure to RCE
- **Fuzzy matching**: Real-world finding titles ("SQL Injection in /api/users") match graph nodes via 3-tier resolution

### Browser Automation Framework

Playwright: async architecture, automatic synchronization, context isolation, Chrome DevTools Protocol access, optimized headless execution.

### Framework Selection

| Framework | Why Not |
|-----------|---------|
| LangChain | High abstraction overhead, limited failure visibility |
| AutoGPT | Multi-agent coordination costs |
| CrewAI | Complex inter-agent communication |

Custom implementation provides fine-grained control over prompt engineering, error handling, attack graph integration, and execution flow.

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to add:
- New tools (`tools/`)
- Recovery patterns (`error_recovery.py`)
- Few-shot examples (`few_shot_examples.py`)
- LLM providers (`router.py`)
- Attack graph nodes/edges (`attack_graph.py`)
- CWE entries (`standards/cwe_mapping.py`)
- Plan templates (`planner.py`)

---

<div align="center">

**Questions?** Open an issue or check [README.md](../README.md)

</div>
