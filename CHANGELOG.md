# Changelog

All notable changes to NumaSec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.2.1] - 2026-02-08 ⚡

### Async MCP + Professional PDF — "Enterprise Polish"

Two quality-of-life upgrades: assessments no longer freeze the MCP client,
and PDF reports look like they were produced by a Fortune-500 security team.

### Added

- **Async assessment session pattern** — 3 new MCP tools (`numasec_assess_start`, `numasec_assess_status`, `numasec_assess_cancel`) for non-blocking audits
  - Background `asyncio.Task` execution with live progress tracking
  - Session lifecycle: start → poll (progress bar + live findings) → complete/cancel
  - Concurrent session limit (max 2), automatic TTL cleanup (1 hour)
  - Works with all MCP transports (stdio, HTTP) and all clients (Claude Desktop, Cursor, VS Code)
- **6 new tests** for async session tools (parameter validation, tool registration)

### Changed

- **PDF report completely redesigned** (`pdf_report.py`)
  - Dark cover page with brand identity (NUMASEC wordmark, green accent, target details)
  - Persistent header/footer on all content pages (branded header, CONFIDENTIAL + page number)
  - Executive summary with metric cards, risk gauge, severity stacked bar chart
  - Finding cards with severity-colored left strip (replaces plain text blocks)
  - Smart page flow — removed forced page breaks between every section
  - Donut chart, stacked severity bars, and horizontal risk gauge visualisations
- MCP tool count: 7 → 10, README and smithery.json updated
- `security_assessment` prompt recommends async pattern (start → poll → share findings)

---

## [3.2.0] - 2026-02-08 🧠

### Intelligence Engine — "Think Like an Attacker"

Major feature release: standards-based findings, multi-stage attack reasoning,
LLM-powered planning, and professional PDF reports. NumaSec now thinks in
exploitation chains, not isolated findings.

### Added

- **CVSS v3.1 calculator** (`standards/cvss.py`) — Full base-score computation, 17+ common vulnerability vectors, severity→score mapping
- **CWE mapping engine** (`standards/cwe_mapping.py`) — 40+ CWE entries with keyword matching, OWASP cross-references
- **OWASP Top 10 2021 mapper** (`standards/owasp.py`) — Full 10-category taxonomy, CWE→OWASP resolution
- **Auto-enrichment pipeline** — Every finding automatically receives CWE, CVSS, and OWASP classification on creation
- **Multi-stage Attack Graph** (`attack_graph.py`) — 31 capability nodes, 25+ edges, 12 exploitation chains, 3-tier fuzzy matching with 15+ keyword aliases
- **LLM-powered planner** — 5 target-type templates (web, WordPress, API, SPA, network) with LLM refinement via `generate_plan_with_llm()`
- **PDF report generation** (`pdf_report.py`) — Professional pentest reports with cover page, executive summary, donut severity chart, CVSS/CWE/OWASP metadata, remediation table
- **Pydantic Finding model** — `Finding` is now a Pydantic BaseModel with field validators and severity enum
- **Attack graph context injection** — Agent system prompt dynamically includes exploitation chain state
- **MCP ToolAnnotations** — All 7 MCP tools annotated with `readOnlyHint`, `destructiveHint`, `openWorldHint`
- **Benchmark suite** (`tests/benchmarks/`) — Ground truth definitions and scoring for DVWA & Juice Shop
- **MCP Integration guide** (`docs/MCP_INTEGRATION.md`) — Complete setup documentation

### Changed

- `generate_plan()` → `generate_plan_with_llm()` as primary planner (async, with sync fallback)
- `Finding.severity` uses `Severity` enum with fuzzy validator
- `add_finding()` auto-enriches with CWE/CVSS/OWASP standards
- Agent injects attack graph context into dynamic system prompt
- `/report` and `/export` CLI commands now support `pdf` format
- README comparison table expanded with 4 new differentiator rows

### Docs

- `docs/MCP_INTEGRATION.md` — MCP client setup (Claude Desktop, Cursor, VS Code)

---

## [3.1.0] - 2026-02-07 🔌

### MCP Integration — "Engine-In-Place, MCP-as-Skin"

MCP support is back, done right. NumaSec is now a native MCP server that works
inside **Claude Desktop**, **Cursor**, **VS Code**, and any MCP-compatible client.

### Added

- **MCP server** (`mcp_server.py`) — 7 tools, 46+ resources, 2 prompts via FastMCP
- **MCP tools** (`mcp_tools.py`) — Bridge layer: `numasec_assess`, `numasec_quick_check`, `numasec_recon`, `numasec_http`, `numasec_browser`, `numasec_get_knowledge`, `create_finding`
- **MCP resources** (`mcp_resources.py`) — Entire knowledge base exposed as `numasec://kb/*` URIs
- **Python-native quick_check** — Security headers, CORS, cookies, sensitive paths audit using httpx. Zero external binaries required
- **Python-native recon fallback** — Port scanning + HTTP probing when nmap/httpx CLI unavailable
- **Tool availability detection** — Agent adapts strategy when external tools missing
- **Session timeouts** — Prevents infinite loops (quick: 2min, standard: 5min, deep: 10min)
- **`--mcp` / `--mcp-http` CLI flags** — Start MCP server via stdio or HTTP transport
- **`numasec setup-claude`** — Auto-configures Claude Desktop with correct MCP config
- **`smithery.json`** — MCP marketplace listing for Smithery registry
- **`[mcp]` optional dependency** — `pip install 'numasec[mcp]'` installs FastMCP
- **SOTA tool descriptions** — All 20 tool schemas rewritten with "When to use" / "When NOT to use"

### Changed

- **Tool count**: 19 → 20 (`create_finding` promoted to first-class tool)
- **Knowledge base**: 39 → 46 entries (new attack chains, cloud, binary analysis)
- **ImportError messages** → stderr (prevents JSON-RPC protocol corruption)

---

## [3.0.0] - 2026-02-05 🚀

### The Great Refactor

**Complete rewrite from 41k lines to ~8k lines.** Simpler, faster, cheaper, smarter.

### Architecture — v3 ReAct Agent

- **ReAct agent loop** — Structured reasoning with loop detection, adaptive timeouts, smart failure handling
- **Attack Planner** — 5-phase hierarchical plan (recon → enumeration → exploitation → post-exploit → reporting) with auto-advance
- **Target Profile** — Structured memory: ports, endpoints, technologies, credentials, vulnerability hypotheses
- **14 Auto-Extractors** — Parse tool output (nmap, httpx, nuclei, sqlmap, ffuf, etc.) into structured data automatically
- **Reflection Engine** — Strategic analysis after each tool call with tool-specific reflectors
- **14 Escalation Chains** — Pre-built attack chains (SQLi→RCE, LFI→RCE, SSTI→RCE, upload→RCE, etc.)
- **Knowledge Base** — 39 curated entries: cheatsheets, payloads, attack patterns, loaded on-demand with LRU cache
- **Task-Type LLM Routing** — 5 task types (PLANNING, TOOL_USE, ANALYSIS, REFLECTION, REPORT) routed to optimal model
- **Report Generator** — Professional MD/HTML/JSON with dark-theme HTML, remediation engine, CVSS mapping
- **Plugin System** — Extend with custom tools, chains, extractors via `~/.numasec/plugins/`
- **19 security tools** — Focused, not bloated
- **Multi-LLM support** — DeepSeek, Claude, OpenAI, Ollama with automatic fallback

### New Modules

| Module | Purpose |
|--------|---------|
| `target_profile.py` | Structured memory (Port, Endpoint, Technology, Credential, VulnHypothesis) |
| `extractors.py` | 14 tool-output extractors → TargetProfile |
| `planner.py` | 5-phase hierarchical attack plan with PhaseStatus tracking |
| `reflection.py` | Strategic reflection with tool-specific analysis |
| `chains.py` | 14 escalation chains for confirmed vulnerabilities |
| `knowledge_loader.py` | On-demand knowledge loading with LRU cache (39 entries) |
| `report.py` | MD/HTML/JSON report generation with remediation guidance |
| `plugins.py` | Plugin discovery, loading, scaffolding |

### SOTA Prompt Engineering

| Technique | Impact | Source |
|-----------|--------|--------|
| Few-Shot Examples | +55% tool accuracy | Brown et al. 2020 |
| Chain-of-Thought | -30% mistakes | Wei et al. 2022 |
| Self-Correction | +40% recovery | Shinn et al. 2023 |
| Error Recovery | +44% retry success | 23 patterns |
| Context Management | 0 API errors | Group-based trimming |

### Tools (19 total)

**Recon:**
- `nmap` - Port scanning, service detection
- `httpx` - HTTP probing, tech fingerprinting  
- `subfinder` - Subdomain enumeration
- `ffuf` - Directory/file fuzzing

**Web:**
- `http` - HTTP requests (SQLi, IDOR, auth bypass)
- `browser_navigate` - JavaScript pages (SPAs)
- `browser_fill` - Form testing, XSS payloads
- `browser_click` - Click elements (CSRF)
- `browser_screenshot` - Visual evidence
- `browser_login` - Authenticated testing
- `browser_get_cookies` - Session analysis
- `browser_set_cookies` - Session hijacking
- `browser_clear_session` - Fresh sessions

**Exploit:**
- `nuclei` - CVE scanning
- `sqlmap` - SQL injection
- `run_exploit` - Custom exploit execution (Python/curl/scripts)

**Core:**
- `read_file` - Read files
- `write_file` - Write evidence
- `run_command` - Shell commands

### Features

- **Browser automation** - Playwright for XSS testing with screenshots
- **Session persistence** - Resume pentests with `/resume`
- **Cost tracking** - Real-time cost display, budget limits
- **Cyberpunk CLI** - Beautiful Rich TUI
- **Context trimming** - Group-based, never breaks tool sequences

### Removed

- ❌ LanceDB/vector storage (not needed)
- ❌ Multi-agent architecture (too expensive)
- ❌ 28 tools → 17 (focused set)
- ❌ 41k lines → 6k lines

### Cost

| Provider | Avg Cost/Pentest |
|----------|------------------|
| DeepSeek | $0.12 |
| Claude | $0.50 |
| OpenAI | $0.80 |

---

## [2.x] - Legacy

Previous versions used MCP architecture with 28+ tools and ~41k lines of code.
Deprecated in favor of simpler single-agent design.

---

[3.2.1]: https://github.com/FrancescoStabile/numasec/releases/tag/v3.2.1
[3.2.0]: https://github.com/FrancescoStabile/numasec/releases/tag/v3.2.0
[3.1.0]: https://github.com/FrancescoStabile/numasec/releases/tag/v3.1.0
[3.0.0]: https://github.com/FrancescoStabile/numasec/releases/tag/v3.0.0
