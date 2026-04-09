# Changelog

---

## [4.1.4] — Agent Intelligence & Tool Reliability

### Improved

- Rewrote agent system prompts for all 5 primary + 4 sub-agents (clearer methodology, less over-prompting)
- Enriched tool output with actionable next-step suggestions across all scanners
- Added OOB (out-of-band) cross-references to ssrf_test and path_test tool descriptions

### Fixed

- Parameter type coercion: injection_test and auth_test now handle JSON arrays from MCP clients
- JS analyzer: detect SPA framework routes (Angular `path: "admin"`) and relative API paths
- Tool descriptions follow consistent WHEN/HOW pattern for better LLM tool selection

### Docs

- README: corrected tool count (21+ scanners), removed hardcoded test count

---

## [4.1.3] - 2026-04-08 — Dependency Updates & ai-sdk v6 Migration

### Dependencies

- **cryptography**: 43.x → 43–46.x (security patches for CVEs)
- **ai** (core): 5.0.124 → 6.0.153 (major — LanguageModel V2→V3 protocol)
- **@ai-sdk/provider**: 2.0.1 → 3.0.8
- **@ai-sdk/provider-utils**: 3.0.21 → 4.0.23
- All 18 `@ai-sdk/*` provider packages bumped to v6-compatible versions
- **@openrouter/ai-sdk-provider**: 1.5.4 → 2.5.0
- **gitlab-ai-provider**: 5.3.3 → 6.4.1
- **strip-ansi**: 7.1.2 → 7.2.0
- **jose**: 6.0.11 → 6.2.2
- **sst**: 3.18.10 → 4.5.12

### Breaking Change Fixes (ai-sdk v5→v6)

- `toModelMessages()` now async (`convertToModelMessages` is async in v6)
- `toModelOutput` signature updated: receives `{toolCallId, input, output}` instead of raw output
- Removed `type: "content"` from `ToolResultOutput` (no longer valid in v6)
- `result.text` is now `PromiseLike<string>` — converted to `try/catch` with `await`
- `Schema.jsonSchema` is now async — added `await`
- `LanguageModelV2` → `LanguageModelV3` types across provider layer
- Middleware requires `specificationVersion: "v3"`
- `StreamTextResult` generic constraint updated (`unknown` → `any`)
- Copilot SDK: renamed `createProviderDefinedToolFactory` → `createProviderToolFactory`
- Copilot SDK: removed `name` property from tool factories (only `id` in v6)
- Content type assertions for new `ToolApprovalResponse` union member

### Maintenance

- Cleaned up 6 obsolete local branches
- Realigned `develop` branch to `main`
- Supersedes Dependabot PRs: #2, #3, #4, #5, #6, #7

---

## [Unreleased]

### Agent Architecture

- 5 primary agents with dedicated system prompts: pentest, recon, hunt, review, report
- Tab cycling through all primary agents with color-coded indicators
- Per-agent permission model (bash restrictions, tool access control)
- 3 subagents with specialized prompts: scanner, analyst, explore
- Agent colors: pentest (green), recon (blue), hunt (red), review (yellow), report (green)

---

## [4.0.0] - 2026-03-27 — Agent Terminal + MCP Server

Major release. numasec is now a full pentesting terminal (forked from the opencode agent, MIT)
in addition to the original MCP server. Two ways to use it:

- **Terminal** — an interactive AI pentesting session with hacker-green TUI, findings panel,
  OWASP coverage bar, and session persistence
- **MCP server** — 21 security tools exposed to any MCP-compatible host (GitHub Copilot,
  Claude Desktop, Cursor)

### Agent terminal

- Interactive terminal UI with hacker-green palette and OWASP coverage bar
- Live findings panel (severity counts + CWE roll-up) updated in real time
- Python MCP bridge: TypeScript agent spawns and communicates with the Python scanner layer
- Slash commands: `/target`, `/findings`, `/report`, `/coverage`, `/creds`, `/evidence`
- 5 security skill files (PTES, OWASP Top 10, injection, auth, API security)
- Scope enforcement: out-of-scope requests are blocked before execution
- `plan_exit` flow: after recon, the AI asks whether to escalate to exploitation
- Credential relay: discovered credentials feed into subsequent authenticated tests
- `install.sh` — one-line installer (Bun + uv + Python env setup)

### MCP server changes

- Consolidated from 47 atomic tools to 21 composite tools — less noise, better LLM guidance
- `run_scanner_batch` for parallel multi-scanner execution
- `oob` tool for out-of-band detection (DNS/HTTP callback)
- Knowledge base expanded to 34 templates (post-exploitation, protocol attacks, reverse shells)
- Auto-enrichment pipeline: CWE → CVSS 3.1 → OWASP → MITRE ATT&CK on every finding

### Tests

- 924 tests passing (22 skipped, platform-specific)
- Bridge integration tests for Python ↔ TypeScript tool contract

---

## [1.0.0] - 2026-03-19 — Initial Internal Release

MCP-only security testing server. 47 tools for Host LLMs (Claude Code, GitHub Copilot, Claude Desktop, Cursor).

### Tools

- **36 atomic security tools** — port scan, HTTP requests, browser automation (Playwright), 22 vulnerability scanners (SQLi, XSS, SSRF, XXE, SSTI, IDOR, CSRF, NoSQL, LFI, CORS, host header, open redirect, auth/JWT, business logic, GraphQL, and more)
- **7 intelligence tools** — KB search, CWE info, attack patterns, PTES scan planning, mandatory test lists, OWASP coverage gap analysis, post-auth retest plan
- **4 session tools** — create session, save finding (auto-enriched), get findings, generate report (SARIF, HTML, Markdown, JSON)
- **3 prompt templates** — security_assessment (PTES workflow), threat_model (STRIDE), code_review (OWASP/CWE)

### Features

- Deterministic PTES 5-phase planning (no internal LLM calls)
- OWASP Top 10 coverage enforcement via `get_mandatory_tests` and `get_coverage_gaps`
- Auto-enrichment on `save_finding`: CVSS v3.1 vector+score, CWE inference, OWASP category, MITRE ATT&CK technique
- Per-session rate limiting with env-configurable limits
- SSRF protection (private IP blocking, overridable for lab targets)
- SQLite WAL-mode session persistence
- Python-native scanners (no external binaries required; nmap/nuclei/sqlmap used if available)

### Benchmark

- **96% recall** on OWASP Juice Shop v17 (25/26 ground truth, 10/10 OWASP categories, 68 findings)

### Tests

- 810 tests passing
