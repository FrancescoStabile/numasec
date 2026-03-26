# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

security-mcp is an MCP (Model Context Protocol) server exposing 21 composite security testing tools to AI assistants. It enables AI-driven penetration testing following the PTES 5-phase methodology with a 34-template knowledge base covering the full engagement lifecycle from detection through post-exploitation. Python 3.11+, built with Hatchling.

## Commands

```bash
# Install
pip install -e ".[mcp]"              # Core + MCP + Playwright
playwright install chromium           # Download Chromium binary
pip install -e ".[protocols]"        # Optional: SSH/SMB protocol probing (asyncssh, smbprotocol)
pip install -e ".[all]"              # Everything including dev tools + protocols

# Run
security-mcp                         # stdio transport (default)
security-mcp --mcp-http              # HTTP transport (Cursor)

# Test
pytest tests/ -v                     # All tests
pytest tests/test_scanners.py -v     # Single test file
pytest tests/ -k "test_sqli" -v      # Single test by name pattern
pytest tests/ -m "not slow" -v       # Skip slow tests
pytest tests/benchmarks/ -v          # Benchmarks (Juice Shop, DVWA, WebGoat)
pytest --cov=src tests/              # Coverage

# Lint & Type Check
ruff check src/
ruff format src/
mypy src/
```

Line length: 120 characters. Ruff rules: E, F, W, I, UP, B, SIM.

## Architecture

**Host-driven, no internal LLM calls.** The host LLM (Claude/Copilot) decides tool execution order. The server is deterministic — `DeterministicPlanner` follows PTES phases rigidly.

```
Host LLM → MCP Protocol (stdio/http) → FastMCP Server → ToolRegistry → Atomic Tools
```

### Key Layers

- **`mcp/`** — MCP server lifecycle, tool bridge, session state, intelligence tools, SSRF protection, rate limiting. `tool_bridge.py` bridges the internal ToolRegistry to MCP. `_singletons.py` holds global instances.
- **`core/`** — `planner.py` (DeterministicPlanner, PTES 5-phase) and `coverage.py` (OWASP coverage tracking).
- **`models/`** — Pydantic models. `Finding` auto-enriches on save: infers CWE → CVSS 3.1 score/vector → OWASP category → MITRE ATT&CK technique. `TargetProfile` is a dataclass accumulating recon data.
- **`scanners/`** — Vulnerability scanners (SQLi, XSS, SSRF, XXE, SSTI, CSRF, NoSQL, LFI, IDOR, CORS, GraphQL, auth, etc.) plus service probing (`service_prober.py`), CVE enrichment (`cve_enricher.py`), and OpenAPI parsing (`openapi_parser.py`). Port scanners inherit from `ScanEngine` ABC in `_base.py`. `_envelope.py` provides standard response format. `_plugin.py` handles scanner discovery. `_encoder.py` provides payload encoding for WAF evasion.
- **`tools/`** — Composite tool wrappers (recon, crawl, injection_test, access_control_test, path_test, browser, oob) plus atomic tools (HTTP, command, exploit). `composite_*.py` files dispatch to scanner implementations.
- **`standards/`** — CWE↔CVSS↔OWASP↔ATT&CK mappings. `cvss.py` computes scores from CWE IDs.
- **`knowledge/`** — BM25 retriever over 34 YAML templates: detection patterns, exploitation methodologies (DBMS/engine/OS-specific), post-exploitation guides, protocol attack patterns, CVE mappings, reverse shells, remediation guides, and payload libraries. Optional semantic reranking via LiteLLM.
- **`reporting/`** — SARIF 2.1.0, Markdown, HTML, JSON output.
- **`storage/`** — SQLite with WAL mode via aiosqlite for session persistence.
- **`security/`** — `sandbox.py` for sandboxed command execution (used by `run_command` tool).

### Tool Categories (21 total)

- **13 composite security tools** — `recon` (ports+tech+services+CVE), `crawl` (HTTP+SPA+OpenAPI import), `injection_test`, `xss_test`, `access_control_test`, `auth_test` (JWT+OAuth+spray), `ssrf_test`, `path_test`, `dir_fuzz`, `js_analyze`, `browser`, `oob`, `http_request`
- **2 intelligence tools** — `kb_search` (unified KB/CWE/attack patterns), `plan` (unified planning/coverage/auth retest)
- **6 state tools** — `create_session`, `save_finding`, `get_findings`, `generate_report`, `run_scanner_batch`, `relay_credentials`
- **3 prompt templates** — `security_assessment` (full PTES workflow), `threat_model` (STRIDE), `code_review` (OWASP/CWE)
- **Optional** — `sqlmap_scan`, `nuclei_scan` (when binaries available)

### Knowledge Base (34 templates)

- **Detection** (11) — SQLi, XSS, SSRF, auth, injection, command injection, WAF bypass, misconfig, business logic, default creds, API security
- **Exploitation** (5) — Injection exploitation (UNION/blind per DBMS, SSTI→RCE per engine, CMDi), server-side (XXE, SSRF, LFI→RCE), client-side (XSS chains, CSRF, CORS), auth (JWT forging, OAuth), cloud (AWS/GCP/Azure IMDS)
- **Post-exploitation** (2) — Linux privesc (SUID, sudo, kernel, capabilities, Docker escape), Windows privesc (Potato attacks, token impersonation, UAC bypass)
- **Protocols** (1) — FTP, SSH, SMB, SMTP, DNS, Redis, MongoDB, MySQL, PostgreSQL, LDAP, SNMP, RDP, Memcached
- **Reference** (3) — CWE mapping, OWASP Top 10, CVE-to-service version mappings (100+ services)
- **Payloads** (4) — SQLi, XSS, SSTI/CMDi, reverse shells + web shells + hash identification
- **Attack chains** (3) — SQLi chains, auth chains, SSRF/XSS/LFI chains
- **Remediation** (4) — SQLi fixes, XSS fixes, injection fixes, header fixes

### Design Patterns

- **Registry Pattern** — ToolRegistry holds all tools; bridged to MCP via `tool_bridge.py`
- **Auto-Enrichment** — Finding model enriches itself via Pydantic validators (CWE → CVSS → OWASP → ATT&CK)
- **Async-first** — All tools are async; FastMCP is async; aiosqlite for persistence
- **Rate limiting** — Per-session (60 calls/min, 5 concurrent) + global (120/min, 10 concurrent), configurable via `SECMCP_RATE_*` env vars
- **SSRF protection** — Blocks private IPs by default; override with `SECMCP_ALLOW_INTERNAL=1`
- **Optional dependencies** — Protocol probing (asyncssh, smbprotocol) degrades gracefully when not installed

## Environment Variables

Passed via MCP config `env` block, not `.env` files:

- `SECMCP_ALLOW_INTERNAL` (0/1) — allow localhost/private IP scanning
- `MCP_TRANSPORT` (stdio/http) — transport protocol
- `SECMCP_RATE_PER_MINUTE` / `SECMCP_RATE_CONCURRENT` — per-session limits
- `SECMCP_RATE_GLOBAL_PER_MINUTE` / `SECMCP_RATE_GLOBAL_CONCURRENT` — global limits
- `SECMCP_NVD_API_KEY` — NVD API key for CVE enrichment (optional; local KB used when absent)

## Testing

Test fixtures in `tests/conftest.py`: `target_profile`, `populated_profile`, `session_state`, `populated_state`. Benchmark suite in `tests/benchmarks/` tests against 3 targets: OWASP Juice Shop v17 (Node.js), DVWA (PHP/MySQL), and WebGoat 2023 (Java/Spring Boot). Benchmark baseline: 96% recall on Juice Shop v17 (25/26 ground truth, 10/10 OWASP categories).
