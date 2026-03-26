# Changelog

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
