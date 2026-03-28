# numasec — Copilot Instructions

## What this project is

**numasec** is an AI-powered penetration testing platform delivered as an MCP (Model Context Protocol) server. It exposes 21 Python security scanners as MCP tools that a host LLM (Claude, GPT-4, etc.) calls to run real pentests. The TypeScript TUI in `agent/` is a separate frontend that communicates with the Python MCP server.

## Build, test, lint

```bash
# Install everything (includes dev deps)
pip install -e ".[all]"

# Run full test suite
pytest tests/ -v

# Run a single test file
pytest tests/test_scanners.py -v

# Run a single test by name
pytest tests/test_scanners.py::TestPortInfo::test_defaults -v

# Lint
ruff check numasec/

# Type check
mypy numasec/
```

Tests use `asyncio_mode = "auto"` — all test functions can be `async def` without extra decorators.

Slow/benchmark/integration tests are marked:
```bash
pytest tests/ -m "not slow and not benchmark and not integration"
```

## Architecture

```
numasec/
  mcp/          # MCP server, tool bridge, session store, rate limiting, SSRF protection
  scanners/     # Individual scanners (sqli, xss, ssrf, auth, etc.) — pure async functions
  tools/        # ToolRegistry + composite tools (recon, injection, access_control, etc.)
  core/         # DeterministicPlanner (PTES-based), coverage tracking
  models/       # Pydantic v2 models: Finding, TargetProfile, Plan, SARIF
  knowledge/    # KB loader, retriever, YAML template packs (34 templates)
  storage/      # CheckpointStore (SQLite via aiosqlite)
  reporting/    # SARIF, HTML, Markdown report generators
  security/     # Input validation, SSRF protection helpers
  standards/    # OWASP Top 10 / CWE mappings
agent/          # TypeScript TUI (forked from OpenCode) — separate package
tests/          # pytest suite (~924 tests)
```

### Data flow

1. Host LLM calls an MCP tool (e.g. `recon`, `injection_test`)
2. `tool_bridge.py` routes the call through `ToolRegistry.call()`
3. Composite tools in `numasec/tools/` orchestrate individual scanners
4. Scanners in `numasec/scanners/` make HTTP requests and return structured dicts
5. Findings are saved via `McpSessionStore` → `CheckpointStore` (SQLite)
6. `generate_report` produces SARIF / Markdown / JSON output

### Tool registration pattern

Every tool is registered with `ToolRegistry` (OpenAI-compatible JSON schema):

```python
registry.register("tool_name", async_func, schema={"description": "...", "parameters": {...}})
```

`bridge_tools_to_mcp(mcp, registry)` then auto-exposes all registered tools as MCP tools. New tools must be registered before the server starts.

### Scanner extensibility

Two mechanisms for adding scanners without touching core code:

- **Python plugins**: drop a `.py` file with a `register(registry)` function into `~/.numasec/plugins/`
- **YAML scanner templates**: drop a `.yaml` file into `~/.numasec/plugins/` using the template format defined in `numasec/scanners/_plugin.py`

`ScanEngineFactory` auto-selects the best port scanner backend: naabu → nmap → pure Python.

### Session lifecycle (MCP path)

```
create_session(target) → save_finding() × N → generate_report()
```

Sessions are persisted in `sessions.db` (SQLite). Rate limiting is per-session via `SessionRateLimiter`; configure with `NUMASEC_RATE_PER_MINUTE` / `NUMASEC_RATE_CONCURRENT` env vars.

## Key conventions

- `from __future__ import annotations` at the top of every module
- Pydantic v2 `BaseModel` for all data models; use `field_validator` / `model_validator`
- Line length: 120 chars (ruff, `E501` ignored)
- `Finding` model auto-generates ID, CVSS score, and OWASP category on creation — don't set these manually
- Tests prefer real implementations over mocks; avoid `unittest.mock` unless testing external I/O
- All scanner functions are `async def`; use `httpx.AsyncClient` for HTTP (not `requests`)
- `verify=False, follow_redirects=True` is the standard `AsyncClient` config for scanners
- SSRF protection is enforced in `mcp/server.py` — internal IPs/localhost are blocked unless `NUMASEC_ALLOW_INTERNAL=1`

## TypeScript TUI (agent/)

The `agent/` directory is a separate Bun/TypeScript monorepo. Its conventions (in `agent/AGENTS.md`) differ from the Python package:

- Default branch: `dev`; use `dev` or `origin/dev` for diffs
- Prefer single-word variable names; avoid destructuring; no `else` statements
- Run tests from package directories (e.g. `packages/numasec`), not the repo root
- `bun typecheck` for type checking, not `tsc` directly
