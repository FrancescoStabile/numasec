# numasec - Copilot Instructions

## Build, test, and lint commands

Most source code lives under `agent/`. The shipped binary is built from `agent/packages/numasec`.

```bash
# Install workspace dependencies
cd agent && bun install

# Workspace typecheck
cd agent && bun typecheck

# Build the numasec binary
cd agent/packages/numasec && bun run build

# Full test suite
cd agent/packages/numasec && bun test --timeout 30000

# Single test file
cd agent/packages/numasec && bun test --timeout 30000 test/security/plan-next.test.ts

# Tests matching a pattern
cd agent/packages/numasec && bun test --timeout 30000 --test-name-pattern "planner"

# Runtime validation
cd agent/packages/numasec && bun run test:runtime
cd agent/packages/numasec && bun run test:runtime-live

# Generate a Drizzle migration
cd agent/packages/numasec && bun run db generate --name <slug>

# Lint (only script exposed in this repo)
cd agent/sdks/vscode && bun run lint
```

`bun test` at the repo root or at `agent/` intentionally exits with code 1. Run tests from `agent/packages/numasec`.

There is no repo-wide lint command for the main package.

## High-level architecture

- `agent/packages/numasec` is the main product package. Top-level files such as `README.md`, `CHANGELOG.md`, and `install.sh` are the public repo surface; the runtime, TUI, server, and security engine live inside the Bun workspace under `agent/`.
- The main execution loop is in `agent/packages/numasec/src/session/processor.ts`. Model output is streamed into `MessageV2` parts, tool calls are persisted, and completed tool envelopes are ingested into the security pipeline.
- The security stack is layered:
  - `src/security/tool/*` contains primitive tools (`browser`, `http-request`, `record-evidence`, `verify-assertion`, `query-graph`, etc.) plus composite scanners.
  - `src/security/planner/*` contains the deterministic planner kernel and policy. `plan-next.ts` advances planner state from events, runtime signals, and remaining budget rather than asking another model what to do next.
  - `src/security/runtime/*` persists browser actors, browser sessions/pages, execution attempts, and target profiles in SQLite so browser and HTTP work can share auth and state across steps.
  - `src/security/evidence-store.ts`, `src/security/finding-projector.ts`, `src/security/chain-projection.ts`, and `src/security/report/*` turn envelopes and findings into canonical graph state, attack paths, and report outputs.
- `agent/packages/numasec/src/server/routes/security.ts` exposes the canonical security read model and sync endpoints. `agent/packages/numasec/src/cli/cmd/tui/security-view-model.ts` reads that API first and only falls back to parsing historical tool output text when canonical data is missing. If you change security data shapes, keep the tool envelope, security API, and TUI fallback logic aligned.
- Slash commands live in `agent/packages/numasec/src/command/index.ts`. The repo keeps canonical v2 commands like `/scope set`, `/verify next`, and `/report generate`, while still registering legacy aliases for v1 compatibility.
- Security tools are registered through `agent/packages/numasec/src/security/index.ts` and loaded by `agent/packages/numasec/src/tool/registry.ts`. Adding a new security tool is not complete until it is exported from `src/security/index.ts`.

## Key conventions

- The style rules in the main package are strict:
  - prefer single-word locals, params, and helper names unless a longer name is genuinely clearer
  - no `else`; use early returns
  - avoid destructuring; prefer dot access
  - prefer `const` over `let`
  - inline single-use values
  - avoid `try`/`catch` where possible
  - prefer Bun APIs such as `Bun.file()` and `Bun.write()`
- Effect code follows the patterns documented in `agent/packages/numasec/AGENTS.md`:
  - use `Effect.gen(function* () { ... })` for composition
  - use `Effect.fn(...)` and `Effect.fnUntraced(...)`
  - use `Schema.Class`, `Schema.brand`, and `Schema.TaggedErrorClass`
  - use `makeRuntime` for shared services and `InstanceState` for per-directory state
  - prefer Effect services such as `FileSystem`, `HttpClient`, `Path`, `Clock`, and `DateTime` over ad hoc platform calls
- Drizzle schema files live in `src/**/*.sql.ts` and use `snake_case`. Generate migrations with `bun run db generate --name <slug>` from `agent/packages/numasec`; do not hand-write migration directories or SQL snapshots.
- Findings are enriched by the security pipeline. Do not manually set auto-generated fields such as `id`, `cvss_score`, `cvss_vector`, `owasp_category`, or `timestamp`.
- Tests prefer real implementations over mocks. Use the `tmpdir` fixture in `agent/packages/numasec/test/fixture/fixture.ts` with `await using` for temp directories, temp repos, and config-backed fixtures.
- `install.sh` is the only supported source installer at the repo root. Keep docs and release flow aligned with that installer instead of introducing alternate install scripts.
- Browser work depends on the Playwright package plus installed Chromium binaries (`npx playwright install chromium`). Keep `playwright` in `agent/packages/numasec` runtime dependencies, and keep `chromium-bidi` and `electron` in devDependencies: clean Bun release builds traverse Playwright server paths and fail without them.
