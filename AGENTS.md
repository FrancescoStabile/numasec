# numasec Agent Guide

This file is for AI agents working in this repository.

numasec is not a generic coding assistant. It is intended to become the Codex CLI for cyber security: a terminal-native cyber operator harness that wraps frontier LLMs with the right environment, tools, memory, evidence, replay, oracles and benchmarks.

When you work here, optimize for that product shape.

## Operating Rules

- Always use parallel tools when applicable.
- Prefer automation: execute requested actions without confirmation unless blocked by missing info, sandbox limits, or destructive/irreversible risk.
- Use `rg`/`rg --files` for search.
- Use Bun only. Do not introduce Node/npm/yarn/pnpm workflows.
- Use Bun APIs such as `Bun.file()` when they fit.
- Do not run `bun test` from the repo root. Root tests are intentionally guarded.
- Keep changes scoped. Do not refactor unrelated systems while implementing a feature.
- Do not revert user changes.
- Do not use mocks for core behavior; test the actual implementation.

## Branches

- The historical default branch is `develop`, but it can lag.
- For release work in this workspace, `release/1.2.0` is based on `main` by explicit user decision.
- Do not assume `main` or `develop` is the correct diff base without checking current branch and user intent.
- Local refs may be missing. Prefer explicit refs after inspection.

## Product Direction

Build toward the PRD in `packages/numasec/FINAL_NUMASEC_PRD.md`.

Core thesis:

- numasec is a cyber operator harness, not an authz scanner.
- The LLM is not modified; the product leverage is the wrapper.
- The wrapper must provide workspace, terminal, installed security tools, browser, HTTP, knowledge, memory, evidence, replay, permissions, oracles and benchmarks.
- Claims must be classified as candidate, observed, verified, rejected or stale.
- Confirmed findings require evidence. Active findings require replay unless a domain explicitly defines why replay is impossible.
- AppSec and Pentest are the first hard-gated capsules for release 1.2.0.
- OSINT, CTF/Hacking, Cloud/Container/IaC and Forensics can ship only with explicit maturity labels unless benchmark-gated.

Avoid:

- flat "200 tools" designs with no semantic parsing;
- LLM-maintained state with no provenance;
- polished reports from weak evidence;
- universal cyber capability claims without benchmark coverage;
- container/lab-image work for this release unless the user reopens that decision.

## Architecture Direction

The current codebase already has a TUI, server, providers, agents, tools, operations, evidence, replay, plays, scanner, browser, vault, permissions and plugins. Do not replace that foundation casually.

The target architecture is:

- Operation Ledger: append-only record of goals, scope, tool calls, approvals, outputs, hypotheses, findings and reports.
- Cyber Workspace Graph: queryable derived fact index with provenance.
- Evidence and Replay Store: immutable proof artifacts and replay bundles.
- Tool Runtime and Adapter Registry: installed tool inventory, tool cards, parsers, degradation when absent.
- Knowledge Service: CVE/advisory/exploit/source lookup with freshness and citations.
- Memory System: session, operation, graph, artifact, procedural and team memory with context packing.
- Oracle Engine: code/procedure based verification, never LLM confidence as final proof.
- Permission and Autonomy Controller: `permissioned` and `auto` modes.
- Domain Capsules: Pentest, AppSec, OSINT, CTF/Hacking, Cloud/Container/IaC, Forensics.

### Graph Rule

Do not make the agent manually maintain the graph.

Graph population must flow through provenance:

```text
ledger event -> deterministic parser/extractor -> candidate fact -> provenance link -> graph projection
```

Allowed graph writers:

- deterministic parsers for tool outputs;
- first-party semantic tools;
- oracle engine;
- explicit operator correction/promotion;
- LLM extractor only for candidate facts.

Forbidden graph writers:

- raw assistant prose;
- unparsed generic output with no evidence;
- LLM-only confirmed facts;
- report generation side effects.

Graph facts must carry status, confidence, source event, evidence link when available, writer kind and timestamps.

Use SQLite/Drizzle for queryable graph and operation metadata. Use JSONL for replay/audit exports. Do not use markdown as canonical state.

### Operation Context

`numasec.md` may exist as an agent-facing context pack, not as canonical state.

The old operation notebook was useful because it helped the agent stay oriented. Keep that benefit, but derive it from ledger, graph, memory and open hypotheses. It should be disposable once context packing is strong enough.

## Package Boundaries

- `packages/numasec` - core app: TUI, server, agents, tools, CLI, Effect services.
- `packages/plugin` - `@numasec/plugin`: tool/TUI extension API.
- `packages/sdk` - `@numasec/sdk`: JS/TypeScript client and server SDK. Build from `packages/sdk`.
- `packages/script` - `@numasec/script`: build/release scripting utilities.
- `packages/shared` - `@numasec/shared`: cross-package filesystem, npm and utility code.

## Commands

From repo root:

- `bun dev` - run the TUI in `packages/numasec`.
- `bun dev <dir>` - run against another project directory.
- `bun dev spawn` - run TUI with server in main thread for breakpoints.
- `bun dev serve` - start headless API server on port 4096.
- `bun typecheck` - turbo typecheck across packages using `tsgo --noEmit`.
- `bun run lint` - oxlint with type-aware rules.

From `packages/numasec`:

- `bun test --timeout 30000` - package tests.
- `bun run build` - standalone binary build.
- `bun run build --single` - single distributable binary.
- `bun run db generate --name <slug>` - Drizzle migration generation.
- `bun run bench:local` - local benchmark runner where applicable.

From `packages/sdk`:

- `bun run build` - SDK build.

Never use `tsc`; this repo uses `tsgo` from `@typescript/native-preview`.

## Environment

Useful variables:

- `NUMASEC_DB=:memory:` - in-memory SQLite for tests.
- `NUMASEC_DISABLE_FILEWATCHER=true` - Windows CI workaround.
- `NUMASEC_PURE=1` or `--pure` - skip external plugins.
- `NUMASEC_MODELS_PATH` - models API snapshot for testing.
- `NUMASEC_TEST_HOME`, `NUMASEC_TEST_MANAGED_CONFIG_DIR` - test isolation.
- `NUMASEC_DISABLE_DEFAULT_PLUGINS=true` - skip built-in plugins in tests.
- `NUMASEC_SERVER_PASSWORD`, `NUMASEC_SERVER_USERNAME` - headless server auth.
- Provider keys include `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY`, `GROQ_API_KEY`, `XAI_API_KEY`, `OPENROUTER_API_KEY`.

## Testing

- Test preload lives at `packages/numasec/test/preload.ts`.
- It isolates XDG dirs under `/tmp/numasec-test-data-<pid>`, clears provider auth vars, sets `NUMASEC_DB=:memory:` and disables default plugins.
- Use `testEffect(layer)` from `packages/numasec/test/lib/effect.ts` for Effect services.
- Use `it.live(...)` for real filesystem/time/git/process behavior.
- Use `it.effect(...)` for `TestClock`/`TestConsole`.
- Use `tmpdir()` for Promise tests.
- Use `provideTmpdirInstance()`, `tmpdirScoped()` or `provideInstance()` for Effect tests.
- See `packages/numasec/test/AGENTS.md` for fixture patterns.
- Windows tests may be continue-on-error in CI; still write portable code where practical.

Benchmark expectations for release 1.2.0:

- AppSec and Pentest benchmarks must gate the release.
- Kernel, graph, evidence, replay, installed-tool inventory, permissioned mode and auto mode need tests.
- Missing optional installed tools should degrade clearly, not pretend success.

## Database And Storage

- Drizzle schemas live in `src/**/*.sql.ts`.
- Table and column names use snake_case.
- Join columns are `<entity>_id`.
- Index names should be descriptive and stable.
- Generate migrations from `packages/numasec` with `bun run db generate --name <slug>`.
- Use SQLite/Drizzle for queryable operation metadata, graph, facts, relations and proof indexes.
- Store immutable artifacts by hash in evidence storage.
- Keep replay/audit exports as JSONL.

Schema style:

```ts
const table = sqliteTable("session", {
  id: text().primaryKey(),
  project_id: text().notNull(),
  created_at: integer().notNull(),
})
```

## Effect Rules

See `packages/numasec/AGENTS.md` for detailed Effect migration rules.

Core points:

- Use `Effect.gen(function* () { ... })` for composition.
- Use `Effect.fn("Domain.method")` for named/traced effects.
- Use `Effect.fnUntraced` for internal hot helpers.
- Use `makeRuntime` from `src/effect/run-service.ts` for service runtimes.
- Use `InstanceState` for per-directory/per-project state.
- Do not add manual `started` flags or custom singleton promises around `InstanceState`.
- Prefer existing Effect services over raw platform APIs when already inside Effect code.
- Prefer `FileSystem.FileSystem`, `ChildProcessSpawner`, `HttpClient.HttpClient`, `Path.Path`, `Clock` and `DateTime` when available.
- `Effect.fork` and `Effect.forkDaemon` do not exist in the current Effect version; use scoped fork APIs documented in package guides.

## Style

- Prefer `const`.
- Prefer early returns over `else`.
- Prefer functional array methods where readable.
- Avoid `any`.
- Rely on inference unless export clarity requires a type annotation.
- Avoid unnecessary destructuring; use dot notation when it preserves context.
- Avoid `try`/`catch` where `.catch()` or Effect errors fit better.
- Keep things in one function unless extraction removes real complexity.
- Add comments only when they explain non-obvious intent or constraints.

## Security Product Standards

When implementing cyber functionality:

- Store raw secrets by reference, not in graph facts or summaries.
- Redact secrets in default output.
- Every finding must link to evidence or remain suspected.
- Every active finding should have replay material.
- Tool output should become evidence first, then parsed facts.
- Parser failures should degrade visibly.
- The model may propose hypotheses; code, replay, independent source corroboration or operator action must verify them.
- Reports must refuse unsupported confirmed claims.

This repository should move toward an industry-standard cyber agent. Treat benchmarked proof, replay and operator trust as product requirements, not polish.
