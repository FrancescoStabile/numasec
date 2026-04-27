- ALWAYS USE PARALLEL TOOLS WHEN APPLICABLE.
- The default branch in this repo is `develop`.
- Local `main` ref may not exist; use `develop` or `origin/develop` for diffs.
- Prefer automation: execute requested actions without confirmation unless blocked by missing info or safety/irreversibility.
- Bun is the only runtime. Use Bun APIs (e.g. `Bun.file()`) when possible.

## Package boundaries

- `packages/numasec` — core app: TUI, server, agents, tools, CLI, Effect services
- `packages/plugin` — `@numasec/plugin`: tool/TUI extension API for third-party plugins
- `packages/sdk` — `@numasec/sdk`: JS/TypeScript client and server SDK. Build with `bun run build` from `packages/sdk`.
- `packages/script` — `@numasec/script`: build/release scripting utilities
- `packages/shared` — `@numasec/shared`: cross-package utilities (filesystem, npm, globals)

## Commands

- **dev:** `bun dev` from repo root (runs TUI in `packages/numasec`). Pass a directory to run against a different project: `bun dev <dir>`. Starts server in a worker thread.
- **dev (direct):** `bun dev spawn` from repo root runs the TUI with server in main thread (needed for breakpoints).
- **serve:** `bun dev serve` starts headless API server on port 4096.
- **typecheck:** `bun typecheck` from repo root runs turbo typecheck across all packages. Each package uses `tsgo --noEmit` (the TypeScript native type checker from `@typescript/native-preview`), never `tsc`.
- **lint:** `bun run lint` runs `oxlint` with `typeAware: true`.
- **build:** `bun run build` from `packages/numasec` (builds standalone binaries). Env vars: `NUMASEC_BUILD_OS` (linux|darwin|win32), `NUMASEC_VERSION`, `NUMASEC_CHANNEL`.
- **single binary:** `bun run build --single` from `packages/numasec` produces a distributable at `packages/numasec/dist/numasec-<platform>/bin/numasec`.
- **test:** `bun test --timeout 30000` from within `packages/numasec`. NEVER run `bun test` from repo root — it's guarded (`bunfig.toml` sets `test.root = "./do-not-run-tests-from-root"`).
- **drizzle:** `bun run db generate --name <slug>` from `packages/numasec` generates a migration from `src/**/*.sql.ts` into `migration/`.

## Build / release

- `NUMASEC_VERSION` and `NUMASEC_BUILD_OS` control build output. Platform-specific artifact dirs follow the pattern `numasec-linux-x64`, `numasec-darwin-arm64`, `numasec-win32-x64`.
- NPM publish uses platform-specific packages (`@numasec/numasec-linux-x64` etc.) as optionalDependencies of the main `numasec` package.
- Release version is resolved by `script/version.ts`.

## Environment variables

- `NUMASEC_DB=:memory:` — use for tests to get in-memory SQLite.
- `NUMASEC_DISABLE_FILEWATCHER=true` — set on Windows CI since file watcher doesn't work.
- `NUMASEC_PURE=1` / `--pure` flag — skip external plugins.
- `NUMASEC_MODELS_PATH` — path to models API snapshot for testing.
- `NUMASEC_TEST_HOME`, `NUMASEC_TEST_MANAGED_CONFIG_DIR` — test isolation directories.
- `NUMASEC_DISABLE_DEFAULT_PLUGINS=true` — skip built-in plugins in tests.
- `NUMASEC_SERVER_PASSWORD`, `NUMASEC_SERVER_USERNAME` — headless server auth.
- Provider API keys: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY`, `GROQ_API_KEY`, `XAI_API_KEY`, `OPENROUTER_API_KEY`, etc.

## Testing

- Test preload file at `packages/numasec/test/preload.ts` sets isolation: XDG dirs in `/tmp/numasec-test-data-<pid>`, clears all provider auth env vars, sets `NUMASEC_DB=:memory:`, disables default plugins.
- Effect-based tests use `testEffect(layer)` from `test/lib/effect.ts` — returns `{ effect, live }` test helpers.
- Use `it.live(...)` for tests needing real time/filesystem/git; `it.effect(...)` for tests with `TestClock`/`TestConsole`.
- Temp directory fixtures: `tmpdir()` for Promise-based tests, `provideTmpdirInstance()` / `tmpdirScoped()` for Effect-based tests.
- Full test fixture and effect patterns detailed in `packages/numasec/test/AGENTS.md`.
- Avoid mocks; test the actual implementation.
- Windows tests run with `continue-on-error: true` in CI.

## Architecture

- **Effect** is the core framework for services, layering, and error handling. See `packages/numasec/AGENTS.md` for detailed Effect rules.
- **`makeRuntime`** (from `src/effect/run-service.ts`) is the factory for all Effect runtimes. It provides `runSync`, `runPromise`, `runFork`, `runCallback` backed by a shared `memoMap`.
- **`InstanceState`** (from `src/effect/instance-state.ts`) manages per-directory/per-project state via `ScopedCache`. Services keyed by project directory get automatically cleaned up on disposal.
- **`Instance`** (from `src/project/instance.ts`) holds the current project directory context via `AsyncLocalStorage`. Use `Instance.bind(fn)` for native addon callbacks that need the directory context.
- **Server** uses Hono, runs on port 4096 by default. TUI connects via WebSocket. `bun dev` spawns the server in a worker thread.
- **Database** is SQLite via Drizzle ORM (bun-sqlite). Schema files in `src/**/*.sql.ts`. Migrations in `migration/`. `drizzle.config.ts` at `packages/numasec/drizzle.config.ts`.
- **CVE bundle** lives at `assets/cve/index.json.gz` — refreshed weekly by `cve-refresh.yml` workflow. Size budget ≤ 8 MB.

## Style Guide

### General

- Keep things in one function unless composable or reusable.
- Avoid `try`/`catch` where possible; prefer `.catch()`.
- Avoid `any` type.
- Rely on type inference; avoid explicit type annotations unless necessary for exports or clarity.
- Prefer functional array methods (`flatMap`, `filter`, `map`) over for loops.
- Inline variables that are only used once.

### Destructuring

Avoid unnecessary destructuring. Use dot notation to preserve context.

### Variables

Prefer `const`. Use ternaries or early returns instead of `let` + reassignment.

### Control Flow

Avoid `else`. Use early returns.

### Schema Definitions (Drizzle)

Use snake_case field names so column names don't need to be redefined:

```ts
const table = sqliteTable("session", {
  id: text().primaryKey(),
  project_id: text().notNull(),
  created_at: integer().notNull(),
})
```
