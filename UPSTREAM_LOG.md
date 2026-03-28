# Upstream Sync Log

Tracks cherry-pick decisions from upstream [OpenCode](https://github.com/sst/opencode) into numasec.

**Fork base**: `ced8898` (v4.0.0, 2026-03-28)

## Sync Strategy

| Zone | Directories | Strategy |
|------|-------------|----------|
| Safe | `provider/`, `auth/`, `effect/`, `id/`, `format/`, `bus/`, `env/`, `packages/ui/`, `packages/plugin/` | Auto cherry-pick via `script/upstream-merge-safe.sh` |
| Review | `session/`, `config/`, `storage/`, `mcp/`, `server/`, `permission/`, `plugin/`, `skill/` | Manual cherry-pick with `-x` flag |
| Diverged | `tool/`, `agent/`, `prompt/`, `command/`, `bridge/`, `lsp/`, `ide/`, `worktree/` | Never sync — read for architectural insights only |

## Decision Log

| Upstream Commit | Date | Zone | Applied? | Notes |
|----------------|------|------|----------|-------|
| — | 2026-03-28 | — | — | Fork created at v4.0.0 (`ced8898`) |
