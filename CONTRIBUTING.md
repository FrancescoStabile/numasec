# Contributing to numasec

numasec is a terminal-native cyber operator harness. Contributions should move the product toward that shape, not back toward a generic chat assistant or markdown-first notebook.

## Workflow rules

- Use Bun only.
- Do not run `bun test` from the repo root.
- Run package tests from `packages/numasec`.
- Keep changes scoped to the system you are working on.
- Do not revert unrelated user or agent changes.

Typical local workflow:

```bash
bun install
bun typecheck
cd packages/numasec
bun test --timeout 30000
bun run build
```

## Product standards

These are release-level standards, not optional polish:

- cyber claims must be evidence-first
- active or reportable findings need replay material, or an explicit structured replay exemption
- reports must not present unsupported confirmed claims
- AppSec and Pentest benchmarks are release gates
- no regressions to markdown-as-canonical-state
- `numasec.md` may exist as context, but the cyber kernel remains the source of truth

If a change weakens those properties, it is probably not ready to merge.

## Architecture expectations

Before adding new abstractions, understand the current foundation:

- `packages/numasec` contains the core app, TUI, agents, tools, operation system, evidence, replay, and Effect services
- `packages/plugin` contains the plugin API
- `packages/sdk` contains the SDK and API client/server surface

Prefer extending existing services and first-party tools over inventing parallel flows.

## PR expectations

- keep pull requests small and focused
- explain the problem and how you verified the fix
- include screenshots or terminal captures for visible UI changes
- include test coverage when behavior changes
- do not submit AI-generated walls of text

PR titles should follow conventional commit style, for example:

- `fix(numasec): tighten external directory boundary`
- `docs: align release positioning`
- `feat(numasec): add evidence proof summary to deliverable`

## Issues and design

Open an issue before starting large product or architecture work.

Use existing issues when possible. For net-new functionality, make the problem statement concrete:

- what user workflow is blocked
- what subsystem is affected
- why the change belongs in numasec
- how the change will be verified

## Release-sensitive areas

Changes in these areas need extra care:

- operation scope and permission enforcement
- evidence, replay, and report semantics
- finding lifecycle and anti-overclaiming logic
- installed-tool degradation behavior
- benchmark and release gate logic

If you touch those systems, include explicit verification notes in the PR.
