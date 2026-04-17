# Operations

An **operation** is a long-running security engagement tracked as a single markdown file: `numasec.md`. It is the persistent memory of your work — observations, findings, failed attempts, scope — that survives across sessions, so day 3 of a pentest starts where day 2 left off instead of from zero.

## TL;DR

- `/operations` in the TUI → create or switch.
- Each operation lives at `<workspace>/.numasec/operation/<slug>/numasec.md`.
- The file is auto-loaded as a system instruction for every turn of every session in that workspace.
- The agent maintains it using the normal `read` / `edit` / `write` tools — no special operation tools.
- `.numasec/operation/**` is gitignored by default (contains client-sensitive data).

## Why

Pentests, CTFs, and bug-hunts run for days. Without shared memory, every new session forces you to re-explain the target, the stack, what you already tried, what the user promoted to a confirmed finding. `numasec.md` is the smallest possible fix: a markdown fascicule the agent reads in every turn and writes to as it learns.

This design is deliberately boring. No knowledge graph. No event store. No extra tools. Just a file that happens to also be a system prompt.

## File layout

```
<workspace>/
└── .numasec/
    └── operation/
        ├── active                    # marker file — contents = slug of active op
        └── <slug>/
            ├── numasec.md            # the fascicule (auto-loaded)
            ├── evidence/             # attachments the agent drops (screenshots, captures)
            └── report-<ts>.md        # outputs of /report (coming in 1.2.1)
```

The skeleton written at `/operations new` looks like:

```markdown
# Operation: <label>
<!-- meta: kind: pentest  target: https://example.com -->

## Scope
- in: https://example.com/*
- out: https://example.com/admin/*

## Stack
-

## Defenses
-

## Findings
- [proposed] XSS in search param  ← evidence/2026-04-17-xss.png

## Attempts
-

## Todos
- [ ]
```

The `## Scope` block is parsed by the boundary guard: lines like `- in: <glob>` / `- out: <glob>` become allow/deny patterns for `http_request` and `webfetch`. No scope block ⇒ everything allowed.

## Finding convention

- `[proposed]` — the agent suspects it, not verified end-to-end. Written freely by the agent.
- `[confirmed]` — you, the user, promoted it. The agent will never write this itself.
- `[dismissed]` — ruled out with a one-line reason, so the agent doesn't retry.

This keeps the agent's write surface wide (fast, no approval friction) while anchoring the truth in user-visible promotions.

## TUI flow

- `/operations` → dialog listing ops with a `+ New operation` entry. Empty workspace → two-step wizard (label → kind).
- Kinds: `pentest`, `ctf`, `bughunt`, `osint`, `research`. Purely cosmetic — same file format under all of them.
- Top-of-session banner shows the active op's glyph, label, kind, target, line count, and "updated Xm ago".
- Close the app, reopen tomorrow, open a new session in the same workspace: the banner is back, the file is back, the agent knows what you did yesterday.

## CLI flow

```
numasec operation new "Juice Shop audit" --kind pentest --target https://juice.example.com
numasec operation list
numasec operation show           # prints active op's numasec.md
numasec operation use <slug>     # switch active
numasec operation archive <slug> # deactivate (files stay on disk)
```

## Budget hint

The prompt tells the agent to keep `numasec.md` under ~1000 lines and summarise the oldest `## Attempts` entries when it grows. Large tool outputs go under `evidence/` and are linked by relative path rather than inlined.

## Dismantling

If this feature proves not useful, removing it is a one-day job:

1. Delete `packages/numasec/src/core/operation/`.
2. Revert `packages/numasec/src/core/boundary/guard.ts` to its pre-1.2.0 version (plain pass-through).
3. Revert `packages/numasec/src/session/instruction.ts` — drop the `numasec.md` auto-injection.
4. Remove the "Operation memory" block from `prompt/default.txt`, `prompt/kimi.txt`, `prompt/trinity.txt`.
5. Delete `OperationBanner`, `DialogOperation`, and their two wire-up sites.
6. `rm -rf .numasec/operation/` in any workspace you want to clean.

No migration, no schema versioning, no data loss concerns — the feature is just a file and a ~200-line namespace.

## Roadmap

1.2.1 will add:
- Sidebar live preview of the active `numasec.md`.
- `/report` slash — LLM reshape of `numasec.md` into a client-ready `report-<ts>.md`.
- Home-screen one-time suggestion when opening a workspace with no active op.
