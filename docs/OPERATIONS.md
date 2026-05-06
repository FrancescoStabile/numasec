# Operations

An operation is numasec's durable unit of cyber work.

It is not a single markdown notebook and it is not just chat history. An operation is the combination of ledger events, projected cyber state, evidence, replay artifacts, workflow state, and deliverables stored under the operation directory.

## Core model

An operation has five important layers:

1. `ledger`
   - append-only activity trail
   - goals, approvals, tool calls, workflow transitions, findings, report events
2. `projected cyber state`
   - queryable derived facts and finding state
   - facts carry provenance, status, timestamps, and writer information
3. `evidence store`
   - immutable proof artifacts and references
   - screenshots, request/response captures, tool outputs, report attachments
4. `replay artifacts`
   - material needed to justify active findings or explain why replay is exempt
5. `deliverables`
   - report builds, summaries, and handoff artifacts

The cyber kernel is the source of truth. JSONL projections and markdown context files are derived views, not canonical state.

## Directory shape

The exact contents can evolve, but an active operation typically lives under:

```text
<workspace>/.numasec/operation/<slug>/
```

Common areas include:

```text
context/       derived prompt/context artifacts
cyber/         projected facts, relations, summaries, exports
evidence/      stored proof artifacts and metadata
replay/        replayable request/command/browser material
deliverable/   report output and packaging
```

You should think of that tree as an operation bundle, not as a notebook.

## Scope, autonomy, and opsec

Operations carry explicit scope and execution posture.

- scope defines what targets, paths, or environments are in bounds
- autonomy controls whether the agent runs in `permissioned` or `auto` mode
- opsec defines how strict the boundary enforcement should be

`permissioned` mode is the review-oriented path: the operator can deny, allow, or allow-always.

`auto` mode is the higher-velocity path: the harness executes within the operation boundary without stopping on every tool call.

`opsec strict` is the hard guardrail. Out-of-scope browser, HTTP, shell, or filesystem actions should be blocked rather than merely noted.

## TUI operation lenses

The TUI is expected to expose the operation as lenses rather than as an unstructured transcript.

Primary lenses:

- findings
- evidence
- replay
- workflow
- report

Those lenses exist to keep the operator oriented while the model acts through tools.

## Finding lifecycle

numasec does not flatten everything into "found" or "not found".

Current finding states:

- `candidate`
  - a machine or model-generated suspicion
  - not yet strong enough to report
- `observed`
  - a meaningful signal seen in evidence or tool output
  - still not a verified claim on its own
- `verified`
  - evidence-backed and promoted through the first-party lifecycle
- `reportable`
  - a derived release/reporting state: verified plus evidence plus replay, or explicit structured replay exemption
- `rejected`
  - ruled out
- `stale`
  - once true, no longer current or no longer trusted

This distinction is product-critical. A report should not overclaim because the model sounded confident.

## Evidence and replay

Evidence comes first.

Tool outputs, browser artifacts, HTTP traces, scanner results, screenshots, and supporting files should land as evidence before they are treated as durable findings.

Active findings should also have replay material when replay is possible. If replay is not possible, the exemption must be explicit and structured. Free-form confidence is not enough.

## numasec.md

`numasec.md` can still exist as a compatibility view or human-readable context pack.

It is useful when:

- an operator wants a compact snapshot
- a prompt context needs a derived summary
- a human wants quick orientation without querying the full operation state

It is not the canonical state of an operation. The canonical state is the cyber kernel plus its derived projections and artifacts.

## Practical operator loop

The intended loop is:

1. start or attach to an operation
2. set scope, autonomy, and opsec posture
3. run a capsule with `runbook`
4. inspect findings, evidence, replay, and workflow lenses
5. promote or reject findings through first-party tools
6. build a deliverable through the `report` tool

That is the core shift in this release: from notebook-first memory to kernel-first cyber work.
