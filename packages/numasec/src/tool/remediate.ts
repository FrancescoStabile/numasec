import z from "zod"
import { Effect } from "effect"
import { readFile } from "node:fs/promises"
import path from "node:path"
import * as Tool from "./tool"
import DESCRIPTION from "./remediate.txt"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { Observation } from "@/core/observation"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

const parameters = z.object({
  observation_id: z.string().min(1).describe("id of the observation to remediate"),
  mode: z.enum(["patch", "advice"]).default("patch").describe("patch scaffolds a unified diff; advice returns structured guidance only"),
})

type Params = z.infer<typeof parameters>

type Metadata = {
  mode: "patch" | "advice"
  observation_id: string
  severity?: string
  found_file: boolean
  refused_fixture: boolean
}

const FIXTURE_DIRS = ["juice-shop", "webgoat", "dvwa", "bwapp"]

function extractFileRef(candidates: Array<string | undefined>): { file: string; line?: number } | undefined {
  const pattern = /([A-Za-z0-9_.\-\/]+\.[A-Za-z0-9]+)(?::(\d+))?/
  for (const c of candidates) {
    if (!c) continue
    const prefix = c.startsWith("file:") ? c.slice(5) : c
    const m = prefix.match(pattern)
    if (!m) continue
    const file = m[1]
    if (!file.includes("/") && !file.includes(".")) continue
    return { file, line: m[2] ? Number(m[2]) : undefined }
  }
  return undefined
}

function inFixtureDir(file: string): string | undefined {
  const normalized = file.replace(/\\/g, "/").toLowerCase()
  for (const f of FIXTURE_DIRS) {
    if (normalized === f || normalized.startsWith(`${f}/`) || normalized.includes(`/${f}/`)) return f
  }
  return undefined
}

function clamp(n: number, lo: number, hi: number) {
  if (n < lo) return lo
  if (n > hi) return hi
  return n
}

function scaffoldPatch(input: {
  file: string
  line: number
  before: string[]
  target: string
  after: string[]
  marker: string
}): string {
  const startLine = Math.max(1, input.line - input.before.length)
  const beforeLen = input.before.length + 1 + input.after.length
  const afterLen = beforeLen + 1
  const lines: string[] = []
  lines.push(`--- a/${input.file}`)
  lines.push(`+++ b/${input.file}`)
  lines.push(`@@ -${startLine},${beforeLen} +${startLine},${afterLen} @@`)
  for (const l of input.before) lines.push(` ${l}`)
  lines.push(` ${input.target}`)
  lines.push(`+${input.marker}`)
  for (const l of input.after) lines.push(` ${l}`)
  return lines.join("\n") + "\n"
}

function adviceSteps(o: Observation.Observation): string[] {
  const sev = o.severity ?? "unknown"
  const steps = [
    `Confirm observation ${o.id} (${sev}, ${o.subtype}) is a true positive by reproducing the issue.`,
    "Identify the component/module that produces the vulnerable behaviour and its test surface.",
    "Draft the minimal code change that removes the defect without altering unrelated behaviour.",
    "Add or extend a regression test that fails before the fix and passes after.",
    "Run the full test suite and any relevant static analysis.",
    `Commit on a disposable branch (e.g. numasec/remediate-${o.id}) and open a review; never apply in-place on an operator's main branch.`,
  ]
  return steps
}

function adviceReferences(o: Observation.Observation): string[] {
  const refs: string[] = []
  for (const t of o.tags ?? []) refs.push(`tag:${t}`)
  if (o.subtype === "vuln") refs.push("owasp:top10", "cwe:search")
  if (o.subtype === "control-gap") refs.push("nist:800-53")
  if (o.subtype === "code-smell") refs.push("cwe:search")
  for (const ev of o.evidence ?? []) refs.push(`evidence:${ev}`)
  return refs
}

function recordRemediation(input: {
  slug: string
  output: string
  observation_id: string
  title: string
  mode: "patch" | "advice"
  severity?: string
  source: "generated" | "not_found" | "no_active_operation" | "refused_fixture" | "unreadable"
  session_id: Tool.Context["sessionID"]
  message_id: Tool.Context["messageID"]
}) {
  return Effect.gen(function* () {
    const workspace = Instance.directory
    const evidence = yield* Effect.promise(() =>
      Evidence.put(workspace, input.slug, input.output, {
        mime: "application/json",
        ext: "json",
        label: `remediate ${input.observation_id} ${input.mode}`,
        source: "remediate",
      }),
    ).pipe(Effect.catch(() => Effect.succeed(undefined)))
    const evidenceRefs = evidence ? [evidence.sha256] : undefined
    const eventID = yield* Cyber.appendLedger({
      kind: "fact.observed",
      source: "remediate",
      summary: `remediate ${input.mode} ${input.observation_id}`,
      session_id: input.session_id,
      message_id: input.message_id,
      evidence_refs: evidenceRefs,
      data: {
        observation_id: input.observation_id,
        title: input.title,
        mode: input.mode,
        severity: input.severity ?? null,
        source: input.source,
      },
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertFact({
      entity_kind: "observation",
      entity_key: input.observation_id,
      fact_name: input.mode === "patch" ? "remediation_patch_scaffold" : "remediation_advice",
      value_json: {
        title: input.title,
        mode: input.mode,
        severity: input.severity,
        source: input.source,
      },
      writer_kind: "tool",
      status: input.source === "generated" ? "observed" : "candidate",
      confidence: input.source === "generated" ? 900 : 700,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed("")))
  })
}

export const RemediateTool = Tool.define<typeof parameters, Metadata, never>(
  "remediate",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const workspace = Instance.directory
          const mode = params.mode ?? "patch"

          yield* ctx.ask({
            permission: "remediate",
            patterns: [params.observation_id],
            always: ["*"],
            metadata: { observation_id: params.observation_id, mode },
          })

          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          if (!slug) {
            const payload = {
              error: "no_active_operation",
              message: "No active operation — start one with /pwn before calling remediate.",
            }
            const output = JSON.stringify(payload, null, 2)
            return {
              title: "remediate: no active op",
              output,
              metadata: {
                mode,
                observation_id: params.observation_id,
                found_file: false,
                refused_fixture: false,
              },
            }
          }

          const obs =
            (yield* Effect.promise(() => Observation.getProjected(workspace, slug, params.observation_id)).pipe(
              Effect.catch(() => Effect.succeed(undefined)),
            )) ??
            (yield* Effect.promise(() => Observation.list(workspace, slug))).find((o) => o.id === params.observation_id)
          if (!obs) {
            const payload = {
              error: "observation_not_found",
              message: `No observation with id "${params.observation_id}" in operation "${slug}".`,
            }
            const output = JSON.stringify(payload, null, 2)
            yield* recordRemediation({
              slug,
              output,
              observation_id: params.observation_id,
              title: "observation not found",
              mode,
              source: "not_found",
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
            })
            return {
              title: "remediate: not found",
              output,
              metadata: {
                mode,
                observation_id: params.observation_id,
                found_file: false,
                refused_fixture: false,
              },
            }
          }

          const ref = extractFileRef([...(obs.evidence ?? []), obs.note])

          if (mode === "advice" || !ref) {
            const payload = {
              observation_id: obs.id,
              title: `Advice for ${obs.title}`,
              severity: obs.severity,
              steps: adviceSteps(obs),
              references: adviceReferences(obs),
            }
            const output = JSON.stringify(payload, null, 2)
            yield* recordRemediation({
              slug,
              output,
              observation_id: obs.id,
              title: obs.title,
              mode: "advice",
              severity: obs.severity,
              source: "generated",
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
            })
            return {
              title: `remediate · advice · ${obs.severity ?? "n/a"}`,
              output,
              metadata: {
                mode,
                observation_id: obs.id,
                severity: obs.severity,
                found_file: false,
                refused_fixture: false,
              },
            }
          }

          const fixture = inFixtureDir(ref.file)
          if (fixture) {
            const payload = {
              observation_id: obs.id,
              title: `Refused to patch canonical fixture "${fixture}"`,
              severity: obs.severity,
              refused_fixture: fixture,
              steps: [
                `The target file "${ref.file}" lives under a canonical fixture directory ("${fixture}/").`,
                "numasec never rewrites a fixture in place.",
                "Clone the fixture to a disposable path and re-run /remediate with that copy, e.g. `git clone <fixture-upstream> /tmp/disposable-<slug>`.",
                "Then link the disposable-copy file:line as evidence on the observation and retry.",
              ],
              references: adviceReferences(obs),
            }
            const output = JSON.stringify(payload, null, 2)
            yield* recordRemediation({
              slug,
              output,
              observation_id: obs.id,
              title: obs.title,
              mode,
              severity: obs.severity,
              source: "refused_fixture",
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
            })
            return {
              title: "remediate · refused (fixture)",
              output,
              metadata: {
                mode,
                observation_id: obs.id,
                severity: obs.severity,
                found_file: false,
                refused_fixture: true,
              },
            }
          }

          const abs = path.isAbsolute(ref.file) ? ref.file : path.join(workspace, ref.file)
          const raw = yield* Effect.promise(() =>
            readFile(abs, "utf8").catch(() => undefined),
          )
          if (raw === undefined) {
            const payload = {
              observation_id: obs.id,
              title: `Could not read ${ref.file}`,
              severity: obs.severity,
              steps: [
                `The observation references "${ref.file}" but the file is not readable from the workspace.`,
                "Verify the path, link corrected evidence to the observation, and retry.",
              ],
              references: adviceReferences(obs),
            }
            const output = JSON.stringify(payload, null, 2)
            yield* recordRemediation({
              slug,
              output,
              observation_id: obs.id,
              title: obs.title,
              mode,
              severity: obs.severity,
              source: "unreadable",
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
            })
            return {
              title: "remediate · advice · unreadable",
              output,
              metadata: {
                mode,
                observation_id: obs.id,
                severity: obs.severity,
                found_file: false,
                refused_fixture: false,
              },
            }
          }

          const all = raw.split("\n")
          const line = clamp(ref.line ?? 1, 1, Math.max(1, all.length))
          const idx = line - 1
          const beforeStart = Math.max(0, idx - 30)
          const afterEnd = Math.min(all.length, idx + 31)
          const before = all.slice(beforeStart, idx)
          const target = all[idx] ?? ""
          const after = all.slice(idx + 1, afterEnd)
          const marker = `// numasec: TODO remediate ${obs.id} (${obs.severity ?? "n/a"}) — ${obs.title}`
          const patch = scaffoldPatch({ file: ref.file, line, before, target, after, marker })

          const rationaleParts = [
            `Observation ${obs.id} (${obs.severity ?? "n/a"}, ${obs.subtype}): ${obs.title}.`,
            obs.note ? `Note: ${obs.note}` : undefined,
            `Context: ${ref.file}:${line} (±${Math.min(30, Math.max(before.length, after.length))} lines inspected).`,
            "This is a scaffold patch — the calling agent must replace the TODO marker with the real fix before review.",
          ].filter(Boolean) as string[]

          const risk: "low" | "medium" | "high" =
            obs.severity === "critical" || obs.severity === "high"
              ? "medium"
              : "low"

          const payload = {
            observation_id: obs.id,
            file: ref.file,
            line,
            severity: obs.severity,
            context: {
              start_line: beforeStart + 1,
              end_line: afterEnd,
              before,
              target,
              after,
            },
            patch,
            rationale: rationaleParts.join(" "),
            risk,
            tested: false,
          }
          const output = JSON.stringify(payload, null, 2)
          yield* recordRemediation({
            slug,
            output,
            observation_id: obs.id,
            title: obs.title,
            mode: "patch",
            severity: obs.severity,
            source: "generated",
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
          })

          return {
            title: `remediate · patch · ${ref.file}:${line}`,
            output,
            metadata: {
              mode,
              observation_id: obs.id,
              severity: obs.severity,
              found_file: true,
              refused_fixture: false,
            },
          }
        }),
    }
  }),
)
