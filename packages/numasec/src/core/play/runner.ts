import {
  type Play,
  type PlayStep,
  type Step,
  type ToolStep,
  type SkillStep,
  isConditional,
  isToolStep,
  isSkillStep,
} from "./play"
import { PlayRegistry } from "./registry"

export type TraceEntry =
  | { kind: "tool"; tool: string; args: Record<string, unknown> }
  | { kind: "skill"; skill: string; brief: string }

export type RunResult = {
  play: Play
  args: Record<string, unknown>
  trace: TraceEntry[]
  skipped: { step: PlayStep; reason: string }[]
}

export class PlayNotFoundError extends Error {
  constructor(id: string) {
    super(`play "${id}" not found. known: ${PlayRegistry.ids().join(", ") || "<none>"}`)
  }
}

export class PlayArgError extends Error {
  constructor(id: string, missing: string[]) {
    super(`play "${id}" missing required args: ${missing.join(", ")}`)
  }
}

const TEMPLATE = /\{\{\s*([a-zA-Z0-9_.-]+)(?:\s*\|\s*([^}]*?))?\s*\}\}/g

function substituteString(input: string, args: Record<string, unknown>): string {
  return input.replace(TEMPLATE, (_match, name: string, fallback?: string) => {
    const value = args[name]
    if (value === undefined || value === null || value === "") return fallback ?? ""
    return String(value)
  })
}

function substitute(value: unknown, args: Record<string, unknown>): unknown {
  if (typeof value === "string") return substituteString(value, args)
  if (Array.isArray(value)) return value.map((v) => substitute(v, args))
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substitute(v, args)]))
  }
  return value
}

function evalCondition(expr: string, args: Record<string, unknown>): boolean {
  const trimmed = expr.trim()
  const eq = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*==\s*(.+)$/)
  if (eq) {
    const lhs = args[eq[1]]
    const rhs = eq[2].trim().replace(/^["'](.*)["']$/, "$1")
    return String(lhs ?? "") === rhs
  }
  const neg = trimmed.match(/^!\s*([a-zA-Z0-9_.-]+)$/)
  if (neg) {
    const v = args[neg[1]]
    return v === undefined || v === null || v === "" || v === false
  }
  const v = args[trimmed]
  return !(v === undefined || v === null || v === "" || v === false)
}

function resolveStep(step: Step, args: Record<string, unknown>): TraceEntry {
  if (isToolStep(step)) {
    const resolved = substitute(step.args, args) as Record<string, unknown>
    return { kind: "tool", tool: step.tool, args: resolved }
  }
  if (isSkillStep(step)) {
    return { kind: "skill", skill: step.skill, brief: substituteString(step.brief, args) }
  }
  throw new Error(`unknown step shape: ${JSON.stringify(step)}`)
}

function validateArgs(play: Play, args: Record<string, unknown>): string[] {
  return play.args
    .filter((spec) => spec.required)
    .filter((spec) => args[spec.name] === undefined || args[spec.name] === null || args[spec.name] === "")
    .map((spec) => spec.name)
}

export namespace PlayRunner {
  export function run(input: { id: string; args?: Record<string, unknown> }): RunResult {
    const play = PlayRegistry.get(input.id)
    if (!play) throw new PlayNotFoundError(input.id)

    const args = input.args ?? {}
    const missing = validateArgs(play, args)
    if (missing.length > 0) throw new PlayArgError(input.id, missing)

    const trace: TraceEntry[] = []
    const skipped: { step: PlayStep; reason: string }[] = []

    for (const step of play.steps) {
      if (isConditional(step)) {
        if (!evalCondition(step.if, args)) {
          skipped.push({ step, reason: `if "${step.if}" was falsy` })
          continue
        }
        trace.push(resolveStep(step.then, args))
        continue
      }
      trace.push(resolveStep(step, args))
    }

    return { play, args, trace, skipped }
  }

  export function format(result: RunResult): string {
    const lines: string[] = []
    lines.push(`# Play: ${result.play.name} (${result.play.id})`)
    lines.push(result.play.description)
    lines.push("")
    lines.push("## Args")
    for (const spec of result.play.args) {
      const val = result.args[spec.name]
      lines.push(`- ${spec.name}${spec.required ? "*" : ""}: ${val === undefined ? "<unset>" : JSON.stringify(val)}`)
    }
    lines.push("")
    lines.push("## Steps (execute in order)")
    result.trace.forEach((entry, i) => {
      if (entry.kind === "tool") {
        lines.push(`${i + 1}. tool: ${entry.tool}`)
        lines.push(`   args: ${JSON.stringify(entry.args)}`)
        return
      }
      lines.push(`${i + 1}. skill: ${entry.skill}`)
      lines.push(`   brief: ${entry.brief}`)
    })
    if (result.skipped.length > 0) {
      lines.push("")
      lines.push("## Skipped")
      for (const s of result.skipped) lines.push(`- ${s.reason}`)
    }
    lines.push("")
    lines.push(
      "Now execute each step above by calling the referenced tool (or `skill` tool with the named skill) with the given args. If a referenced tool is not registered, report it and continue with the remaining steps.",
    )
    return lines.join("\n")
  }
}

export type { Step, ToolStep, SkillStep, PlayStep }
