import z from "zod"
import { Effect } from "effect"
import { and, eq, inArray } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { Database } from "../../storage/db"
import { EvidenceNodeTable } from "../evidence.sql"
import { EvidenceGraphStore } from "../evidence-store"
import { canonicalSecuritySessionID } from "../security-session"
import { makeToolResultEnvelope } from "./result-envelope"

type EvidenceNodeID = (typeof EvidenceNodeTable)["$inferInsert"]["id"]

function nodeID(value: string): EvidenceNodeID {
  return value as EvidenceNodeID
}

const DESCRIPTION = `Verify a predicate against one or more evidence nodes.
Returns deterministic verification outcome, confidence score, and optional verification node.`

export const AssertionMode = z.enum(["substring", "exact", "regex"])
export const AssertionControl = z.enum(["positive", "negative", "neutral"])
const JsonOp = z.enum(["exists", "equals", "contains"])
export const TypedAssertion = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("http_status"),
    equals: z.number().int(),
  }),
  z.object({
    kind: z.literal("header"),
    name: z.string(),
    equals: z.string().optional(),
    contains: z.string().optional(),
  }),
  z.object({
    kind: z.literal("json_path"),
    path: z.string(),
    op: JsonOp.default("exists"),
    value: z.any().optional(),
  }),
  z.object({
    kind: z.literal("jwt_claim"),
    claim: z.string(),
    equals: z.string().optional(),
    contains: z.string().optional(),
    token_path: z.string().optional(),
  }),
])
export const VerificationAssertionInput = z
  .object({
    predicate: z.string().optional(),
    mode: AssertionMode.optional(),
    require_all: z.boolean().optional(),
    control: AssertionControl.optional(),
    typed: TypedAssertion.optional(),
  })
  .refine((item) => item.typed || (item.predicate ?? "").trim().length > 0, "assertion requires predicate or typed input")

function collectText(input: unknown, out: string[]) {
  if (typeof input === "string") {
    out.push(input)
    return
  }
  if (!input || typeof input !== "object") return
  if (Array.isArray(input)) {
    for (const item of input) collectText(item, out)
    return
  }
  const value = input as Record<string, unknown>
  for (const key of Object.keys(value)) {
    collectText(value[key], out)
  }
}

function matches(text: string, predicate: string, mode: z.infer<typeof AssertionMode>) {
  if (mode === "exact") return text === predicate
  if (mode === "substring") return text.toLowerCase().includes(predicate.toLowerCase())
  const re = new RegExp(predicate, "i")
  return re.test(text)
}

function readJSON(text: string): unknown {
  const value = text.trim()
  if (!value) return undefined
  if (!(value.startsWith("{") || value.startsWith("["))) return undefined
  try {
    return JSON.parse(value)
  } catch {
    return undefined
  }
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split(".")
  if (parts.length < 2) return {}
  const body = parts[1] ?? ""
  if (!body) return {}
  const pad = body.length % 4 === 0 ? body : `${body}${"=".repeat(4 - (body.length % 4))}`
  try {
    const raw = Buffer.from(pad.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")
    const parsed = JSON.parse(raw)
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) return parsed as Record<string, unknown>
  } catch {
    return {}
  }
  return {}
}

function readPath(input: unknown, value: string): unknown {
  if (!value) return input
  const keys = value
    .replace(/\[(\d+)\]/g, ".$1")
    .split(".")
    .map((item) => item.trim())
    .filter(Boolean)
  let current: unknown = input
  for (const key of keys) {
    if (typeof current === "string") {
      const parsed = readJSON(current)
      if (parsed === undefined) return undefined
      current = parsed
    }
    if (Array.isArray(current)) {
      const index = Number(key)
      if (!Number.isInteger(index)) return undefined
      current = current[index]
      continue
    }
    if (!current || typeof current !== "object") return undefined
    current = (current as Record<string, unknown>)[key]
  }
  return current
}

function headersFromPayload(input: unknown): Record<string, string> {
  const out: Record<string, string> = {}
  const push = (value: unknown) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return
    const row = value as Record<string, unknown>
    for (const key of Object.keys(row)) {
      const item = row[key]
      if (typeof item !== "string") continue
      out[key.toLowerCase()] = item
    }
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) return out
  const payload = input as Record<string, unknown>
  push(payload.headers)
  push(payload.response && typeof payload.response === "object" ? (payload.response as Record<string, unknown>).headers : undefined)
  push(payload.request && typeof payload.request === "object" ? (payload.request as Record<string, unknown>).headers : undefined)
  return out
}

function statusFromPayload(input: unknown): number | undefined {
  const direct = readPath(input, "response.status")
  if (typeof direct === "number") return direct
  const alt = readPath(input, "status")
  if (typeof alt === "number") return alt
  const http = readPath(input, "http_status")
  if (typeof http === "number") return http
  return undefined
}

function tokenFromPayload(input: unknown, tokenPath: string): string {
  const picked = readPath(input, tokenPath)
  if (typeof picked === "string") return picked
  const text: string[] = []
  collectText(input, text)
  const found = text.find((item) => /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(item))
  return found ?? ""
}

function matchTyped(payload: unknown, typed: z.infer<typeof TypedAssertion>): boolean {
  if (typed.kind === "http_status") {
    const status = statusFromPayload(payload)
    return status === typed.equals
  }
  if (typed.kind === "header") {
    const headers = headersFromPayload(payload)
    const value = headers[typed.name.toLowerCase()]
    if (value === undefined) return false
    if (typed.equals) return value.toLowerCase() === typed.equals.toLowerCase()
    if (typed.contains) return value.toLowerCase().includes(typed.contains.toLowerCase())
    return true
  }
  if (typed.kind === "json_path") {
    const value = readPath(payload, typed.path)
    if (typed.op === "exists") return value !== undefined && value !== null
    if (typed.op === "equals") return JSON.stringify(value) === JSON.stringify(typed.value)
    const text = typeof value === "string" ? value : JSON.stringify(value)
    if (typeof text !== "string") return false
    return text.toLowerCase().includes(String(typed.value ?? "").toLowerCase())
  }
  const token = tokenFromPayload(payload, typed.token_path ?? "idToken")
  if (!token) return false
  const claims = decodeJwtPayload(token)
  const claim = claims[typed.claim]
  if (typed.equals) return String(claim ?? "").toLowerCase() === typed.equals.toLowerCase()
  if (typed.contains) return String(claim ?? "").toLowerCase().includes(typed.contains.toLowerCase())
  return claim !== undefined
}

export const VerifyAssertionTool = Tool.define("verify_assertion", {
  description: DESCRIPTION,
  parameters: z.object({
    predicate: z.string().optional().describe("Assertion or predicate to verify"),
    evidence_refs: z.array(z.string()).min(1).describe("Evidence node ids"),
    hypothesis_id: z.string().optional().describe("Optional hypothesis node id to link from"),
    mode: AssertionMode.optional().describe("Match mode"),
    require_all: z.boolean().optional().describe("Require every evidence ref to match"),
    control: AssertionControl.optional().describe("Assertion control type: positive expects matches, negative expects no matches"),
    persist: z.boolean().optional().describe("Persist verification node"),
    typed: TypedAssertion.optional().describe("Structured assertion mode for HTTP status, headers, JSON paths, and JWT claims"),
  }),
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const predicate = (params.predicate ?? "").trim()
    const typed = params.typed
    if (!typed && !predicate) {
      throw new Error("verify_assertion requires predicate or typed assertion input")
    }

    const refs = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(
          and(
            eq(EvidenceNodeTable.session_id, sessionID),
            inArray(EvidenceNodeTable.id, params.evidence_refs.map(nodeID)),
          ),
        )
        .all(),
    )

    if (refs.length !== params.evidence_refs.length) {
      throw new Error("verify_assertion received one or more unknown evidence_refs")
    }

    const mode = params.mode ?? "substring"
    const control = params.control ?? "positive"
    const verdict: Array<{ ref: string; passed: boolean }> = []
    for (const row of refs) {
      let passed = false
      if (typed) {
        passed = matchTyped(row.payload, typed)
      }
      if (!typed) {
        const texts: string[] = []
        collectText(row.payload, texts)
        passed = texts.some((item) => matches(item, predicate, mode))
      }
      verdict.push({
        ref: row.id,
        passed,
      })
    }

    const matchCount = verdict.filter((item) => item.passed).length
    const requireAll = params.require_all ?? (control === "negative")
    const passed = control === "negative" ? (requireAll ? matchCount === 0 : matchCount < verdict.length) : requireAll ? matchCount === verdict.length : matchCount > 0
    const confidence = verdict.length === 0 ? 0 : control === "negative" ? (verdict.length - matchCount) / verdict.length : matchCount / verdict.length
    const status = passed ? "ok" : "inconclusive"

    let verificationNodeID = ""
    if (params.persist !== false) {
      const row = Effect.runSync(
        EvidenceGraphStore.use((store) =>
          store.upsertNode({
            sessionID,
            type: "verification",
            confidence,
            status: passed ? "confirmed" : "open",
            sourceTool: "verify_assertion",
            payload: {
              predicate: params.predicate,
              typed,
              mode,
              control,
              require_all: requireAll,
              evidence_refs: params.evidence_refs,
              passed,
              verdict,
            },
          }),
        ).pipe(Effect.provide(EvidenceGraphStore.layer)),
      )
      verificationNodeID = row.id
      for (const ref of params.evidence_refs) {
        Effect.runSync(
          EvidenceGraphStore.use((store) =>
            store.upsertEdge({
              sessionID,
              fromNodeID: ref,
              toNodeID: row.id,
              relation: "supports",
              weight: 1,
              metadata: {
                source: "verify_assertion",
              },
            }),
          ).pipe(Effect.provide(EvidenceGraphStore.layer)),
        )
      }
      const hypothesisID = params.hypothesis_id ?? ""
      if (hypothesisID) {
        Effect.runSync(
          EvidenceGraphStore.use((store) =>
            store.upsertEdge({
              sessionID,
              fromNodeID: hypothesisID,
              toNodeID: row.id,
              relation: "verifies",
              weight: 1,
              metadata: {
                source: "verify_assertion",
              },
            }),
          ).pipe(Effect.provide(EvidenceGraphStore.layer)),
        )
      }
    }

    return {
      title: `Verification ${passed ? "passed" : "not passed"}`,
      metadata: {
        passed,
        confidence,
        checked: verdict.length,
        verificationNodeID,
      } as any,
      envelope: makeToolResultEnvelope({
        status,
        verifications: [
          {
            type: "verification",
            verification_node_id: verificationNodeID,
            passed,
            confidence,
            predicate: params.predicate,
            typed,
            mode,
            control,
          },
        ],
        metrics: {
          checked: verdict.length,
          matches: matchCount,
        },
      }),
      output: JSON.stringify(
        {
          passed,
          confidence,
          checked: verdict.length,
          matches: matchCount,
          control,
          require_all: requireAll,
          typed,
          verification_node_id: verificationNodeID,
          verdict,
        },
        null,
        2,
      ),
    }
  },
})
