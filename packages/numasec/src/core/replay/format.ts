import { createHash } from "node:crypto"
import type { MessageV2 } from "@/session/message-v2"
import type { Session } from "@/session"
import { InstallationVersion } from "@/installation/version"
import { redactValue, redactString, type RedactMode } from "./redact"

export const FORMAT = "numasec/1"

export type Header = {
  type: "header"
  format: string
  id: string
  scope: "session"
  kind?: string
  title?: string
  created_at: string
  exported_at: string
  numasec_version: string
  model?: { provider: string; id: string }
  redacted: boolean
}

export type EventLine = {
  type: "event"
  event: "message" | "tool_call" | "tool_result" | "op_event"
  ts: string
  seq: number
  session_id: string
  message_id?: string
  data: Record<string, unknown>
}

export type Trailer = {
  type: "trailer"
  events: number
  duration_ms: number
  sha256_body: string
  signed: boolean
  signature: null | { scheme: string; public_key_id?: string; value: string }
}

export type ReplayLine = Header | EventLine | Trailer

function iso(ms: number) {
  return new Date(ms).toISOString()
}

function modelOf(messages: MessageV2.WithParts[]): { provider: string; id: string } | undefined {
  for (const m of messages) {
    if (m.info.role === "assistant") {
      return { provider: m.info.providerID, id: m.info.modelID }
    }
  }
  return undefined
}

function kindOf(messages: MessageV2.WithParts[]): string | undefined {
  for (const m of messages) {
    if (m.info.role === "assistant") return m.info.agent
  }
  return undefined
}

function* eventsFor(
  messages: MessageV2.WithParts[],
  mode: RedactMode,
  sessionID: string,
): Generator<Omit<EventLine, "seq">> {
  for (const m of messages) {
    const message_id = m.info.id
    const created = (m.info.time as { created: number }).created ?? Date.now()
    for (const p of m.parts) {
      if (p.type === "text") {
        const text = redactString(p.text, mode)
        yield {
          type: "event",
          event: "message",
          ts: iso(created),
          session_id: sessionID,
          message_id,
          data: { role: m.info.role, text },
        }
        continue
      }
      if (p.type === "tool") {
        const state = p.state
        const callTs = (state as { time?: { start?: number } }).time?.start ?? created
        yield {
          type: "event",
          event: "tool_call",
          ts: iso(callTs),
          session_id: sessionID,
          message_id,
          data: {
            tool: p.tool,
            call_id: p.callID,
            input:
              state.status === "pending" || state.status === "running"
                ? undefined
                : redactValue((state as { input?: unknown }).input, mode),
            input_redacted: mode === "on",
          },
        }
        if (state.status === "completed" || state.status === "error") {
          const endTs = (state as { time?: { end?: number } }).time?.end ?? callTs
          const dur = Math.max(0, endTs - callTs)
          const output = (state as { output?: unknown }).output
          yield {
            type: "event",
            event: "tool_result",
            ts: iso(endTs),
            session_id: sessionID,
            message_id,
            data: {
              call_id: p.callID,
              status: state.status,
              duration_ms: dur,
              output: redactValue(output, mode),
              error: state.status === "error" ? (state as { error?: string }).error : undefined,
            },
          }
        }
      }
    }
  }
}

export function buildReplay(input: {
  info: Session.Info
  messages: MessageV2.WithParts[]
  redact: RedactMode
}): { lines: string[]; header: Header; trailer: Trailer } {
  const { info, messages, redact } = input
  const sessionID = info.id
  const created = info.time.created
  const exported = Date.now()
  const model = modelOf(messages)

  const header: Header = {
    type: "header",
    format: FORMAT,
    id: sessionID,
    scope: "session",
    kind: kindOf(messages),
    title: redact === "on" ? `[redacted:title]` : info.title,
    created_at: iso(created),
    exported_at: iso(exported),
    numasec_version: InstallationVersion,
    model,
    redacted: redact === "on",
  }

  const eventLines: string[] = []
  let seq = 0
  let lastTs = created
  for (const ev of eventsFor(messages, redact, sessionID)) {
    seq += 1
    const line = JSON.stringify({ ...ev, seq })
    eventLines.push(line)
    const t = Date.parse(ev.ts)
    if (Number.isFinite(t)) lastTs = Math.max(lastTs, t)
  }

  const headerLine = JSON.stringify(header)
  const body = headerLine + "\n" + (eventLines.length ? eventLines.join("\n") + "\n" : "")
  const sha = createHash("sha256").update(body).digest("hex")

  const trailer: Trailer = {
    type: "trailer",
    events: seq,
    duration_ms: Math.max(0, lastTs - created),
    sha256_body: sha,
    signed: false,
    signature: null,
  }

  return {
    lines: [headerLine, ...eventLines, JSON.stringify(trailer)],
    header,
    trailer,
  }
}

export function parseReplay(text: string): { header: Header; events: EventLine[]; trailer: Trailer } {
  const rawLines = text.split("\n").filter((l) => l.length > 0)
  if (rawLines.length < 2) throw new Error("replay file too short")
  const header = JSON.parse(rawLines[0]) as Header
  if (header.type !== "header") throw new Error("missing header line")
  if (header.format !== FORMAT) throw new Error(`unsupported format: ${header.format}`)
  const trailer = JSON.parse(rawLines[rawLines.length - 1]) as Trailer
  if (trailer.type !== "trailer") throw new Error("missing trailer line")
  const events: EventLine[] = []
  for (let i = 1; i < rawLines.length - 1; i++) {
    const obj = JSON.parse(rawLines[i]) as EventLine
    if (obj.type !== "event") throw new Error(`line ${i + 1}: expected event`)
    events.push(obj)
  }
  return { header, events, trailer }
}

export function verifyBody(text: string): { ok: boolean; expected: string; actual: string } {
  const lines = text.split("\n").filter((l) => l.length > 0)
  const trailer = JSON.parse(lines[lines.length - 1]) as Trailer
  const body = lines.slice(0, -1).join("\n") + "\n"
  const actual = createHash("sha256").update(body).digest("hex")
  return { ok: actual === trailer.sha256_body, expected: trailer.sha256_body, actual }
}
