import { createHash } from "crypto"
import { and, eq } from "../../storage/db"
import type { SessionID } from "../../session/schema"
import { SessionTable } from "../../session/session.sql"
import { Database } from "../../storage/db"
import { canonicalSecuritySessionID } from "../security-session"
import {
  SecurityTargetProfileTable,
  type SecurityTargetProfileID,
} from "./runtime.sql"

export interface TargetExecutionProfile {
  id: SecurityTargetProfileID
  session_id: SessionID
  origin: string
  status: string
  concurrency_budget: number
  pacing_ms: number
  jitter_ms: number
  retry_budget: number
  browser_preferred: boolean
  last_signal: string
  notes: Record<string, unknown>
}

function id(sessionID: SessionID, origin: string) {
  const currentSessionID = canonicalSecuritySessionID(sessionID)
  return `TPRF-${createHash("sha256").update(`${currentSessionID}:${origin}`).digest("hex").slice(0, 12).toUpperCase()}` as SecurityTargetProfileID
}

function origin(input: string) {
  try {
    const url = new URL(input)
    if (url.protocol !== "http:" && url.protocol !== "https:") return ""
    return url.origin
  } catch {
    return ""
  }
}

function profile(input: SessionID, url: string) {
  const sessionID = canonicalSecuritySessionID(input)
  const value = origin(url)
  if (!value) return
  return {
    id: id(sessionID, value),
    session_id: sessionID,
    origin: value,
    status: "baseline",
    concurrency_budget: 1,
    pacing_ms: 0,
    jitter_ms: 0,
    retry_budget: 1,
    browser_preferred: false,
    last_signal: "",
    notes: {},
  } satisfies TargetExecutionProfile
}

function next(current: TargetExecutionProfile, signal: string, browserPreferred?: boolean) {
  if (signal === "waf_suspected") {
    return {
      ...current,
      status: "blocked",
      pacing_ms: Math.max(current.pacing_ms, 3000),
      jitter_ms: Math.max(current.jitter_ms, 750),
      retry_budget: 0,
      browser_preferred: true,
      last_signal: signal,
      notes: {
        ...current.notes,
        blocked: true,
      },
    } satisfies TargetExecutionProfile
  }
  if (signal === "rate_limited") {
    return {
      ...current,
      status: "throttled",
      pacing_ms: Math.max(current.pacing_ms, 1500),
      jitter_ms: Math.max(current.jitter_ms, 250),
      retry_budget: 0,
      browser_preferred: browserPreferred ?? current.browser_preferred,
      last_signal: signal,
    } satisfies TargetExecutionProfile
  }
  if (signal === "navigation_timeout" || signal === "transient_network") {
    return {
      ...current,
      status: current.status === "blocked" ? current.status : "cautious",
      pacing_ms: Math.max(current.pacing_ms, 250),
      jitter_ms: Math.max(current.jitter_ms, 50),
      retry_budget: Math.max(current.retry_budget, 1),
      browser_preferred: browserPreferred ?? current.browser_preferred,
      last_signal: signal,
    } satisfies TargetExecutionProfile
  }
  if (signal === "success" && current.status !== "blocked") {
    const pacing = Math.max(0, current.pacing_ms - 100)
    const jitter = Math.max(0, current.jitter_ms - 25)
    return {
      ...current,
      status: pacing === 0 && jitter === 0 ? "baseline" : "cautious",
      pacing_ms: pacing,
      jitter_ms: jitter,
      retry_budget: Math.max(1, current.retry_budget),
      browser_preferred: browserPreferred ?? current.browser_preferred,
      last_signal: signal,
    } satisfies TargetExecutionProfile
  }
  return {
    ...current,
    browser_preferred: browserPreferred ?? current.browser_preferred,
    last_signal: signal,
  } satisfies TargetExecutionProfile
}

export async function ensureTargetProfile(sessionID: SessionID, url: string) {
  const currentSessionID = canonicalSecuritySessionID(sessionID)
  const seed = profile(currentSessionID, url)
  if (!seed) return
  return Database.use((db) => {
    const session = db
        .select({
          id: SessionTable.id,
        })
        .from(SessionTable)
        .where(eq(SessionTable.id, currentSessionID))
        .get()
    if (!session) return seed
    const current = db
      .select()
      .from(SecurityTargetProfileTable)
      .where(and(eq(SecurityTargetProfileTable.session_id, currentSessionID), eq(SecurityTargetProfileTable.origin, seed.origin)))
      .get()
    if (current) return current satisfies TargetExecutionProfile
    db.insert(SecurityTargetProfileTable).values(seed).run()
    return seed
  })
}

export async function noteTargetSignal(sessionID: SessionID, url: string, signal: string, browserPreferred?: boolean) {
  const currentSessionID = canonicalSecuritySessionID(sessionID)
  const current = await ensureTargetProfile(sessionID, url)
  if (!current) return
  const updated = next(current, signal, browserPreferred)
  Database.use((db) => {
    const session = db
        .select({
          id: SessionTable.id,
        })
        .from(SessionTable)
        .where(eq(SessionTable.id, currentSessionID))
        .get()
    if (!session) return
    db
      .insert(SecurityTargetProfileTable)
      .values(updated)
      .onConflictDoUpdate({
        target: SecurityTargetProfileTable.id,
        set: {
          status: updated.status,
          concurrency_budget: updated.concurrency_budget,
          pacing_ms: updated.pacing_ms,
          jitter_ms: updated.jitter_ms,
          retry_budget: updated.retry_budget,
          browser_preferred: updated.browser_preferred,
          last_signal: updated.last_signal,
          notes: updated.notes,
          time_updated: Date.now(),
        },
      })
      .run()
  })
  return updated
}

export async function applyTargetProfile(sessionID: SessionID, url: string) {
  const current = await ensureTargetProfile(sessionID, url)
  if (!current) return
  const pause = current.pacing_ms + Math.floor(Math.random() * (current.jitter_ms + 1))
  if (pause > 0) {
    await Bun.sleep(pause)
  }
  return current
}
