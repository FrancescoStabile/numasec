import { createHash } from "crypto"
import { SessionTable } from "../session/session.sql"
import type { SessionID } from "../session/schema"
import { and, Database, eq } from "../storage/db"
import { canonicalSecuritySessionID } from "./security-session"
import { TargetTable, type TargetID } from "./security.sql"
import { Scope } from "./scope"

function id(sessionID: SessionID, url: string) {
  return `TARG-${createHash("sha256").update(`${sessionID}:${url}`).digest("hex").slice(0, 12).toUpperCase()}` as TargetID
}

function canonical(input: string) {
  const value = input.trim()
  if (!value) return ""
  if (value.includes("*") || value.includes("?")) return ""
  const raw = value.startsWith("http://") || value.startsWith("https://") ? value : `http://${value}`
  if (!URL.canParse(raw)) return ""
  const url = new URL(raw)
  if (url.protocol !== "http:" && url.protocol !== "https:") return ""
  return url.origin
}

export function persistEngagementTarget(input: {
  sessionID: SessionID
  url: string
  source: string
}) {
  const sessionID = canonicalSecuritySessionID(input.sessionID)
  const url = canonical(input.url)
  if (!url) return
  const scope = Scope.fromTargets(url).allowedPatterns
  Database.use((db) => {
    const session = db
      .select({
        id: SessionTable.id,
      })
      .from(SessionTable)
      .where(eq(SessionTable.id, sessionID))
      .get()
    if (!session) return
    const row = db
      .select({
        id: TargetTable.id,
      })
      .from(TargetTable)
      .where(and(eq(TargetTable.session_id, sessionID), eq(TargetTable.url, url)))
      .get()
    if (row) return
    db.insert(TargetTable).values({
      id: id(sessionID, url),
      session_id: sessionID,
      url,
      scope,
      notes: input.source,
    }).run()
  })
  return url
}
