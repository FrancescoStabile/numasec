import { createHash } from "crypto"
import { eq } from "../../storage/db"
import type { SessionID } from "../../session/schema"
import { SessionTable } from "../../session/session.sql"
import { Database } from "../../storage/db"
import { canonicalSecuritySessionID } from "../security-session"
import {
  SecurityExecutionAttemptTable,
  type SecurityActorSessionID,
  type SecurityBrowserPageID,
  type SecurityBrowserSessionID,
  type SecurityExecutionAttemptID,
} from "./runtime.sql"

export interface ExecutionAttemptInput {
  sessionID: SessionID
  toolName: string
  action: string
  status: string
  errorCode?: string
  actorSessionID?: string
  browserSessionID?: string
  pageID?: string
  notes?: Record<string, unknown>
}

function id(input: ExecutionAttemptInput) {
  const sessionID = canonicalSecuritySessionID(input.sessionID)
  const value = [
    sessionID,
    input.toolName,
    input.action,
    input.status,
    input.errorCode ?? "",
    Date.now(),
    Math.random(),
  ].join(":")
  return `EATT-${createHash("sha256").update(value).digest("hex").slice(0, 12).toUpperCase()}` as SecurityExecutionAttemptID
}

export async function recordExecutionAttempt(input: ExecutionAttemptInput) {
  const sessionID = canonicalSecuritySessionID(input.sessionID)
  Database.use((db) => {
    const session = db
        .select({
          id: SessionTable.id,
        })
        .from(SessionTable)
        .where(eq(SessionTable.id, sessionID))
        .get()
    if (!session) return
    db
      .insert(SecurityExecutionAttemptTable)
      .values({
        id: id(input),
        session_id: sessionID,
        actor_session_id: input.actorSessionID as SecurityActorSessionID | undefined,
        browser_session_id: input.browserSessionID as SecurityBrowserSessionID | undefined,
        page_id: input.pageID as SecurityBrowserPageID | undefined,
        tool_name: input.toolName,
        action: input.action,
        status: input.status,
        error_code: input.errorCode ?? "",
        notes: input.notes ?? {},
      })
      .run()
  })
}
