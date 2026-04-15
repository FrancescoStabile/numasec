import type { SessionID } from "../session/schema"
import { SessionTable } from "../session/session.sql"
import { Database, eq } from "../storage/db"

function cycleSessionID(sessionID: SessionID): SessionID {
  const rows = Database.use((db) =>
    db
      .select({
        id: SessionTable.id,
        parentID: SessionTable.parent_id,
      })
      .from(SessionTable)
      .all(),
  )
  const graph = new Map<SessionID, Set<SessionID>>()
  for (const row of rows) {
    const node = graph.get(row.id) ?? new Set<SessionID>()
    graph.set(row.id, node)
    if (!row.parentID) continue
    node.add(row.parentID)
    const parent = graph.get(row.parentID) ?? new Set<SessionID>()
    parent.add(row.id)
    graph.set(row.parentID, parent)
  }
  const todo = [sessionID]
  const list = new Set<SessionID>()
  while (todo.length > 0) {
    const item = todo.pop()
    if (!item || list.has(item)) continue
    list.add(item)
    const next = graph.get(item)
    if (!next) continue
    for (const value of next) {
      if (list.has(value)) continue
      todo.push(value)
    }
  }
  const ids = [...list].sort()
  if (ids.length > 0) return ids[0] as SessionID
  return sessionID
}

export function canonicalSecuritySessionID(sessionID: SessionID): SessionID {
  const seen = new Set<string>()
  let current = sessionID
  while (!seen.has(current)) {
    seen.add(current)
    const row = Database.use((db) =>
      db
        .select({
          parentID: SessionTable.parent_id,
        })
        .from(SessionTable)
        .where(eq(SessionTable.id, current))
        .get(),
    )
    if (!row?.parentID) return current
    current = row.parentID
  }
  return cycleSessionID(sessionID)
}
