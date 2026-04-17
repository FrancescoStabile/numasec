import { Instance } from "@/project/instance"
import { Session } from "@/session"
import { SessionID } from "@/session/schema"
import { NotFoundError } from "@/storage/db"

export async function assertCurrentProjectSession(sessionID: SessionID) {
  const session = await Session.get(sessionID)
  if (session.projectID === Instance.project.id) return session
  throw new NotFoundError({ message: `Session not found: ${sessionID}` })
}
