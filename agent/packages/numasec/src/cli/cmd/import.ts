import type { Argv } from "yargs"
import type { Session as SDKSession, Message, Part } from "@numasec/sdk/v2"
import { Session } from "../../session"
import { MessageV2 } from "../../session/message-v2"
import { cmd } from "./cmd"
import { bootstrap } from "../bootstrap"
import { Database } from "../../storage/db"
import { SessionTable, MessageTable, PartTable } from "../../session/session.sql"
import { Instance } from "../../project/instance"
import { EOL } from "os"
import { Filesystem } from "../../util/filesystem"

export const ImportCommand = cmd({
  command: "import <file>",
  describe: "import session data from a local JSON file",
  builder: (yargs: Argv) => {
    return yargs.positional("file", {
      describe: "path to a local JSON file",
      type: "string",
      demandOption: true,
    })
  },
  handler: async (args) => {
    await bootstrap(process.cwd(), async () => {
      let exportData:
        | {
            info: SDKSession
            messages: Array<{
              info: Message
              parts: Part[]
            }>
          }
        | undefined

      if (args.file.startsWith("http://") || args.file.startsWith("https://")) {
        process.stdout.write("Importing remote share URLs is no longer supported in local-first numasec builds.")
        process.stdout.write(EOL)
        process.stdout.write("Export the session to a local JSON file and import that file instead.")
        process.stdout.write(EOL)
        return
      }

      exportData = await Filesystem.readJson<NonNullable<typeof exportData>>(args.file).catch(() => undefined)
      if (!exportData) {
        process.stdout.write(`File not found: ${args.file}`)
        process.stdout.write(EOL)
        return
      }

      if (!exportData) {
        process.stdout.write(`Failed to read session data`)
        process.stdout.write(EOL)
        return
      }

      const info = Session.Info.parse({
        ...exportData.info,
        projectID: Instance.project.id,
      })
      const row = Session.toRow(info)
      Database.use((db) =>
        db
          .insert(SessionTable)
          .values(row)
          .onConflictDoUpdate({ target: SessionTable.id, set: { project_id: row.project_id } })
          .run(),
      )

      for (const msg of exportData.messages) {
        const msgInfo = MessageV2.Info.parse(msg.info)
        const { id, sessionID: _, ...msgData } = msgInfo
        Database.use((db) =>
          db
            .insert(MessageTable)
            .values({
              id,
              session_id: row.id,
              time_created: msgInfo.time?.created ?? Date.now(),
              data: msgData,
            })
            .onConflictDoNothing()
            .run(),
        )

        for (const part of msg.parts) {
          const partInfo = MessageV2.Part.parse(part)
          const { id: partId, sessionID: _s, messageID, ...partData } = partInfo
          Database.use((db) =>
            db
              .insert(PartTable)
              .values({
                id: partId,
                message_id: messageID,
                session_id: row.id,
                data: partData,
              })
              .onConflictDoNothing()
              .run(),
          )
        }
      }

      process.stdout.write(`Imported session: ${exportData.info.id}`)
      process.stdout.write(EOL)
    })
  },
})
