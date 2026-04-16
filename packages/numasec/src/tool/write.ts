import z from "zod"
import * as path from "path"
import { Effect } from "effect"
import * as Tool from "./tool"
import { createTwoFilesPatch } from "diff"
import DESCRIPTION from "./write.txt"
import { Bus } from "../bus"
import { File } from "../file"
import { FileWatcher } from "../file/watcher"
import { Format } from "../format"
import { FileTime } from "../file/time"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Instance } from "../project/instance"
import { trimDiff } from "./edit"
import { assertExternalDirectoryEffect } from "./external-directory"

export const WriteTool = Tool.define(
  "write",
  Effect.gen(function* () {
    const fs = yield* AppFileSystem.Service
    const filetime = yield* FileTime.Service
    const bus = yield* Bus.Service
    const format = yield* Format.Service

    return {
      description: DESCRIPTION,
      parameters: z.object({
        content: z.string().describe("The content to write to the file"),
        filePath: z.string().describe("The absolute path to the file to write (must be absolute, not relative)"),
      }),
      execute: (params: { content: string; filePath: string }, ctx: Tool.Context) =>
        Effect.gen(function* () {
          const filepath = path.isAbsolute(params.filePath)
            ? params.filePath
            : path.join(Instance.directory, params.filePath)
          yield* assertExternalDirectoryEffect(ctx, filepath)

          const exists = yield* fs.existsSafe(filepath)
          const contentOld = exists ? yield* fs.readFileString(filepath) : ""
          if (exists) yield* filetime.assert(ctx.sessionID, filepath)

          const diff = trimDiff(createTwoFilesPatch(filepath, filepath, contentOld, params.content))
          yield* ctx.ask({
            permission: "edit",
            patterns: [path.relative(Instance.worktree, filepath)],
            always: ["*"],
            metadata: {
              filepath,
              diff,
            },
          })

          yield* fs.writeWithDirs(filepath, params.content)
          yield* format.file(filepath)
          yield* bus.publish(File.Event.Edited, { file: filepath })
          yield* bus.publish(FileWatcher.Event.Updated, {
            file: filepath,
            event: exists ? "change" : "add",
          })
          yield* filetime.read(ctx.sessionID, filepath)

          const output = "Wrote file successfully."

          return {
            title: path.relative(Instance.worktree, filepath),
            metadata: {
              filepath,
              exists: exists,
            },
            output,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
