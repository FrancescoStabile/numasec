import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import { Doctor } from "../core/doctor"
import DESCRIPTION from "./doctor.txt"

const parameters = z.object({})

type Metadata = {
  tools_present: number
  tools_total: number
  vault_present: boolean
  workspace_writable: boolean
  plays_ready: number
  plays_total: number
  verticals_ready: number
  verticals_total: number
  browser_present: boolean
}

export const DoctorTool = Tool.define<typeof parameters, Metadata, never>(
  "doctor",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (_args: z.infer<typeof parameters>, _ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const report = yield* Doctor.probe(process.cwd())
          const present = report.binaries.filter((b) => b.present).length
          const plays_ready = report.capability.plays.filter((item) => item.status === "ready").length
          const verticals_ready = report.capability.verticals.filter((item) => item.status === "ready").length
          return {
            title: `doctor · ${present}/${report.binaries.length} tools`,
            output: Doctor.format(report),
            metadata: {
              tools_present: present,
              tools_total: report.binaries.length,
              vault_present: report.vault.present,
              workspace_writable: report.workspace.writable,
              plays_ready,
              plays_total: report.capability.plays.length,
              verticals_ready,
              verticals_total: report.capability.verticals.length,
              browser_present: report.browser.present,
            },
          }
        }).pipe(Effect.orDie),
    }
  }),
)
