import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import { Doctor } from "../core/doctor"
import type { DoctorReport } from "../core/doctor"
import DESCRIPTION from "./doctor.txt"
import { Cyber } from "@/core/cyber"
import { Instance } from "@/project/instance"

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

export const persistDoctorProjection = Effect.fn("Doctor.persistDoctorProjection")(function* (input: {
  report: DoctorReport
  eventID?: string
}) {
  const present = input.report.binaries.filter((b) => b.present).length
  const plays_ready = input.report.capability.plays.filter((item) => item.status === "ready").length
  const verticals_ready = input.report.capability.verticals.filter((item) => item.status === "ready").length

  yield* Cyber.upsertFact({
    entity_kind: "environment",
    entity_key: "local",
    fact_name: "doctor_summary",
    value_json: {
      runtime: input.report.runtime,
      os: input.report.os,
      browser: input.report.browser,
      vault: input.report.vault,
      cve: input.report.cve,
      workspace: input.report.workspace,
      tools_present: present,
      tools_total: input.report.binaries.length,
      plays_ready,
      plays_total: input.report.capability.plays.length,
      verticals_ready,
      verticals_total: input.report.capability.verticals.length,
    },
    writer_kind: "tool",
    status: "observed",
    confidence: 1000,
    source_event_id: input.eventID || undefined,
  }).pipe(Effect.catch(() => Effect.succeed("")))

  for (const binary of input.report.binaries) {
    yield* Cyber.upsertFact({
      entity_kind: "tool_adapter",
      entity_key: binary.name,
      fact_name: "presence",
      value_json: binary,
      writer_kind: "tool",
      status: binary.present ? "observed" : "stale",
      confidence: 1000,
      source_event_id: input.eventID || undefined,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertRelation({
      src_kind: "environment",
      src_key: "local",
      relation: binary.present ? "has_tool" : "missing_tool",
      dst_kind: "tool_adapter",
      dst_key: binary.name,
      writer_kind: "tool",
      status: binary.present ? "observed" : "stale",
      confidence: 1000,
      source_event_id: input.eventID || undefined,
    }).pipe(Effect.catch(() => Effect.succeed("")))
  }

  for (const item of input.report.capability.plays) {
    yield* Cyber.upsertFact({
      entity_kind: "play",
      entity_key: item.id,
      fact_name: "readiness",
      value_json: item,
      writer_kind: "tool",
      status: item.status === "unavailable" ? "stale" : "observed",
      confidence: 1000,
      source_event_id: input.eventID || undefined,
    }).pipe(Effect.catch(() => Effect.succeed("")))
  }

  for (const item of input.report.capability.verticals) {
    yield* Cyber.upsertFact({
      entity_kind: "vertical",
      entity_key: item.id,
      fact_name: "readiness",
      value_json: item,
      writer_kind: "tool",
      status: item.status === "unavailable" ? "stale" : "observed",
      confidence: 1000,
      source_event_id: input.eventID || undefined,
    }).pipe(Effect.catch(() => Effect.succeed("")))
  }
})

export const DoctorTool = Tool.define<typeof parameters, Metadata, never>(
  "doctor",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (_args: z.infer<typeof parameters>, _ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const report = yield* Doctor.probe(Instance.directory)
          const present = report.binaries.filter((b) => b.present).length
          const plays_ready = report.capability.plays.filter((item) => item.status === "ready").length
          const verticals_ready = report.capability.verticals.filter((item) => item.status === "ready").length
          const eventID = yield* Cyber.appendLedger({
            kind: "fact.observed",
            source: "doctor",
            session_id: _ctx.sessionID,
            message_id: _ctx.messageID,
            summary: `doctor ${present}/${report.binaries.length} tools ready`,
            data: {
              tools_present: present,
              tools_total: report.binaries.length,
              browser_present: report.browser.present,
              plays_ready,
              plays_total: report.capability.plays.length,
              verticals_ready,
              verticals_total: report.capability.verticals.length,
              workspace_writable: report.workspace.writable,
              vault_present: report.vault.present,
              cve_present: report.cve.present,
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* persistDoctorProjection({ report, eventID })
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
