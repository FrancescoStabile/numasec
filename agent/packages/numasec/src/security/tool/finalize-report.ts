import z from "zod"
import { Tool } from "../../tool/tool"
import { GenerateReportTool } from "./generate-report"
import { ReportStatusTool } from "./report-status"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Finalize reporting through the default closure-aware path.
Wraps report_status plus generate_report so the caller gets either a ready report or a structured blocker response in one tool call.`
const BLOCKED = "REPORT_BLOCKED_INCOMPLETE_STATE"

export const FinalizeReportTool = Tool.define("finalize_report", {
  description: DESCRIPTION,
  parameters: z.object({
    format: z.enum(["sarif", "markdown", "html"]).default("markdown").describe("Report format"),
    mode: z.enum(["working", "final"]).default("final").describe("working renders the current report state; final enforces closure readiness"),
    note: z.string().optional().describe("Optional operator note embedded in the rendered report"),
    output_path: z.string().optional().describe("Optional file path to write the generated report"),
    include_ids: z.boolean().optional().describe("Include open hypothesis ids and promotion gap ids in blocker output"),
  }),
  async execute(params, ctx) {
    const readiness = await (await ReportStatusTool.init()).execute(
      {
        include_ids: params.include_ids,
      } as never,
      ctx,
    )
    if (params.mode === "final" && (readiness.metadata as any).finalReady !== true) {
      return {
        title: "Final report blocked",
        metadata: {
          ...(readiness.metadata as any),
          blocked_code: BLOCKED,
          requestedMode: params.mode,
          nextAction: "Resolve the remaining closure debt or rerun finalize_report in working mode.",
        } as any,
        envelope: makeToolResultEnvelope({
          status: "inconclusive",
          observations: [
            {
              type: "report_finalize",
              blocked: true,
              blocked_code: BLOCKED,
              requested_mode: params.mode,
              state: String((readiness.metadata as any).state ?? ""),
            },
          ],
          metrics: {
            verified_findings: Number((readiness.metadata as any).projection?.verified ?? 0),
            provisional_findings: Number((readiness.metadata as any).closure?.provisional ?? 0),
            promotion_gaps: Number((readiness.metadata as any).projection?.promotion_gaps ?? 0),
            open_hypotheses: Number((readiness.metadata as any).closure?.hypothesis_open ?? 0),
          },
        }),
        output: JSON.stringify(
          {
            blocked: true,
            blocked_code: BLOCKED,
            requested_mode: params.mode,
            state: (readiness.metadata as any).state,
            truth_reasons: (readiness.metadata as any).truthReasons,
            closure: (readiness.metadata as any).closure,
            projection: (readiness.metadata as any).projection,
            promotion_gap_ids: (readiness.metadata as any).promotionGapIds,
            next_action: "Run finalize_report with mode=working for a working draft, or close the remaining readiness debt before mode=final.",
          },
          null,
          2,
        ),
      }
    }
    const report = await (await GenerateReportTool.init()).execute(
      {
        format: params.format,
        mode: params.mode,
        note: params.note,
        output_path: params.output_path,
      } as never,
      ctx,
    )
    return {
      title: report.title,
      metadata: {
        ...(report.metadata as any),
        readiness: readiness.metadata,
      } as any,
      envelope: report.envelope,
      output: report.output,
    }
  },
})
