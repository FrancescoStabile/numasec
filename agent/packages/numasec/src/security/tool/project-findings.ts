import z from "zod"
import { Tool } from "../../tool/tool"
import { projectFindings } from "../finding-projector"
import { canonicalSecuritySessionID } from "../security-session"
import { makeToolResultEnvelope } from "./result-envelope"

export const ProjectFindingsTool = Tool.define("project_findings", {
  description: "Project deterministic findings from graph evidence and manual overrides.",
  parameters: z.object({}),
  async execute(_, ctx) {
    const result = projectFindings(canonicalSecuritySessionID(ctx.sessionID))
    return {
      title: `Projected findings: ${result.counts.raw}`,
      metadata: result.counts as any,
      envelope: makeToolResultEnvelope({
        status: result.counts.promotion_gaps > 0 ? "inconclusive" : "ok",
        observations: [
          {
            type: "finding_projection",
            raw: result.counts.raw,
            verified: result.counts.verified,
            provisional: result.counts.provisional,
            suppressed: result.counts.suppressed,
            refuted: result.counts.refuted,
            promotion_gaps: result.counts.promotion_gaps,
          },
        ],
        metrics: result.counts,
      }),
      output: [
        `Raw: ${result.counts.raw}`,
        `Verified: ${result.counts.verified}`,
        `Provisional: ${result.counts.provisional}`,
        `Suppressed: ${result.counts.suppressed}`,
        `Refuted: ${result.counts.refuted}`,
        `Reportable: ${result.counts.reportable}`,
        `Promotion gaps: ${result.counts.promotion_gaps}`,
      ].join("\n"),
    }
  },
})
