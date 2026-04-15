import z from "zod"
import { Database, and, eq } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { canonicalSecuritySessionID } from "../security-session"
import { FindingTable } from "../security.sql"
import { ReplayRequest } from "./batch-replay"
import { ConfirmFindingTool } from "./confirm-finding"
import { CreateControlCaseTool } from "./create-control-case"
import { VerificationAssertionInput } from "./verify-assertion"

function readJson(input: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(input)
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) return parsed as Record<string, unknown>
  } catch {}
  return {}
}

const DESCRIPTION = `Finalize a finding through the default closure path.
Wraps confirm_finding and can optionally create the missing negative control case before confirmation.`

export const FinalizeFindingTool = Tool.define("finalize_finding", {
  description: DESCRIPTION,
  parameters: z.object({
    finding_id: z.string().optional().describe("Optional existing finding id to finalize using stored title, severity, impact, and target context"),
    hypothesis_id: z.string().optional().describe("Hypothesis node id"),
    title: z.string().optional().describe("Finding title"),
    severity: z.string().optional().describe("Finding severity"),
    impact: z.string().optional().describe("Business or technical impact"),
    evidence_refs: z.array(z.string()).optional().describe("Optional positive verification refs"),
    negative_control_refs: z.array(z.string()).optional().describe("Optional negative control verification refs"),
    impact_refs: z.array(z.string()).optional().describe("Optional impact evidence refs"),
    lookback_limit: z.number().int().min(20).max(500).optional().describe("Recent evidence window for auto-suggestions"),
    confidence: z.number().min(0).max(1).optional(),
    status: z.string().optional(),
    target_finding_id: z.string().optional().describe("Optional existing finding id to update in place"),
    root_cause_key: z.string().optional().describe("Optional stable root cause key for update and dedup semantics"),
    strict_assertion: z.boolean().optional(),
    url: z.string().optional(),
    method: z.string().optional(),
    parameter: z.string().optional(),
    payload: z.string().optional(),
    remediation: z.string().optional(),
    taxonomy_tags: z.array(z.string()).optional(),
    tool_used: z.string().optional(),
    control_case: z
      .object({
        requests: z.array(ReplayRequest).min(1).max(100),
        assertion: VerificationAssertionInput,
        timeout: z.number().min(1).max(120000).optional(),
        stop_on_error: z.boolean().optional(),
        planner_state: z.string().optional(),
        run_id: z.string().optional(),
        persist_artifacts: z.boolean().optional(),
      })
      .optional()
      .describe("Optional negative control case to create before confirmation"),
  }),
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const existing = params.finding_id
      ? Database.use((db) =>
          db
            .select()
            .from(FindingTable)
            .where(and(eq(FindingTable.session_id, sessionID), eq(FindingTable.id, params.finding_id as any)))
            .get(),
        )
      : undefined
    if (params.finding_id && !existing) {
      throw new Error(`finalize_finding could not find ${params.finding_id} in the current session`)
    }
    const hypothesisID = params.hypothesis_id ?? existing?.source_hypothesis_id ?? ""
    if (!hypothesisID) {
      throw new Error("finalize_finding requires hypothesis_id or finding_id with a linked source_hypothesis_id")
    }
    const title = params.title ?? existing?.title ?? ""
    if (!title) {
      throw new Error("finalize_finding requires title or finding_id with a stored title")
    }
    const severity = params.severity ?? existing?.severity ?? ""
    if (!severity) {
      throw new Error("finalize_finding requires severity or finding_id with a stored severity")
    }
    const impact = params.impact ?? existing?.description ?? ""
    if (!impact) {
      throw new Error("finalize_finding requires impact or finding_id with a stored description")
    }
    const negative = Array.from(new Set(params.negative_control_refs ?? []))
    let controlCase: Record<string, unknown> | undefined
    if (params.control_case) {
      const control = params.control_case.assertion.control ?? "negative"
      if (control !== "negative") {
        throw new Error("finalize_finding control_case currently supports only negative controls")
      }
      const created = await (await CreateControlCaseTool.init()).execute(
        {
          requests: params.control_case.requests,
          assertion: {
            ...params.control_case.assertion,
            control,
          },
          hypothesis_id: hypothesisID,
          timeout: params.control_case.timeout,
          stop_on_error: params.control_case.stop_on_error,
          planner_state: params.control_case.planner_state,
          run_id: params.control_case.run_id,
          persist_artifacts: params.control_case.persist_artifacts ?? true,
        } as never,
        ctx,
      )
      controlCase = readJson(created.output)
      const verificationNodeID = String((created.metadata as any).verificationNodeID ?? controlCase.verification_node_id ?? "")
      if (!verificationNodeID) {
        throw new Error("finalize_finding control_case completed without a verification_node_id")
      }
      if (!negative.includes(verificationNodeID)) negative.push(verificationNodeID)
    }
    const confirm = await (await ConfirmFindingTool.init()).execute(
      {
        hypothesis_id: hypothesisID,
        title,
        severity,
        impact,
        evidence_refs: params.evidence_refs,
        negative_control_refs: negative,
        impact_refs: params.impact_refs,
        lookback_limit: params.lookback_limit,
        confidence: params.confidence,
        status: params.status,
        target_finding_id: params.target_finding_id ?? existing?.id,
        root_cause_key: params.root_cause_key ?? existing?.root_cause_key,
        strict_assertion: params.strict_assertion,
        url: params.url ?? existing?.url,
        method: params.method ?? existing?.method,
        parameter: params.parameter ?? existing?.parameter,
        payload: params.payload ?? existing?.payload,
        tool_used: params.tool_used ?? "finalize_finding",
        remediation: params.remediation ?? existing?.remediation_summary,
        taxonomy_tags: params.taxonomy_tags,
      } as never,
      ctx,
    )
    const body = readJson(confirm.output)
    const output = controlCase
      ? JSON.stringify(
          {
            ...body,
            control_case: controlCase,
          },
          null,
          2,
        )
      : confirm.output
    return {
      title: confirm.title,
      metadata: {
        ...(confirm.metadata as any),
        sourceFindingID: existing?.id ?? "",
        controlCase,
      } as any,
      envelope: confirm.envelope,
      output,
    }
  },
})
