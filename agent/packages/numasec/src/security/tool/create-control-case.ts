import z from "zod"
import { Tool } from "../../tool/tool"
import { BatchReplayTool, ReplayRequest } from "./batch-replay"
import { makeToolResultEnvelope } from "./result-envelope"
import { VerificationAssertionInput, VerifyAssertionTool } from "./verify-assertion"

function readJson(input: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(input)
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) return parsed as Record<string, unknown>
  } catch {}
  return {}
}

function artifactNodeIDs(input: string) {
  const parsed = readJson(input)
  const results = Array.isArray(parsed.results) ? parsed.results : []
  const out: string[] = []
  for (const item of results) {
    if (!item || typeof item !== "object" || Array.isArray(item)) continue
    const value = (item as Record<string, unknown>).artifact_node_id
    if (typeof value !== "string" || !value) continue
    out.push(value)
  }
  return out
}

const DESCRIPTION = `Create and verify a reusable control case in one tool call.
Wraps batch_replay plus verify_assertion so control-case artifacts and the resulting verification node are returned together.`

export const CreateControlCaseTool = Tool.define("create_control_case", {
  description: DESCRIPTION,
  parameters: z.object({
    requests: z.array(ReplayRequest).min(1).max(100).describe("HTTP requests to replay for the control case"),
    assertion: VerificationAssertionInput.describe("Predicate or typed assertion to verify against the replayed artifacts"),
    hypothesis_id: z.string().optional().describe("Optional hypothesis node id to link from"),
    timeout: z.number().min(1).max(120000).optional().describe("Per-request timeout in milliseconds"),
    stop_on_error: z.boolean().optional().describe("Stop replay at first network error"),
    planner_state: z.string().optional().describe("Planner state annotation"),
    run_id: z.string().optional().describe("Optional replay run id"),
    persist_artifacts: z.boolean().optional().describe("Persist replay request/response as artifact nodes"),
  }),
  async execute(params, ctx) {
    const replay = await (await BatchReplayTool.init()).execute(
      {
        requests: params.requests,
        timeout: params.timeout,
        stop_on_error: params.stop_on_error,
        planner_state: params.planner_state,
        hypothesis_id: params.hypothesis_id,
        run_id: params.run_id,
        persist_artifacts: params.persist_artifacts ?? true,
      } as never,
      ctx,
    )
    const refs = artifactNodeIDs(replay.output)
    if (refs.length === 0) {
      throw new Error("create_control_case could not recover any artifact_node_id values from batch_replay. Re-run with persist_artifacts=true.")
    }
    const verify = await (await VerifyAssertionTool.init()).execute(
      {
        evidence_refs: refs,
        hypothesis_id: params.hypothesis_id,
        predicate: params.assertion.predicate,
        typed: params.assertion.typed,
        mode: params.assertion.mode,
        control: params.assertion.control ?? "negative",
        require_all: params.assertion.require_all,
        persist: true,
      } as never,
      ctx,
    )
    const replayBody = readJson(replay.output)
    const verifyBody = readJson(verify.output)
    const verificationNodeID = String((verify.metadata as any).verificationNodeID ?? verifyBody.verification_node_id ?? "")
    return {
      title: `Control case ${verifyBody.passed === true ? "passed" : "not passed"}`,
      metadata: {
        runID: String((replay.metadata as any).runID ?? replayBody.run_id ?? ""),
        artifactNodeIDs: refs,
        verificationNodeID,
        control: params.assertion.control ?? "negative",
        replay: replay.metadata,
        verification: verify.metadata,
      } as any,
      envelope: makeToolResultEnvelope({
        status: verifyBody.passed === true ? "ok" : "inconclusive",
        observations: [
          {
            type: "control_case",
            run_id: String((replay.metadata as any).runID ?? replayBody.run_id ?? ""),
            artifact_count: refs.length,
            verification_node_id: verificationNodeID,
            control: params.assertion.control ?? "negative",
            passed: verifyBody.passed === true,
          },
        ],
        metrics: {
          artifact_count: refs.length,
          checked: Number((verify.metadata as any).checked ?? verifyBody.checked ?? 0),
          matches: Number(verifyBody.matches ?? 0),
        },
      }),
      output: JSON.stringify(
        {
          run_id: String((replay.metadata as any).runID ?? replayBody.run_id ?? ""),
          artifact_node_ids: refs,
          verification_node_id: verificationNodeID,
          control: params.assertion.control ?? "negative",
          replay: replayBody,
          verification: verifyBody,
        },
        null,
        2,
      ),
    }
  },
})

