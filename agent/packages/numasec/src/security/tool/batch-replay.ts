import z from "zod"
import { Effect } from "effect"
import { Tool } from "../../tool/tool"
import { httpRequest } from "../http-client"
import { EvidenceGraphStore } from "../evidence-store"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Replay a batch of HTTP requests for deterministic retest.
Useful for rerunning prior evidence steps and collecting reproducibility metrics.`

export const ReplayRequest = z.object({
  url: z.string(),
  method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]).optional(),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.string().optional(),
  cookies: z.string().optional(),
})

function createRunID() {
  const seed = `${Date.now()}-${Math.random()}`
  return `ERUN-${Bun.hash(seed).toString(16).slice(0, 12).toUpperCase()}`
}

export const BatchReplayTool = Tool.define("batch_replay", {
  description: DESCRIPTION,
  parameters: z.object({
    requests: z.array(ReplayRequest).min(1).max(100).describe("HTTP requests to replay"),
    timeout: z.number().min(1).max(120000).optional().describe("Per-request timeout in milliseconds"),
    stop_on_error: z.boolean().optional().describe("Stop replay at first network error"),
    planner_state: z.string().optional().describe("Planner state annotation"),
    hypothesis_id: z.string().optional().describe("Hypothesis id annotation"),
    run_id: z.string().optional().describe("Optional replay run id"),
    persist_artifacts: z.boolean().optional().describe("Persist replay request/response as artifact nodes"),
  }),
  async execute(params, ctx) {
    const urls = params.requests.map((item) => item.url)
    await ctx.ask({
      permission: "batch_replay",
      patterns: urls,
      always: [] as string[],
      metadata: {
        count: params.requests.length,
        urls,
      } as Record<string, any>,
    })

    const timeout = params.timeout ?? 15000
    const persist = params.persist_artifacts === true
    const runID = params.run_id ?? createRunID()
    const statuses: Array<{
      index: number
      url: string
      method: string
      status: number
      elapsed: number
      error?: string
      artifact_node_id?: string
    }> = []

    let attempts = 0
    for (let idx = 0; idx < params.requests.length; idx++) {
      attempts++
      const request = params.requests[idx]
      const method = request.method ?? "GET"
      let error = ""
      let status = 0
      let elapsed = 0
      let artifactNodeID = ""

      try {
        const response = await httpRequest(request.url, {
          method,
          headers: request.headers,
          body: request.body,
          cookies: request.cookies,
          timeout,
          sessionID: ctx.sessionID,
        })
        status = response.status
        elapsed = response.elapsed

        if (persist) {
          const row = Effect.runSync(
            EvidenceGraphStore.use((store) =>
              store.upsertNode({
                sessionID: ctx.sessionID,
                type: "artifact",
                status: "active",
                confidence: 0.9,
                sourceTool: "batch_replay",
                payload: {
                  run_id: runID,
                  request: {
                    url: request.url,
                    method,
                    headers: request.headers ?? {},
                    body: request.body ?? "",
                  },
                  response: {
                    status: response.status,
                    status_text: response.statusText,
                    headers: response.headers,
                    body: response.body.slice(0, 12000),
                    elapsed_ms: response.elapsed,
                  },
                },
              }),
            ).pipe(Effect.provide(EvidenceGraphStore.layer)),
          )
          artifactNodeID = row.id
        }
      } catch (cause) {
        error = cause instanceof Error ? cause.message : "replay request failed"
        if (params.stop_on_error) {
          statuses.push({
            index: idx,
            url: request.url,
            method,
            status,
            elapsed,
            error,
            artifact_node_id: artifactNodeID,
          })
          break
        }
      }

      statuses.push({
        index: idx,
        url: request.url,
        method,
        status,
        elapsed,
        error: error || undefined,
        artifact_node_id: artifactNodeID || undefined,
      })
    }

    const failures = statuses.filter((item) => item.error || item.status === 0).length
    const successes = statuses.length - failures
    const totalElapsed = statuses.reduce((sum, item) => sum + item.elapsed, 0)

    Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertRun({
          id: runID,
          sessionID: ctx.sessionID,
          plannerState: params.planner_state ?? "",
          hypothesisID: params.hypothesis_id ?? "",
          status: failures === 0 ? "ok" : successes === 0 ? "failed" : "partial",
          attempts,
          notes: {
            request_count: params.requests.length,
            replayed_count: statuses.length,
            success_count: successes,
            failure_count: failures,
            elapsed_ms: totalElapsed,
          },
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

    return {
      title: `Batch replay ${runID}: ${successes}/${statuses.length} ok`,
      metadata: {
        runID,
        replayed: statuses.length,
        success: successes,
        failed: failures,
        elapsed: totalElapsed,
      } as any,
      envelope: makeToolResultEnvelope({
        status: failures === 0 ? "ok" : successes === 0 ? "fatal_error" : "inconclusive",
        artifacts: [
          {
            type: "replay_run",
            run_id: runID,
            request_count: params.requests.length,
            replayed_count: statuses.length,
          },
        ],
        observations: statuses.map((item) => ({
          type: "replay_result",
          index: item.index,
          url: item.url,
          method: item.method,
          status: item.status,
          elapsed_ms: item.elapsed,
          error: item.error ?? "",
          artifact_node_id: item.artifact_node_id ?? "",
        })),
        metrics: {
          request_count: params.requests.length,
          replayed_count: statuses.length,
          success_count: successes,
          failure_count: failures,
          elapsed_ms: totalElapsed,
        },
      }),
      output: JSON.stringify(
        {
          run_id: runID,
          replayed: statuses.length,
          success_count: successes,
          failure_count: failures,
          results: statuses,
        },
        null,
        2,
      ),
    }
  },
})
