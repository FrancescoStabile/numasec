/**
 * Tool: race_test
 *
 * Race condition testing.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { testRaceCondition } from "../scanner/race-tester"

const DESCRIPTION = `Test for race condition / TOCTOU vulnerabilities.
Sends multiple identical requests simultaneously to detect state inconsistencies.

Common targets: coupon/discount redemption, fund transfers, vote systems,
OTP verification, account creation with unique constraints.

CHAIN POTENTIAL: Race conditions enable:
- Double spending / multiple redemptions
- Bypassing rate limits
- Creating duplicate resources that bypass uniqueness checks`

export const RaceTestTool = Tool.define("race_test", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("Target URL"),
    method: z.enum(["GET", "POST", "PUT", "DELETE"]).default("POST"),
    body: z.string().optional().describe("Request body"),
    headers: z.record(z.string(), z.string()).optional().describe("Headers"),
    cookies: z.string().optional().describe("Cookies"),
    concurrency: z.number().optional().describe("Number of simultaneous requests (default 10)"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "race_test",
      patterns: [params.url],
      always: [] as string[],
      metadata: { url: params.url, concurrency: params.concurrency ?? 10 } as Record<string, any>,
    })

    ctx.metadata({ title: `Testing race condition (${params.concurrency ?? 10} concurrent)...` })
    const result = await testRaceCondition(params.url, {
      method: params.method,
      body: params.body,
      headers: params.headers,
      cookies: params.cookies,
      count: params.concurrency,
      sessionID: ctx.sessionID,
    })

    const parts: string[] = [`── Race Condition Test (${result.responses.length} requests, ${result.elapsed}ms) ──`]
    parts.push(`Unique statuses: ${result.uniqueStatuses.join(", ")}`)
    parts.push(`Unique response lengths: ${result.uniqueLengths.length}`)

    if (result.vulnerable) {
      parts.push("")
      parts.push("⚠ RACE CONDITION DETECTED")
      parts.push(`Evidence: ${result.evidence}`)
      parts.push("")
      parts.push("Indicators of race condition:")
      parts.push("- Multiple success responses to idempotent operation")
      parts.push("- Varying response content suggests inconsistent state")
    } else {
      parts.push("")
      parts.push("No race condition detected — responses are consistent.")
    }

    return {
      title: result.vulnerable ? "⚠ Race condition detected" : "No race condition",
      metadata: { detected: result.vulnerable, requests: result.responses.length } as any,
      output: parts.join("\n"),
    }
  },
})
