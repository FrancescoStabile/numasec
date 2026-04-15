/**
 * Scanner: race condition tester
 *
 * Sends N identical requests simultaneously to detect TOCTOU flaws,
 * double-spend bugs, and state inconsistencies.
 */

import { httpRequest, type HttpRequestOptions } from "../http-client"
import type { SessionID } from "../../session/schema"

export interface RaceResult {
  vulnerable: boolean
  evidence: string
  responses: RaceResponse[]
  uniqueStatuses: number[]
  uniqueLengths: number[]
  elapsed: number
}

export interface RaceResponse {
  index: number
  status: number
  bodyLength: number
  bodySnippet: string
  elapsed: number
}

/**
 * Send N identical requests in parallel and analyze for inconsistencies.
 */
export async function testRaceCondition(
  url: string,
  options: {
    method?: string
    headers?: Record<string, string>
    body?: string
    cookies?: string
    count?: number
    timeout?: number
    sessionID?: SessionID | string
  } = {},
): Promise<RaceResult> {
  const { method = "POST", headers = {}, body, cookies, count = 10, timeout = 15_000, sessionID } = options
  const start = Date.now()

  const reqOptions: HttpRequestOptions = {
    method,
    headers,
    body,
    cookies,
    timeout,
    followRedirects: true,
    sessionID,
  }

  // Fire all requests simultaneously
  const promises = Array.from({ length: count }, (_, i) =>
    httpRequest(url, reqOptions).then((resp) => ({
      index: i,
      status: resp.status,
      bodyLength: resp.body.length,
      bodySnippet: resp.body.slice(0, 200),
      elapsed: resp.elapsed,
    })),
  )

  const responses = await Promise.all(promises)
  const elapsed = Date.now() - start

  // Analyze for inconsistencies
  const uniqueStatuses = [...new Set(responses.map((r) => r.status))]
  const uniqueLengths = [...new Set(responses.map((r) => r.bodyLength))]

  let vulnerable = false
  const evidenceParts: string[] = []

  // Different status codes suggest race condition
  if (uniqueStatuses.length > 1) {
    vulnerable = true
    evidenceParts.push(
      `Multiple status codes returned: ${uniqueStatuses.join(", ")} — indicates inconsistent state handling`,
    )
  }

  // Significantly different response lengths
  const lengths = responses.map((r) => r.bodyLength)
  const minLen = Math.min(...lengths)
  const maxLen = Math.max(...lengths)
  if (maxLen > 0 && (maxLen - minLen) / maxLen > 0.3) {
    vulnerable = true
    evidenceParts.push(
      `Response lengths vary significantly: min=${minLen}, max=${maxLen} — suggests different execution paths`,
    )
  }

  // Check for success responses that should have been rate-limited or rejected
  const successCount = responses.filter((r) => r.status >= 200 && r.status < 300).length
  if (successCount > 1 && method === "POST") {
    evidenceParts.push(
      `${successCount}/${count} requests returned success — potential double-processing vulnerability`,
    )
    if (successCount === count) vulnerable = true
  }

  return {
    vulnerable,
    evidence: evidenceParts.join("\n") || "No race condition indicators detected.",
    responses,
    uniqueStatuses,
    uniqueLengths,
    elapsed,
  }
}
