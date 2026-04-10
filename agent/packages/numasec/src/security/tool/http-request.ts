/**
 * Tool: http_request
 *
 * Raw HTTP request tool for security testing. Full control over method,
 * headers, body, cookies.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { httpRequest } from "../http-client"

const DESCRIPTION = `Make an HTTP request to a target URL. Use for:
- Sending crafted requests during security testing
- Testing specific endpoints with custom headers/body
- Verifying vulnerabilities with proof-of-concept payloads
- Checking server responses to malformed input

Returns: status code, headers, body, redirect chain, elapsed time.`

export const HttpRequestTool = Tool.define("http_request", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("The URL to request"),
    method: z
      .enum(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
      .default("GET")
      .describe("HTTP method"),
    headers: z.record(z.string(), z.string()).optional().describe("Request headers as key-value pairs"),
    body: z.string().optional().describe("Request body (for POST/PUT/PATCH)"),
    cookies: z.string().optional().describe("Cookie header value"),
    timeout: z.number().optional().describe("Timeout in milliseconds (default 15000)"),
    follow_redirects: z.boolean().optional().describe("Follow redirects (default true)"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "http_request",
      patterns: [params.url],
      always: ["*"] as string[],
      metadata: { url: params.url, method: params.method } as Record<string, any>,
    })

    const response = await httpRequest(params.url, {
      method: params.method,
      headers: params.headers,
      body: params.body,
      cookies: params.cookies,
      timeout: params.timeout,
      followRedirects: params.follow_redirects,
    })

    const headerLines = Object.entries(response.headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n")

    const bodyPreview = response.body.length > 8000
      ? response.body.slice(0, 8000) + `\n... (truncated, ${response.body.length} bytes total)`
      : response.body

    const output = [
      `HTTP ${response.status} ${response.statusText}`,
      `URL: ${response.url}`,
      `Elapsed: ${response.elapsed}ms`,
      response.redirectChain.length > 0 ? `Redirect chain: ${response.redirectChain.join(" → ")} → ${response.url}` : "",
      "",
      "── Response Headers ──",
      headerLines,
      "",
      "── Response Body ──",
      bodyPreview,
    ]
      .filter(Boolean)
      .join("\n")

    return {
      title: `${params.method} ${params.url} → ${response.status}`,
      metadata: {
        status: response.status,
        elapsed: response.elapsed,
        contentLength: response.body.length,
        redirects: response.redirectChain.length,
      },
      output,
    }
  },
})
