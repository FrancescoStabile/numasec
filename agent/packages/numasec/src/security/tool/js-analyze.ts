/**
 * Tool: js_analyze
 *
 * JavaScript file analyzer tool wrapper.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { analyzeJs } from "../scanner/js-analyzer"

const DESCRIPTION = `Analyze JavaScript files on a web application to discover:
- API endpoints and hidden routes
- Secrets (API keys, tokens, credentials)
- Technologies and frameworks in use
- SPA routes (React/Angular/Vue)
- Chatbot/support widget indicators
- Source map files (which may leak source code)

NEXT STEPS with findings:
- Discovered API endpoints → test with injection_test
- Secrets found → validate and report
- SPA routes → test each route for auth issues
- Source maps → download and analyze for vulnerabilities`

export const JsAnalyzeTool = Tool.define("js_analyze", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("Target URL to analyze"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "js_analyze",
      patterns: [params.url],
      always: ["*"] as string[],
      metadata: { url: params.url } as Record<string, any>,
    })

    ctx.metadata({ title: `Analyzing JavaScript at ${params.url}...` })
    const result = await analyzeJs(params.url)

    const parts: string[] = [`── JS Analysis (${result.jsFiles.length} files, ${result.elapsed}ms) ──`]

    if (result.endpoints.length > 0) {
      parts.push(`\n── API Endpoints (${result.endpoints.length}) ──`)
      for (const ep of result.endpoints.slice(0, 30)) parts.push(`  ${ep}`)
      if (result.endpoints.length > 30) parts.push(`  ... +${result.endpoints.length - 30} more`)
    }

    if (result.secrets.length > 0) {
      parts.push(`\n── ⚠ Secrets Found ──`)
      for (const s of result.secrets) {
        parts.push(`  [${s.type}] ${s.value.slice(0, 50)} in ${s.file}`)
      }
    }

    if (result.spaRoutes.length > 0) {
      parts.push(`\n── SPA Routes (${result.spaRoutes.length}) ──`)
      for (const r of result.spaRoutes.slice(0, 20)) parts.push(`  ${r}`)
    }

    if (result.chatbotIndicators.length > 0) {
      parts.push(`\n── Chatbot Detected: ${result.chatbotIndicators.join(", ")} ──`)
    }

    return {
      title: `JS: ${result.endpoints.length} endpoints, ${result.secrets.length} secrets`,
      metadata: {
        endpoints: result.endpoints.length,
        secrets: result.secrets.length,
      } as any,
      output: parts.join("\n"),
    }
  },
})
