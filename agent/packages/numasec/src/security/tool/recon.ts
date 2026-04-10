/**
 * Tool: recon
 *
 * Composite reconnaissance tool. Orchestrates port scanning + service
 * probing + JS analysis. The first tool called in any assessment.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { scanPorts } from "../scanner/port-scanner"
import { probeServices } from "../scanner/service-prober"
import { analyzeJs } from "../scanner/js-analyzer"

const DESCRIPTION = `Run reconnaissance on a target. This is typically the FIRST tool to call.
Performs: port scanning, service detection, technology fingerprinting, JS analysis.

Returns: open ports, detected services, technologies, API endpoints, secrets found in JS.

NEXT STEPS after recon:
- If web ports found (80/443/8080): run crawl to discover endpoints
- If API detected: test for injection, auth issues
- If GraphQL found: run graphql-specific tests
- If secrets found in JS: validate them immediately
- If JWT detected: run auth_test for JWT analysis`

export const ReconTool = Tool.define("recon", {
  description: DESCRIPTION,
  parameters: z.object({
    target: z.string().describe("Target hostname or URL"),
    ports: z.array(z.number()).optional().describe("Specific ports to scan (default: top 30)"),
    skip_js: z.boolean().optional().describe("Skip JS analysis (faster)"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "recon",
      patterns: [params.target],
      always: ["*"] as string[],
      metadata: { target: params.target } as Record<string, any>,
    })

    const parts: string[] = []
    const host = params.target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0]

    // Port scan
    ctx.metadata({ title: `Scanning ports on ${host}...` })
    const portResult = await scanPorts(host, { ports: params.ports })
    parts.push(`── Port Scan (${portResult.elapsed}ms) ──`)
    if (portResult.openPorts.length === 0) {
      parts.push("No open ports found.")
    } else {
      for (const p of portResult.openPorts) {
        const svc = p.service ? ` (${p.service})` : ""
        const ver = p.version ? ` — ${p.version.slice(0, 80)}` : ""
        parts.push(`  ${p.port}/tcp open${svc}${ver}`)
      }
    }

    // Service probing on open ports
    const openPorts = portResult.openPorts.map((p) => p.port)
    let services: { port: number; protocol: string; service: string; banner?: string }[] = []
    if (openPorts.length > 0) {
      ctx.metadata({ title: `Probing ${openPorts.length} services...` })
      const probeResult = await probeServices(host, openPorts)
      services = probeResult.services
      if (services.length > 0) {
        parts.push("")
        parts.push(`── Service Detection (${probeResult.elapsed}ms) ──`)
        for (const s of services) {
          parts.push(`  ${s.port}: ${s.service} (${s.protocol})${s.banner ? ` — ${s.banner.slice(0, 80)}` : ""}`)
        }
      }
    }

    // JS analysis on web ports
    let jsResult: Awaited<ReturnType<typeof analyzeJs>> | undefined
    const webPorts = openPorts.filter((p) => [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090].includes(p))
    if (!params.skip_js && (webPorts.length > 0 || params.target.startsWith("http"))) {
      const targetUrl = params.target.startsWith("http") ? params.target : `http://${host}:${webPorts[0] || 80}`
      ctx.metadata({ title: "Analyzing JavaScript..." })
      jsResult = await analyzeJs(targetUrl)

      if (jsResult.endpoints.length > 0) {
        parts.push("")
        parts.push(`── API Endpoints (${jsResult.endpoints.length}) ──`)
        for (const ep of jsResult.endpoints.slice(0, 20)) {
          parts.push(`  ${ep}`)
        }
        if (jsResult.endpoints.length > 20) parts.push(`  ... and ${jsResult.endpoints.length - 20} more`)
      }

      if (jsResult.secrets.length > 0) {
        parts.push("")
        parts.push("── ⚠ Secrets Found in JS ──")
        for (const s of jsResult.secrets) {
          parts.push(`  [${s.type}] ${s.value.slice(0, 40)}... in ${s.file}`)
        }
      }

      if (jsResult.spaRoutes.length > 0) {
        parts.push("")
        parts.push(`── SPA Routes (${jsResult.spaRoutes.length}) ──`)
        for (const r of jsResult.spaRoutes.slice(0, 15)) parts.push(`  ${r}`)
      }

      if (jsResult.chatbotIndicators.length > 0) {
        parts.push("")
        parts.push(`── Chatbot Detected: ${jsResult.chatbotIndicators.join(", ")} ──`)
      }
    }

    return {
      title: `Recon: ${host} — ${portResult.openPorts.length} ports, ${jsResult?.endpoints.length ?? 0} endpoints`,
      metadata: {
        openPorts: openPorts.length,
        secrets: jsResult?.secrets.length ?? 0,
        endpoints: jsResult?.endpoints.length ?? 0,
      } as any,
      output: parts.join("\n"),
    }
  },
})
