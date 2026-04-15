/**
 * Tool: recon
 *
 * Composite reconnaissance tool. Orchestrates port scanning + service
 * probing + JS analysis. The first tool called in any assessment.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { runObserveSurfaceProfile } from "./observe-surface"

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
      always: [] as string[],
      metadata: { target: params.target } as Record<string, any>,
    })

    const profile = await runObserveSurfaceProfile(
      {
        target: params.target,
        sessionID: ctx.sessionID,
        modes: ["recon"],
        ports: params.ports,
        skip_js: params.skip_js,
      },
      {
        onStage: (title) => ctx.metadata({ title }),
      },
    )

    const host = profile.host
    const portResult = profile.recon?.port_scan
    if (!portResult) {
      return {
        title: `Recon: ${host} — 0 ports, 0 endpoints`,
        metadata: {
          openPorts: 0,
          secrets: 0,
          endpoints: 0,
        } as any,
        output: "No reconnaissance results.",
      }
    }

    const parts: string[] = []
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

    const openPorts = portResult.openPorts.map((item) => item.port)
    const probeResult = profile.recon?.service_probe
    const services = probeResult?.services ?? []
    if (services.length > 0) {
      parts.push("")
      parts.push(`── Service Detection (${probeResult?.elapsed ?? 0}ms) ──`)
      for (const service of services) {
        parts.push(`  ${service.port}: ${service.service} (${service.protocol})${service.banner ? ` — ${service.banner.slice(0, 80)}` : ""}`)
      }
    }

    const jsResult = profile.recon?.js_analysis
    if (jsResult) {
      if (jsResult.endpoints.length > 0) {
        parts.push("")
        parts.push(`── API Endpoints (${jsResult.endpoints.length}) ──`)
        for (const endpoint of jsResult.endpoints.slice(0, 20)) {
          parts.push(`  ${endpoint}`)
        }
        if (jsResult.endpoints.length > 20) parts.push(`  ... and ${jsResult.endpoints.length - 20} more`)
      }

      if (jsResult.secrets.length > 0) {
        parts.push("")
        parts.push("── ⚠ Secrets Found in JS ──")
        for (const secret of jsResult.secrets) {
          parts.push(`  [${secret.type}] ${secret.value.slice(0, 40)}... in ${secret.file}`)
        }
      }

      if (jsResult.spaRoutes.length > 0) {
        parts.push("")
        parts.push(`── SPA Routes (${jsResult.spaRoutes.length}) ──`)
        for (const route of jsResult.spaRoutes.slice(0, 15)) parts.push(`  ${route}`)
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
