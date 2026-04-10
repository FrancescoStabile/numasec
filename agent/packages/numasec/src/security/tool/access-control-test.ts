/**
 * Tool: access_control_test
 *
 * Tests for IDOR, CSRF, CORS misconfigurations, and mass assignment.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { httpRequest } from "../http-client"

const DESCRIPTION = `Test for access control vulnerabilities:
- IDOR: change resource IDs to access other users' data
- CSRF: check for missing anti-CSRF protections
- CORS: test for permissive cross-origin policies
- Mass Assignment: send extra fields to modify protected attributes

Requires: target URL. For IDOR, also provide the parameter with the resource ID.

CHAIN POTENTIAL:
- IDOR → data leak of all users' data
- CORS misconfiguration → cross-site data theft via victim's browser
- CSRF + IDOR → modify other users' data from attacker's site
- Mass assignment → privilege escalation (role: "admin")`

export const AccessControlTestTool = Tool.define("access_control_test", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("Target URL"),
    test_type: z
      .enum(["idor", "csrf", "cors", "mass_assignment", "all"])
      .default("all")
      .describe("Specific test type or all"),
    parameter: z.string().optional().describe("Parameter with resource ID (for IDOR)"),
    method: z.enum(["GET", "POST", "PUT", "DELETE"]).optional().describe("HTTP method"),
    headers: z.record(z.string(), z.string()).optional().describe("Headers including auth"),
    cookies: z.string().optional().describe("Cookies"),
    body: z.string().optional().describe("Request body"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "access_control_test",
      patterns: [params.url],
      always: ["*"] as string[],
      metadata: { url: params.url, test_type: params.test_type } as Record<string, any>,
    })

    const tests = params.test_type === "all" ? ["idor", "csrf", "cors", "mass_assignment"] : [params.test_type]
    const parts: string[] = []
    let totalFindings = 0

    // CORS test
    if (tests.includes("cors")) {
      ctx.metadata({ title: "Testing CORS..." })
      const origins = ["https://evil.com", "null", "https://evil." + new URL(params.url).hostname]

      for (const origin of origins) {
        const resp = await httpRequest(params.url, {
          method: "GET",
          headers: { ...params.headers, Origin: origin },
          cookies: params.cookies,
        })

        const acao = resp.headers["access-control-allow-origin"]
        const acac = resp.headers["access-control-allow-credentials"]

        if (acao && (acao === "*" || acao === origin)) {
          parts.push(`\n── ⚠ CORS Misconfiguration ──`)
          parts.push(`  Origin: ${origin}`)
          parts.push(`  Access-Control-Allow-Origin: ${acao}`)
          parts.push(`  Access-Control-Allow-Credentials: ${acac ?? "not set"}`)
          if (acac === "true") {
            parts.push(`  ⚠ CRITICAL: Credentials allowed with reflected origin!`)
          }
          totalFindings++
        }
      }
      if (!parts.some((l) => l.includes("CORS"))) {
        parts.push("\n── CORS: properly configured ──")
      }
    }

    // CSRF test
    if (tests.includes("csrf")) {
      ctx.metadata({ title: "Testing CSRF..." })
      const method = params.method ?? "POST"

      if (["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
        // Send request without CSRF token
        const resp = await httpRequest(params.url, {
          method,
          headers: {
            ...params.headers,
            "Content-Type": "application/x-www-form-urlencoded",
            Referer: "https://evil.com",
            Origin: "https://evil.com",
          },
          body: params.body ?? "test=1",
          cookies: params.cookies,
        })

        if (resp.status >= 200 && resp.status < 400) {
          parts.push(`\n── ⚠ Potential CSRF ──`)
          parts.push(`  ${method} ${params.url} accepted cross-origin request`)
          parts.push(`  Status: ${resp.status}`)
          parts.push(`  No CSRF token validation detected`)
          totalFindings++
        } else {
          parts.push(`\n── CSRF: ${method} request rejected (status ${resp.status}) ──`)
        }
      } else {
        parts.push("\n── CSRF: GET requests not vulnerable by design ──")
      }
    }

    // IDOR test
    if (tests.includes("idor") && params.parameter) {
      ctx.metadata({ title: `Testing IDOR on ${params.parameter}...` })

      // Try to enumerate other IDs
      const testIds = ["1", "2", "0", "999999", "-1", "admin", "test"]
      const baseUrl = new URL(params.url)
      let idorFindings = 0

      for (const id of testIds) {
        const testUrl = new URL(params.url)
        testUrl.searchParams.set(params.parameter, id)

        const resp = await httpRequest(testUrl.toString(), {
          method: params.method ?? "GET",
          headers: params.headers,
          cookies: params.cookies,
        })

        if (resp.status === 200 && resp.body.length > 100) {
          idorFindings++
          parts.push(`  ID ${id}: ${resp.status} (${resp.body.length} bytes)`)
        }
      }

      if (idorFindings > 1) {
        parts.push(`\n── ⚠ IDOR: ${idorFindings} different IDs returned data ──`)
        parts.push(`  Parameter: ${params.parameter}`)
        totalFindings++
      } else {
        parts.push(`\n── IDOR: no enumeration detected on ${params.parameter} ──`)
      }
    }

    // Mass assignment test
    if (tests.includes("mass_assignment")) {
      ctx.metadata({ title: "Testing mass assignment..." })
      const extraFields = ["role", "admin", "is_admin", "isAdmin", "privilege", "status", "verified", "active"]

      const baseBody = params.body ? JSON.parse(params.body) : {}
      for (const field of extraFields) {
        const testBody = { ...baseBody, [field]: field === "role" ? "admin" : true }
        const resp = await httpRequest(params.url, {
          method: params.method ?? "POST",
          headers: { ...params.headers, "Content-Type": "application/json" },
          body: JSON.stringify(testBody),
          cookies: params.cookies,
        })

        if (resp.status >= 200 && resp.status < 300) {
          const respLower = resp.body.toLowerCase()
          if (respLower.includes(`"${field}"`) || respLower.includes(`"${field}":true`) || respLower.includes(`"${field}":"admin"`)) {
            parts.push(`\n── ⚠ Mass Assignment: "${field}" accepted ──`)
            parts.push(`  Response includes the injected field`)
            parts.push(`  Response: ${resp.body.slice(0, 300)}`)
            totalFindings++
          }
        }
      }
      if (!parts.some((l) => l.includes("Mass Assignment"))) {
        parts.push("\n── Mass Assignment: extra fields not reflected ──")
      }
    }

    return {
      title: totalFindings > 0
        ? `⚠ ${totalFindings} access control issue(s)`
        : "Access control: no issues",
      metadata: { findings: totalFindings, tests: tests.length } as any,
      output: parts.join("\n"),
    }
  },
})
