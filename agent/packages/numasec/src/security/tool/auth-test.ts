/**
 * Tool: auth_test
 *
 * Authentication and authorization testing. JWT analysis, credential
 * testing, OAuth checks.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { analyzeJwt, testJwtAuth } from "../scanner/jwt-analyzer"
import { httpRequest } from "../http-client"

const DESCRIPTION = `Test authentication and authorization mechanisms.
Covers: JWT analysis (decode, crack, alg:none, expiration), default credentials,
authentication bypass, session management.

Requires: target URL. Optionally provide a JWT token for analysis.

CHAIN POTENTIAL: Auth weaknesses lead to:
- Cracked JWT → forge tokens for any user → full account takeover
- Default credentials → admin access → data exfiltration
- Session fixation → hijack other users' sessions
- Auth bypass → access all protected endpoints`

const DEFAULT_CREDS = [
  { username: "admin", password: "admin" },
  { username: "admin", password: "password" },
  { username: "admin", password: "admin123" },
  { username: "root", password: "root" },
  { username: "test", password: "test" },
  { username: "user", password: "user" },
  { username: "admin", password: "123456" },
  { username: "admin@admin.com", password: "admin" },
]

export const AuthTestTool = Tool.define("auth_test", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("Target URL (login endpoint or protected resource)"),
    jwt: z.string().optional().describe("JWT token to analyze"),
    test_defaults: z.boolean().optional().describe("Test default credentials (default true)"),
    username_field: z.string().optional().describe("Username field name (default 'username' or 'email')"),
    password_field: z.string().optional().describe("Password field name (default 'password')"),
    cookies: z.string().optional().describe("Session cookies"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "auth_test",
      patterns: [params.url],
      always: ["*"] as string[],
      metadata: { url: params.url } as Record<string, any>,
    })

    const parts: string[] = []
    let totalFindings = 0

    // JWT analysis
    if (params.jwt) {
      ctx.metadata({ title: "Analyzing JWT token..." })
      const analysis = analyzeJwt(params.jwt)

      if (analysis.decoded) {
        parts.push("── JWT Analysis ──")
        parts.push(`Algorithm: ${analysis.decoded.header.alg}`)
        parts.push(`Payload: ${JSON.stringify(analysis.decoded.payload, null, 2)}`)
        if (analysis.decoded.expired) parts.push(`⚠ Token EXPIRED: ${analysis.decoded.expiresAt}`)
      }

      if (analysis.weaknesses.length > 0) {
        parts.push("")
        parts.push("── JWT Weaknesses ──")
        for (const w of analysis.weaknesses) {
          parts.push(`  [${w.severity.toUpperCase()}] ${w.description}`)
          parts.push(`  Evidence: ${w.evidence}`)
          totalFindings++
        }
      }

      if (analysis.cracked) {
        parts.push("")
        parts.push(`⚠ JWT SECRET CRACKED: "${analysis.cracked.secret}"`)
        parts.push("  → Can forge tokens for ANY user")
        totalFindings++
      }

      // Test JWT auth endpoint
      ctx.metadata({ title: "Testing JWT auth bypass..." })
      const authResult = await testJwtAuth(params.url, params.jwt)
      for (const w of authResult.weaknesses) {
        parts.push(`  [${w.severity.toUpperCase()}] ${w.description}`)
        parts.push(`  Evidence: ${w.evidence}`)
        totalFindings++
      }
    }

    // Default credential testing
    if (params.test_defaults !== false) {
      ctx.metadata({ title: "Testing default credentials..." })
      const userField = params.username_field ?? "email"
      const passField = params.password_field ?? "password"

      for (const cred of DEFAULT_CREDS) {
        const body = JSON.stringify({ [userField]: cred.username, [passField]: cred.password })
        const resp = await httpRequest(params.url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
          cookies: params.cookies,
        })

        // Check if login succeeded
        const lower = resp.body.toLowerCase()
        const isSuccess =
          (resp.status >= 200 && resp.status < 300 && !lower.includes("invalid") && !lower.includes("error") && !lower.includes("fail")) ||
          lower.includes("token") ||
          lower.includes("session") ||
          lower.includes("welcome")

        if (isSuccess) {
          parts.push("")
          parts.push(`⚠ DEFAULT CREDENTIALS WORK: ${cred.username}:${cred.password}`)
          parts.push(`  Status: ${resp.status}`)
          parts.push(`  Response: ${resp.body.slice(0, 300)}`)
          totalFindings++
        }
      }
    }

    if (totalFindings === 0) {
      parts.push("No authentication weaknesses found.")
    }

    return {
      title: totalFindings > 0 ? `⚠ ${totalFindings} auth issue(s)` : "Auth: no issues",
      metadata: { findings: totalFindings } as any,
      output: parts.join("\n"),
    }
  },
})
