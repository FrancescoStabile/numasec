/**
 * Tool: auth_test
 *
 * Authentication and authorization testing. JWT analysis, credential
 * testing, OAuth checks.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { analyzeJwt, decodeJwt, testJwtAuth } from "../scanner/jwt-analyzer"
import {
  actorSessionRequest,
  httpAuthMaterial,
  mergeActorSession,
} from "../runtime/actor-session-store"
import { executeHttpWithRecovery } from "../runtime/http-execution"
import { makeToolResultEnvelope } from "./result-envelope"

function slug(value: string) {
  return value.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase()
}

function family(type: string) {
  if (type.includes("credential")) return "auth"
  return "jwt"
}

function text(input: unknown) {
  if (typeof input === "string") return input
  if (typeof input === "number") return String(input)
  return ""
}

function actorFromValue(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return
  const row = input as Record<string, unknown>
  const data = typeof row.data === "object" && row.data && !Array.isArray(row.data) ? row.data as Record<string, unknown> : row
  const id = text(data.id)
  const email = text(data.email)
  const role = text(data.role)
  if (!id && !email && !role) return
  return {
    id,
    email,
    role,
  }
}

function tokenFromHeaders(input?: Record<string, string>) {
  if (!input) return ""
  for (const item of Object.keys(input)) {
    if (item.toLowerCase() !== "authorization") continue
    const value = input[item] ?? ""
    if (!value.toLowerCase().startsWith("bearer ")) return ""
    return value.slice(7).trim()
  }
  return ""
}

function pathname(input: string) {
  try {
    return new URL(input).pathname.toLowerCase()
  } catch {
    return input.toLowerCase()
  }
}

function registrationEndpoint(input: string) {
  const path = pathname(input)
  if (/(register|signup|sign-up|create-account|create_user|create-user)/.test(path)) return true
  return /\/(users|customers|accounts)\/?$/.test(path)
}

function authProof(input: ReturnType<typeof httpAuthMaterial>) {
  return Boolean(input.headers.authorization) || input.cookies.length > 0
}

const DESCRIPTION = `Test authentication and authorization mechanisms.
Covers: JWT analysis (decode, crack, alg:none, expiration), common/default credentials,
authentication bypass, session management.

Requires: target URL. Optionally provide a JWT token for analysis.

CHAIN POTENTIAL: Auth weaknesses lead to:
- Cracked JWT → forge tokens for any user → full account takeover
- Weak/common credentials → admin access → data exfiltration
- Session fixation → hijack other users' sessions
- Auth bypass → access all protected endpoints`

const COMMON_CREDS = [
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
    test_defaults: z.boolean().optional().describe("Test common/default credentials (default true)"),
    username_field: z.string().optional().describe("Username field name (default 'username' or 'email')"),
    password_field: z.string().optional().describe("Password field name (default 'password')"),
    cookies: z.string().optional().describe("Session cookies"),
    actor_session_id: z.string().optional().describe("Optional shared actor session ID for automatic auth hydration"),
    actor_label: z.string().optional().describe("Optional shared actor label used to derive actor_session_id when omitted"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "auth_test",
      patterns: [params.url],
      always: [] as string[],
      metadata: { url: params.url } as Record<string, any>,
    })

    const parts: string[] = []
    let totalFindings = 0
    const artifacts: Record<string, any>[] = []
    const observations: Record<string, any>[] = []
    const verifications: Record<string, any>[] = []
    const seeded = await mergeActorSession({
      sessionID: ctx.sessionID,
      actorSessionID: params.actor_session_id,
      actorLabel: params.actor_label,
      material: httpAuthMaterial({
        actorLabel: params.actor_label,
        url: params.url,
        requestHeaders: params.jwt
          ? {
              authorization: `Bearer ${params.jwt}`,
            }
          : undefined,
        requestCookies: params.cookies,
      }),
    })
    const auth = actorSessionRequest(
      seeded,
      params.jwt
        ? {
            authorization: `Bearer ${params.jwt}`,
          }
        : undefined,
      params.cookies,
    )
    const jwt = params.jwt || tokenFromHeaders(auth.headers)

    // JWT analysis
    if (jwt) {
      ctx.metadata({ title: "Analyzing JWT token..." })
      const analysis = analyzeJwt(jwt)

      if (analysis.decoded) {
        parts.push("── JWT Analysis ──")
        parts.push(`Algorithm: ${analysis.decoded.header.alg}`)
        parts.push(`Payload: ${JSON.stringify(analysis.decoded.payload, null, 2)}`)
        if (analysis.decoded.expired) parts.push(`⚠ Token EXPIRED: ${analysis.decoded.expiresAt}`)
        artifacts.push({
          key: "jwt-token",
          subtype: "jwt_analysis",
          jwt,
          header: analysis.decoded.header,
          payload: analysis.decoded.payload,
          expired: analysis.decoded.expired,
          expires_at: analysis.decoded.expiresAt ?? "",
        })
        observations.push({
          key: "jwt-present",
          family: "jwt",
          kind: "token_present",
          url: params.url,
        })
        const actor = actorFromValue(analysis.decoded.payload)
        if (actor) {
          observations.push({
            key: `actor-jwt-${slug(actor.email || actor.id || "jwt")}`,
            family: "actor_inventory",
            kind: "authenticated_actor",
            actor_label: "jwt",
            actor_id: actor.id,
            actor_email: actor.email,
            actor_role: actor.role,
            privileged: /(admin|root|super|staff|support|manager|operator|internal)/i.test(actor.role),
            source: "jwt",
            actor_session_id: seeded.actorSessionID,
            url: params.url,
          })
          await mergeActorSession({
            sessionID: ctx.sessionID,
            actorSessionID: seeded.actorSessionID,
            actorLabel: params.actor_label || "jwt",
            material: {
              actorLabel: params.actor_label || "jwt",
              actorID: actor.id,
              actorEmail: actor.email,
              actorRole: actor.role,
              lastURL: params.url,
            },
          })
        }
      }

      if (analysis.weaknesses.length > 0) {
        parts.push("")
        parts.push("── JWT Weaknesses ──")
        for (const w of analysis.weaknesses) {
          parts.push(`  [${w.severity.toUpperCase()}] ${w.description}`)
          parts.push(`  Evidence: ${w.evidence}`)
          totalFindings++
          verifications.push({
            key: `jwt-${slug(w.type)}`,
            family: family(w.type),
            kind: w.type,
            title: w.description,
            technical_severity: w.severity,
            passed: true,
            control: "positive",
            url: params.url,
            evidence: w.evidence,
            evidence_keys: analysis.decoded ? ["jwt-token"] : [],
          })
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
      const authResult = await testJwtAuth(params.url, jwt, {
        sessionID: ctx.sessionID,
      })
      for (const w of authResult.weaknesses) {
        parts.push(`  [${w.severity.toUpperCase()}] ${w.description}`)
        parts.push(`  Evidence: ${w.evidence}`)
        totalFindings++
        verifications.push({
          key: `jwt-auth-${slug(w.type)}`,
          family: family(w.type),
          kind: w.type,
          title: w.description,
          technical_severity: w.severity,
          passed: true,
          control: "positive",
          url: params.url,
          evidence: w.evidence,
          evidence_keys: analysis.decoded ? ["jwt-token"] : [],
        })
      }
    }

    // Common/default credential testing
    if (params.test_defaults !== false) {
      if (registrationEndpoint(params.url)) {
        parts.push("Skipped common/default credential checks on an account-creation endpoint.")
      } else {
        ctx.metadata({ title: "Testing common/default credentials..." })
        const userField = params.username_field ?? "email"
        const passField = params.password_field ?? "password"

        for (const cred of COMMON_CREDS) {
          const body = JSON.stringify({ [userField]: cred.username, [passField]: cred.password })
          const attempt = await executeHttpWithRecovery({
            sessionID: ctx.sessionID,
            toolName: "auth_test",
            action: "common_credentials",
            actorSessionID: seeded.actorSessionID,
            url: params.url,
            request: {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body,
              cookies: auth.cookies || undefined,
            },
          })
          const resp = attempt.response
          const material = httpAuthMaterial({
            actorLabel: params.actor_label || cred.username,
            url: resp.url,
            requestHeaders: {
              "content-type": "application/json",
            },
            responseHeaders: resp.headers,
            responseBody: resp.body,
            setCookies: resp.setCookies,
          })

          if (!authProof(material)) continue

          parts.push("")
          parts.push(`⚠ COMMON CREDENTIALS WORK: ${cred.username}:${cred.password}`)
          parts.push(`  Status: ${resp.status}`)
          parts.push(`  Response: ${resp.body.slice(0, 300)}`)
          totalFindings++
          artifacts.push({
            key: `default-creds-${slug(cred.username)}-${slug(cred.password)}`,
            subtype: "http_exchange",
            request: {
              url: params.url,
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body,
            },
            response: {
              status: resp.status,
              headers: resp.headers,
              body: resp.body,
              elapsed: resp.elapsed,
              url: resp.url,
            },
          })
          verifications.push({
            key: `default-creds-${slug(cred.username)}-${slug(cred.password)}-verified`,
            family: "auth",
            kind: "common_credentials",
            title: `Common credentials work for ${cred.username}`,
            technical_severity: "high",
            passed: true,
            control: "positive",
            url: params.url,
            evidence_keys: [`default-creds-${slug(cred.username)}-${slug(cred.password)}`],
          })
          const merged = await mergeActorSession({
            sessionID: ctx.sessionID,
            actorSessionID: seeded.actorSessionID,
            actorLabel: params.actor_label || cred.username,
            material,
          })
          try {
            const parsed = JSON.parse(resp.body) as Record<string, unknown>
            const token = text((parsed.authentication as Record<string, unknown> | undefined)?.token)
            const actor = actorFromValue(token ? decodeJwt(token)?.payload : parsed)
            if (actor) {
              observations.push({
                key: `actor-default-${slug(actor.email || actor.id || cred.username)}`,
                family: "actor_inventory",
                kind: "authenticated_actor",
                actor_label: cred.username,
                actor_id: actor.id,
                actor_email: actor.email,
                actor_role: actor.role,
                privileged: /(admin|root|super|staff|support|manager|operator|internal)/i.test(actor.role),
                source: "common_credentials",
                actor_session_id: merged.actorSessionID,
                url: params.url,
              })
            }
          } catch {}
        }
      }
    }

    if (totalFindings === 0) {
      parts.push("No authentication weaknesses found.")
    }

    return {
      title: totalFindings > 0 ? `⚠ ${totalFindings} auth issue(s)` : "Auth: no issues",
      metadata: { findings: totalFindings } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        artifacts,
        observations,
        verifications,
        metrics: {
          findings: totalFindings,
        },
      }),
      output: parts.join("\n"),
    }
  },
})
