const HEADER_KEYS = new Set(["authorization", "cookie", "set-cookie", "proxy-authorization"])
const SECRET_KEYS = new Set([
  "password",
  "passwd",
  "pass",
  "api_key",
  "apikey",
  "token",
  "secret",
  "access_token",
  "refresh_token",
])
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g

export type RedactMode = "off" | "on"

export function redactString(value: string, mode: RedactMode): string {
  if (mode === "off") return value
  return value.replace(JWT_RE, "[redacted:jwt]")
}

export function redactValue(value: unknown, mode: RedactMode, keyHint?: string): unknown {
  if (mode === "off") return value
  if (value === null || value === undefined) return value
  if (typeof value === "string") {
    if (keyHint && HEADER_KEYS.has(keyHint.toLowerCase())) return `[redacted:header:${keyHint}]`
    if (keyHint && SECRET_KEYS.has(keyHint.toLowerCase())) return `[redacted:secret:${keyHint}]`
    return redactString(value, mode)
  }
  if (Array.isArray(value)) return value.map((item) => redactValue(item, mode))
  if (typeof value === "object") {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactValue(v, mode, k)
    }
    return out
  }
  return value
}
