import { Boundary, type Decision, type Request } from "./schema"

function globToRegex(glob: string): RegExp {
  const esc = glob
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\u0000")
    .replace(/\*/g, "[^/]*")
    .replace(/\u0000/g, ".*")
    .replace(/\?/g, ".")
  return new RegExp("^" + esc + "$", "i")
}

function matches(pattern: string, req: Request): boolean {
  if (!pattern) return false
  if (req.kind === "url") {
    try {
      const u = new URL(req.value)
      if (pattern.includes("://")) return u.origin === pattern || req.value.startsWith(pattern)
      if (pattern.startsWith("*.")) return u.hostname.endsWith(pattern.slice(1))
      if (pattern.includes("/")) return req.value.startsWith(pattern)
      return u.hostname === pattern
    } catch {
      return false
    }
  }
  if (req.kind === "host") {
    if (pattern.startsWith("*.")) return req.value.endsWith(pattern.slice(1))
    return req.value === pattern
  }
  if (req.kind === "path" || req.kind === "raw") {
    if (pattern.includes("*") || pattern.includes("?")) return globToRegex(pattern).test(req.value)
    return req.value === pattern || req.value.startsWith(pattern.endsWith("/") ? pattern : pattern + "/")
  }
  return false
}

export function evaluate(boundary: unknown, req: Request): Decision {
  const parsed = Boundary.safeParse(boundary ?? {})
  const b = parsed.success
    ? parsed.data
    : { default: "ask" as const, in_scope: [], out_of_scope: [] }

  for (const p of b.out_of_scope) {
    if (matches(p, req)) return { mode: "deny", reason: "matched out_of_scope", matched: p }
  }
  for (const p of b.in_scope) {
    if (matches(p, req)) return { mode: "allow", reason: "matched in_scope", matched: p }
  }
  if (b.in_scope.length === 0 && b.out_of_scope.length === 0) {
    return { mode: b.default, reason: "no boundary defined" }
  }
  return { mode: b.default, reason: "no pattern matched" }
}
