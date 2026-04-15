/**
 * Target scope enforcement.
 *
 * Every outbound request (HTTP, browser, shell-driven scanners) MUST pass
 * through `Scope.check()` before execution. Scope is session-scoped so
 * concurrent pentest sessions do not bleed into each other.
 */

import type { SessionID } from "../session/schema"
import { canonicalSecuritySessionID } from "./security-session"

export namespace Scope {
  /** Immutable scope definition for a pentest session. */
  export interface Definition {
    /** Allowed URL patterns (glob-style: *.example.com, https://target.com/*) */
    allowedPatterns: string[]
    /** Explicitly blocked patterns (takes precedence over allowed) */
    blockedPatterns: string[]
    /** Allow private/internal IP ranges (default: false) */
    allowInternal: boolean
  }

  export class ScopeViolationError extends Error {
    constructor(message: string) {
      super(message)
      this.name = "ScopeViolationError"
    }
  }

  type SessionKey = SessionID | string

  const PRIVATE_RANGES = [
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^::1$/,
    /^fc00:/,
    /^fe80:/,
    /^fd/,
    /^0\.0\.0\.0$/,
    /^localhost$/i,
  ]
  const LOCAL_SCHEMES = /^(about|blob|data|file|javascript):/i
  const scopes = new Map<string, Definition>()

  function sessionKey(sessionID: SessionKey) {
    return String(canonicalSecuritySessionID(sessionID as SessionID))
  }

  function clone(scope: Definition): Definition {
    return {
      allowedPatterns: [...scope.allowedPatterns],
      blockedPatterns: [...scope.blockedPatterns],
      allowInternal: scope.allowInternal,
    }
  }

  function isPattern(input: string) {
    return input.includes("*") || input.includes("?")
  }

  function targetInfo(urlOrHost: string) {
    const value = urlOrHost.trim()
    if (!value) {
      return {
        hostname: "",
        local: false,
        value,
      }
    }
    if (LOCAL_SCHEMES.test(value)) {
      return {
        hostname: "",
        local: true,
        value,
      }
    }
    try {
      const parsed = value.includes("://") ? new URL(value) : new URL(`https://${value}`)
      return {
        hostname: parsed.hostname,
        local: false,
        value,
      }
    } catch {
      return {
        hostname: value.split(":")[0].split("/")[0],
        local: false,
        value,
      }
    }
  }

  function patternsForTarget(input: string) {
    const value = input.trim()
    if (!value) return []
    if (isPattern(value)) return [value]
    const info = targetInfo(value)
    if (!info.hostname) return [value]
    const patterns = new Set<string>()
    patterns.add(info.hostname)
    if (value.startsWith("http://") || value.startsWith("https://")) {
      const parsed = new URL(value)
      patterns.add(`${parsed.origin}/*`)
    }
    return Array.from(patterns)
  }

  function allowInternal(targets: string[], explicit?: boolean) {
    if (typeof explicit === "boolean") return explicit
    return targets.some((item) => isPrivate(targetInfo(item).hostname))
  }

  function normalizeTargets(input: string | string[]) {
    if (Array.isArray(input)) return input.map((item) => item.trim()).filter(Boolean)
    const value = input.trim()
    if (!value) return []
    return [value]
  }

  export function fromTargets(
    input: string | string[],
    options: {
      blockedPatterns?: string[]
      allowInternal?: boolean
    } = {},
  ): Definition {
    const targets = normalizeTargets(input)
    const allowed = new Set<string>()
    for (const item of targets) {
      const patterns = patternsForTarget(item)
      for (const pattern of patterns) {
        allowed.add(pattern)
      }
    }
    return {
      allowedPatterns: Array.from(allowed),
      blockedPatterns: [...(options.blockedPatterns ?? [])],
      allowInternal: allowInternal(targets, options.allowInternal),
    }
  }

  /** Set the engagement scope for a specific pentest session. */
  export function set(sessionID: SessionKey, scope: Definition): void {
    scopes.set(sessionKey(sessionID), clone(scope))
  }

  /** Get current scope or null if not set. */
  export function get(sessionID: SessionKey): Definition | null {
    const current = scopes.get(sessionKey(sessionID))
    if (!current) return null
    return clone(current)
  }

  /** Clear one session scope or all scopes (for testing). */
  export function clear(sessionID?: SessionKey): void {
    if (sessionID !== undefined) {
      scopes.delete(sessionKey(sessionID))
      return
    }
    scopes.clear()
  }

  /**
   * Check if a URL/host is within the engagement scope.
   * Returns { allowed: true } or { allowed: false, reason: string }.
   */
  export function check(sessionID: SessionKey, urlOrHost: string): { allowed: boolean; reason?: string } {
    const current = get(sessionID)
    if (!current) {
      return { allowed: false, reason: "No scope defined. Use /scope set to define engagement scope (legacy: /target)." }
    }

    const info = targetInfo(urlOrHost)
    if (info.local) return { allowed: true }
    const hostname = info.hostname || info.value

    for (const pattern of current.blockedPatterns) {
      if (matchGlob(hostname, pattern) || matchGlob(info.value, pattern)) {
        return { allowed: false, reason: `Blocked by pattern: ${pattern}` }
      }
    }
    if (!current.allowInternal && isPrivate(hostname)) {
      return {
        allowed: false,
        reason: `Private/internal address "${hostname}" not allowed. Set allowInternal=true to permit.`,
      }
    }
    for (const pattern of current.allowedPatterns) {
      if (matchGlob(hostname, pattern) || matchGlob(info.value, pattern)) {
        return { allowed: true }
      }
    }
    return {
      allowed: false,
      reason: `"${hostname}" is not in scope. Allowed: ${current.allowedPatterns.join(", ")}`,
    }
  }

  /**
   * Ensure the session has a scope. If unset, seed it from the explicit targets.
   * If already set, every target must still pass scope checks.
   */
  export function ensure(
    sessionID: SessionKey,
    input: string | string[],
    options: {
      blockedPatterns?: string[]
      allowInternal?: boolean
    } = {},
  ): Definition {
    const targets = normalizeTargets(input)
    const current = get(sessionID)
    if (!current) {
      const next = fromTargets(targets, options)
      set(sessionID, next)
      return next
    }
    for (const item of targets) {
      assert(sessionID, item)
    }
    return current
  }

  export function assert(sessionID: SessionKey, urlOrHost: string): void {
    const result = check(sessionID, urlOrHost)
    if (result.allowed) return
    throw new ScopeViolationError(result.reason ?? "Target is out of scope.")
  }

  function isPrivate(hostname: string): boolean {
    return PRIVATE_RANGES.some((re) => re.test(hostname))
  }

  /** Simple glob matching: * matches any sequence, ? matches one char. */
  function matchGlob(input: string, pattern: string): boolean {
    const regex = new RegExp(
      "^" +
        pattern
          .replace(/[.+^${}()|[\]\\]/g, "\\$&")
          .replace(/\*/g, ".*")
          .replace(/\?/g, ".") +
        "$",
      "i",
    )
    return regex.test(input)
  }
}
