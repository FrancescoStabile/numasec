/**
 * Target scope enforcement.
 *
 * Every outbound request (HTTP, scanning, fuzzing) MUST pass through
 * `Scope.check()` before execution. This prevents accidental scanning
 * of hosts outside the engagement scope.
 */

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

  let currentScope: Definition | null = null

  /** Set the engagement scope. Call once at session start. */
  export function set(scope: Definition): void {
    currentScope = { ...scope }
  }

  /** Get current scope or null if not set. */
  export function get(): Definition | null {
    return currentScope
  }

  /** Clear the scope (for testing). */
  export function clear(): void {
    currentScope = null
  }

  /**
   * Check if a URL/host is within the engagement scope.
   * Returns { allowed: true } or { allowed: false, reason: string }.
   */
  export function check(urlOrHost: string): { allowed: boolean; reason?: string } {
    if (!currentScope) {
      return { allowed: false, reason: "No scope defined. Use /target to set engagement scope." }
    }

    let hostname: string
    try {
      const parsed = new URL(urlOrHost.startsWith("http") ? urlOrHost : `https://${urlOrHost}`)
      hostname = parsed.hostname
    } catch {
      hostname = urlOrHost.split(":")[0].split("/")[0]
    }

    // Check blocked patterns first (highest priority)
    for (const pattern of currentScope.blockedPatterns) {
      if (matchGlob(hostname, pattern) || matchGlob(urlOrHost, pattern)) {
        return { allowed: false, reason: `Blocked by pattern: ${pattern}` }
      }
    }

    // Check private IP ranges
    if (!currentScope.allowInternal && isPrivate(hostname)) {
      return {
        allowed: false,
        reason: `Private/internal address "${hostname}" not allowed. Set allowInternal=true to permit.`,
      }
    }

    // Check allowed patterns
    for (const pattern of currentScope.allowedPatterns) {
      if (matchGlob(hostname, pattern) || matchGlob(urlOrHost, pattern)) {
        return { allowed: true }
      }
    }

    return {
      allowed: false,
      reason: `"${hostname}" is not in scope. Allowed: ${currentScope.allowedPatterns.join(", ")}`,
    }
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
