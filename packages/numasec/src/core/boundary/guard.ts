// Boundary guard — reads scope from the active operation's numasec.md.
//
// This module is intentionally thin: it locates the active op, parses its
// Scope block, and delegates matching to `evaluate`. No state, no cache.
//
// Opsec lockdown (T09): when the active operation declares `opsec: strict`,
// the guard additionally refuses any request that targets a third-party
// intel service (passive OSINT leakage) and upgrades unmatched "ask"
// decisions to "deny" so traffic stays within the declared target boundary.

import { Operation } from "@/core/operation"
import { parseScope } from "@/core/operation/scope"
import { evaluate } from "./evaluate"
import type { Decision, Request } from "./schema"

// Third-party intel services that would leak the active target if contacted.
// Configurable via this constant list — keep lowercase, hostname only.
export const OPSEC_BLOCKLIST: ReadonlyArray<string> = [
  "crt.sh",
  "otx.alienvault.com",
  "www.virustotal.com",
  "api.shodan.io",
  "urlscan.io",
  "wayback-api.archive.org",
]

const LOCALHOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"])

function extractHost(request: Request): string | undefined {
  if (request.kind === "url") {
    try {
      return new URL(request.value).hostname.toLowerCase()
    } catch {
      return undefined
    }
  }
  if (request.kind === "host") return request.value.toLowerCase()
  return undefined
}

function isBlocklisted(host: string): boolean {
  return OPSEC_BLOCKLIST.some((h) => host === h || host.endsWith("." + h))
}

function isLocalhost(host: string): boolean {
  if (LOCALHOSTS.has(host)) return true
  return host.endsWith(".localhost")
}

export class ScopeDeniedError extends Error {
  readonly decision: Decision
  readonly request: Request
  readonly operation?: string
  constructor(request: Request, decision: Decision, operation?: string) {
    super(
      `out of scope: ${request.kind}=${request.value}` +
        (decision.matched ? ` (matched ${decision.matched})` : "") +
        (operation ? ` [op=${operation}]` : ""),
    )
    this.name = "ScopeDeniedError"
    this.request = request
    this.decision = decision
    this.operation = operation
  }
}

export async function resolveActiveBoundary(
  workspace: string,
): Promise<{ slug: string; boundary: unknown; opsec: Operation.Opsec } | undefined> {
  const slug = await Operation.activeSlug(workspace).catch(() => undefined)
  if (!slug) return undefined
  const [markdown, info] = await Promise.all([
    Operation.readMarkdown(workspace, slug).catch(() => undefined),
    Operation.read(workspace, slug).catch(() => undefined),
  ])
  if (!markdown) return undefined
  return { slug, boundary: parseScope(markdown), opsec: info?.opsec ?? "normal" }
}

export async function opsec(workspace: string): Promise<Operation.Opsec> {
  const info = await Operation.active(workspace).catch(() => undefined)
  return info?.opsec ?? "normal"
}

export async function check(workspace: string, request: Request): Promise<Decision> {
  const ctx = await resolveActiveBoundary(workspace)
  if (!ctx) return { mode: "allow", reason: "no active operation" }

  if (ctx.opsec === "strict") {
    const host = extractHost(request)
    if (host && isBlocklisted(host)) {
      const decision: Decision = {
        mode: "deny",
        reason: "opsec strict: 3rd-party intel host blocked",
        matched: host,
      }
      throw new ScopeDeniedError(request, decision, ctx.slug)
    }
  }

  const decision = evaluate(ctx.boundary, request)
  if (decision.mode === "deny") throw new ScopeDeniedError(request, decision, ctx.slug)

  if (ctx.opsec === "strict" && decision.mode === "ask") {
    const host = extractHost(request)
    if (!host || !isLocalhost(host)) {
      const denied: Decision = {
        mode: "deny",
        reason: "opsec strict: outside declared target boundary",
      }
      throw new ScopeDeniedError(request, denied, ctx.slug)
    }
  }

  return decision
}

export async function checkUrl(workspace: string, url: string): Promise<Decision> {
  return check(workspace, { kind: "url", value: url })
}

export async function checkHost(workspace: string, host: string): Promise<Decision> {
  return check(workspace, { kind: "host", value: host })
}

export async function checkPath(workspace: string, path: string): Promise<Decision> {
  return check(workspace, { kind: "path", value: path })
}
