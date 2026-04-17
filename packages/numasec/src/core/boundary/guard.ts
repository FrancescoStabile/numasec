import { OperationActive } from "@/core/operation"
import { evaluate } from "./evaluate"
import type { Decision, Request } from "./schema"

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
): Promise<{ slug: string; boundary: unknown } | undefined> {
  const info = await OperationActive.resolveActive(workspace).catch(() => undefined)
  if (!info) return undefined
  return { slug: info.slug, boundary: info.boundary }
}

export async function check(workspace: string, request: Request): Promise<Decision> {
  const ctx = await resolveActiveBoundary(workspace)
  if (!ctx) return { mode: "allow", reason: "no active operation" }
  const decision = evaluate(ctx.boundary, request)
  if (decision.mode === "deny") throw new ScopeDeniedError(request, decision, ctx.slug)
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
