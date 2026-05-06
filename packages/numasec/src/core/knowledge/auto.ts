import { Effect } from "effect"
import { KnowledgeBroker, persistKnowledgeResult, workspaceKnowledgeCache } from "@/core/knowledge"
import { Operation } from "@/core/operation"
import type { KnowledgeAction, KnowledgeIntent, KnowledgeMode } from "./types"

type AutoItem = {
  intent: KnowledgeIntent
  action: KnowledgeAction
  query: string
  observed_refs?: string[]
  limit?: number
}

function modeFromOpsec(opsec?: string): KnowledgeMode {
  return opsec === "strict" ? "opsec_strict" : "live"
}

function dedupe(items: AutoItem[]) {
  const seen = new Set<string>()
  return items.filter((item) => {
    const key = `${item.intent}:${item.action}:${item.query}:${item.observed_refs?.join(",") ?? ""}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

export function autoEnrichKnowledge(input: {
  workspace: string
  operation_slug?: string
  session_id?: string
  message_id?: string
  source: string
  items: AutoItem[]
  timeout_ms?: number
}) {
  return Effect.gen(function* () {
    if (!input.operation_slug) return
    const op = yield* Effect.promise(() => Operation.read(input.workspace, input.operation_slug!).catch(() => undefined))
    const mode = modeFromOpsec(op?.opsec)
    const items = dedupe(input.items).slice(0, 4)
    for (const item of items) {
      const task = KnowledgeBroker.query(
        {
          intent: item.intent,
          action: item.action,
          query: item.query,
          observed_refs: item.observed_refs,
          mode,
          limit: item.limit ?? 5,
        },
        workspaceKnowledgeCache(input.workspace),
      )
      const result = yield* Effect.promise(() =>
        Promise.race([
          task,
          new Promise<undefined>((resolve) => setTimeout(() => resolve(undefined), input.timeout_ms ?? 7_000)),
        ]),
      ).pipe(Effect.catch(() => Effect.succeed(undefined)))
      if (!result) continue
      yield* persistKnowledgeResult({
        workspace: input.workspace,
        operation_slug: input.operation_slug,
        result,
        session_id: input.session_id,
        message_id: input.message_id,
        source: input.source,
      }).pipe(Effect.catch(() => Effect.succeed(undefined)))
    }
  })
}
