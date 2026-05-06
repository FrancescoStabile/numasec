import { Effect } from "effect"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import type { KnowledgeCard, KnowledgeResult, ResearchCard, VulnIntelCard } from "./types"

function queryKey(result: KnowledgeResult, legacyKey?: string) {
  return legacyKey ?? `${result.request.intent}:${result.request.action}:${result.request.query}`
}

function factStatus(result: KnowledgeResult) {
  return result.degraded ? "stale" : "observed"
}

function cardSourceNames(card: KnowledgeCard) {
  return card.sources.map((item) => item.name)
}

function persistVulnCard(input: {
  operation_slug?: string
  card: VulnIntelCard
  query_key: string
  event_id?: string
  evidence_refs?: string[]
}) {
  const status = "observed" as const
  return Effect.all([
    Cyber.upsertFact({
      operation_slug: input.operation_slug,
      entity_kind: "vulnerability",
      entity_key: input.card.id,
      fact_name: "details",
      value_json: input.card,
      writer_kind: "tool",
      status,
      confidence: 850,
      source_event_id: input.event_id,
      evidence_refs: input.evidence_refs,
      expires_at: input.card.stale_after,
    }).pipe(Effect.catch(() => Effect.succeed(""))),
    Cyber.upsertFact({
      operation_slug: input.operation_slug,
      entity_kind: "vulnerability",
      entity_key: input.card.id,
      fact_name: "exploitation_signal",
      value_json: input.card.exploitation,
      writer_kind: "tool",
      status,
      confidence: 800,
      source_event_id: input.event_id,
      evidence_refs: input.evidence_refs,
      expires_at: input.card.stale_after,
    }).pipe(Effect.catch(() => Effect.succeed(""))),
    ...(input.card.id.startsWith("CVE-")
      ? [
          Cyber.upsertFact({
            operation_slug: input.operation_slug,
            entity_kind: "cve",
            entity_key: input.card.id,
            fact_name: "details",
            value_json: input.card,
            writer_kind: "tool",
            status,
            confidence: 850,
            source_event_id: input.event_id,
            evidence_refs: input.evidence_refs,
            expires_at: input.card.stale_after,
          }).pipe(Effect.catch(() => Effect.succeed(""))),
        ]
      : []),
    Cyber.upsertRelation({
      operation_slug: input.operation_slug,
      src_kind: "knowledge_query",
      src_key: input.query_key,
      relation: "matched",
      dst_kind: "vulnerability",
      dst_key: input.card.id,
      writer_kind: "tool",
      status,
      confidence: 850,
      source_event_id: input.event_id,
      evidence_refs: input.evidence_refs,
    }).pipe(Effect.catch(() => Effect.succeed(""))),
    ...(input.card.applicability.matched_component
      ? [
          Cyber.upsertFact({
            operation_slug: input.operation_slug,
            entity_kind: "component",
            entity_key: input.card.applicability.matched_component,
            fact_name: "descriptor",
            value_json: {
              name: input.card.applicability.matched_component,
              version: input.card.applicability.matched_version,
              source: "knowledge",
            },
            writer_kind: "tool",
            status,
            confidence: input.card.applicability.confidence === "high" ? 850 : input.card.applicability.confidence === "medium" ? 650 : 400,
            source_event_id: input.event_id,
            evidence_refs: input.evidence_refs,
          }).pipe(Effect.catch(() => Effect.succeed(""))),
          Cyber.upsertRelation({
            operation_slug: input.operation_slug,
            src_kind: "component",
            src_key: input.card.applicability.matched_component,
            relation: "affected_by",
            dst_kind: "vulnerability",
            dst_key: input.card.id,
            writer_kind: "tool",
            status,
            confidence: input.card.applicability.confidence === "high" ? 850 : input.card.applicability.confidence === "medium" ? 650 : 400,
            source_event_id: input.event_id,
            evidence_refs: input.evidence_refs,
          }).pipe(Effect.catch(() => Effect.succeed(""))),
        ]
      : []),
  ])
}

function persistResearchCard(input: {
  operation_slug?: string
  card: ResearchCard
  query_key: string
  event_id?: string
  evidence_refs?: string[]
}) {
  const entityKind = input.card.source_pack === "tool_docs" ? "tool_usage" : "technique"
  const entityKey = `${input.card.source_pack}:${input.card.topic}`.toLowerCase().replace(/[^a-z0-9._:-]+/g, "_").slice(0, 180)
  return Effect.all([
    Cyber.upsertFact({
      operation_slug: input.operation_slug,
      entity_kind: entityKind,
      entity_key: entityKey,
      fact_name: "guidance",
      value_json: input.card,
      writer_kind: "tool",
      status: input.card.sources.some((item) => item.degraded) ? "stale" : "observed",
      confidence: input.card.claims.length ? 750 : 350,
      source_event_id: input.event_id,
      evidence_refs: input.evidence_refs,
      expires_at: input.card.stale_after,
    }).pipe(Effect.catch(() => Effect.succeed(""))),
    Cyber.upsertRelation({
      operation_slug: input.operation_slug,
      src_kind: "knowledge_query",
      src_key: input.query_key,
      relation: "guided_by",
      dst_kind: entityKind,
      dst_key: entityKey,
      writer_kind: "tool",
      status: input.card.sources.some((item) => item.degraded) ? "stale" : "observed",
      confidence: input.card.claims.length ? 750 : 350,
      source_event_id: input.event_id,
      evidence_refs: input.evidence_refs,
    }).pipe(Effect.catch(() => Effect.succeed(""))),
  ])
}

export function persistKnowledgeResult(input: {
  workspace: string
  operation_slug?: string
  result: KnowledgeResult
  session_id?: string
  message_id?: string
  source?: string
  fact_name?: string
  legacy_query_key?: string
}) {
  return Effect.gen(function* () {
    const output = JSON.stringify(input.result, null, 2)
    const evidence =
      !input.operation_slug
        ? undefined
        : yield* Effect.promise(() =>
            Evidence.put(input.workspace, input.operation_slug!, output, {
              mime: "application/json",
              ext: "json",
              label: `knowledge ${input.result.request.intent} ${input.result.request.query}`,
              source: input.source ?? "knowledge",
            }),
          ).pipe(Effect.catch(() => Effect.succeed(undefined)))
    const evidenceRefs = evidence ? [evidence.sha256] : undefined
    const key = queryKey(input.result, input.legacy_query_key)
    const eventID = yield* Cyber.appendLedger({
      operation_slug: input.operation_slug,
      kind: "fact.observed",
      source: input.source ?? "knowledge",
      status: input.result.degraded ? "degraded" : "completed",
      summary: input.result.summary,
      session_id: input.session_id,
      message_id: input.message_id,
      evidence_refs: evidenceRefs,
      data: {
        intent: input.result.request.intent,
        action: input.result.request.action,
        mode: input.result.request.mode,
        query: input.result.request.query,
        cards: input.result.cards.length,
        sources: input.result.sources.map((item) => item.name),
        degraded: input.result.degraded,
      },
    }).pipe(Effect.catch(() => Effect.succeed("")))

    yield* Cyber.upsertFact({
      operation_slug: input.operation_slug,
      entity_kind: "knowledge_query",
      entity_key: key,
      fact_name: input.fact_name ?? "result",
      value_json: {
        query: input.result.request.query,
        intent: input.result.request.intent,
        action: input.result.request.action,
        mode: input.result.request.mode,
        returned: input.result.cards.length,
        card_count: input.result.cards.length,
        source_pack: input.result.request.intent,
        sources: input.result.sources.map((item) => ({
          name: item.name,
          source_type: item.source_type,
          trust: item.trust,
          degraded: item.degraded ?? false,
          url: item.url,
        })),
        degraded: input.result.degraded,
        errors: input.result.errors,
        fetched_at: input.result.fetched_at,
        stale_after: input.result.stale_after,
        cards: input.result.cards.map((card) => ({
          kind: card.kind,
          id: card.kind === "vuln_intel" ? card.id : undefined,
          topic: card.kind === "research" ? card.topic : undefined,
          applicability_state: card.kind === "vuln_intel" ? card.applicability.state : undefined,
          epss_probability: card.kind === "vuln_intel" ? (card.exploitation.epss_probability ?? card.exploitation.epss) : undefined,
          kev: card.kind === "vuln_intel" ? card.exploitation.kev : undefined,
          sources: cardSourceNames(card),
        })),
      },
      writer_kind: "tool",
      status: factStatus(input.result),
      confidence: input.result.degraded ? 450 : 850,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
      expires_at: input.result.stale_after,
    }).pipe(Effect.catch(() => Effect.succeed("")))

    for (const card of input.result.cards) {
      if (card.kind === "vuln_intel") {
        yield* persistVulnCard({
          operation_slug: input.operation_slug,
          card,
          query_key: key,
          event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        })
      } else {
        yield* persistResearchCard({
          operation_slug: input.operation_slug,
          card,
          query_key: key,
          event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        })
      }
    }

    return { evidence, evidence_refs: evidenceRefs, event_id: eventID || undefined, query_key: key }
  })
}
