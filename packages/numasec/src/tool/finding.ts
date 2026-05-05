import { Effect } from "effect"
import z from "zod"
import * as Tool from "./tool"
import DESCRIPTION from "./finding.txt"
import { Cyber } from "@/core/cyber"
import {
  bucketFindings,
  candidateSummary,
  candidateTitle,
  isRejectedFinding,
  isReportableFinding,
  normalizeReplayExemption,
  REPLAY_EXEMPTION_CATEGORIES,
  isSuspectedFinding,
  replayState,
  summarizeFindingFact,
  type FindingRecord,
} from "@/core/cyber/finding"
import { Oracle } from "@/core/cyber/oracle"
import { Evidence } from "@/core/evidence"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

const parameters = z.object({
  action: z.enum(["list", "status", "promote", "reject"]).default("list"),
  key: z.string().optional().describe("Candidate or finding key"),
  title: z.string().optional(),
  summary: z.string().optional(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
  evidence: z.array(z.string()).optional().describe("Evidence SHA-256 refs to attach"),
  replay: z.string().optional().describe("Replay bundle or reproduction steps"),
  replay_reason: z.string().optional().describe("Legacy free-form replay exemption reason"),
  replay_exemption_category: z.enum(REPLAY_EXEMPTION_CATEGORIES).optional(),
  replay_exemption_rationale: z.string().optional(),
  note: z.string().optional().describe("Optional promotion or rejection note"),
})

type Params = z.infer<typeof parameters>
type Metadata = Record<string, unknown>

function asObject(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

function formatRecord(record: FindingRecord) {
  const replay = replayState(record)
  return [
    `${record.kind} · ${record.key}`,
    `status: ${record.status}`,
    record.severity ? `severity: ${record.severity}` : undefined,
    record.title ? `title: ${record.title}` : undefined,
    record.summary ? `summary: ${record.summary}` : undefined,
    record.proof_summary && record.proof_summary !== record.summary ? `proof_summary: ${record.proof_summary}` : undefined,
    record.evidence_refs?.length ? `evidence: ${record.evidence_refs.join(", ")}` : undefined,
    replay ? `replay: ${replay}` : undefined,
    record.kind === "finding" && record.operator_promoted ? "origin: operator_promoted" : undefined,
    record.kind === "finding" && record.replay_reason ? `replay_reason: ${record.replay_reason}` : undefined,
    record.kind === "finding" && record.oracle_status ? `oracle: ${record.oracle_status}` : undefined,
    record.kind === "finding" && record.oracle_reason ? `oracle_reason: ${record.oracle_reason}` : undefined,
  ]
    .filter(Boolean)
    .join("\n")
}

function isReportable(record: FindingRecord) {
  return isReportableFinding(record)
}

function isRejected(record: FindingRecord) {
  return isRejectedFinding(record)
}

function isSuspected(record: FindingRecord) {
  return isSuspectedFinding(record)
}

function formatListBucket(title: string, records: FindingRecord[]) {
  if (records.length === 0) return `## ${title}\n_empty_`
  return [
    `## ${title}`,
    ...records.map(
      (item) =>
        `${item.kind === "finding" ? "*" : "-"} ${item.key} · ${item.status}${item.severity ? ` · ${item.severity}` : ""}${item.title ? ` · ${item.title}` : ""}`,
    ),
  ].join("\n")
}

async function readActiveSlug(workspace: string) {
  return Operation.activeSlug(workspace).catch(() => undefined)
}

export const FindingTool = Tool.define<typeof parameters, Metadata, never>(
  "finding",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context) =>
        Effect.gen(function* () {
          const workspace = Instance.directory
          const slug = yield* Effect.promise(() => readActiveSlug(workspace))
          if (!slug) {
            return {
              title: "finding · no active operation",
              output: "No active operation.",
              metadata: { action: params.action, active: false },
            }
          }
          const active = yield* Effect.promise(() => Operation.active(workspace).catch(() => undefined))

          const facts = yield* Cyber.listFacts({ operation_slug: slug, limit: 500 }).pipe(
            Effect.catch(() => Effect.succeed([])),
          )
          const records = facts.map(summarizeFindingFact).filter((item): item is FindingRecord => Boolean(item))
          const buckets = bucketFindings(records)
          const visibleRecords = buckets.all

          if (params.action === "list") {
            const output =
              visibleRecords.length === 0
                ? "No candidate or promoted findings."
                : [
                    `total=${visibleRecords.length} reportable=${buckets.reportable.length} suspected=${buckets.suspected.length} rejected=${buckets.rejected.length}`,
                    "",
                    formatListBucket("Reportable Findings", buckets.reportable),
                    "",
                    formatListBucket("Suspected Findings", buckets.suspected),
                    "",
                    formatListBucket("Rejected Or Stale Findings", buckets.rejected),
                  ].join("\n")
            return {
              title: `finding · ${visibleRecords.length}`,
              output,
              metadata: {
                action: "list",
                slug,
                count: visibleRecords.length,
                candidates: buckets.candidates.length,
                findings: buckets.findings.length,
                reportable_findings: buckets.reportable.length,
                suspected_findings: buckets.suspected.length,
                rejected_findings: buckets.rejected.length,
              },
            }
          }

          if (!params.key) {
            return {
              title: `finding ${params.action}`,
              output: "Provide key for this action.",
              metadata: { action: params.action, slug },
            }
          }

          const record = visibleRecords.find((item) => item.key === params.key) ?? records.find((item) => item.key === params.key)
          const candidateFact = facts.find(
            (fact) => fact.entity_kind === "finding_candidate" && fact.entity_key === params.key,
          )
          const findingFact = facts.find(
            (fact) => fact.entity_kind === "finding" && fact.entity_key === params.key && fact.fact_name === "record",
          )

          if (params.action === "status") {
            if (!record) {
              return {
                title: `finding · ${params.key}`,
                output: "No candidate or finding with that key.",
                metadata: { action: "status", slug, key: params.key, found: false },
              }
            }
            return {
              title: `finding · ${params.key}`,
              output: formatRecord(record),
              metadata: {
                action: "status",
                slug,
                key: params.key,
                found: true,
                kind: record.kind,
                status: record.status,
                replay_present: record.replay_present,
                replay_reason: record.replay_reason,
                replay_exempt: Boolean(record.replay_reason) && !record.replay_present,
              },
            }
          }

          if (params.action === "reject") {
            if (!candidateFact && !findingFact) {
              return {
                title: `finding reject · ${params.key}`,
                output: "No candidate or finding with that key.",
                metadata: { action: "reject", slug, key: params.key, found: false },
              }
            }
            const eventID = yield* Cyber.appendLedger({
              operation_slug: slug,
              kind: "fact.verified",
              source: "finding",
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              status: "rejected",
              summary: `rejected finding ${params.key}`,
              data: { key: params.key, note: params.note ?? null },
            }).pipe(Effect.catch(() => Effect.succeed("")))
            if (candidateFact) {
              yield* Cyber.upsertFact({
                operation_slug: slug,
                entity_kind: candidateFact.entity_kind,
                entity_key: candidateFact.entity_key,
                fact_name: candidateFact.fact_name,
                value_json: {
                  ...(asObject(candidateFact.value_json) ?? {}),
                  rejected_note: params.note,
                },
                writer_kind: "operator",
                status: "rejected",
                confidence: candidateFact.confidence ?? 1000,
                source_event_id: eventID || undefined,
                evidence_refs: candidateFact.evidence_refs,
              }).pipe(Effect.catch(() => Effect.succeed("")))
            }
            if (findingFact) {
              const value = asObject(findingFact.value_json) ?? {}
              yield* Cyber.upsertFact({
                operation_slug: slug,
                entity_kind: "finding",
                entity_key: findingFact.entity_key,
                fact_name: "record",
                value_json: {
                  ...value,
                  rejected_note: params.note,
                },
                writer_kind: "operator",
                status: "rejected",
                confidence: findingFact.confidence ?? 1000,
                source_event_id: eventID || undefined,
                evidence_refs: findingFact.evidence_refs,
              }).pipe(Effect.catch(() => Effect.succeed("")))
            }
            return {
              title: `finding reject · ${params.key}`,
              output: `Rejected ${params.key}.`,
              metadata: { action: "reject", slug, key: params.key, rejected: true },
            }
          }

          const baseEvidenceRefs = [
            ...(params.evidence ?? []),
            ...(candidateFact?.evidence_refs ?? []),
            ...(findingFact?.evidence_refs ?? []),
          ].filter((item, index, array) => item && array.indexOf(item) === index)
          let replayRef: string | undefined
          const hasStructuredExemption = Boolean(params.replay_exemption_category || params.replay_exemption_rationale)
          if (params.replay && (params.replay_reason || hasStructuredExemption)) {
            return {
              title: `finding promote · ${params.key}`,
              output: "Provide either replay steps or replay exemption input, not both.",
              metadata: { action: "promote", slug, key: params.key, promoted: false, invalid_replay_input: true },
            }
          }
          if ((params.replay_exemption_category && !params.replay_exemption_rationale) || (!params.replay_exemption_category && params.replay_exemption_rationale)) {
            return {
              title: `finding promote · ${params.key}`,
              output: "Structured replay exemptions require both replay_exemption_category and replay_exemption_rationale.",
              metadata: { action: "promote", slug, key: params.key, promoted: false, invalid_replay_input: true },
            }
          }
          if (params.replay) {
            const replayEntry = yield* Effect.promise(() =>
              Evidence.put(workspace, slug, params.replay!, {
                mime: "text/plain",
                ext: "replay",
                label: `${params.key} replay`,
                source: "finding promote",
              }),
            )
            replayRef = replayEntry.sha256
          }
          const replayExemption = normalizeReplayExemption({
            replay_reason: params.replay_reason,
            replay_exemption:
              params.replay_exemption_category && params.replay_exemption_rationale
                ? {
                    category: params.replay_exemption_category,
                    rationale: params.replay_exemption_rationale,
                    domain: active?.kind,
                    approved_by_kind: "operator",
                  }
                : undefined,
          })
          const evidenceRefs = [...baseEvidenceRefs, replayRef].filter(
            (item, index, array): item is string => Boolean(item) && array.indexOf(item) === index,
          )
          if (evidenceRefs.length === 0) {
            return {
              title: `finding promote · ${params.key}`,
              output: "Promotion requires at least one evidence reference or a candidate that already carries evidence.",
              metadata: { action: "promote", slug, key: params.key, promoted: false },
            }
          }
          const proofVerdict = yield* Oracle.verifyFindingProof({
            operation_slug: slug,
            finding_key: params.key,
            domain: active?.kind,
            evidence_refs: evidenceRefs,
            replay_present: Boolean(replayRef),
            replay_exemption: replayExemption,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
          })
          const status = proofVerdict.status === "passed" ? "verified" : "observed"
          const eventID = yield* Cyber.appendLedger({
            operation_slug: slug,
            kind: status === "verified" ? "fact.verified" : "fact.observed",
            source: "finding",
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            status,
            evidence_refs: evidenceRefs,
            summary: `promoted finding ${params.key}`,
            data: {
              key: params.key,
              title: params.title ?? record?.title ?? null,
              severity: params.severity ?? record?.severity ?? null,
              replay_present: Boolean(replayRef),
              replay_reason: replayExemption?.rationale ?? null,
              replay_exemption: replayExemption ?? null,
              oracle_status: proofVerdict.status,
              oracle_reason: proofVerdict.reason,
              note: params.note ?? null,
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          const candidateValue = asObject(candidateFact?.value_json)
          const recordTitle = params.title ?? record?.title ?? candidateTitle(candidateFact?.fact_name ?? "finding", candidateValue, params.key)
          const recordSummary = params.summary ?? record?.summary ?? candidateSummary(candidateValue) ?? params.key
          const proofSummary = candidateSummary(candidateValue) ?? record?.proof_summary ?? recordSummary
          const operatorPromoted = !candidateFact
          yield* Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "finding",
            entity_key: params.key,
            fact_name: "record",
            value_json: {
              title: recordTitle,
              summary: recordSummary,
              proof_summary: proofSummary,
              severity: params.severity ?? record?.severity,
              promoted_from: candidateFact ? params.key : null,
              operator_promoted: operatorPromoted,
              replay_present: Boolean(replayRef),
              replay_reason: replayExemption?.rationale,
              replay_exemption: replayExemption,
              oracle_status: proofVerdict.status,
              oracle_reason: proofVerdict.reason,
              note: params.note,
            },
            writer_kind: "operator",
            status,
            confidence: 1000,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          if (candidateFact) {
            yield* Cyber.upsertRelation({
              operation_slug: slug,
              src_kind: "finding",
              src_key: params.key,
              relation: "promotes",
              dst_kind: "finding_candidate",
              dst_key: candidateFact.entity_key,
              writer_kind: "operator",
              status,
              confidence: 1000,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }
          for (const ref of evidenceRefs) {
            yield* Cyber.upsertRelation({
              operation_slug: slug,
              src_kind: "finding",
              src_key: params.key,
              relation: "backed_by",
              dst_kind: replayRef === ref ? "replay_artifact" : "evidence_artifact",
              dst_key: ref,
              writer_kind: "operator",
              status,
              confidence: 1000,
              source_event_id: eventID || undefined,
              evidence_refs: [ref],
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }
          if (replayRef) {
            yield* Cyber.upsertFact({
              operation_slug: slug,
              entity_kind: "finding",
              entity_key: params.key,
              fact_name: "replay_bundle",
              value_json: {
                sha256: replayRef,
                kind: "text/plain",
              },
              writer_kind: "operator",
              status: "verified",
              confidence: 1000,
              source_event_id: eventID || undefined,
              evidence_refs: [replayRef],
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }
          return {
            title: `finding promote · ${params.key}`,
            output: [
              `Promoted ${params.key}.`,
              `status: ${status}`,
              `oracle: ${proofVerdict.status}`,
              `evidence: ${evidenceRefs.join(", ")}`,
              `replay: ${replayRef ? replayRef : replayExemption ? `exempt (${replayExemption.category})` : "missing"}`,
            ].join("\n"),
            metadata: {
              action: "promote",
              slug,
              key: params.key,
              status,
              oracle_status: proofVerdict.status,
              oracle_reason: proofVerdict.reason,
              evidence_refs: evidenceRefs,
              replay_ref: replayRef,
              replay_exemption: replayExemption,
            },
          }
        }),
    }
  }),
)
