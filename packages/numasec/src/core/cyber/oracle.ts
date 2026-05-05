import { Effect } from "effect"
import { Cyber } from "./cyber"
import {
  isStructuredReplayExemption,
  type ReplayExemption,
  type ReplayExemptionCategory,
} from "./finding"

const DOMAIN_REPLAY_EXEMPTIONS: Record<string, ReplayExemptionCategory[]> = {
  appsec: ["destructive_target", "operator_controlled_state", "external_dependency"],
  pentest: ["destructive_target", "external_dependency", "time_bound_access"],
  osint: ["external_dependency", "time_bound_access"],
  hacking: ["destructive_target", "external_dependency"],
  bughunt: ["destructive_target", "operator_controlled_state", "external_dependency"],
  ctf: ["operator_controlled_state", "external_dependency"],
  research: ["external_dependency", "time_bound_access"],
}

export type FindingProofVerdict = {
  status: "passed" | "failed"
  reason: string
  replay_state: "present" | "exempt" | "missing"
  evidence_present: boolean
  exemption_valid: boolean
}

function allowedReplayExemption(domain?: string) {
  return DOMAIN_REPLAY_EXEMPTIONS[domain ?? ""] ?? ["external_dependency", "operator_controlled_state"]
}

function replayVerdict(input: {
  domain?: string
  replay_present?: boolean
  replay_exemption?: ReplayExemption
}) {
  if (input.replay_present) {
    return {
      replay_state: "present" as const,
      exemption_valid: false,
      reason: "replay bundle present",
    }
  }
  if (input.replay_exemption && isStructuredReplayExemption(input.replay_exemption)) {
    const replayExemption = input.replay_exemption
    const allowed = allowedReplayExemption(input.domain)
    if (allowed.includes(replayExemption.category)) {
      return {
        replay_state: "exempt" as const,
        exemption_valid: true,
        reason: `structured replay exemption accepted (${replayExemption.category})`,
      }
    }
    return {
      replay_state: "exempt" as const,
      exemption_valid: false,
      reason: `replay exemption category not allowed for ${input.domain ?? "this domain"}`,
    }
  }
  return {
    replay_state: "missing" as const,
    exemption_valid: false,
    reason: "replay bundle missing and no structured replay exemption provided",
  }
}

export namespace Oracle {
  export const verifyFindingProof = Effect.fn("Oracle.verifyFindingProof")(function* (input: {
    operation_slug: string
    finding_key: string
    domain?: string
    evidence_refs?: string[]
    replay_present?: boolean
    replay_exemption?: ReplayExemption
    session_id?: string
    message_id?: string
  }) {
    const evidence_present = Array.isArray(input.evidence_refs) && input.evidence_refs.length > 0
    const replay = replayVerdict({
      domain: input.domain,
      replay_present: input.replay_present,
      replay_exemption: input.replay_exemption,
    })
    const passed = evidence_present && (input.replay_present || replay.exemption_valid)
    const verdict: FindingProofVerdict = {
      status: passed ? "passed" : "failed",
      reason: !evidence_present ? "finding promotion is missing evidence refs" : replay.reason,
      replay_state: replay.replay_state,
      evidence_present,
      exemption_valid: replay.exemption_valid,
    }

    const eventID = yield* Cyber.appendLedger({
      operation_slug: input.operation_slug,
      kind: passed ? "fact.verified" : "fact.observed",
      source: "oracle",
      session_id: input.session_id,
      message_id: input.message_id,
      status: passed ? "verified" : "observed",
      evidence_refs: input.evidence_refs,
      summary: `oracle proof ${verdict.status} for ${input.finding_key}`,
      data: {
        finding_key: input.finding_key,
        domain: input.domain ?? null,
        replay_state: verdict.replay_state,
        evidence_present: verdict.evidence_present,
        exemption_valid: verdict.exemption_valid,
        reason: verdict.reason,
      },
    }).pipe(Effect.catch(() => Effect.succeed("")))

    yield* Cyber.upsertFact({
      operation_slug: input.operation_slug,
      entity_kind: "finding",
      entity_key: input.finding_key,
      fact_name: "proof_verdict",
      value_json: {
        domain: input.domain,
        status: verdict.status,
        reason: verdict.reason,
        replay_state: verdict.replay_state,
        evidence_present: verdict.evidence_present,
        exemption_valid: verdict.exemption_valid,
      },
      writer_kind: "oracle",
      status: passed ? "verified" : "observed",
      confidence: passed ? 1000 : 300,
      source_event_id: eventID || undefined,
      evidence_refs: input.evidence_refs,
    }).pipe(Effect.catch(() => Effect.succeed("")))

    return verdict
  })
}
