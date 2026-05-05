import { describe, expect, test } from "bun:test"
import {
  candidateSummary,
  candidateTitle,
  isRejectedFinding,
  isReplayBackedFinding,
  isReplayExemptFinding,
  isReportableFinding,
  isStructuredReplayExemption,
  isSuspectedFinding,
  normalizeReplayExemption,
  replayState,
  summarizeFindingFact,
} from "../../../src/core/cyber/finding"

describe("core/cyber/finding", () => {
  test("classifies reportable, suspected, and rejected findings", () => {
    expect(
      isReportableFinding({
        kind: "finding",
        status: "verified",
        evidence_refs: ["ev1"],
        replay_present: true,
      }),
    ).toBe(true)
    expect(isSuspectedFinding({ kind: "candidate", status: "candidate" })).toBe(true)
    expect(isRejectedFinding({ kind: "finding", status: "rejected" })).toBe(true)
    expect(isSuspectedFinding({ kind: "finding", status: "rejected" })).toBe(false)
  })

  test("derives replay state consistently", () => {
    expect(replayState({ kind: "candidate" })).toBeUndefined()
    expect(replayState({ kind: "finding", replay_present: true })).toBe("present")
    expect(replayState({ kind: "finding", replay_present: false, replay_reason: "manual-only" })).toBe("exempt")
    expect(replayState({ kind: "finding", replay_present: false })).toBe("missing")
    expect(isReplayBackedFinding({ kind: "finding", replay_present: true })).toBe(true)
    expect(isReplayExemptFinding({ kind: "finding", replay_present: false, replay_reason: "manual-only" })).toBe(true)
    expect(
      isStructuredReplayExemption(
        normalizeReplayExemption({
          replay_exemption: {
            category: "external_dependency",
            rationale: "3rd party callback unavailable",
          },
        }),
      ),
    ).toBe(true)
  })

  test("summarizes candidate and promoted finding facts consistently", () => {
    const candidate = summarizeFindingFact({
      id: "f1",
      project_id: "p1",
      operation_slug: "op1",
      entity_kind: "finding_candidate",
      entity_key: "cand_1",
      fact_name: "container_vulnerability",
      value_json: {
        check_name: "Outdated package",
        description: "candidate only",
        severity: "high",
      },
      writer_kind: "parser",
      status: "candidate",
      time_created: 1,
      time_updated: 1,
    })
    const promoted = summarizeFindingFact({
      id: "f2",
      project_id: "p1",
      operation_slug: "op1",
      entity_kind: "finding",
      entity_key: "find_1",
      fact_name: "record",
      value_json: {
        title: "Confirmed issue",
        summary: "verified by replay",
        severity: "critical",
        replay_present: true,
        oracle_status: "passed",
      },
      writer_kind: "operator",
      status: "verified",
      evidence_refs: ["ev1"],
      time_created: 1,
      time_updated: 1,
    })

    expect(candidate?.title).toBe("Outdated package")
    expect(candidate?.summary).toBe("candidate only")
    expect(candidate?.severity).toBe("high")
    expect(promoted?.kind).toBe("finding")
    expect(promoted?.title).toBe("Confirmed issue")
    expect(promoted?.summary).toBe("verified by replay")
    expect(promoted?.replay_present).toBe(true)
    expect(promoted?.oracle_status).toBe("passed")
    expect(candidateTitle("record", { line: "GET /admin" }, "k")).toBe("GET /admin")
    expect(candidateSummary({ message: "msg" })).toBe("msg")
  })
})
