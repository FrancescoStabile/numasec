import { describe, expect, test } from "bun:test"
import {
  findingsBadgeCount,
  findingsRows,
  replayCoveredCount,
  reportStatus,
  type OperationConsoleSnapshot,
} from "../../../src/cli/cmd/tui/component/operation-lens/snapshot"

describe("tui operation lens snapshot helpers", () => {
  test("findingsRows sorts by severity then proof status", () => {
    const snapshot = {
      directory: "/tmp/project",
      evidenceCount: 0,
      evidenceEntries: [],
      timeline: [],
      projected: {
        findings: [
          {
            key: "cand-low",
            kind: "candidate",
            status: "candidate",
            title: "Candidate low",
            severity: "low",
          },
          {
            key: "sus-high",
            kind: "finding",
            status: "observed",
            title: "Suspected high",
            severity: "high",
            evidence_refs: ["ev1"],
            replay_present: false,
          },
          {
            key: "rep-high",
            kind: "finding",
            status: "verified",
            title: "Reportable high",
            severity: "high",
            evidence_refs: ["ev1"],
            replay_present: true,
          },
          {
            key: "rej-critical",
            kind: "finding",
            status: "rejected",
            title: "Rejected critical",
            severity: "critical",
          },
        ],
        summary: {
          reportable_findings: 1,
          verified_findings: 1,
          replay_backed_findings: 1,
          replay_exempt_findings: 0,
          findings: 3,
          candidate_findings: 1,
        },
      },
    } as unknown as OperationConsoleSnapshot

    const rows = findingsRows(snapshot)
    expect(rows.map((item) => `${item.severityCode}:${item.status}:${item.title}`)).toEqual([
      "C:rejected:Rejected critical",
      "H:reportable:Reportable high",
      "H:suspected:Suspected high",
      "L:candidate:Candidate low",
    ])
  })

  test("badge, replay, and report summaries derive from the snapshot", () => {
    const snapshot = {
      directory: "/tmp/project",
      evidenceCount: 12,
      evidenceEntries: [],
      timeline: [],
      deliverable: {
        key: "bundle",
        report_path: "/tmp/project/report.md",
        time_updated: 1,
      },
      projected: {
        findings: [],
        summary: {
          reportable_findings: 2,
          verified_findings: 3,
          replay_backed_findings: 2,
          replay_exempt_findings: 1,
          findings: 3,
          candidate_findings: 0,
        },
      },
    } as unknown as OperationConsoleSnapshot

    expect(findingsBadgeCount(snapshot)).toBe(2)
    expect(replayCoveredCount(snapshot)).toBe(3)
    expect(reportStatus(snapshot)).toBe("ready")
  })
})
