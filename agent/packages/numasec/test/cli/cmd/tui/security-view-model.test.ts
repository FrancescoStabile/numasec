import { describe, expect, test } from "bun:test"
import type { Part } from "@numasec/sdk/v2"
import {
  fallbackChains,
  fallbackCoverage,
  fallbackFindings,
  fallbackTarget,
  reportStateLabel,
  selectCurrentEndpoint,
  selectChains,
  selectCoverage,
  selectFindingSummary,
  selectFindings,
  selectReportSummary,
  selectTarget,
  type SecurityReadState,
} from "../../../../src/cli/cmd/tui/security-view-model"

function toolPart(input: {
  id: string
  tool: string
  output?: string
  state?: Record<string, unknown>
}) {
  return {
    id: input.id,
    sessionID: "ses_test",
    messageID: "msg_test",
    type: "tool",
    tool: input.tool,
    state: {
      status: "completed",
      input: input.state ?? {},
      output: input.output,
    },
  } as Part
}

describe("security view model", () => {
  test("prefers canonical read model when canonical state is available", () => {
    const messages = [{ id: "msg_test", role: "assistant" }]
    const parts: Record<string, Part[]> = {
      msg_test: [
        toolPart({
          id: "prt_target",
          tool: "security/create_session",
          state: { target: "https://legacy.example" },
        }),
        toolPart({
          id: "prt_findings",
          tool: "security/get_findings",
          output: JSON.stringify({
            findings: [
              {
                id: "LEGACY-1",
                title: "Legacy finding",
                severity: "low",
                chain_id: "LEGACY-CHAIN",
                owasp_category: "A01:2021",
                url: "https://legacy.example/login",
              },
            ],
          }),
        }),
      ],
    }

    const legacyFindings = fallbackFindings(messages, parts)
    const legacyChains = fallbackChains(messages, parts, legacyFindings)
    const legacyTarget = fallbackTarget(messages, parts)
    const legacyCoverage = fallbackCoverage(messages, parts)

    const canonical: SecurityReadState = {
      scope: ["https://canonical.example"],
      findings: [
        {
          id: "CAN-1",
          title: "Canonical SQLi",
          severity: "high",
          chain_id: "CAN-CHAIN",
          owasp_category: "A03:2021",
          url: "https://canonical.example/search",
        },
        {
          id: "CAN-2",
          title: "Canonical auth bypass",
          severity: "medium",
          chain_id: "CAN-CHAIN",
          owasp_category: "A07:2021",
          url: "https://canonical.example/admin",
        },
      ],
      chains: [
        {
          chain_id: "CAN-CHAIN",
          severity: "high",
          finding_ids: ["CAN-1", "CAN-2"],
          urls: ["https://canonical.example/search"],
        },
      ],
      coverage: [
        {
          category: "A05:2021",
          tested: true,
          finding_count: 0,
        },
      ],
      engagement: {
        engagement_target_url: "https://canonical.example",
        current_endpoint_url: "https://canonical.example/admin",
        last_tested_url: "https://canonical.example/search",
        findings: {
          total: 2,
          verified: 1,
          provisional: 1,
          suppressed: 0,
          severity: {
            critical: 0,
            high: 1,
            medium: 1,
            low: 0,
            info: 0,
          },
        },
        report: {
          state: "working_draft",
          working_ready: true,
          final_ready: false,
          final_blocked: true,
          truth_reasons: ["1 provisional reportable finding"],
          verification_debt: {
            promotion_gaps: 1,
            open_hypotheses: 1,
            open_critical_hypotheses: 0,
          },
        },
        updated_at: 1234,
        revision: 1234,
      },
    }

    const selectedFindings = selectFindings(canonical, legacyFindings)
    const selectedChains = selectChains(canonical, legacyChains, selectedFindings)
    const selectedTarget = selectTarget(canonical, legacyTarget)
    const selectedEndpoint = selectCurrentEndpoint(canonical)
    const selectedSummary = selectFindingSummary(canonical, selectedFindings)
    const selectedReport = selectReportSummary(canonical)
    const selectedCoverage = selectCoverage(canonical, legacyCoverage, selectedFindings)

    expect(selectedFindings.map((item) => item.id)).toEqual(["CAN-1", "CAN-2"])
    expect(selectedChains.map((item) => item.chain_id)).toEqual(["CAN-CHAIN"])
    expect(selectedTarget).toBe("https://canonical.example")
    expect(selectedEndpoint).toBe("https://canonical.example/admin")
    expect(selectedSummary.verified).toBe(1)
    expect(selectedSummary.provisional).toBe(1)
    expect(selectedReport?.state).toBe("working_draft")
    expect(selectedReport?.final_snapshot.state).toBe("absent")
    expect(selectedCoverage.tested.has("A05")).toBe(true)
    expect(selectedCoverage.vulnerable.has("A03")).toBe(true)
  })

  test("does not resurrect parsed tool output when canonical state is present but empty", () => {
    const messages = [{ id: "msg_test", role: "assistant" }]
    const parts: Record<string, Part[]> = {
      msg_test: [
        toolPart({
          id: "prt_target",
          tool: "security/recon",
          state: { target: "https://legacy.example" },
        }),
        toolPart({
          id: "prt_findings",
          tool: "security/get_findings",
          output: JSON.stringify({
            findings: [
              {
                id: "LEGACY-1",
                title: "Legacy finding",
                severity: "high",
                chain_id: "LEGACY-CHAIN",
                owasp_category: "A02:2021",
                url: "https://legacy.example/login",
              },
              {
                id: "LEGACY-2",
                title: "Legacy second finding",
                severity: "medium",
                chain_id: "LEGACY-CHAIN",
                owasp_category: "A03:2021",
                url: "https://legacy.example/admin",
              },
            ],
          }),
        }),
      ],
    }

    const legacyFindings = fallbackFindings(messages, parts)
    const legacyChains = fallbackChains(messages, parts, legacyFindings)
    const legacyTarget = fallbackTarget(messages, parts)
    const legacyCoverage = fallbackCoverage(messages, parts)

    const canonical: SecurityReadState = {
      scope: [],
      findings: [],
      chains: [],
      coverage: [],
    }

    const selectedFindings = selectFindings(canonical, legacyFindings)
    const selectedChains = selectChains(canonical, legacyChains, selectedFindings)
    const selectedTarget = selectTarget(canonical, legacyTarget)
    const selectedEndpoint = selectCurrentEndpoint(canonical)
    const selectedSummary = selectFindingSummary(canonical, selectedFindings)
    const selectedReport = selectReportSummary(canonical)
    const selectedCoverage = selectCoverage(canonical, legacyCoverage, selectedFindings)

    expect(selectedFindings).toEqual([])
    expect(selectedChains).toEqual([])
    expect(selectedTarget).toBeUndefined()
    expect(selectedEndpoint).toBeUndefined()
    expect(selectedSummary.total).toBe(0)
    expect(selectedReport).toBeUndefined()
    expect(selectedCoverage.testedCount).toBe(0)
    expect(selectedCoverage.vulnerable.has("A02")).toBe(false)
  })

  test("falls back to parsed tool output only when canonical state is unavailable", () => {
    const messages = [{ id: "msg_test", role: "assistant" }]
    const parts: Record<string, Part[]> = {
      msg_test: [
        toolPart({
          id: "prt_target",
          tool: "security/recon",
          state: { target: "https://legacy.example" },
        }),
        toolPart({
          id: "prt_findings",
          tool: "security/get_findings",
          output: JSON.stringify({
            findings: [
              {
                id: "LEGACY-1",
                title: "Legacy finding",
                severity: "high",
                chain_id: "LEGACY-CHAIN",
                owasp_category: "A02:2021",
                url: "https://legacy.example/login",
              },
              {
                id: "LEGACY-2",
                title: "Legacy second finding",
                severity: "medium",
                chain_id: "LEGACY-CHAIN",
                owasp_category: "A03:2021",
                url: "https://legacy.example/admin",
              },
            ],
          }),
        }),
      ],
    }

    const legacyFindings = fallbackFindings(messages, parts)
    const legacyChains = fallbackChains(messages, parts, legacyFindings)
    const legacyTarget = fallbackTarget(messages, parts)
    const legacyCoverage = fallbackCoverage(messages, parts)

    const selectedFindings = selectFindings(undefined, legacyFindings)
    const selectedChains = selectChains(undefined, legacyChains, selectedFindings)
    const selectedTarget = selectTarget(undefined, legacyTarget)
    const selectedEndpoint = selectCurrentEndpoint(undefined)
    const selectedSummary = selectFindingSummary(undefined, selectedFindings)
    const selectedReport = selectReportSummary(undefined)
    const selectedCoverage = selectCoverage(undefined, legacyCoverage, selectedFindings)

    expect(selectedFindings.map((item) => item.id)).toEqual(["LEGACY-1", "LEGACY-2"])
    expect(selectedChains.map((item) => item.chain_id)).toEqual(["LEGACY-CHAIN"])
    expect(selectedTarget).toBe("https://legacy.example")
    expect(selectedEndpoint).toBeUndefined()
    expect(selectedSummary.total).toBe(2)
    expect(selectedSummary.verified).toBe(2)
    expect(selectedReport).toBeUndefined()
    expect(selectedCoverage.vulnerable.has("A02")).toBe(true)
  })

  test("does not derive canonical target from finding urls when scope and engagement target are absent", () => {
    const canonical: SecurityReadState = {
      findings: [
        {
          id: "CAN-1",
          title: "Endpoint finding",
          severity: "high",
          url: "https://canonical.example/rest/user/security-question",
        },
      ],
      engagement: {
        engagement_target_url: null,
        current_endpoint_url: "https://canonical.example/rest/user/security-question",
        last_tested_url: "https://canonical.example/rest/user/security-question",
        findings: {
          total: 1,
          verified: 1,
          provisional: 0,
          suppressed: 0,
          severity: {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            info: 0,
          },
        },
        report: {
          state: "working_draft",
          working_ready: true,
          final_ready: false,
          final_blocked: true,
          truth_reasons: [],
          verification_debt: {
            promotion_gaps: 0,
            open_hypotheses: 0,
            open_critical_hypotheses: 0,
          },
        },
        updated_at: 99,
        revision: 99,
      },
    }

    expect(selectTarget(canonical, "https://legacy.example")).toBeUndefined()
    expect(selectCurrentEndpoint(canonical)).toBe("https://canonical.example/rest/user/security-question")
  })

  test("keeps build_chains parser fallback for legacy sessions without canonical findings", () => {
    const messages = [{ id: "msg_test", role: "assistant" }]
    const parts: Record<string, Part[]> = {
      msg_test: [
        toolPart({
          id: "prt_chain",
          tool: "security/build_chains",
          output: JSON.stringify({
            chains: {
              "LEGACY-CHAIN": ["SSEC-LEG-1", "SSEC-LEG-2"],
            },
          }),
        }),
      ],
    }

    const legacyFindings = fallbackFindings(messages, parts)
    const legacyChains = fallbackChains(messages, parts, legacyFindings)

    expect(legacyFindings.length).toBe(0)
    expect(legacyChains.length).toBe(1)
    expect(legacyChains[0].chain_id).toBe("LEGACY-CHAIN")
    expect(legacyChains[0].items.map((item) => item.title)).toEqual(["SSEC-LEG-1", "SSEC-LEG-2"])
  })

  test("preserves canonical reopened final snapshot state", () => {
    const canonical: SecurityReadState = {
      engagement: {
        engagement_target_url: "https://canonical.example",
        current_endpoint_url: "https://canonical.example/admin",
        last_tested_url: "https://canonical.example/admin",
        findings: {
          total: 1,
          verified: 1,
          provisional: 0,
          suppressed: 0,
          severity: {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            info: 0,
          },
        },
        report: {
          state: "final_ready",
          working_ready: true,
          final_ready: true,
          final_blocked: false,
          truth_reasons: [],
          final_snapshot: {
            state: "reopened",
            exported_at: 10,
            exported_revision: 5,
          },
          verification_debt: {
            promotion_gaps: 0,
            open_hypotheses: 0,
            open_critical_hypotheses: 0,
          },
        },
        updated_at: 12,
        revision: 12,
      },
    }

    expect(selectReportSummary(canonical)?.final_snapshot.state).toBe("reopened")
    expect(selectReportSummary(canonical)?.final_snapshot.exported_revision).toBe(5)
  })

  test("reports explicit labels for exported and reopened final snapshots", () => {
    expect(
      reportStateLabel({
        state: "final_ready",
        working_ready: true,
        final_ready: true,
        final_blocked: false,
        truth_reasons: [],
        final_snapshot: {
          state: "current",
          exported_at: 10,
          exported_revision: 5,
        },
        verification_debt: {
          promotion_gaps: 0,
          open_hypotheses: 0,
          open_critical_hypotheses: 0,
        },
      }),
    ).toBe("Final snapshot exported")

    expect(
      reportStateLabel({
        state: "working_draft",
        working_ready: true,
        final_ready: false,
        final_blocked: true,
        truth_reasons: ["1 provisional finding"],
        final_snapshot: {
          state: "reopened",
          exported_at: 10,
          exported_revision: 5,
        },
        verification_debt: {
          promotion_gaps: 1,
          open_hypotheses: 1,
          open_critical_hypotheses: 0,
        },
      }),
    ).toBe("Reopened after final export")
  })
})
