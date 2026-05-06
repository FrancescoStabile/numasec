import { describe, expect, test } from "bun:test"
import { parseArgs, passesScenario, scenarioFailures, scenariosFor, type BenchResult } from "../../script/bench/cyber-lib"
import { scoreWebSurface } from "../../script/bench/rubric"

function result(input: Partial<BenchResult> & Pick<BenchResult, "scenario">): BenchResult {
  return {
    scenario: input.scenario,
    command_ok: input.command_ok ?? true,
    command_error: input.command_error ?? null,
    completion_mode: input.completion_mode ?? "command",
    command_completed: input.command_completed ?? true,
    projection_completed: input.projection_completed ?? false,
    aborted_after_projection: input.aborted_after_projection ?? false,
    result: {
      score: input.result?.score ?? 100,
      max: input.result?.max ?? 100,
      checks: input.result?.checks ?? [],
      error: input.result?.error,
    },
  }
}

describe("script/bench/cyber-lib", () => {
  test("parses domain args with all as default", () => {
    expect(parseArgs([])).toEqual({ domain: "all" })
    expect(parseArgs(["--domain", "appsec"])).toEqual({ domain: "appsec" })
    expect(() => parseArgs(["--domain", "weird"])).toThrow("invalid --domain value")
  })

  test("maps domains to scenarios", () => {
    expect(scenariosFor("appsec")).toEqual(["appsec-triage"])
    expect(scenariosFor("pentest")).toEqual(["web-surface", "pwn"])
    expect(scenariosFor("all")).toEqual(["web-surface", "appsec-triage", "pwn"])
  })

  test("bench result can represent projection-based completion without forcing command failure", () => {
    const bench = result({
      scenario: "web-surface",
      completion_mode: "projection",
      command_completed: false,
      projection_completed: true,
      aborted_after_projection: true,
      result: {
        score: 90,
        max: 100,
        checks: [
          { id: "endpoints", label: "endpoints", points: 50, earned: 50 },
          { id: "forms", label: "forms", points: 30, earned: 30 },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "route_facts", label: "routes", points: 0, earned: 0, evidence: "1 facts" },
          { id: "relations_projected", label: "rels", points: 0, earned: 0, evidence: "1 relations" },
          { id: "workflow_step_statuses", label: "steps", points: 0, earned: 0, evidence: "1 facts" },
        ],
      },
    })
    expect(passesScenario(bench)).toBe(true)
  })

  test("fails appsec when threshold check is not passed", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "failed: 1/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "3 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "3 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "2 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(passesScenario(bench)).toBe(false)
    expect(scenarioFailures(bench)).toContain("appsec_threshold")
  })

  test("fails appsec when no evidence artifacts were captured", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "0 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "0 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "2 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(passesScenario(bench)).toBe(false)
    expect(scenarioFailures(bench)).toContain("appsec_observations")
    expect(scenarioFailures(bench)).toContain("appsec_observations_projected")
  })

  test("fails appsec when no active context artifact was projected", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "context_artifacts", label: "ctx", points: 0, earned: 0, evidence: "0 files" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("appsec_context_artifacts")
  })

  test("fails appsec when no workflow artifacts were projected", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "0 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(passesScenario(bench)).toBe(false)
    expect(scenarioFailures(bench)).toContain("appsec_workflows")
  })

  test("fails appsec when no workflow steps completed", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "0 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(passesScenario(bench)).toBe(false)
    expect(scenarioFailures(bench)).toContain("appsec_completed_steps")
  })

  test("fails appsec when no candidate findings were projected", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(passesScenario(bench)).toBe(false)
    expect(scenarioFailures(bench)).toContain("appsec_candidate_findings")
  })

  test("fails appsec when operation state is expected but not projected", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("appsec_operation_state_facts")
  })

  test("fails appsec when scope policy is expected but not projected", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "scope_policy_facts", label: "scope", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("appsec_scope_policy_facts")
  })

  test("fails appsec when knowledge queries are expected but none were projected", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "knowledge_queries", label: "kq", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("appsec_knowledge_queries")
  })

  test("fails appsec when identity checks are present but no identity state was projected", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "identities", label: "ident", points: 0, earned: 0, evidence: "0 facts" },
          { id: "active_identities", label: "act-ident", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("appsec_identities")
    expect(scenarioFailures(bench)).toContain("appsec_active_identities")
  })

  test("fails appsec when deliverable checks are present but no bundle was projected", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "deliverables", label: "deliv", points: 0, earned: 0, evidence: "0 bundles" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("appsec_deliverables")
  })

  test("fails appsec when capsule checks are present but no readiness or recommendation facts were projected", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "knowledge_queries", label: "kq", points: 0, earned: 0, evidence: "1 facts" },
          { id: "capsules", label: "caps", points: 0, earned: 0, evidence: "0 facts" },
          { id: "executed_capsules", label: "exec", points: 0, earned: 0, evidence: "0 facts" },
          { id: "recommended_capsules", label: "rec", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("appsec_capsules")
    expect(scenarioFailures(bench)).toContain("appsec_executed_capsules")
  })

  test("fails appsec when capsule readiness exists but no capsule execution was projected", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "knowledge_queries", label: "kq", points: 0, earned: 0, evidence: "1 facts" },
          { id: "capsules", label: "caps", points: 0, earned: 0, evidence: "1 facts" },
          { id: "executed_capsules", label: "exec", points: 0, earned: 0, evidence: "0 facts" },
          { id: "recommended_capsules", label: "rec", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("appsec_executed_capsules")
    expect(scenarioFailures(bench)).not.toContain("appsec_capsules")
  })

  test("fails appsec when tool inventory or autonomy policy checks are present but unprojected", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "tool_adapters_present", label: "tap", points: 0, earned: 0, evidence: "0 facts" },
          { id: "tool_adapters_missing", label: "tam", points: 0, earned: 0, evidence: "0 facts" },
          { id: "ready_verticals", label: "rv", points: 0, earned: 0, evidence: "0 facts" },
          { id: "degraded_verticals", label: "dv", points: 0, earned: 0, evidence: "0 facts" },
          { id: "unavailable_verticals", label: "uv", points: 0, earned: 0, evidence: "0 facts" },
          { id: "autonomy_policy_facts", label: "ap", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("appsec_tool_adapters")
    expect(scenarioFailures(bench)).toContain("appsec_verticals")
    expect(scenarioFailures(bench)).toContain("appsec_autonomy_policy")
  })

  test("fails appsec when promoted findings exist without verified status", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "1 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "2 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(passesScenario(bench)).toBe(false)
    expect(scenarioFailures(bench)).toContain("appsec_reportable_findings")
    expect(scenarioFailures(bench)).toContain("appsec_verified_findings")
  })

  test("fails appsec when verified findings exist without replay-backed proof", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "1 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "1 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "1 facts" },
          { id: "evidence_backed_findings", label: "eb", points: 0, earned: 0, evidence: "1 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(passesScenario(bench)).toBe(false)
    expect(scenarioFailures(bench)).toContain("appsec_replay_backed_findings")
  })

  test("allows appsec verified findings when replay is explicitly exempt", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "1 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "1 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "1 facts" },
          { id: "evidence_backed_findings", label: "eb", points: 0, earned: 0, evidence: "1 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_exempt_findings", label: "re", points: 0, earned: 0, evidence: "1 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).not.toContain("appsec_replay_backed_findings")
  })

  test("fails appsec when verified findings are not evidence-backed", () => {
    const bench = result({
      scenario: "appsec-triage",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "threshold", label: "gate", points: 0, earned: 0, evidence: "passed: 2/5" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "candidate_findings", label: "find", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "1 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "1 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "1 facts" },
          { id: "evidence_backed_findings", label: "eb", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "1 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("appsec_evidence_backed_findings")
  })

  test("requires endpoints and forms for web-surface", () => {
    const bench = result({
      scenario: "web-surface",
      result: {
        score: 90,
        max: 100,
        checks: [
          { id: "endpoints", label: "endpoints", points: 50, earned: 0 },
          { id: "forms", label: "forms", points: 30, earned: 30 },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "route_facts", label: "routes", points: 0, earned: 0, evidence: "1 facts" },
          { id: "relations_projected", label: "rels", points: 0, earned: 0, evidence: "1 relations" },
          { id: "workflow_step_statuses", label: "steps", points: 0, earned: 0, evidence: "1 facts" },
        ],
      },
    })
    expect(passesScenario(bench)).toBe(false)
    expect(scenarioFailures(bench)).toContain("endpoints")
  })

  test("scores web-surface forms from projected http_form facts", () => {
    const scored = scoreWebSurface("", {
      slug: "op-1",
      observations: 0,
      observations_projected: 0,
      context_artifacts: 0,
      workflows: 1,
      completed_steps: 1,
      route_facts: 1,
      http_forms: 3,
      relations_projected: 1,
      workflow_step_statuses: 1,
      candidate_findings: 0,
      findings: 0,
      knowledge_queries: 0,
      identities: 0,
      active_identities: 0,
      deliverables: 0,
      tool_adapters_present: 0,
      tool_adapters_missing: 0,
      capsules: 0,
      executed_capsules: 0,
      recommended_capsules: 0,
      ready_capsules: 0,
      degraded_capsules: 0,
      unavailable_capsules: 0,
      ready_verticals: 0,
      degraded_verticals: 0,
      unavailable_verticals: 0,
      reportable_findings: 0,
      suspected_findings: 0,
      rejected_findings: 0,
      verified_findings: 0,
      evidence_backed_findings: 0,
      replay_backed_findings: 0,
      replay_exempt_findings: 0,
      operation_state_facts: 0,
      scope_policy_facts: 0,
      autonomy_policy_facts: 0,
    })
    expect(scored.checks.find((item) => item.id === "forms")?.earned).toBe(30)
  })

  test("requires operation creation and observations for pwn", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 0 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "0 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(passesScenario(bench)).toBe(false)
    expect(scenarioFailures(bench)).toContain("observations")
    expect(scenarioFailures(bench)).toContain("pwn_observations_projected")
  })

  test("fails pwn when no active context artifact was projected", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "context_artifacts", label: "ctx", points: 0, earned: 0, evidence: "0 files" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("pwn_context_artifacts")
  })

  test("requires workflow artifacts for pentest scenarios", () => {
    const web = result({
      scenario: "web-surface",
      result: {
        score: 90,
        max: 100,
        checks: [
          { id: "endpoints", label: "endpoints", points: 50, earned: 50 },
          { id: "forms", label: "forms", points: 30, earned: 30 },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "0 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "0 steps" },
          { id: "route_facts", label: "routes", points: 0, earned: 0, evidence: "1 facts" },
          { id: "relations_projected", label: "rels", points: 0, earned: 0, evidence: "1 relations" },
          { id: "workflow_step_statuses", label: "steps", points: 0, earned: 0, evidence: "1 facts" },
        ],
      },
    })
    const pwn = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "0 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "0 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(web)).toContain("workflows")
    expect(scenarioFailures(pwn)).toContain("workflows")
  })

  test("requires completed workflow steps for pentest scenarios", () => {
    const web = result({
      scenario: "web-surface",
      result: {
        score: 90,
        max: 100,
        checks: [
          { id: "endpoints", label: "endpoints", points: 50, earned: 50 },
          { id: "forms", label: "forms", points: 30, earned: 30 },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "0 steps" },
          { id: "route_facts", label: "routes", points: 0, earned: 0, evidence: "1 facts" },
          { id: "relations_projected", label: "rels", points: 0, earned: 0, evidence: "1 relations" },
          { id: "workflow_step_statuses", label: "steps", points: 0, earned: 0, evidence: "1 facts" },
        ],
      },
    })
    const pwn = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "0 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(web)).toContain("completed_steps")
    expect(scenarioFailures(pwn)).toContain("completed_steps")
  })

  test("requires structured cyber projections for pentest scenarios", () => {
    const web = result({
      scenario: "web-surface",
      result: {
        score: 90,
        max: 100,
        checks: [
          { id: "endpoints", label: "endpoints", points: 50, earned: 50 },
          { id: "forms", label: "forms", points: 30, earned: 30 },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "route_facts", label: "routes", points: 0, earned: 0, evidence: "0 facts" },
          { id: "relations_projected", label: "rels", points: 0, earned: 0, evidence: "0 relations" },
          { id: "workflow_step_statuses", label: "steps", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    const pwn = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(web)).toContain("route_facts")
    expect(scenarioFailures(web)).toContain("relations_projected")
    expect(scenarioFailures(web)).toContain("workflow_step_statuses")
    expect(scenarioFailures(pwn)).toContain("operation_state_facts")
  })

  test("does not fail pwn solely because no knowledge queries were projected", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "knowledge_queries", label: "kq", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).not.toContain("pwn_knowledge_queries")
  })

  test("fails pwn when identity checks are present but no identity state was projected", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 90,
        max: 100,
        checks: [
          { id: "operation_created", label: "op", points: 0, earned: 0, evidence: "created" },
          { id: "observations", label: "obs", points: 0, earned: 0, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "context_artifacts", label: "ctx", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "scope_policy_facts", label: "scope", points: 0, earned: 0, evidence: "1 facts" },
          { id: "identities", label: "ident", points: 0, earned: 0, evidence: "0 facts" },
          { id: "active_identities", label: "act-ident", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("pwn_identities")
    expect(scenarioFailures(bench)).toContain("pwn_active_identities")
  })

  test("fails pwn when scope policy is expected but not projected", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "scope_policy_facts", label: "scope", points: 0, earned: 0, evidence: "0 facts" },
          { id: "knowledge_queries", label: "kq", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("pwn_scope_policy_facts")
  })

  test("fails pwn when capsule checks are present but no readiness or recommendation facts were projected", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "knowledge_queries", label: "kq", points: 0, earned: 0, evidence: "1 facts" },
          { id: "capsules", label: "caps", points: 0, earned: 0, evidence: "0 facts" },
          { id: "executed_capsules", label: "exec", points: 0, earned: 0, evidence: "0 facts" },
          { id: "recommended_capsules", label: "rec", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("pwn_capsules")
    expect(scenarioFailures(bench)).toContain("pwn_executed_capsules")
  })

  test("fails pwn when capsule readiness exists but no capsule execution was projected", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "knowledge_queries", label: "kq", points: 0, earned: 0, evidence: "1 facts" },
          { id: "capsules", label: "caps", points: 0, earned: 0, evidence: "1 facts" },
          { id: "executed_capsules", label: "exec", points: 0, earned: 0, evidence: "0 facts" },
          { id: "recommended_capsules", label: "rec", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("pwn_executed_capsules")
    expect(scenarioFailures(bench)).not.toContain("pwn_capsules")
  })

  test("fails pwn when tool inventory, verticals, or autonomy policy checks are present but unprojected", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "tool_adapters_present", label: "tap", points: 0, earned: 0, evidence: "0 facts" },
          { id: "tool_adapters_missing", label: "tam", points: 0, earned: 0, evidence: "0 facts" },
          { id: "ready_verticals", label: "rv", points: 0, earned: 0, evidence: "0 facts" },
          { id: "degraded_verticals", label: "dv", points: 0, earned: 0, evidence: "0 facts" },
          { id: "unavailable_verticals", label: "uv", points: 0, earned: 0, evidence: "0 facts" },
          { id: "autonomy_policy_facts", label: "ap", points: 0, earned: 0, evidence: "0 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("pwn_tool_adapters")
    expect(scenarioFailures(bench)).toContain("pwn_verticals")
    expect(scenarioFailures(bench)).toContain("pwn_autonomy_policy")
  })

  test("fails pwn when deliverable checks are present but no bundle was projected", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 80,
        max: 100,
        checks: [
          { id: "operation_created", label: "op", points: 40, earned: 40, evidence: "slug-1" },
          { id: "observations", label: "obs", points: 30, earned: 30, evidence: "2 files" },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "2 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "os", points: 0, earned: 0, evidence: "1 facts" },
          { id: "deliverables", label: "deliv", points: 0, earned: 0, evidence: "0 bundles" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "0 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("pwn_deliverables")
  })

  test("allows suspected-only pwn findings without forcing verified or reportable promotion", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "1 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "0 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "1 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).not.toContain("pwn_reportable_findings")
    expect(scenarioFailures(bench)).not.toContain("pwn_verified_findings")

    const replayMissing = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "1 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "1 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "1 facts" },
          { id: "evidence_backed_findings", label: "eb", points: 0, earned: 0, evidence: "1 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
        ],
      },
    })
    expect(scenarioFailures(replayMissing)).toContain("pwn_replay_backed_findings")
  })

  test("allows pwn verified findings when replay is explicitly exempt", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "1 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "1 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "1 facts" },
          { id: "evidence_backed_findings", label: "eb", points: 0, earned: 0, evidence: "1 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_exempt_findings", label: "re", points: 0, earned: 0, evidence: "1 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).not.toContain("pwn_replay_backed_findings")
  })

  test("fails pwn when verified findings are not evidence-backed", () => {
    const bench = result({
      scenario: "pwn",
      result: {
        score: 100,
        max: 100,
        checks: [
          { id: "operation_created", label: "operation", points: 40, earned: 40 },
          { id: "observations", label: "observations", points: 30, earned: 30 },
          { id: "observations_projected", label: "obsp", points: 0, earned: 0, evidence: "1 facts" },
          { id: "workflow_artifacts", label: "wf", points: 0, earned: 0, evidence: "1 files" },
          { id: "workflow_completed_steps", label: "wfc", points: 0, earned: 0, evidence: "1 steps" },
          { id: "operation_state_facts", label: "ops", points: 0, earned: 0, evidence: "1 facts" },
          { id: "findings", label: "finding", points: 0, earned: 0, evidence: "1 facts" },
          { id: "reportable_findings", label: "reportable", points: 0, earned: 0, evidence: "1 facts" },
          { id: "suspected_findings", label: "suspected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "rejected_findings", label: "rejected", points: 0, earned: 0, evidence: "0 facts" },
          { id: "verified_findings", label: "vf", points: 0, earned: 0, evidence: "1 facts" },
          { id: "evidence_backed_findings", label: "eb", points: 0, earned: 0, evidence: "0 facts" },
          { id: "replay_backed_findings", label: "rf", points: 0, earned: 0, evidence: "1 facts" },
        ],
      },
    })
    expect(scenarioFailures(bench)).toContain("pwn_evidence_backed_findings")
  })

  test("fails immediately on command or scenario errors", () => {
    const bench = result({
      scenario: "pwn",
      command_ok: false,
      command_error: "boom",
      result: { score: 0, max: 100, checks: [], error: "broken" },
    })
    expect(scenarioFailures(bench)).toEqual(["command_not_ok", "command_error", "scenario_error"])
  })
})
