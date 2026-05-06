export type Domain = "appsec" | "pentest" | "all"
export type Scenario = "web-surface" | "appsec-triage" | "pwn"

export type Check = {
  id: string
  label: string
  points: number
  earned: number
  evidence?: string
}

export type BenchResult = {
  scenario: Scenario
  result: {
    score: number
    max: number
    checks: Check[]
    error?: string
  }
  command_ok: boolean
  command_error: string | null
  completion_mode?: "command" | "projection" | "timeout"
  command_completed?: boolean
  projection_completed?: boolean
  aborted_after_projection?: boolean
}

export function parseArgs(argv: string[]) {
  const domainIndex = argv.indexOf("--domain")
  const domain = (domainIndex >= 0 ? argv[domainIndex + 1] : "all") as Domain
  if (!["appsec", "pentest", "all"].includes(domain)) {
    throw new Error(`invalid --domain value: ${domain}`)
  }
  return { domain }
}

export function scenariosFor(domain: Domain): Scenario[] {
  if (domain === "appsec") return ["appsec-triage"]
  if (domain === "pentest") return ["web-surface", "pwn"]
  return ["web-surface", "appsec-triage", "pwn"]
}

export function check(result: BenchResult, id: string) {
  return result.result.checks.find((item) => item.id === id)
}

export function scenarioFailures(result: BenchResult) {
  const failures: string[] = []
  if (!result.command_ok) failures.push("command_not_ok")
  if (result.command_error) failures.push("command_error")
  if (result.result.error) failures.push("scenario_error")
  if (failures.length > 0) return failures

  if (result.scenario === "appsec-triage") {
    const threshold = check(result, "threshold")
    const observations = check(result, "observations")
    const observationsProjected = check(result, "observations_projected")
    const contextArtifacts = check(result, "context_artifacts")
    const workflows = check(result, "workflow_artifacts")
    const completed = check(result, "workflow_completed_steps")
    const findings = check(result, "candidate_findings")
    const operationState = check(result, "operation_state_facts")
    const scopePolicy = check(result, "scope_policy_facts")
    const knowledgeQueries = check(result, "knowledge_queries")
    const identities = check(result, "identities")
    const activeIdentities = check(result, "active_identities")
    const deliverables = check(result, "deliverables")
    const toolAdaptersPresent = check(result, "tool_adapters_present")
    const toolAdaptersMissing = check(result, "tool_adapters_missing")
    const capsules = check(result, "capsules")
    const executedCapsules = check(result, "executed_capsules")
    const recommendedCapsules = check(result, "recommended_capsules")
    const readyVerticals = check(result, "ready_verticals")
    const degradedVerticals = check(result, "degraded_verticals")
    const unavailableVerticals = check(result, "unavailable_verticals")
    const promoted = check(result, "findings")
    const reportable = check(result, "reportable_findings")
    const verified = check(result, "verified_findings")
    const evidenceBacked = check(result, "evidence_backed_findings")
    const replayBacked = check(result, "replay_backed_findings")
    const replayExempt = check(result, "replay_exempt_findings")
    const autonomyPolicy = check(result, "autonomy_policy_facts")
    const observationCount = Number.parseInt((observations?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const projectedObservationCount = Number.parseInt((observationsProjected?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const contextArtifactCount = Number.parseInt((contextArtifacts?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const workflowCount = Number.parseInt((workflows?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const completedCount = Number.parseInt((completed?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const findingCount = Number.parseInt((findings?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const operationStateCount = Number.parseInt((operationState?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const scopePolicyCount = Number.parseInt((scopePolicy?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const knowledgeQueryCount = Number.parseInt((knowledgeQueries?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const identityCount = Number.parseInt((identities?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const activeIdentityCount = Number.parseInt((activeIdentities?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const deliverableCount = Number.parseInt((deliverables?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const toolAdaptersPresentCount = Number.parseInt((toolAdaptersPresent?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const toolAdaptersMissingCount = Number.parseInt((toolAdaptersMissing?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const capsuleCount = Number.parseInt((capsules?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const executedCapsuleCount = Number.parseInt((executedCapsules?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const recommendedCapsuleCount = Number.parseInt((recommendedCapsules?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const readyVerticalCount = Number.parseInt((readyVerticals?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const degradedVerticalCount = Number.parseInt((degradedVerticals?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const unavailableVerticalCount = Number.parseInt((unavailableVerticals?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const promotedCount = Number.parseInt((promoted?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const reportableCount = Number.parseInt((reportable?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const verifiedCount = Number.parseInt((verified?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const evidenceBackedCount = Number.parseInt((evidenceBacked?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const replayCount = Number.parseInt((replayBacked?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const replayExemptCount = Number.parseInt((replayExempt?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const autonomyPolicyCount = Number.parseInt((autonomyPolicy?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    if (!(threshold?.evidence?.startsWith("passed:") ?? false)) failures.push("appsec_threshold")
    if (!(observationCount > 0)) failures.push("appsec_observations")
    if (!(projectedObservationCount > 0)) failures.push("appsec_observations_projected")
    if (contextArtifacts && !(contextArtifactCount > 0)) failures.push("appsec_context_artifacts")
    if (!(workflowCount > 0)) failures.push("appsec_workflows")
    if (!(completedCount > 0)) failures.push("appsec_completed_steps")
    if (!(findingCount > 0)) failures.push("appsec_candidate_findings")
    if (operationState && !(operationStateCount > 0)) failures.push("appsec_operation_state_facts")
    if (scopePolicy && !(scopePolicyCount > 0)) failures.push("appsec_scope_policy_facts")
    if (knowledgeQueries && !(knowledgeQueryCount > 0)) failures.push("appsec_knowledge_queries")
    if (identities && !(identityCount > 0)) failures.push("appsec_identities")
    if (activeIdentities && !(activeIdentityCount > 0)) failures.push("appsec_active_identities")
    if (deliverables && !(deliverableCount > 0)) failures.push("appsec_deliverables")
    if ((toolAdaptersPresent || toolAdaptersMissing) && !(toolAdaptersPresentCount > 0 || toolAdaptersMissingCount > 0)) failures.push("appsec_tool_adapters")
    if ((capsules || recommendedCapsules) && !(capsuleCount > 0 || recommendedCapsuleCount > 0)) failures.push("appsec_capsules")
    if ((capsules || executedCapsules || recommendedCapsules) && !(executedCapsuleCount > 0)) failures.push("appsec_executed_capsules")
    if ((readyVerticals || degradedVerticals || unavailableVerticals) && !(readyVerticalCount > 0 || degradedVerticalCount > 0 || unavailableVerticalCount > 0)) failures.push("appsec_verticals")
    if (autonomyPolicy && !(autonomyPolicyCount > 0)) failures.push("appsec_autonomy_policy")
    if (promotedCount > 0 && !(reportableCount > 0)) failures.push("appsec_reportable_findings")
    if (promotedCount > 0 && !(verifiedCount > 0)) failures.push("appsec_verified_findings")
    if (verifiedCount > evidenceBackedCount) failures.push("appsec_evidence_backed_findings")
    if (verifiedCount > 0 && !(replayCount > 0 || replayExemptCount > 0)) failures.push("appsec_replay_backed_findings")
    return failures
  }

  if (result.scenario === "web-surface") {
    if (result.result.score < 60) failures.push("score")
    if ((check(result, "endpoints")?.earned ?? 0) === 0) failures.push("endpoints")
    if ((check(result, "forms")?.earned ?? 0) === 0) failures.push("forms")
    const workflowCount = Number.parseInt((check(result, "workflow_artifacts")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const completedCount = Number.parseInt((check(result, "workflow_completed_steps")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const routeFacts = Number.parseInt((check(result, "route_facts")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const projectedRelations = Number.parseInt((check(result, "relations_projected")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const stepStatuses = Number.parseInt((check(result, "workflow_step_statuses")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    if (!(workflowCount > 0)) failures.push("workflows")
    if (!(completedCount > 0)) failures.push("completed_steps")
    if (!(routeFacts > 0)) failures.push("route_facts")
    if (!(projectedRelations > 0)) failures.push("relations_projected")
    if (!(stepStatuses > 0)) failures.push("workflow_step_statuses")
    return failures
  }

  if (result.scenario === "pwn") {
    if (result.result.score < 70) failures.push("score")
    if ((check(result, "operation_created")?.earned ?? 0) === 0) failures.push("operation_created")
    if ((check(result, "observations")?.earned ?? 0) === 0) failures.push("observations")
    const knowledgeQueries = check(result, "knowledge_queries")
    const deliverables = check(result, "deliverables")
    const identities = check(result, "identities")
    const activeIdentities = check(result, "active_identities")
    const toolAdaptersPresent = check(result, "tool_adapters_present")
    const toolAdaptersMissing = check(result, "tool_adapters_missing")
    const capsules = check(result, "capsules")
    const executedCapsules = check(result, "executed_capsules")
    const recommendedCapsules = check(result, "recommended_capsules")
    const readyVerticals = check(result, "ready_verticals")
    const degradedVerticals = check(result, "degraded_verticals")
    const unavailableVerticals = check(result, "unavailable_verticals")
    const autonomyPolicy = check(result, "autonomy_policy_facts")
    const observationsProjected = Number.parseInt((check(result, "observations_projected")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const contextArtifacts = Number.parseInt((check(result, "context_artifacts")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const workflowCount = Number.parseInt((check(result, "workflow_artifacts")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const completedCount = Number.parseInt((check(result, "workflow_completed_steps")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const operationStateFacts = Number.parseInt((check(result, "operation_state_facts")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const scopePolicyFacts = Number.parseInt((check(result, "scope_policy_facts")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const knowledgeQueryCount = Number.parseInt((knowledgeQueries?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const identityCount = Number.parseInt((identities?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const activeIdentityCount = Number.parseInt((activeIdentities?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const deliverableCount = Number.parseInt((deliverables?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const toolAdaptersPresentCount = Number.parseInt((toolAdaptersPresent?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const toolAdaptersMissingCount = Number.parseInt((toolAdaptersMissing?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const capsuleCount = Number.parseInt((capsules?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const executedCapsuleCount = Number.parseInt((executedCapsules?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const recommendedCapsuleCount = Number.parseInt((recommendedCapsules?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const readyVerticalCount = Number.parseInt((readyVerticals?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const degradedVerticalCount = Number.parseInt((degradedVerticals?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const unavailableVerticalCount = Number.parseInt((unavailableVerticals?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const promotedCount = Number.parseInt((check(result, "findings")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const reportableCount = Number.parseInt((check(result, "reportable_findings")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const verifiedCount = Number.parseInt((check(result, "verified_findings")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const evidenceBackedCount = Number.parseInt((check(result, "evidence_backed_findings")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const replayCount = Number.parseInt((check(result, "replay_backed_findings")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const replayExemptCount = Number.parseInt((check(result, "replay_exempt_findings")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const autonomyPolicyCount = Number.parseInt((autonomyPolicy?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    if (!(observationsProjected > 0)) failures.push("pwn_observations_projected")
    if ((check(result, "context_artifacts")) && !(contextArtifacts > 0)) failures.push("pwn_context_artifacts")
    if (!(workflowCount > 0)) failures.push("workflows")
    if (!(completedCount > 0)) failures.push("completed_steps")
    if (!(operationStateFacts > 0)) failures.push("operation_state_facts")
    if ((check(result, "scope_policy_facts")) && !(scopePolicyFacts > 0)) failures.push("pwn_scope_policy_facts")
    const suspectedCount = Number.parseInt((check(result, "suspected_findings")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    const rejectedCount = Number.parseInt((check(result, "rejected_findings")?.evidence ?? "0").split(" ")[0] ?? "0", 10)
    if (identities && !(identityCount > 0)) failures.push("pwn_identities")
    if (activeIdentities && !(activeIdentityCount > 0)) failures.push("pwn_active_identities")
    if (deliverables && !(deliverableCount > 0)) failures.push("pwn_deliverables")
    if ((toolAdaptersPresent || toolAdaptersMissing) && !(toolAdaptersPresentCount > 0 || toolAdaptersMissingCount > 0)) failures.push("pwn_tool_adapters")
    if ((capsules || recommendedCapsules) && !(capsuleCount > 0 || recommendedCapsuleCount > 0)) failures.push("pwn_capsules")
    if ((capsules || executedCapsules || recommendedCapsules) && !(executedCapsuleCount > 0)) failures.push("pwn_executed_capsules")
    if ((readyVerticals || degradedVerticals || unavailableVerticals) && !(readyVerticalCount > 0 || degradedVerticalCount > 0 || unavailableVerticalCount > 0)) failures.push("pwn_verticals")
    if (autonomyPolicy && !(autonomyPolicyCount > 0)) failures.push("pwn_autonomy_policy")
    const hasOnlySurfaceFindings = promotedCount > 0 && verifiedCount === 0 && suspectedCount + rejectedCount > 0
    if (promotedCount > 0 && !hasOnlySurfaceFindings && !(reportableCount > 0)) failures.push("pwn_reportable_findings")
    if (promotedCount > 0 && !hasOnlySurfaceFindings && !(verifiedCount > 0)) failures.push("pwn_verified_findings")
    if (verifiedCount > evidenceBackedCount) failures.push("pwn_evidence_backed_findings")
    if (verifiedCount > 0 && !(replayCount > 0 || replayExemptCount > 0)) failures.push("pwn_replay_backed_findings")
    return failures
  }

  return failures
}

export function passesScenario(result: BenchResult) {
  return scenarioFailures(result).length === 0
}
