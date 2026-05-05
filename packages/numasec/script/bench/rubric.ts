// Rubrics for the three benchmark scenarios. Each rubric takes the raw text
// corpus produced by the numasec session (derived operation context first,
// legacy numasec.md only as fallback, plus concatenated assistant message parts)
// and returns a 0-100 score plus per-check details.
//
// Scoring prefers structured kernel artifacts and uses free text only as a
// recall supplement. A benchmark should not pass because the assistant named
// the right issue while failing to persist evidence-backed state.

export type Check = {
  id: string
  label: string
  points: number
  earned: number
  evidence?: string
}

export type Score = {
  scenario: string
  score: number
  max: number
  checks: Check[]
}

function countMatches(corpus: string, re: RegExp): string[] {
  const m = corpus.match(re)
  return m ? Array.from(new Set(m)) : []
}

function awardProRata(found: number, target: number, points: number): number {
  if (target <= 0) return points
  return Math.round((Math.min(found, target) / target) * points)
}

type OpContext = {
  slug?: string
  observations: number
  observations_projected: number
  context_artifacts: number
  workflows: number
  completed_steps: number
  route_facts: number
  relations_projected: number
  workflow_step_statuses: number
  candidate_findings: number
  findings: number
  knowledge_queries: number
  identities: number
  active_identities: number
  deliverables: number
  tool_adapters_present: number
  tool_adapters_missing: number
  capsules: number
  executed_capsules: number
  recommended_capsules: number
  ready_capsules: number
  degraded_capsules: number
  unavailable_capsules: number
  ready_verticals: number
  degraded_verticals: number
  unavailable_verticals: number
  reportable_findings: number
  suspected_findings: number
  rejected_findings: number
  verified_findings: number
  evidence_backed_findings: number
  replay_backed_findings: number
  replay_exempt_findings: number
  operation_state_facts: number
  scope_policy_facts: number
  autonomy_policy_facts: number
}

export function scoreWebSurface(corpus: string, opContext: OpContext): Score {
  const endpoints = countMatches(corpus, /\/(rest|api)\/[A-Za-z0-9_\-\/]+/g)
  const forms = countMatches(corpus, /<form[^>]*|type=["']password["']|name=["'](email|password|login|username)["']/gi)
  const secretsShape = /(api[_-]?key|secret|token|jwt|bearer|password)\s*[:=]\s*["'][A-Za-z0-9+/=_.\-]{16,}["']/i.test(
    corpus,
  ) || /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/.test(corpus)

  const checks: Check[] = [
    {
      id: "endpoints",
      label: "≥20 endpoints discovered",
      points: 50,
      earned: awardProRata(Math.max(endpoints.length, opContext.route_facts), 20, 50),
      evidence: `${Math.max(endpoints.length, opContext.route_facts)} observed/projection hits`,
    },
    {
      id: "forms",
      label: "≥3 forms / credential fields",
      points: 30,
      earned: awardProRata(forms.length, 3, 30),
      evidence: `${forms.length} hits`,
    },
    {
      id: "secrets_shape",
      label: "≥1 secret-shaped string in a JS chunk",
      points: 20,
      earned: secretsShape ? 20 : 0,
    },
    {
      id: "workflow_artifacts",
      label: "≥1 workflow artifact projected under the operation",
      points: 0,
      earned: 0,
      evidence: `${opContext.workflows} files`,
    },
    {
      id: "workflow_completed_steps",
      label: "≥1 workflow step completed",
      points: 0,
      earned: 0,
      evidence: `${opContext.completed_steps} steps`,
    },
    {
      id: "route_facts",
      label: "≥1 http_route fact projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.route_facts} facts`,
    },
    {
      id: "relations_projected",
      label: "≥1 relation projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.relations_projected} relations`,
    },
    {
      id: "workflow_step_statuses",
      label: "≥1 workflow step-status fact projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.workflow_step_statuses} facts`,
    },
  ]

  return {
    scenario: "web-surface",
    max: 100,
    score: checks.reduce((a, c) => a + c.earned, 0),
    checks,
  }
}

export function scoreAppsecTriage(corpus: string, opContext: OpContext): Score {
  const lc = corpus.toLowerCase()
  const vulns = [
    {
      id: "sqli_search",
      label: "SQL injection in /rest/products/search",
      points: 20,
      hit:
        /\/rest\/products\/search/i.test(corpus) &&
        /(sql\s*injection|sqli|union\s+select|or\s+1\s*=\s*1)/i.test(lc),
    },
    {
      id: "xss_search",
      label: "XSS in search",
      points: 20,
      hit: /\b(xss|cross[-\s]site\s+scripting|<script)/i.test(corpus) && /search/i.test(lc),
    },
    {
      id: "broken_auth_jwt",
      label: "Broken auth / JWT weakness on /rest/user/login",
      points: 20,
      hit:
        /\/rest\/user\/login/i.test(corpus) &&
        /(jwt|broken\s+auth|weak\s+algorithm|alg\s*=\s*none|hs256|rs256)/i.test(lc),
    },
    {
      id: "idor_basket",
      label: "IDOR in basket",
      points: 20,
      hit: /basket/i.test(corpus) && /(idor|insecure\s+direct\s+object|broken\s+object\s+level)/i.test(lc),
    },
    {
      id: "weak_cors",
      label: "Weak CORS policy",
      points: 20,
      hit: /(cors|access-control-allow-origin)/i.test(lc) && /(weak|\*|misconfig|any|permissive)/i.test(lc),
    },
  ]

  const checks: Check[] = vulns.map((v) => ({
    id: v.id,
    label: v.label,
    points: v.points,
    earned: v.hit ? v.points : 0,
  }))

  const flagged = checks.filter((c) => c.earned > 0).length
  const passThreshold = flagged >= 2 && (opContext.candidate_findings > 0 || opContext.reportable_findings > 0)

  return {
    scenario: "appsec-triage",
    max: 100,
    score: passThreshold ? checks.reduce((a, c) => a + c.earned, 0) : 0,
    checks: [
      ...checks,
      {
        id: "threshold",
        label: "≥2 of 5 known vulns flagged (gate)",
        points: 0,
        earned: 0,
        evidence: passThreshold ? `passed: ${flagged}/5` : `failed: ${flagged}/5`,
      },
      {
        id: "observations",
        label: "≥1 evidence artifact captured by the operation",
        points: 0,
        earned: 0,
        evidence: `${opContext.observations} files`,
      },
      {
        id: "observations_projected",
        label: "≥1 observation projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.observations_projected} facts`,
      },
      {
        id: "context_artifacts",
        label: "≥1 active context artifact projected under the operation",
        points: 0,
        earned: 0,
        evidence: `${opContext.context_artifacts} files`,
      },
      {
        id: "workflow_artifacts",
        label: "≥1 workflow artifact projected under the operation",
        points: 0,
        earned: 0,
        evidence: `${opContext.workflows} files`,
      },
      {
        id: "workflow_completed_steps",
        label: "≥1 workflow step completed",
        points: 0,
        earned: 0,
        evidence: `${opContext.completed_steps} steps`,
      },
      {
        id: "candidate_findings",
        label: "≥1 finding_candidate fact projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.candidate_findings} facts`,
      },
      {
        id: "operation_state_facts",
        label: "≥1 operation_state fact projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.operation_state_facts} facts`,
      },
      {
        id: "scope_policy_facts",
        label: "≥1 scope_policy fact projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.scope_policy_facts} facts`,
      },
      {
        id: "knowledge_queries",
        label: "knowledge queries projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.knowledge_queries} facts`,
      },
      {
        id: "identities",
        label: "identity descriptor facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.identities} facts`,
      },
      {
        id: "active_identities",
        label: "active identity facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.active_identities} facts`,
      },
      {
        id: "deliverables",
        label: "deliverable bundles projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.deliverables} bundles`,
      },
      {
        id: "tool_adapters_present",
        label: "present tool adapters projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.tool_adapters_present} facts`,
      },
      {
        id: "tool_adapters_missing",
        label: "missing tool adapters projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.tool_adapters_missing} facts`,
      },
      {
        id: "capsules",
        label: "capsule readiness facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.capsules} facts`,
      },
      {
        id: "executed_capsules",
        label: "capsule execution facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.executed_capsules} facts`,
      },
      {
        id: "recommended_capsules",
        label: "capsule recommendation facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.recommended_capsules} facts`,
      },
      {
        id: "ready_capsules",
        label: "ready capsule facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.ready_capsules} facts`,
      },
      {
        id: "degraded_capsules",
        label: "degraded capsule facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.degraded_capsules} facts`,
      },
      {
        id: "unavailable_capsules",
        label: "unavailable capsule facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.unavailable_capsules} facts`,
      },
      {
        id: "ready_verticals",
        label: "ready vertical facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.ready_verticals} facts`,
      },
      {
        id: "degraded_verticals",
        label: "degraded vertical facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.degraded_verticals} facts`,
      },
      {
        id: "unavailable_verticals",
        label: "unavailable vertical facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.unavailable_verticals} facts`,
      },
      {
        id: "findings",
        label: "promoted findings projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.findings} facts`,
      },
      {
        id: "reportable_findings",
        label: "reportable findings projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.reportable_findings} facts`,
      },
      {
        id: "suspected_findings",
        label: "suspected findings projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.suspected_findings} facts`,
      },
      {
        id: "rejected_findings",
        label: "rejected or stale findings projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.rejected_findings} facts`,
      },
      {
        id: "verified_findings",
        label: "verified findings projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.verified_findings} facts`,
      },
      {
        id: "evidence_backed_findings",
        label: "verified findings with evidence refs projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.evidence_backed_findings} facts`,
      },
      {
        id: "replay_backed_findings",
        label: "replay-backed findings projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.replay_backed_findings} facts`,
      },
      {
        id: "replay_exempt_findings",
        label: "replay-exempt findings projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.replay_exempt_findings} facts`,
      },
      {
        id: "autonomy_policy_facts",
        label: "autonomy policy facts projected from the cyber kernel",
        points: 0,
        earned: 0,
        evidence: `${opContext.autonomy_policy_facts} facts`,
      },
    ],
  }
}

export function scorePwn(corpus: string, opContext: OpContext): Score {
  const checks: Check[] = [
    {
      id: "operation_created",
      label: "Operation slug created by pwn_bootstrap",
      points: 40,
      earned: opContext.slug ? 40 : 0,
      evidence: opContext.slug ?? "none",
    },
    {
      id: "play_invoked",
      label: "web-surface play trace executed",
      points: 30,
      earned: opContext.executed_capsules > 0 || opContext.workflows > 0 || opContext.route_facts > 0 ? 30 : 0,
      evidence: `executed_capsules=${opContext.executed_capsules} workflows=${opContext.workflows} route_facts=${opContext.route_facts}`,
    },
    {
      id: "observations",
      label: "≥1 observation written",
      points: 30,
      earned: opContext.observations >= 1 ? 30 : 0,
      evidence: `${opContext.observations} files`,
    },
    {
      id: "observations_projected",
      label: "≥1 observation projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.observations_projected} facts`,
    },
    {
      id: "context_artifacts",
      label: "≥1 active context artifact projected under the operation",
      points: 0,
      earned: 0,
      evidence: `${opContext.context_artifacts} files`,
    },
    {
      id: "workflow_artifacts",
      label: "≥1 workflow artifact projected under the operation",
      points: 0,
      earned: 0,
      evidence: `${opContext.workflows} files`,
    },
    {
      id: "workflow_completed_steps",
      label: "≥1 workflow step completed",
      points: 0,
      earned: 0,
      evidence: `${opContext.completed_steps} steps`,
    },
    {
      id: "operation_state_facts",
      label: "≥1 operation_state fact projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.operation_state_facts} facts`,
    },
    {
      id: "scope_policy_facts",
      label: "≥1 scope_policy fact projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.scope_policy_facts} facts`,
    },
    {
      id: "findings",
      label: "promoted findings projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.findings} facts`,
    },
    {
      id: "knowledge_queries",
      label: "knowledge queries projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.knowledge_queries} facts`,
    },
    {
      id: "identities",
      label: "identity descriptor facts projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.identities} facts`,
    },
    {
      id: "active_identities",
      label: "active identity facts projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.active_identities} facts`,
    },
    {
      id: "deliverables",
      label: "deliverable bundles projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.deliverables} bundles`,
    },
    {
      id: "tool_adapters_present",
      label: "present tool adapters projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.tool_adapters_present} facts`,
    },
    {
      id: "tool_adapters_missing",
      label: "missing tool adapters projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.tool_adapters_missing} facts`,
    },
    {
      id: "capsules",
      label: "capsule readiness facts projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.capsules} facts`,
    },
    {
      id: "executed_capsules",
      label: "capsule execution facts projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.executed_capsules} facts`,
    },
    {
      id: "recommended_capsules",
      label: "capsule recommendation facts projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.recommended_capsules} facts`,
    },
    {
      id: "ready_capsules",
      label: "ready capsule facts projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.ready_capsules} facts`,
    },
    {
      id: "ready_verticals",
      label: "ready vertical facts projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.ready_verticals} facts`,
    },
    {
      id: "degraded_verticals",
      label: "degraded vertical facts projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.degraded_verticals} facts`,
    },
    {
      id: "unavailable_verticals",
      label: "unavailable vertical facts projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.unavailable_verticals} facts`,
    },
    {
      id: "reportable_findings",
      label: "reportable findings projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.reportable_findings} facts`,
    },
    {
      id: "suspected_findings",
      label: "suspected findings projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.suspected_findings} facts`,
    },
    {
      id: "rejected_findings",
      label: "rejected or stale findings projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.rejected_findings} facts`,
    },
    {
      id: "verified_findings",
      label: "verified findings projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.verified_findings} facts`,
    },
    {
      id: "evidence_backed_findings",
      label: "verified findings with evidence refs projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.evidence_backed_findings} facts`,
    },
    {
      id: "replay_backed_findings",
      label: "replay-backed findings projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.replay_backed_findings} facts`,
    },
    {
      id: "replay_exempt_findings",
      label: "replay-exempt findings projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.replay_exempt_findings} facts`,
    },
    {
      id: "autonomy_policy_facts",
      label: "autonomy policy facts projected from the cyber kernel",
      points: 0,
      earned: 0,
      evidence: `${opContext.autonomy_policy_facts} facts`,
    },
  ]

  return {
    scenario: "pwn",
    max: 100,
    score: checks.reduce((a, c) => a + c.earned, 0),
    checks,
  }
}

export function scoreFor(
  scenario: string,
  corpus: string,
  opContext: OpContext,
): Score {
  if (scenario === "web-surface") return scoreWebSurface(corpus, opContext)
  if (scenario === "appsec-triage") return scoreAppsecTriage(corpus, opContext)
  if (scenario === "pwn") return scorePwn(corpus, opContext)
  throw new Error(`unknown scenario: ${scenario}`)
}
