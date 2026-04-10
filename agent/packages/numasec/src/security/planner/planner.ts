/**
 * Deterministic Planner — PTES 5-phase methodology.
 *
 * Based on CHECKMATE paper (arxiv 2512.11143). No LLM calls.
 * Generates a structured attack plan based on target profile.
 */

export type PTESPhase = "recon" | "service_mapping" | "vuln_testing" | "exploitation" | "reporting"
export type Scope = "quick" | "standard" | "deep"

export interface AttackStep {
  tool: string
  description: string
  parameters: Record<string, any>
  priority: number // 1=must, 2=should, 3=nice
  condition?: string // when to include this step
}

export interface AttackPhase {
  phase: PTESPhase
  steps: AttackStep[]
}

export interface AttackPlan {
  target: string
  scope: Scope
  phases: AttackPhase[]
  timeout: number // seconds
  notes: string[]
}

interface TargetProfile {
  url: string
  technologies?: string[]
  openPorts?: number[]
  hasGraphql?: boolean
  hasApi?: boolean
  hasAuth?: boolean
  hasUpload?: boolean
  hasForms?: boolean
}

export function generatePlan(target: TargetProfile, scope: Scope = "standard"): AttackPlan {
  const timeouts: Record<Scope, number> = { quick: 180, standard: 600, deep: 1800 }
  const notes: string[] = []
  const phases: AttackPhase[] = []

  // Phase 1: Reconnaissance
  const reconSteps: AttackStep[] = [
    { tool: "recon", description: "Port scan, service detection, tech fingerprint", parameters: { target: target.url }, priority: 1 },
    { tool: "crawl", description: "Discover URLs, forms, technologies", parameters: { url: target.url }, priority: 1 },
  ]

  if (scope !== "quick") {
    reconSteps.push({
      tool: "dir_fuzz",
      description: "Brute-force hidden directories",
      parameters: { url: target.url },
      priority: 2,
    })
    reconSteps.push({
      tool: "js_analyze",
      description: "Analyze JavaScript for endpoints and secrets",
      parameters: { url: target.url },
      priority: 2,
    })
  }

  phases.push({ phase: "recon", steps: reconSteps })

  // Phase 2: Service Mapping (implicit in recon results)
  // No separate phase needed — recon + crawl cover this.

  // Phase 3: Vulnerability Testing
  const vulnSteps: AttackStep[] = []

  // Always test for injection
  vulnSteps.push({
    tool: "injection_test",
    description: "Test discovered parameters for SQL/command/template injection",
    parameters: { url: target.url },
    priority: 1,
  })

  // Always test for XSS
  vulnSteps.push({
    tool: "xss_test",
    description: "Test parameters for reflected XSS",
    parameters: { url: target.url },
    priority: 1,
  })

  // SSRF if URL parameters detected
  vulnSteps.push({
    tool: "ssrf_test",
    description: "Test URL-accepting parameters for SSRF",
    parameters: { url: target.url },
    priority: 2,
    condition: "url_params_found",
  })

  // Auth testing if login/auth endpoints
  if (target.hasAuth !== false) {
    vulnSteps.push({
      tool: "auth_test",
      description: "Test authentication: default creds, JWT, session management",
      parameters: { url: target.url },
      priority: 1,
    })
  }

  // Access control
  vulnSteps.push({
    tool: "access_control_test",
    description: "Test IDOR, CSRF, CORS, mass assignment",
    parameters: { url: target.url, test_type: "all" },
    priority: 1,
  })

  // GraphQL-specific
  if (target.hasGraphql) {
    vulnSteps.push({
      tool: "graphql_test",
      description: "Test GraphQL: introspection, depth, batching",
      parameters: { url: target.url },
      priority: 1,
    })
  }

  // Upload testing
  if (target.hasUpload) {
    vulnSteps.push({
      tool: "upload_test",
      description: "Test file upload bypass",
      parameters: { url: target.url },
      priority: 2,
    })
  }

  // Race conditions (standard/deep only)
  if (scope !== "quick") {
    vulnSteps.push({
      tool: "race_test",
      description: "Test for race conditions on state-changing endpoints",
      parameters: { url: target.url },
      priority: 3,
    })
  }

  // Technology-specific tests
  const techs = target.technologies ?? []
  if (techs.some((t) => /flask|jinja|django/i.test(t))) {
    notes.push("Python web framework detected — prioritize SSTI and deserialization testing")
  }
  if (techs.some((t) => /node|express/i.test(t))) {
    notes.push("Node.js detected — test for prototype pollution, NoSQL injection")
  }
  if (techs.some((t) => /java|spring/i.test(t))) {
    notes.push("Java detected — test for deserialization, XXE, Log4Shell")
  }
  if (techs.some((t) => /php/i.test(t))) {
    notes.push("PHP detected — prioritize LFI, type juggling, deserialization")
  }

  phases.push({ phase: "vuln_testing", steps: vulnSteps })

  // Phase 4: Exploitation Validation (standard/deep only)
  if (scope !== "quick") {
    phases.push({
      phase: "exploitation",
      steps: [
        {
          tool: "build_chains",
          description: "Build attack chains from discovered findings",
          parameters: {},
          priority: 1,
        },
      ],
    })
  }

  // Phase 5: Reporting
  phases.push({
    phase: "reporting",
    steps: [
      {
        tool: "generate_report",
        description: "Generate assessment report",
        parameters: { format: "markdown" },
        priority: 1,
      },
    ],
  })

  return {
    target: target.url,
    scope,
    phases,
    timeout: timeouts[scope],
    notes,
  }
}

// Replan signals — conditions that should modify the plan
export interface ReplanSignal {
  type:
    | "waf_detected"
    | "auth_obtained"
    | "technology_identified"
    | "rate_limited"
    | "escalation_found"
    | "large_surface"
    | "api_detected"
    | "spa_detected"
    | "graphql_detected"
  data?: Record<string, any>
}

export function applyReplanSignal(plan: AttackPlan, signal: ReplanSignal): AttackPlan {
  const updated = { ...plan, phases: plan.phases.map((p) => ({ ...p, steps: [...p.steps] })) }

  switch (signal.type) {
    case "waf_detected":
      updated.notes.push("WAF detected — use encoding/evasion techniques in payloads")
      break

    case "auth_obtained":
      updated.notes.push("Credentials obtained — re-test all endpoints with authentication")
      break

    case "rate_limited":
      updated.notes.push("Rate limiting detected — reduce concurrency, add delays")
      break

    case "graphql_detected": {
      const vulnPhase = updated.phases.find((p) => p.phase === "vuln_testing")
      if (vulnPhase && !vulnPhase.steps.some((s) => s.tool === "graphql_test")) {
        vulnPhase.steps.push({
          tool: "graphql_test",
          description: "GraphQL endpoint discovered — test for introspection, depth, batching",
          parameters: { url: signal.data?.url ?? plan.target },
          priority: 1,
        })
      }
      break
    }

    case "large_surface":
      updated.notes.push("Large attack surface — focus on highest-priority tests, parallelize where possible")
      break

    case "escalation_found":
      updated.notes.push("Privilege escalation opportunity — validate and chain with existing findings")
      break

    default:
      break
  }

  return updated
}

export function formatPlan(plan: AttackPlan): string {
  const lines: string[] = [
    `── Attack Plan ──`,
    `Target: ${plan.target}`,
    `Scope: ${plan.scope}`,
    `Timeout: ${plan.timeout}s`,
    "",
  ]

  for (const phase of plan.phases) {
    lines.push(`Phase: ${phase.phase.toUpperCase()}`)
    for (const step of phase.steps) {
      const pri = step.priority === 1 ? "MUST" : step.priority === 2 ? "SHOULD" : "MAY"
      lines.push(`  [${pri}] ${step.tool}: ${step.description}`)
    }
    lines.push("")
  }

  if (plan.notes.length > 0) {
    lines.push("Notes:")
    for (const note of plan.notes) lines.push(`  • ${note}`)
  }

  return lines.join("\n")
}
