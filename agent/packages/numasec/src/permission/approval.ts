export type ApprovalRisk = "low" | "medium" | "high"
export type ApprovalScope = "none" | "hypothesis" | "scope"

export interface ApprovalContext {
  risk: ApprovalRisk
  scope: ApprovalScope
  reason_required: boolean
}

const LOW = new Set<string>(["read", "list", "glob", "grep"])
const MEDIUM = new Set<string>([
  "webfetch",
  "websearch",
  "codesearch",
  "todo",
  "skill",
  "recon",
  "crawl",
  "dir_fuzz",
  "js_analyze",
  "observe_surface",
  "extract_observation",
  "query_graph",
  "plan_next",
  "upsert_hypothesis",
  "upsert_finding",
  "save_finding",
  "get_findings",
  "build_chains",
  "derive_attack_paths",
  "generate_report",
  "report_status",
  "kb_search",
  "pentest_plan",
])
const HIGH = new Set<string>([
  "edit",
  "write",
  "apply_patch",
  "multiedit",
  "bash",
  "task",
  "doom_loop",
  "external_directory",
  "external_directory_mutation",
  "exec_command",
  "security_shell",
  "browser",
  "http_request",
  "batch_replay",
  "mutate_input",
  "verify_assertion",
  "record_evidence",
  "link_evidence",
  "injection_test",
  "xss_test",
  "ssrf_test",
  "auth_test",
  "access_control_test",
  "upload_test",
  "race_test",
  "graphql_test",
])

function riskValue(input: unknown) {
  if (input === "low") return input
  if (input === "medium") return input
  if (input === "high") return input
}

function scopeValue(input: unknown) {
  if (input === "none") return input
  if (input === "hypothesis") return input
  if (input === "scope") return input
}

function boolValue(input: unknown) {
  if (typeof input === "boolean") return input
}

export function resolveApproval(input: {
  permission: string
  metadata?: Record<string, any>
}): ApprovalContext {
  const metadata = input.metadata ?? {}
  const forcedRisk = riskValue(metadata["approval_risk"])
  if (forcedRisk) {
    const forcedScope = scopeValue(metadata["approval_scope"])
    const forcedReason = boolValue(metadata["approval_reason_required"])
    return {
      risk: forcedRisk,
      scope: forcedScope ?? defaultScope(forcedRisk),
      reason_required: forcedReason ?? forcedRisk === "high",
    }
  }

  if (LOW.has(input.permission)) {
    const forcedScope = scopeValue(metadata["approval_scope"])
    const forcedReason = boolValue(metadata["approval_reason_required"])
    return {
      risk: "low",
      scope: forcedScope ?? "none",
      reason_required: forcedReason ?? false,
    }
  }

  if (HIGH.has(input.permission) || input.permission.startsWith("security_")) {
    const forcedScope = scopeValue(metadata["approval_scope"])
    const forcedReason = boolValue(metadata["approval_reason_required"])
    return {
      risk: "high",
      scope: forcedScope ?? "scope",
      reason_required: forcedReason ?? true,
    }
  }

  if (MEDIUM.has(input.permission)) {
    const forcedScope = scopeValue(metadata["approval_scope"])
    const forcedReason = boolValue(metadata["approval_reason_required"])
    return {
      risk: "medium",
      scope: forcedScope ?? "hypothesis",
      reason_required: forcedReason ?? false,
    }
  }

  if (input.permission.includes("_")) {
    const forcedScope = scopeValue(metadata["approval_scope"])
    const forcedReason = boolValue(metadata["approval_reason_required"])
    return {
      risk: "high",
      scope: forcedScope ?? "scope",
      reason_required: forcedReason ?? true,
    }
  }

  const forcedScope = scopeValue(metadata["approval_scope"])
  const forcedReason = boolValue(metadata["approval_reason_required"])
  return {
    risk: "medium",
    scope: forcedScope ?? "hypothesis",
    reason_required: forcedReason ?? false,
  }
}

function defaultScope(risk: ApprovalRisk): ApprovalScope {
  if (risk === "low") return "none"
  if (risk === "high") return "scope"
  return "hypothesis"
}

export function allowLabel(scope: ApprovalScope): string | undefined {
  if (scope === "none") return
  if (scope === "hypothesis") return "Allow in hypothesis"
  return "Allow in scope"
}

export function annotateApprovalMetadata(
  metadata: Record<string, any> | undefined,
  approval: ApprovalContext,
): Record<string, any> {
  const out = metadata ? { ...metadata } : {}
  out["approval_risk"] = approval.risk
  out["approval_scope"] = approval.scope
  out["approval_reason_required"] = approval.reason_required
  return out
}

export function selectApprovalPatterns(input: {
  always: string[]
  patterns: string[]
  approval: ApprovalContext
}): string[] {
  if (input.always.length > 0) return input.always
  if (input.approval.scope === "none") return []
  return input.patterns
}

export function formatRejectionConstraint(input: {
  permission: string
  patterns: string[]
  message: string
}): string {
  const text = input.message.trim().replace(/\s+/g, " ")
  if (!text) return ""

  const first = input.patterns.find((item) => item.trim().length > 0)
  const context = first ? ` (${first})` : ""
  const result = `Do not run ${input.permission}${context}: ${text}`
  if (result.length <= 220) return result
  return result.slice(0, 217) + "..."
}

export function formatConstraintPrompt(input: string[]): string | undefined {
  if (input.length === 0) return
  return [
    "<approval-constraints>",
    "User approval constraints from recent rejected actions:",
    ...input.map((item) => "- " + item),
    "Respect these constraints when selecting tools and planning next steps.",
    "</approval-constraints>",
  ].join("\n")
}
