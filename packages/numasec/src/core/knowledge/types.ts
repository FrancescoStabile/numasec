export const KnowledgeIntents = [
  "vuln_intel",
  "methodology",
  "tradecraft",
  "exploit_signal",
  "tool_docs",
  "field_research",
] as const

export type KnowledgeIntent = (typeof KnowledgeIntents)[number]

export const KnowledgeActions = [
  "lookup",
  "match_component",
  "enrich_observed",
  "enrich_dependency",
  "prioritize",
  "safe_next_actions",
] as const

export type KnowledgeAction = (typeof KnowledgeActions)[number]

export const KnowledgeModes = ["live", "offline", "opsec_strict"] as const
export type KnowledgeMode = (typeof KnowledgeModes)[number]

export type KnowledgeSource = {
  name: string
  url?: string
  source_type: "structured" | "methodology" | "tradecraft" | "local_tool" | "web" | "cache"
  trust: "canonical" | "high" | "medium" | "low"
  fetched_at?: number
  stale_after?: number
  degraded?: boolean
  error?: string
}

export type KnowledgeClaim = {
  claim: string
  source_url?: string
  confidence: number
  freshness?: string
  applies_to_observed_target: true | false | "unknown"
}

export type VulnApplicabilityState = "applicable" | "conditional" | "possible" | "not_applicable" | "unknown"

export type VulnIntelCard = {
  kind: "vuln_intel"
  id: string
  aliases: string[]
  title?: string
  summary?: string
  affected: Array<{
    ecosystem?: string
    package?: string
    version_range?: string
    patched_versions?: string[]
    cpe?: string
  }>
  severity: {
    cvss_v3?: number
    cvss_v4?: number
    level?: string
    source?: string
  }
  exploitation: {
    kev?: boolean
    kev_due_date?: string
    epss_probability?: number
    epss?: number
    epss_percentile?: number
    public_exploit_signal?: boolean
    metasploit_signal?: boolean
    nuclei_signal?: boolean
    exploitdb_signal?: boolean
  }
  applicability: {
    matched_component?: string
    matched_version?: string
    state?: VulnApplicabilityState
    confidence: "low" | "medium" | "high" | "unknown"
    reason: string
    version_match?: boolean | "unknown"
    affected_range?: string
    matched_criteria?: string
    preconditions?: string[]
    fixed_versions?: string[]
    distro_backport_note?: string
    verification_steps?: string[]
    source_disagreements?: string[]
  }
  references: string[]
  safe_next_actions: string[]
  fetched_at: number
  source_freshness?: string
  stale_after: number
  sources: KnowledgeSource[]
}

export type ResearchCard = {
  kind: "research"
  topic: string
  source_pack: Exclude<KnowledgeIntent, "vuln_intel">
  sources: KnowledgeSource[]
  claims: KnowledgeClaim[]
  recommended_next_actions: string[]
  unsafe_or_out_of_scope_actions: string[]
  applies_to_observed_target: true | false | "unknown"
  fetched_at: number
  stale_after: number
}

export type KnowledgeCard = VulnIntelCard | ResearchCard

export type KnowledgeRequest = {
  intent: KnowledgeIntent
  action: KnowledgeAction
  query: string
  observed_refs?: string[]
  mode: KnowledgeMode
  limit: number
}

export type KnowledgeResult = {
  request: KnowledgeRequest
  cards: KnowledgeCard[]
  sources: KnowledgeSource[]
  degraded: boolean
  errors: string[]
  fetched_at: number
  stale_after: number
  summary: string
  operator_summary?: string
  cards_compact?: Array<{
    kind: KnowledgeCard["kind"]
    id?: string
    topic?: string
    title?: string
    applicability_state?: VulnApplicabilityState
    confidence?: string
    kev?: boolean
    epss_probability?: number
    epss_percentile?: number
    safe_next_actions?: string[]
  }>
}
