/**
 * Finding enrichment pipeline.
 *
 * Auto-enriches a finding with CWE, CVSS v3.1, OWASP Top 10, and MITRE ATT&CK.
 * Called after save_finding creates the Finding record.
 *
 * Enrichment order:
 * 1. CWE — inferred from title + description if not set
 * 2. OWASP category — mapped from CWE
 * 3. CVSS v3.1 vector + score — from CWE vector map; fallback to severity
 * 4. MITRE ATT&CK technique — mapped from CWE
 */

import { getCweInfo } from "./cwe-map"
import { cvssFromCwe, cvssFromSeverity, formatVectorString, deriveVectorFromCwe, calculateBaseScore } from "./cvss-calculator"
import { getOwaspCategory } from "./owasp-map"
import { getAttackTechnique } from "./attack-map"
import { getNextActions } from "./next-actions"
import type { FindingID } from "../security.sql"
import { createHash } from "crypto"

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export interface FindingInput {
  sessionID?: string
  title: string
  severity: Severity
  description?: string
  evidence?: string
  confirmed?: boolean
  url?: string
  method?: string
  parameter?: string
  payload?: string
  requestDump?: string
  responseStatus?: number
  cweId?: string
  cvssScore?: number
  cvssVector?: string
  owaspCategory?: string
  attackTechnique?: string
  ruleId?: string
  wstgId?: string
  remediationSummary?: string
  confidence?: number
  relatedFindingIds?: string[]
  chainId?: string
  toolUsed?: string
}

export interface EnrichedFinding extends FindingInput {
  id: FindingID
  cweId: string
  cvssScore: number
  cvssVector: string
  owaspCategory: string
  attackTechnique: string
  confidence: number
  nextActions: string[]
}

/** Normalize severity aliases to canonical values. */
export function normalizeSeverity(raw: string): Severity {
  const s = raw.toLowerCase().trim()
  if (s === "crit" || s === "critical") return "critical"
  if (s === "hi" || s === "high") return "high"
  if (s === "med" || s === "medium") return "medium"
  if (s === "lo" || s === "low") return "low"
  return "info"
}

/** Generate deterministic session-scoped finding ID: SSEC-{SHA256(session:method:url:parameter:title)[:12]}. */
export function generateFindingId(finding: FindingInput): FindingID {
  const key = `${finding.sessionID ?? ""}:${finding.method ?? ""}:${finding.url ?? ""}:${finding.parameter ?? ""}:${finding.title}`
  const hash = createHash("sha256").update(key).digest("hex").slice(0, 12).toUpperCase()
  return `SSEC-${hash}` as FindingID
}

/** Enrich a finding with CWE, CVSS, OWASP, and ATT&CK data. */
export function enrichFinding(input: FindingInput): EnrichedFinding {
  const finding: EnrichedFinding = {
    ...input,
    id: generateFindingId(input),
    cweId: input.cweId ?? "",
    cvssScore: input.cvssScore ?? 0,
    cvssVector: input.cvssVector ?? "",
    owaspCategory: input.owaspCategory ?? "",
    attackTechnique: input.attackTechnique ?? "",
    confidence: input.confidence ?? 0.5,
    nextActions: [],
  }

  // Step 1: CWE inference from title + description
  if (!finding.cweId) {
    const cweInfo = getCweInfo(finding.title, finding.description)
    if (cweInfo) finding.cweId = cweInfo.id
  }

  // Step 2: OWASP category from CWE
  if (!finding.owaspCategory && finding.cweId) {
    finding.owaspCategory = getOwaspCategory(finding.cweId)
  }

  // Step 3: CVSS v3.1 from CWE vector map
  if (!finding.cvssVector && finding.cweId) {
    const vector = deriveVectorFromCwe(finding.cweId)
    if (vector) {
      finding.cvssScore = calculateBaseScore(vector)
      finding.cvssVector = formatVectorString(vector)
    }
  }

  // Fallback: severity-based approximate score
  if (finding.cvssScore === 0) {
    finding.cvssScore = cvssFromSeverity(finding.severity)
  }

  // Step 4: ATT&CK technique from CWE
  if (!finding.attackTechnique && finding.cweId) {
    const technique = getAttackTechnique(finding.cweId)
    if (technique) {
      finding.attackTechnique = `${technique.techniqueId} - ${technique.techniqueName}`
    }
  }

  // Step 5: Deterministic next-action suggestions
  finding.nextActions = getNextActions(finding.cweId, finding.title)

  return finding
}
