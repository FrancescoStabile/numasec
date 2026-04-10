/**
 * CVSS v3.1 base score calculator — FIRST.org specification compliant.
 *
 * Implements the official formula from
 * https://www.first.org/cvss/v3.1/specification-document (Section 7.1).
 */

type AttackVector = "N" | "A" | "L" | "P"
type AttackComplexity = "L" | "H"
type PrivilegesRequired = "N" | "L" | "H"
type UserInteraction = "N" | "R"
type Scope = "U" | "C"
type Impact = "N" | "L" | "H"

export interface CVSSv31Vector {
  AV: AttackVector
  AC: AttackComplexity
  PR: PrivilegesRequired
  UI: UserInteraction
  S: Scope
  C: Impact
  I: Impact
  A: Impact
}

// Metric value multipliers — CVSS v3.1 spec Table 14
const AV_WEIGHTS: Record<AttackVector, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 }
const AC_WEIGHTS: Record<AttackComplexity, number> = { L: 0.77, H: 0.44 }
const PR_U_WEIGHTS: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.62, H: 0.27 }
const PR_C_WEIGHTS: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.68, H: 0.50 }
const UI_WEIGHTS: Record<UserInteraction, number> = { N: 0.85, R: 0.62 }
const IMP_WEIGHTS: Record<Impact, number> = { N: 0.00, L: 0.22, H: 0.56 }

/** CVSS v3.1 spec §7.1 roundup: round up to the nearest 0.1 */
function roundup(value: number): number {
  const intInput = Math.round(value * 100_000)
  if (intInput % 10_000 === 0) return intInput / 100_000
  return (Math.floor(intInput / 10_000) + 1) / 10.0
}

/** Calculate CVSS v3.1 base score using the official FIRST.org formula. */
export function calculateBaseScore(v: CVSSv31Vector): number {
  const iscBase = 1.0 - (1.0 - IMP_WEIGHTS[v.C]) * (1.0 - IMP_WEIGHTS[v.I]) * (1.0 - IMP_WEIGHTS[v.A])

  if (iscBase === 0.0) return 0.0

  const impact = v.S === "U"
    ? 6.42 * iscBase
    : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)

  const prTable = v.S === "C" ? PR_C_WEIGHTS : PR_U_WEIGHTS
  const exploitability = 8.22 * AV_WEIGHTS[v.AV] * AC_WEIGHTS[v.AC] * prTable[v.PR] * UI_WEIGHTS[v.UI]

  const base = v.S === "U"
    ? Math.min(impact + exploitability, 10.0)
    : Math.min(1.08 * (impact + exploitability), 10.0)

  return roundup(base)
}

/** Return canonical CVSS v3.1 vector string. */
export function formatVectorString(v: CVSSv31Vector): string {
  return `CVSS:3.1/AV:${v.AV}/AC:${v.AC}/PR:${v.PR}/UI:${v.UI}/S:${v.S}/C:${v.C}/I:${v.I}/A:${v.A}`
}

// CWE → default CVSS 3.1 vector mapping (heuristic defaults per vuln class)
export const CWE_VECTOR_MAP: Record<string, CVSSv31Vector> = {
  // Injection
  "CWE-89": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N" },
  "CWE-564": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N" },
  "CWE-78": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
  "CWE-77": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
  "CWE-917": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
  "CWE-74": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N" },
  // XSS
  "CWE-79": { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "L", A: "N" },
  "CWE-80": { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "L", A: "N" },
  "CWE-87": { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "L", A: "N" },
  // Path Traversal / LFI
  "CWE-22": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  "CWE-23": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  "CWE-35": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  // SSRF
  "CWE-918": { AV: "N", AC: "L", PR: "N", UI: "N", S: "C", C: "H", I: "H", A: "N" },
  // SSTI / Code Injection
  "CWE-94": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
  "CWE-95": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
  // XXE
  "CWE-611": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  // Deserialization
  "CWE-502": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
  // Authentication & Session
  "CWE-287": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N" },
  "CWE-306": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
  "CWE-798": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
  "CWE-521": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N" },
  "CWE-384": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  "CWE-613": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  "CWE-345": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N" },
  // Access Control
  "CWE-284": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  "CWE-285": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  "CWE-639": { AV: "N", AC: "L", PR: "L", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  // Information Disclosure
  "CWE-200": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" },
  "CWE-209": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" },
  // Security Misconfiguration
  "CWE-16": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" },
  "CWE-942": { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "H", I: "N", A: "N" },
  "CWE-614": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" },
  "CWE-693": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" },
  // Cryptographic
  "CWE-327": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  "CWE-326": { AV: "N", AC: "H", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  "CWE-311": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  // Other
  "CWE-829": { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "L", A: "N" },
  "CWE-20": { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "L", A: "N" },
  "CWE-601": { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "L", A: "N" },
  "CWE-352": { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "H", I: "H", A: "H" },
  "CWE-1035": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
  "CWE-434": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N" },
  "CWE-1321": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "H", A: "N" },
  "CWE-1385": { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "H", I: "H", A: "N" },
  "CWE-444": { AV: "N", AC: "H", PR: "N", UI: "N", S: "C", C: "H", I: "H", A: "N" },
  "CWE-1022": { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "N", I: "L", A: "N" },
  "CWE-770": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "H" },
  "CWE-400": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "H" },
  "CWE-943": { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N" },
}

/** Get CVSS vector for a CWE ID, or undefined if unmapped. */
export function deriveVectorFromCwe(cweId: string): CVSSv31Vector | undefined {
  return CWE_VECTOR_MAP[cweId]
}

// Severity-based fallback scores (when no CWE available)
const SEVERITY_FALLBACK: Record<string, number> = {
  critical: 9.5,
  high: 7.5,
  medium: 5.5,
  low: 2.5,
  info: 0.0,
}

/** Approximate CVSS score from severity label (fallback). */
export function cvssFromSeverity(severity: string): number {
  return SEVERITY_FALLBACK[severity.toLowerCase()] ?? 0.0
}

/** Convert CVSS score to severity label. */
export function cvssToSeverity(score: number): "critical" | "high" | "medium" | "low" | "info" {
  if (score >= 9.0) return "critical"
  if (score >= 7.0) return "high"
  if (score >= 4.0) return "medium"
  if (score >= 0.1) return "low"
  return "info"
}

/** Get (score, vectorString) for a CWE ID. Returns [0, ""] if unmapped. */
export function cvssFromCwe(cweId: string): { score: number; vector: string } {
  const v = deriveVectorFromCwe(cweId)
  if (!v) return { score: 0, vector: "" }
  return { score: calculateBaseScore(v), vector: formatVectorString(v) }
}
