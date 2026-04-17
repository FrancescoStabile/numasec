import { describe, expect, test } from "bun:test"
import { enrichFinding, generateFindingId, normalizeSeverity } from "../../src/security/enrichment/enrich"
import { getCweInfo, getCweDetails, CWE_DATABASE, VULN_CWE_MAP } from "../../src/security/enrichment/cwe-map"
import { getNextActions } from "../../src/security/enrichment/next-actions"
import { getOwaspCategory } from "../../src/security/enrichment/owasp-map"
import { getAttackTechnique } from "../../src/security/enrichment/attack-map"
import {
  calculateBaseScore,
  formatVectorString,
  deriveVectorFromCwe,
  cvssFromSeverity,
  cvssToSeverity,
  type CVSSv31Vector,
} from "../../src/security/enrichment/cvss-calculator"

// ── normalizeSeverity ────────────────────────────────────────

describe("normalizeSeverity", () => {
  test("canonical values pass through", () => {
    expect(normalizeSeverity("critical")).toBe("critical")
    expect(normalizeSeverity("high")).toBe("high")
    expect(normalizeSeverity("medium")).toBe("medium")
    expect(normalizeSeverity("low")).toBe("low")
    expect(normalizeSeverity("info")).toBe("info")
  })

  test("aliases are normalized", () => {
    expect(normalizeSeverity("crit")).toBe("critical")
    expect(normalizeSeverity("hi")).toBe("high")
    expect(normalizeSeverity("med")).toBe("medium")
    expect(normalizeSeverity("lo")).toBe("low")
  })

  test("case insensitive with whitespace", () => {
    expect(normalizeSeverity("  CRITICAL  ")).toBe("critical")
    expect(normalizeSeverity("High")).toBe("high")
    expect(normalizeSeverity("MED")).toBe("medium")
  })

  test("unknown values default to info", () => {
    expect(normalizeSeverity("unknown")).toBe("info")
    expect(normalizeSeverity("")).toBe("info")
    expect(normalizeSeverity("banana")).toBe("info")
  })
})

// ── generateFindingId ────────────────────────────────────────

describe("generateFindingId", () => {
  test("deterministic — same input produces same ID", () => {
    const input = { title: "SQL Injection", severity: "critical" as const, url: "http://example.com/api", method: "GET", parameter: "id" }
    const id1 = generateFindingId(input)
    const id2 = generateFindingId(input)
    expect(id1).toBe(id2)
  })

  test("format is SSEC-{12 hex chars uppercase}", () => {
    const id = generateFindingId({ title: "Test", severity: "low" })
    expect(id).toMatch(/^SSEC-[A-F0-9]{12}$/)
  })

  test("different inputs produce different IDs", () => {
    const id1 = generateFindingId({ title: "SQL Injection", severity: "high", url: "http://a.com" })
    const id2 = generateFindingId({ title: "XSS", severity: "high", url: "http://a.com" })
    expect(id1).not.toBe(id2)
  })

  test("session id scopes otherwise identical findings", () => {
    const id1 = generateFindingId({ title: "SQL Injection", severity: "high", url: "http://a.com", sessionID: "sess-a" })
    const id2 = generateFindingId({ title: "SQL Injection", severity: "high", url: "http://a.com", sessionID: "sess-b" })
    expect(id1).not.toBe(id2)
  })

  test("missing optional fields use empty strings", () => {
    const id = generateFindingId({ title: "Test Finding", severity: "info" })
    expect(id).toMatch(/^SSEC-/)
  })
})

// ── getCweInfo (3-pass matching) ─────────────────────────────

describe("getCweInfo", () => {
  test("pass 1: specific keyword in title", () => {
    const result = getCweInfo("SQL Injection in login form")
    expect(result).toBeDefined()
    expect(result!.id).toBe("CWE-89")
  })

  test("pass 1: case insensitive", () => {
    const result = getCweInfo("CROSS-SITE SCRIPTING found")
    expect(result).toBeDefined()
    expect(result!.id).toBe("CWE-79")
  })

  test("pass 1: longer keyword wins over shorter", () => {
    const result = getCweInfo("Server-Side Template Injection in Jinja2")
    expect(result).toBeDefined()
    expect(result!.id).toBe("CWE-1336")
  })

  test("pass 2: generic keyword fallback in title", () => {
    const result = getCweInfo("Prometheus Metrics Exposed")
    expect(result).toBeDefined()
    expect(result!.id).toBe("CWE-200")
  })

  test("pass 3: specific keyword in description when title has no match", () => {
    const result = getCweInfo("Unexpected Server Behavior", "The endpoint reveals sql injection when tested")
    expect(result).toBeDefined()
    expect(result!.id).toBe("CWE-89")
  })

  test("returns undefined when no match", () => {
    const result = getCweInfo("Something completely unrelated", "No vulnerability keywords here")
    expect(result).toBeUndefined()
  })

  test("field testing: Prometheus Metrics → CWE-200, not CWE-434", () => {
    const result = getCweInfo("Prometheus Metrics Exposed")
    expect(result!.id).not.toBe("CWE-434")
    expect(result!.id).toBe("CWE-200")
  })
})

describe("getCweDetails", () => {
  test("returns entry for known CWE", () => {
    const entry = getCweDetails("CWE-89")
    expect(entry).toBeDefined()
    expect(entry!.name).toBe("SQL Injection")
    expect(entry!.owasp2021).toContain("Injection")
  })

  test("returns undefined for unknown CWE", () => {
    expect(getCweDetails("CWE-99999")).toBeUndefined()
  })
})

// ── CWE database integrity ───────────────────────────────────

describe("CWE database", () => {
  test("has 80+ entries", () => {
    expect(Object.keys(CWE_DATABASE).length).toBeGreaterThanOrEqual(80)
  })

  test("every entry has required fields", () => {
    for (const [id, entry] of Object.entries(CWE_DATABASE)) {
      expect(entry.id).toBe(id)
      expect(entry.name).toBeTruthy()
      expect(entry.description).toBeTruthy()
      expect(["critical", "high", "medium", "low", "info"]).toContain(entry.severity)
      expect(entry.owasp2021).toMatch(/^A\d{2}:2021/)
    }
  })

  test("every VULN_CWE_MAP entry has valid id format", () => {
    for (const [_keyword, ref] of Object.entries(VULN_CWE_MAP)) {
      expect(ref.id).toMatch(/^CWE-\d+$/)
      expect(ref.name).toBeTruthy()
    }
  })
})

// ── OWASP mapping ────────────────────────────────────────────

describe("getOwaspCategory", () => {
  test("maps injection CWEs to A03:2021", () => {
    expect(getOwaspCategory("CWE-89")).toContain("A03:2021")
    expect(getOwaspCategory("CWE-79")).toContain("A03:2021")
    expect(getOwaspCategory("CWE-78")).toContain("A03:2021")
  })

  test("maps access control CWEs to A01:2021", () => {
    expect(getOwaspCategory("CWE-284")).toContain("A01:2021")
    expect(getOwaspCategory("CWE-862")).toContain("A01:2021")
  })

  test("returns empty string for unknown CWE", () => {
    expect(getOwaspCategory("CWE-99999")).toBe("")
  })
})

// ── ATT&CK mapping ──────────────────────────────────────────

describe("getAttackTechnique", () => {
  test("maps SQLi to T1190", () => {
    const technique = getAttackTechnique("CWE-89")
    expect(technique).toBeDefined()
    expect(technique!.techniqueId).toBe("T1190")
  })

  test("returns undefined for unmapped CWE", () => {
    expect(getAttackTechnique("CWE-99999")).toBeUndefined()
  })
})

// ── CVSS v3.1 calculator ─────────────────────────────────────

describe("calculateBaseScore", () => {
  test("critical: network/low/none/none/changed/high/high/high = 10.0", () => {
    const vector: CVSSv31Vector = { AV: "N", AC: "L", PR: "N", UI: "N", S: "C", C: "H", I: "H", A: "H" }
    expect(calculateBaseScore(vector)).toBe(10.0)
  })

  test("zero impact returns 0.0", () => {
    const vector: CVSSv31Vector = { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "N" }
    expect(calculateBaseScore(vector)).toBe(0.0)
  })

  test("medium: typical web vuln", () => {
    const vector: CVSSv31Vector = { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "L", I: "L", A: "N" }
    const score = calculateBaseScore(vector)
    expect(score).toBeGreaterThan(4.0)
    expect(score).toBeLessThan(7.0)
  })

  test("score is always 0-10", () => {
    const vectors: CVSSv31Vector[] = [
      { AV: "P", AC: "H", PR: "H", UI: "R", S: "U", C: "L", I: "N", A: "N" },
      { AV: "N", AC: "L", PR: "N", UI: "N", S: "C", C: "H", I: "H", A: "H" },
      { AV: "A", AC: "L", PR: "L", UI: "N", S: "U", C: "H", I: "L", A: "N" },
    ]
    for (const v of vectors) {
      const score = calculateBaseScore(v)
      expect(score).toBeGreaterThanOrEqual(0)
      expect(score).toBeLessThanOrEqual(10)
    }
  })
})

describe("formatVectorString", () => {
  test("produces standard CVSS v3.1 format", () => {
    const vector: CVSSv31Vector = { AV: "N", AC: "L", PR: "N", UI: "N", S: "C", C: "H", I: "H", A: "H" }
    const str = formatVectorString(vector)
    expect(str).toContain("CVSS:3.1")
    expect(str).toContain("AV:N")
    expect(str).toContain("AC:L")
  })
})

describe("deriveVectorFromCwe", () => {
  test("returns vector for mapped CWE", () => {
    const vector = deriveVectorFromCwe("CWE-89")
    expect(vector).toBeDefined()
    expect(vector!.AV).toBe("N")
  })

  test("returns undefined for unmapped CWE", () => {
    expect(deriveVectorFromCwe("CWE-99999")).toBeUndefined()
  })
})

describe("cvssFromSeverity", () => {
  test("returns approximate scores", () => {
    expect(cvssFromSeverity("critical")).toBeGreaterThanOrEqual(9.0)
    expect(cvssFromSeverity("high")).toBeGreaterThanOrEqual(7.0)
    expect(cvssFromSeverity("medium")).toBeGreaterThanOrEqual(4.0)
    expect(cvssFromSeverity("low")).toBeGreaterThanOrEqual(1.0)
    expect(cvssFromSeverity("info")).toBe(0)
  })
})

describe("cvssToSeverity", () => {
  test("maps score ranges correctly", () => {
    expect(cvssToSeverity(9.5)).toBe("critical")
    expect(cvssToSeverity(8.0)).toBe("high")
    expect(cvssToSeverity(5.5)).toBe("medium")
    expect(cvssToSeverity(2.0)).toBe("low")
    expect(cvssToSeverity(0)).toBe("info")
  })
})

// ── Next actions ─────────────────────────────────────────────

describe("getNextActions", () => {
  test("matches by CWE prefix (priority 1)", () => {
    const actions = getNextActions("CWE-89", "Something unrelated in title")
    expect(actions.length).toBeGreaterThanOrEqual(3)
    expect(actions[0]).toContain("sqlmap")
  })

  test("matches by title keyword (priority 2)", () => {
    const actions = getNextActions("", "XSS vulnerability found")
    expect(actions.length).toBeGreaterThanOrEqual(3)
    expect(actions.some((a) => a.toLowerCase().includes("cookie") || a.toLowerCase().includes("stored"))).toBe(true)
  })

  test("CWE match takes priority over title match", () => {
    const actions = getNextActions("CWE-89", "XSS in search page")
    expect(actions[0]).toContain("sqlmap")
  })

  test("returns generic fallback for unknown vuln type", () => {
    const actions = getNextActions("", "Completely Unknown Issue Type")
    expect(actions.length).toBe(3)
    expect(actions[0]).toContain("exploitable")
  })
})

// ── Full enrichment pipeline ─────────────────────────────────

describe("enrichFinding", () => {
  test("enriches SQL injection finding end-to-end", () => {
    const enriched = enrichFinding({
      title: "SQL Injection in /api/users",
      severity: "critical",
      url: "http://example.com/api/users",
      method: "GET",
      parameter: "id",
    })

    expect(enriched.id).toMatch(/^SSEC-/)
    expect(enriched.cweId).toBe("CWE-89")
    expect(enriched.owaspCategory).toContain("A03:2021")
    expect(enriched.cvssScore).toBeGreaterThan(0)
    expect(enriched.cvssVector).toContain("CVSS:3.1")
    expect(enriched.attackTechnique).toContain("T1190")
    expect(enriched.nextActions.length).toBeGreaterThanOrEqual(3)
    expect(enriched.confidence).toBe(0.5)
  })

  test("preserves user-provided CWE and OWASP", () => {
    const enriched = enrichFinding({
      title: "Custom Finding",
      severity: "medium",
      cweId: "CWE-79",
      owaspCategory: "Custom Category",
    })

    expect(enriched.cweId).toBe("CWE-79")
    expect(enriched.owaspCategory).toBe("Custom Category")
  })

  test("preserves user-provided CVSS", () => {
    const enriched = enrichFinding({
      title: "Custom Finding",
      severity: "high",
      cvssScore: 8.5,
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    })

    expect(enriched.cvssScore).toBe(8.5)
    expect(enriched.cvssVector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
  })

  test("severity fallback for CVSS when no CWE vector", () => {
    const enriched = enrichFinding({
      title: "Completely Unknown Issue",
      severity: "high",
    })

    expect(enriched.cvssScore).toBeGreaterThanOrEqual(7.0)
  })

  test("custom confidence is preserved", () => {
    const enriched = enrichFinding({
      title: "SQL Injection",
      severity: "critical",
      confidence: 0.95,
    })

    expect(enriched.confidence).toBe(0.95)
  })
})
