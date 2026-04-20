import { describe, expect, test } from "bun:test"
import { Methodology } from "../../../src/core/methodology"

describe("core/methodology", () => {
  test("exposes mitre, ptes, wstg frameworks", () => {
    expect(Object.keys(Methodology.frameworks).sort()).toEqual(["mitre", "ptes", "wstg"])
  })

  test("every framework has phases, every phase has techniques", () => {
    for (const id of Methodology.ids) {
      const fw = Methodology.get(id)
      expect(fw.id).toBe(id)
      expect(fw.name.length).toBeGreaterThan(0)
      expect(fw.version.length).toBeGreaterThan(0)
      expect(fw.phases.length).toBeGreaterThan(0)
      for (const phase of fw.phases) {
        expect(phase.id.length).toBeGreaterThan(0)
        expect(phase.name.length).toBeGreaterThan(0)
        expect(phase.description.length).toBeGreaterThan(0)
        expect(phase.techniques.length).toBeGreaterThan(0)
        for (const tech of phase.techniques) {
          expect(tech.id.length).toBeGreaterThan(0)
          expect(tech.name.length).toBeGreaterThan(0)
          expect(tech.description.length).toBeGreaterThan(0)
        }
      }
    }
  })

  test("mitre covers all 14 enterprise tactics", () => {
    const mitre = Methodology.get("mitre")
    expect(mitre.phases.length).toBe(14)
    const names = mitre.phases.map((p) => p.name)
    expect(names).toContain("Reconnaissance")
    expect(names).toContain("Initial Access")
    expect(names).toContain("Impact")
    expect(names).toContain("Command and Control")
  })

  test("T1595 Active Scanning is under Reconnaissance", () => {
    const recon = Methodology.findPhase("mitre", "Reconnaissance")
    expect(recon).toBeDefined()
    const t1595 = recon!.techniques.find((t) => t.id === "T1595")
    expect(t1595?.name).toBe("Active Scanning")
  })

  test("PTES has 7 phases including Exploitation", () => {
    const ptes = Methodology.get("ptes")
    expect(ptes.phases.length).toBe(7)
    expect(ptes.phases.map((p) => p.name)).toContain("Exploitation")
  })

  test("WSTG has 12 categories including API testing", () => {
    const wstg = Methodology.get("wstg")
    expect(wstg.phases.length).toBe(12)
    const ids = wstg.phases.map((p) => p.id)
    expect(ids).toContain("WSTG-INFO")
    expect(ids).toContain("WSTG-ATHN")
    expect(ids).toContain("WSTG-APIT")
  })

  test("WSTG contains real SQLi technique id", () => {
    const inpv = Methodology.findPhase("wstg", "WSTG-INPV")
    expect(inpv?.techniques.find((t) => t.id === "WSTG-INPV-05")?.name).toMatch(/SQL Injection/)
  })

  test("findPhase is case-insensitive and accepts id or name", () => {
    expect(Methodology.findPhase("mitre", "ta0001")?.name).toBe("Initial Access")
    expect(Methodology.findPhase("mitre", "initial access")?.id).toBe("TA0001")
  })

  test("search matches across phases", () => {
    const ssrf = Methodology.search("wstg", "ssrf")
    expect(ssrf.length).toBeGreaterThan(0)
    expect(ssrf[0].technique.id).toBe("WSTG-INPV-18")

    const kerb = Methodology.search("mitre", "kerberos")
    expect(kerb.length).toBeGreaterThan(0)
    expect(kerb.some((m) => m.technique.id === "T1558")).toBe(true)
  })
})
