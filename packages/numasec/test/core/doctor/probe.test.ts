import { describe, expect, it } from "bun:test"
import { Effect } from "effect"
import { Doctor } from "@/core/doctor"

describe("Doctor.probe", () => {
  it("returns a structured report with expected shape", async () => {
    const report = await Effect.runPromise(Doctor.probe())

    expect(report.runtime).toBeDefined()
    expect(typeof report.runtime.node).toBe("string")
    expect(report.runtime.node.length).toBeGreaterThan(0)

    expect(report.os).toBeDefined()
    expect(typeof report.os.platform).toBe("string")
    expect(typeof report.os.arch).toBe("string")
    expect(typeof report.os.release).toBe("string")

    expect(Array.isArray(report.binaries)).toBe(true)
    expect(report.binaries.length).toBeGreaterThanOrEqual(10)
    for (const b of report.binaries) {
      expect(typeof b.name).toBe("string")
      expect(typeof b.present).toBe("boolean")
    }
    const names = report.binaries.map((b) => b.name)
    for (const required of ["curl", "jq", "git", "rg", "nmap", "nuclei"]) {
      expect(names).toContain(required)
    }

    expect(report.vault).toBeDefined()
    expect(typeof report.vault.present).toBe("boolean")
    expect(typeof report.vault.path).toBe("string")

    expect(report.cve).toBeDefined()
    expect(typeof report.cve.present).toBe("boolean")
    expect(typeof report.cve.path).toBe("string")

    expect(report.workspace).toBeDefined()
    expect(typeof report.workspace.writable).toBe("boolean")
    expect(typeof report.workspace.path).toBe("string")
  })

  it("formats a report as markdown", async () => {
    const report = await Effect.runPromise(Doctor.probe())
    const text = Doctor.format(report)
    expect(text).toContain("# numasec doctor")
    expect(text).toContain("## binaries")
    expect(text).toContain("## vault")
    expect(text).toContain("## workspace")
  })
})
