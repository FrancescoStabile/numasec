import { describe, expect, it } from "bun:test"
import { Effect } from "effect"
import { chmod } from "fs/promises"
import path from "path"
import { Doctor } from "@/core/doctor"
import { evaluateBrowserRuntime } from "@/core/doctor/probe"
import { tmpdir } from "../../fixture/fixture"

describe("Doctor.probe", () => {
  it("returns a structured report with capability surface fields", async () => {
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

    expect(report.browser).toBeDefined()
    expect(typeof report.browser.present).toBe("boolean")

    expect(report.capability).toBeDefined()
    expect(Array.isArray(report.capability.plays)).toBe(true)
    expect(Array.isArray(report.capability.verticals)).toBe(true)
    expect(report.capability.plays.some((item) => item.id === "web-surface")).toBe(true)
    expect(report.capability.verticals.some((item) => item.id === "active-web-testing")).toBe(true)
  })

  it("formats browser and capability sections as markdown", () => {
    const text = Doctor.format({
      runtime: { node: "24.0.0", bun: "1.3.11" },
      os: { platform: "linux", arch: "x64", release: "6.13.0" },
      binaries: [
        { name: "curl", present: true, path: "/usr/bin/curl", version: "curl 8.7.1" },
        { name: "rg", present: true, path: "/usr/bin/rg", version: "ripgrep 14.1.1" },
      ],
      browser: { present: false, reason: "Run: npx playwright install chromium" },
      vault: { present: false, path: "/tmp/vault.json" },
      cve: { present: false, path: "/tmp/latest.json" },
      workspace: { path: "/tmp/work", writable: true },
      capability: {
        plays: [
          {
            id: "web-surface",
            label: "Web Surface Map",
            status: "degraded",
            missing_required: [],
            missing_optional: ["browser runtime"],
          },
        ],
        verticals: [
          {
            id: "browser-inspection",
            label: "Browser Inspection",
            status: "unavailable",
            missing_required: ["browser runtime"],
            missing_optional: [],
          },
        ],
      },
    })

    expect(text).toContain("# numasec doctor")
    expect(text).toContain("## browser")
    expect(text).toContain("## play readiness")
    expect(text).toContain("Web Surface Map")
    expect(text).toContain("## vertical readiness")
    expect(text).toContain("Browser Inspection")
  })

  it("treats browser runtime as unavailable when chromium cannot launch", async () => {
    await using fixture = await tmpdir()
    const executable = path.join(fixture.path, "chromium")
    await Bun.write(executable, "#!/bin/sh\nexit 0\n")
    await chmod(executable, 0o755)

    const browser = await evaluateBrowserRuntime({
      chromium: {
        executablePath: () => executable,
        launch: async () => {
          throw new Error("missing runtime dependency")
        },
      },
    })

    expect(browser.present).toBe(false)
    expect(browser.reason).toContain("npx playwright install chromium")
  })
})
