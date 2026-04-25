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
      browser: { present: false, reason: "Playwright unavailable. Run: bun add playwright && npx playwright install chromium" },
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
    expect(browser.reason).toContain("missing runtime dependency")
  })

  it("includes the actual launch error in the reason", async () => {
    await using fixture = await tmpdir()
    const executable = path.join(fixture.path, "chromium")
    await Bun.write(executable, "#!/bin/sh\nexit 1\n")
    await chmod(executable, 0o755)

    const browser = await evaluateBrowserRuntime({
      chromium: {
        executablePath: () => executable,
        launch: async () => {
          throw new Error("ENOENT: no such file or directory, libnss3.so")
        },
      },
    })

    expect(browser.present).toBe(false)
    expect(browser.reason).toContain("npx playwright install chromium")
    expect(browser.reason).toContain("libnss3.so")
  })

  it("tries system chromium as fallback when playwright chromium fails", async () => {
    await using fixture = await tmpdir()
    const pwExecutable = path.join(fixture.path, "pw-chromium")
    await Bun.write(pwExecutable, "#!/bin/sh\nexit 0\n")
    await chmod(pwExecutable, 0o755)

    const systemExecutable = path.join(fixture.path, "numasec-test-chromium")
    await Bun.write(systemExecutable, "#!/bin/sh\nexit 0\n")
    await chmod(systemExecutable, 0o755)

    // Use env var to point to fixture chromium since PATH manipulation with Bun.which is unreliable in tests
    process.env.NUMASEC_CHROMIUM_PATH = systemExecutable

    try {
      const browser = await evaluateBrowserRuntime({
        chromium: {
          executablePath: () => pwExecutable,
          launch: async (opts) => {
            const execPath = (opts as any).executablePath
            // Playwright's default executable exists but launch fails
            if (!execPath) throw new Error("missing runtime dependency")
            // System fallback via executablePath should succeed
            return { close: async () => {} }
          },
        },
      })

      expect(browser.present).toBe(true)
      expect(browser.executable).toBe(systemExecutable)
    } finally {
      delete process.env.NUMASEC_CHROMIUM_PATH
    }
  })

  it("uses NUMASEC_CHROMIUM_PATH env var as fallback", async () => {
    await using fixture = await tmpdir()
    const pwExecutable = path.join(fixture.path, "pw-chromium")
    await Bun.write(pwExecutable, "#!/bin/sh\nexit 0\n")
    await chmod(pwExecutable, 0o755)

    const customExecutable = path.join(fixture.path, "my-custom-chromium")
    await Bun.write(customExecutable, "#!/bin/sh\nexit 0\n")
    await chmod(customExecutable, 0o755)

    process.env.NUMASEC_CHROMIUM_PATH = customExecutable

    try {
      const browser = await evaluateBrowserRuntime({
        chromium: {
          executablePath: () => pwExecutable,
          launch: async (opts) => {
            const execPath = (opts as any).executablePath
            if (!execPath) throw new Error("no chromium")
            return { close: async () => {} }
          },
        },
      })

      expect(browser.present).toBe(true)
      expect(browser.executable).toBe(customExecutable)
    } finally {
      delete process.env.NUMASEC_CHROMIUM_PATH
    }
  })

  it("reports NUMASEC_CHROMIUM_PATH in reason when env var is set but fails", async () => {
    await using fixture = await tmpdir()
    const executable = path.join(fixture.path, "chromium")
    await Bun.write(executable, "#!/bin/sh\nexit 0\n")
    await chmod(executable, 0o755)

    process.env.NUMASEC_CHROMIUM_PATH = "/nonexistent/path/chromium"

    try {
      const browser = await evaluateBrowserRuntime({
        chromium: {
          executablePath: () => executable,
          launch: async () => {
            throw new Error("no chromium")
          },
        },
      })

      expect(browser.present).toBe(false)
      expect(browser.reason).toContain("Tried NUMASEC_CHROMIUM_PATH=/nonexistent/path/chromium")
    } finally {
      delete process.env.NUMASEC_CHROMIUM_PATH
    }
  })
})
