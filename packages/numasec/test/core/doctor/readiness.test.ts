import { describe, expect, test } from "bun:test"
import { evaluateCapabilitySurface } from "@/core/doctor/readiness"

describe("doctor readiness evaluator", () => {
  test("marks current plays and verticals as ready, degraded, or unavailable", () => {
    const surface = evaluateCapabilitySurface({
      binaries: new Set(["curl", "jq", "git", "rg", "nmap", "nuclei", "subfinder", "ffuf"]),
      browser_present: false,
    })

    const appsec = surface.plays.find((item) => item.id === "appsec-triage")
    const webSurface = surface.plays.find((item) => item.id === "web-surface")
    const browserVertical = surface.verticals.find((item) => item.id === "browser-inspection")

    expect(appsec?.status).toBe("ready")
    expect(webSurface?.status).toBe("degraded")
    expect(webSurface?.missing_optional).toContain("browser runtime")
    expect(browserVertical?.status).toBe("unavailable")
    expect(browserVertical?.missing_required).toContain("browser runtime")
  })
})
