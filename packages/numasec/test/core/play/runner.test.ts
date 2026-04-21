import { describe, expect, test } from "bun:test"
import { PlayRegistry, PlayRunner, PlayArgError, PlayNotFoundError } from "../../../src/core/play"
import type { Play } from "../../../src/core/play"

describe("core/play/runner", () => {
  test("registry exposes the 5 GA plays", () => {
    const ids = PlayRegistry.ids().sort()
    expect(ids).toEqual(["appsec-triage", "ctf-warmup", "network-surface", "osint-target", "web-surface"])
    for (const id of ids) {
      const p = PlayRegistry.get(id)!
      expect(p.id).toBe(id)
      expect(p.name.length).toBeGreaterThan(0)
      expect(p.description.length).toBeGreaterThan(0)
      expect(p.steps.length).toBeGreaterThan(0)
    }
  })

  test("runner resolves tool and skill steps in declared order with template substitution", () => {
    const fake: Play = {
      id: "__fake",
      name: "Fake",
      description: "test-only",
      args: [{ name: "target", required: true, type: "string" }],
      steps: [
        { skill: "passive-osint", brief: "sweep {{target}}" },
        { tool: "scanner", args: { target: "{{target}}", profile: "light" } },
        { tool: "bash", args: { command: "echo {{target}} {{missing|fallback}}" } },
      ],
    }
    ;(PlayRegistry as any).list // force module evaluation
    const plays = (PlayRegistry as any)
    const plays_map: Record<string, Play> = (plays as any)
    // inject fake into the registry's internal map via monkey patch for this test only
    const originalGet = PlayRegistry.get
    ;(PlayRegistry as any).get = (id: string) => (id === fake.id ? fake : originalGet(id))
    try {
      const res = PlayRunner.run({ id: "__fake", args: { target: "acme.com" } })
      expect(res.trace.length).toBe(3)
      expect(res.trace[0]).toEqual({ kind: "skill", skill: "passive-osint", brief: "sweep acme.com" })
      expect(res.trace[1]).toEqual({ kind: "tool", tool: "scanner", args: { target: "acme.com", profile: "light" } })
      expect(res.trace[2]).toEqual({ kind: "tool", tool: "bash", args: { command: "echo acme.com fallback" } })
    } finally {
      ;(PlayRegistry as any).get = originalGet
    }
    void plays_map
  })

  test("runner rejects missing required args", () => {
    expect(() => PlayRunner.run({ id: "web-surface", args: {} })).toThrow(PlayArgError)
  })

  test("runner rejects unknown play id", () => {
    expect(() => PlayRunner.run({ id: "does-not-exist" })).toThrow(PlayNotFoundError)
  })

  test("web-surface play resolves target into every templated step", () => {
    const res = PlayRunner.run({ id: "web-surface", args: { target: "https://example.com", domain: "example.com" } })
    const serialized = JSON.stringify(res.trace)
    expect(serialized).toContain("https://example.com")
    expect(serialized).toContain("example.com")
    expect(serialized).not.toContain("{{target}}")
    expect(serialized).not.toContain("{{domain}}")
  })

  test("format renders an ordered, numbered step list", () => {
    const res = PlayRunner.run({ id: "network-surface", args: { target: "10.0.0.0/24" } })
    const out = PlayRunner.format(res)
    expect(out).toContain("# Play: Network Surface Map")
    expect(out).toMatch(/1\. tool: scanner/)
    expect(out).toMatch(/2\. tool: scanner/)
  })
})
