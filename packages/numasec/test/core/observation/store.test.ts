import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "fs"
import { tmpdir } from "os"
import path from "path"
import { Observation } from "@/core/observation"

function mkws() {
  const dir = mkdtempSync(path.join(tmpdir(), "numasec-obs-"))
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

describe("core/observation store", () => {
  test("add/list/update roundtrip", async () => {
    const { dir, cleanup } = mkws()
    try {
      const o = await Observation.add(dir, "op1", {
        subtype: "vuln",
        title: "SQLi on /login",
        severity: "high",
        confidence: 0.9,
      })
      const listed = await Observation.list(dir, "op1")
      expect(listed.length).toBe(1)
      expect(listed[0].id).toBe(o.id)
      expect(listed[0].severity).toBe("high")
      expect(listed[0].status).toBe("open")

      await Observation.update(dir, "op1", o.id, { status: "confirmed", severity: "critical" })
      const after = await Observation.list(dir, "op1")
      expect(after[0].status).toBe("confirmed")
      expect(after[0].severity).toBe("critical")
    } finally {
      cleanup()
    }
  })

  test("link evidence dedupes and remove drops entry", async () => {
    const { dir, cleanup } = mkws()
    try {
      const o = await Observation.add(dir, "op1", { subtype: "flag", title: "CTF flag" })
      await Observation.linkEvidence(dir, "op1", o.id, "abc123")
      await Observation.linkEvidence(dir, "op1", o.id, "abc123")
      await Observation.linkEvidence(dir, "op1", o.id, "def456")
      let items = await Observation.list(dir, "op1")
      expect(items[0].evidence).toEqual(["abc123", "def456"])

      await Observation.remove(dir, "op1", o.id)
      items = await Observation.list(dir, "op1")
      expect(items.length).toBe(0)
    } finally {
      cleanup()
    }
  })

  test("severity counts group properly", async () => {
    const { dir, cleanup } = mkws()
    try {
      await Observation.add(dir, "op1", { subtype: "vuln", title: "a", severity: "critical" })
      await Observation.add(dir, "op1", { subtype: "vuln", title: "b", severity: "high" })
      await Observation.add(dir, "op1", { subtype: "risk", title: "c" })
      const items = await Observation.list(dir, "op1")
      const counts = Observation.severityCounts(items)
      expect(counts.critical).toBe(1)
      expect(counts.high).toBe(1)
      expect(counts.none).toBe(1)
    } finally {
      cleanup()
    }
  })

  test("replay deterministic: reading same jsonl yields same projection", async () => {
    const { dir, cleanup } = mkws()
    try {
      const o1 = await Observation.add(dir, "op1", { subtype: "vuln", title: "x" })
      await Observation.update(dir, "op1", o1.id, { note: "triaged" })
      const a = await Observation.list(dir, "op1")
      const b = await Observation.list(dir, "op1")
      expect(a).toEqual(b)
    } finally {
      cleanup()
    }
  })
})
