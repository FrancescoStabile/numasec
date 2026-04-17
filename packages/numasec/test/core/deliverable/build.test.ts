import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync, readFileSync } from "fs"
import { tmpdir } from "os"
import path from "path"
import { createHash } from "crypto"
import { Operation } from "@/core/operation"
import { Plan } from "@/core/plan"
import { Observation } from "@/core/observation"
import { Evidence } from "@/core/evidence"
import { Deliverable } from "@/core/deliverable"

function mkws() {
  const dir = mkdtempSync(path.join(tmpdir(), "numasec-deliv-"))
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

describe("core/deliverable build", () => {
  test("builds bundle with report.md + report.json + manifest.json", async () => {
    const { dir, cleanup } = mkws()
    try {
      const op = await Operation.create(dir, { label: "Deliv Op", kind: "security" })
      await Operation.setBoundary(dir, op.slug, {
        default: "ask",
        in_scope: ["target.test"],
        out_of_scope: [],
      })
      await Plan.add(dir, op.slug, { title: "Recon" })
      const sub = await Plan.add(dir, op.slug, { title: "Nmap scan" })
      await Plan.update(dir, op.slug, sub.id, { status: "done" })
      const o = await Observation.add(dir, op.slug, {
        subtype: "vuln",
        title: "SQLi on /login",
        severity: "critical",
      })
      const ev = await Evidence.put(dir, op.slug, "proof bytes", { mime: "text/plain" })
      await Observation.linkEvidence(dir, op.slug, o.id, ev.sha256)

      const res = await Deliverable.build(dir, op.slug)
      expect(res.manifest.counts.plan).toBe(2)
      expect(res.manifest.counts.observations).toBe(1)
      expect(res.manifest.counts.evidence).toBe(1)
      expect(res.manifest.files.length).toBe(2)

      const reportMd = readFileSync(res.reportPath, "utf8")
      expect(reportMd).toContain("Deliv Op")
      expect(reportMd).toContain("SQLi on /login")
      expect(reportMd).toContain("target.test")
      expect(reportMd).toContain(ev.sha256)

      for (const f of res.manifest.files) {
        const bytes = readFileSync(path.join(res.bundleDir, f.path))
        const h = createHash("sha256").update(bytes).digest("hex")
        expect(h).toBe(f.sha256)
      }

      const digestFile = readFileSync(path.join(res.bundleDir, "manifest.sha256"), "utf8")
      const manifestBytes = readFileSync(res.manifestPath)
      const expected = createHash("sha256").update(manifestBytes).digest("hex")
      expect(digestFile).toContain(expected)
    } finally {
      cleanup()
    }
  })

  test("json-only mode skips report.md", async () => {
    const { dir, cleanup } = mkws()
    try {
      const op = await Operation.create(dir, { label: "JSON only", kind: "security" })
      const res = await Deliverable.build(dir, op.slug, { format: "json" })
      expect(res.manifest.files.map((f) => f.path)).toEqual(["report.json"])
    } finally {
      cleanup()
    }
  })

  test("unknown operation throws", async () => {
    const { dir, cleanup } = mkws()
    try {
      await expect(Deliverable.build(dir, "does-not-exist")).rejects.toThrow(/not found/)
    } finally {
      cleanup()
    }
  })
})
