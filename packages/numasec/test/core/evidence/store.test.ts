import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync, writeFileSync } from "fs"
import { tmpdir } from "os"
import path from "path"
import { Evidence } from "@/core/evidence"

function mkws() {
  const dir = mkdtempSync(path.join(tmpdir(), "numasec-ev-"))
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

describe("core/evidence store", () => {
  test("put bytes, get roundtrip, sha256 stable", async () => {
    const { dir, cleanup } = mkws()
    try {
      const bytes = Buffer.from("hello numasec")
      const entry = await Evidence.put(dir, "op1", new Uint8Array(bytes), {
        mime: "text/plain",
        label: "greeting",
      })
      expect(entry.sha256).toHaveLength(64)
      expect(entry.size).toBe(bytes.length)
      expect(entry.ext).toBe("txt")

      const got = await Evidence.get(dir, "op1", entry.sha256)
      expect(got).toBeDefined()
      expect(Buffer.from(got!.bytes).toString("utf8")).toBe("hello numasec")
    } finally {
      cleanup()
    }
  })

  test("dedupe: same bytes = one manifest entry", async () => {
    const { dir, cleanup } = mkws()
    try {
      const bytes = "same content"
      await Evidence.put(dir, "op1", bytes, { mime: "text/plain" })
      await Evidence.put(dir, "op1", bytes, { mime: "text/plain", label: "second time" })
      const list = await Evidence.list(dir, "op1")
      expect(list.length).toBe(1)
    } finally {
      cleanup()
    }
  })

  test("put from file path", async () => {
    const { dir, cleanup } = mkws()
    try {
      const p = path.join(dir, "sample.json")
      writeFileSync(p, '{"ok":true}')
      const entry = await Evidence.put(dir, "op1", { path: p }, { mime: "application/json" })
      expect(entry.ext).toBe("json")
      expect(entry.size).toBe(11)
    } finally {
      cleanup()
    }
  })

  test("different bytes yield different hashes", async () => {
    const { dir, cleanup } = mkws()
    try {
      const a = await Evidence.put(dir, "op1", "alpha")
      const b = await Evidence.put(dir, "op1", "beta")
      expect(a.sha256).not.toBe(b.sha256)
      const list = await Evidence.list(dir, "op1")
      expect(list.length).toBe(2)
    } finally {
      cleanup()
    }
  })
})
