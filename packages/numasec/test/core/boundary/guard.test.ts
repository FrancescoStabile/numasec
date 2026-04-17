import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "fs"
import { tmpdir } from "os"
import path from "path"
import { Operation, OperationActive } from "@/core/operation"
import { Guard, ScopeDeniedError } from "@/core/boundary"

function mkws() {
  const dir = mkdtempSync(path.join(tmpdir(), "numasec-guard-"))
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

describe("core/boundary guard", () => {
  test("no active op → allow passthrough", async () => {
    const { dir, cleanup } = mkws()
    try {
      const d = await Guard.checkUrl(dir, "https://evil.example.com/")
      expect(d.mode).toBe("allow")
      expect(d.reason).toMatch(/no active operation/)
    } finally {
      cleanup()
    }
  })

  test("deny URL out-of-scope throws ScopeDeniedError", async () => {
    const { dir, cleanup } = mkws()
    try {
      const op = await Operation.create(dir, { label: "Guard Op", kind: "security" })
      await OperationActive.setActive(dir, op.slug)
      await Operation.setBoundary(dir, op.slug, {
        default: "ask",
        in_scope: ["target.test"],
        out_of_scope: ["*.evil.com"],
      })

      await expect(Guard.checkUrl(dir, "https://api.evil.com/")).rejects.toBeInstanceOf(
        ScopeDeniedError,
      )
      const d = await Guard.checkUrl(dir, "https://target.test/a")
      expect(d.mode).toBe("allow")
    } finally {
      cleanup()
    }
  })

  test("ask default when no in_scope match returns ask (no throw)", async () => {
    const { dir, cleanup } = mkws()
    try {
      const op = await Operation.create(dir, { label: "Guard Op", kind: "security" })
      await OperationActive.setActive(dir, op.slug)
      await Operation.setBoundary(dir, op.slug, {
        default: "ask",
        in_scope: ["only.test"],
        out_of_scope: [],
      })
      const d = await Guard.checkUrl(dir, "https://other.test/")
      expect(d.mode).toBe("ask")
    } finally {
      cleanup()
    }
  })
})
