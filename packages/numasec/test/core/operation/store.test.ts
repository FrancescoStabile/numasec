import { describe, expect, test } from "bun:test"
import { mkdtemp, readFile } from "fs/promises"
import { tmpdir } from "os"
import path from "path"
import { Operation, OperationActive } from "../../../src/core/operation"

async function scratch(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "op-"))
}

describe("Operation.Store", () => {
  test("create → list → get round trip", async () => {
    const ws = await scratch()
    const a = await Operation.create(ws, { label: "Juice Shop", kind: "pentest" })
    expect(a.label).toBe("Juice Shop")
    expect(a.kind).toBe("pentest")
    expect(a.status).toBe("active")
    expect(a.slug).toBe("juice-shop")

    const b = await Operation.create(ws, { label: "Juice Shop", kind: "pentest" })
    expect(b.slug).toBe("juice-shop-2")

    const all = await Operation.list(ws)
    expect(all.map((o) => o.slug).sort()).toEqual(["juice-shop", "juice-shop-2"])

    const loaded = await Operation.get(ws, "juice-shop")
    expect(loaded?.id).toBe(a.id)
  })

  test("events replay deterministically", async () => {
    const ws = await scratch()
    const op = await Operation.create(ws, { label: "Acme Review", kind: "appsec" })
    await Operation.rename(ws, op.slug, "Acme Code Review")
    await Operation.setMode(ws, op.slug, { depth: "deep" })
    await Operation.attachSession(ws, op.slug, "ses_abc")
    await Operation.attachSession(ws, op.slug, "ses_abc") // duplicate, must dedupe
    await Operation.attachSession(ws, op.slug, "ses_def")

    const info = await Operation.get(ws, op.slug)
    expect(info?.label).toBe("Acme Code Review")
    expect(info?.mode.depth).toBe("deep")
    expect(info?.sessions).toEqual(["ses_abc", "ses_def"])

    // Snapshot is in sync with projection.
    const snap = JSON.parse(
      await readFile(path.join(Operation.opDir(ws, op.slug), "meta.json"), "utf8"),
    )
    expect(snap.sessions).toEqual(["ses_abc", "ses_def"])
  })

  test("archive transitions status", async () => {
    const ws = await scratch()
    const op = await Operation.create(ws, { label: "Old Run", kind: "security" })
    const after = await Operation.archive(ws, op.slug)
    expect(after.status).toBe("archived")
  })

  test("active marker + resolveActive fallback", async () => {
    const ws = await scratch()
    const op1 = await Operation.create(ws, { label: "First", kind: "osint" })
    const op2 = await Operation.create(ws, { label: "Second", kind: "osint" })

    expect(await OperationActive.getActiveSlug(ws)).toBeUndefined()

    await OperationActive.setActive(ws, op1.slug)
    const active = await OperationActive.getActive(ws)
    expect(active?.slug).toBe(op1.slug)

    // Archiving the active op hides it from getActive.
    await Operation.archive(ws, op1.slug)
    expect(await OperationActive.getActive(ws)).toBeUndefined()

    // resolveActive falls back to most-recent non-archived op when no marker.
    await OperationActive.clearActive(ws)
    const resolved = await OperationActive.resolveActive(ws)
    expect(resolved?.slug).toBe(op2.slug)
  })
})
