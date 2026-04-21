import { afterEach, beforeEach, describe, expect, it } from "bun:test"
import { mkdtemp, rm } from "fs/promises"
import { tmpdir } from "os"
import path from "path"
import { Operation } from "@/core/operation"

describe("Operation v3 core", () => {
  let ws: string
  beforeEach(async () => {
    ws = await mkdtemp(path.join(tmpdir(), "numasec-op-"))
  })
  afterEach(async () => {
    await rm(ws, { recursive: true, force: true })
  })

  it("create writes skeleton, activates, and round-trips via read", async () => {
    const info = await Operation.create({
      workspace: ws,
      label: "Juice Shop",
      kind: "pentest",
      target: "https://juice.example.com",
    })
    expect(info.slug).toBe("juice-shop")
    expect(info.active).toBe(true)

    const md = await Operation.readMarkdown(ws, info.slug)
    expect(md).toContain("# Operation: Juice Shop")
    expect(md).toContain("## Scope")

    const reread = await Operation.read(ws, info.slug)
    expect(reread?.label).toBe("Juice Shop")
    expect(reread?.kind).toBe("pentest")
    expect(reread?.target).toBe("https://juice.example.com")
  })

  it("activeSlug reflects latest create and survives archive", async () => {
    const a = await Operation.create({ workspace: ws, label: "Alpha", kind: "ctf" })
    const b = await Operation.create({ workspace: ws, label: "Beta", kind: "bughunt" })
    expect(await Operation.activeSlug(ws)).toBe(b.slug)
    await Operation.archive(ws, b.slug)
    expect(await Operation.activeSlug(ws)).toBeUndefined()
    await Operation.activate(ws, a.slug)
    expect(await Operation.activeSlug(ws)).toBe(a.slug)
  })

  it("list sorts by updated_at desc", async () => {
    await Operation.create({ workspace: ws, label: "Old", kind: "pentest" })
    await new Promise((r) => setTimeout(r, 20))
    await Operation.create({ workspace: ws, label: "New", kind: "pentest" })
    const ops = await Operation.list(ws)
    expect(ops[0].label).toBe("New")
    expect(ops[1].label).toBe("Old")
  })
})
