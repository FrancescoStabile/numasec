import { describe, expect, test } from "bun:test"
import { mkdtemp } from "fs/promises"
import { tmpdir } from "os"
import path from "path"
import { Operation } from "../../../src/core/operation"
import { Plan } from "../../../src/core/plan"

async function scratch(): Promise<{ ws: string; slug: string }> {
  const ws = await mkdtemp(path.join(tmpdir(), "plan-"))
  const op = await Operation.create(ws, { label: "Test", kind: "pentest" })
  return { ws, slug: op.slug }
}

describe("Plan.Store", () => {
  test("add → list round trip", async () => {
    const { ws, slug } = await scratch()
    const n1 = await Plan.add(ws, slug, { title: "recon" })
    const n2 = await Plan.add(ws, slug, { title: "exploit", parent_id: n1.id })
    const nodes = await Plan.list(ws, slug)
    expect(nodes.map((n) => n.title)).toEqual(["recon", "exploit"])
    expect(nodes[1].parent_id).toBe(n1.id)
    expect(nodes.every((n) => n.status === "planned")).toBe(true)
  })

  test("status transitions replay deterministically", async () => {
    const { ws, slug } = await scratch()
    const n = await Plan.add(ws, slug, { title: "enum" })
    await Plan.update(ws, slug, n.id, { status: "running" })
    await Plan.update(ws, slug, n.id, { status: "done", note: "owned it" })
    const [node] = await Plan.list(ws, slug)
    expect(node.status).toBe("done")
    expect(node.note).toBe("owned it")
  })

  test("remove drops node, move reparents", async () => {
    const { ws, slug } = await scratch()
    const a = await Plan.add(ws, slug, { title: "a" })
    const b = await Plan.add(ws, slug, { title: "b" })
    const c = await Plan.add(ws, slug, { title: "c", parent_id: a.id })
    await Plan.move(ws, slug, c.id, b.id)
    await Plan.remove(ws, slug, a.id)
    const nodes = await Plan.list(ws, slug)
    expect(nodes.map((n) => n.id).sort()).toEqual([b.id, c.id].sort())
    expect(nodes.find((n) => n.id === c.id)?.parent_id).toBe(b.id)
  })

  test("progress counts by status", async () => {
    const { ws, slug } = await scratch()
    const a = await Plan.add(ws, slug, { title: "a" })
    const b = await Plan.add(ws, slug, { title: "b" })
    const c = await Plan.add(ws, slug, { title: "c" })
    await Plan.update(ws, slug, a.id, { status: "done" })
    await Plan.update(ws, slug, b.id, { status: "running" })
    await Plan.update(ws, slug, c.id, { status: "blocked" })
    const p = Plan.progress(await Plan.list(ws, slug))
    expect(p).toEqual({ done: 1, running: 1, blocked: 1, total: 3 })
  })
})
