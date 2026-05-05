import { afterEach, beforeEach, describe, expect, it } from "bun:test"
import { mkdtemp, mkdir, rm, writeFile } from "fs/promises"
import { existsSync } from "fs"
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

  it("create seeds the kernel, activates, and round-trips via read", async () => {
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
    expect(info.lines).toBe(0)
    expect(existsSync(path.join(ws, ".numasec", "operation", info.slug, "numasec.md"))).toBe(false)

    const reread = await Operation.read(ws, info.slug)
    expect(reread?.label).toBe("Juice Shop")
    expect(reread?.kind).toBe("pentest")
    expect(reread?.target).toBe("https://juice.example.com")
    expect(reread?.lines).toBe(0)

    const cyberFacts = await Bun.file(path.join(ws, ".numasec", "operation", info.slug, "cyber", "facts.jsonl")).text()
    const cyberLedger = await Bun.file(path.join(ws, ".numasec", "operation", info.slug, "cyber", "ledger.jsonl")).text()
    const cyberRelations = await Bun.file(path.join(ws, ".numasec", "operation", info.slug, "cyber", "relations.jsonl")).text()
    const contextPack = await Operation.readContextPack(ws, info.slug)
    const projectedState = await Operation.readProjectedState(ws, info.slug)
    const projectedScope = await Operation.readProjectedScopePolicy(ws, info.slug)

    expect(cyberFacts).toContain('"fact_name":"operation_state"')
    expect(cyberFacts).toContain('"fact_name":"scope_policy"')
    expect(cyberLedger).toContain('"kind":"operation.note"')
    expect(cyberRelations).toContain('"relation":"targets"')
    expect(contextPack).toContain("# Active Operation Context")
    expect(contextPack).toContain(`slug: ${info.slug}`)
    expect(contextPack).toContain("- in: juice.example.com")
    expect(projectedState?.label).toBe("Juice Shop")
    expect(projectedState?.kind).toBe("pentest")
    expect(projectedState?.target).toBe("https://juice.example.com")
    expect(projectedScope?.default).toBe("ask")
    expect(projectedScope?.in_scope).toEqual(["juice.example.com"])
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

  it("attachSession persists a session artifact under the operation", async () => {
    const info = await Operation.create({ workspace: ws, label: "Alpha", kind: "pentest" })
    await Operation.attachSession(ws, info.slug, "ses_test_123")
    const sessionFile = path.join(ws, ".numasec", "operation", info.slug, "sessions", "ses_test_123.json")
    const content = await Bun.file(sessionFile).text()
    expect(content).toContain('"session_id": "ses_test_123"')
  })

  it("recordWorkflowStep marks the first matching planned tool step as completed", async () => {
    const info = await Operation.create({ workspace: ws, label: "Workflow", kind: "pentest" })
    await Operation.writeWorkflow(ws, info.slug, {
      kind: "play",
      id: "custom-play",
      payload: {
        trace: [
          { kind: "tool", tool: "workspace", args: { action: "status" } },
          { kind: "tool", tool: "scanner", args: { mode: "crawl" } },
        ],
        skipped: [],
      },
    })
    await Operation.setActiveWorkflow(ws, info.slug, { kind: "play", id: "custom-play" })

    const match = await Operation.recordWorkflowStep(ws, info.slug, {
      tool: "workspace",
      success: true,
      title: "workspace completed",
    })
    const workflow = await Operation.readWorkflow(ws, info.slug, { kind: "play", id: "custom-play" })

    expect(match?.step_index).toBe(1)
    expect(match?.status).toBe("completed")
    expect(Array.isArray(workflow?.trace)).toBe(true)
    expect((workflow?.trace as Array<any>)[0]?.outcome).toBe("completed")
    expect(workflow?.completed_steps).toBe(1)
    expect(workflow?.pending_steps).toBe(1)
  })

  it("recordWorkflowStep prefers the unresolved tool step whose planned args match the actual args", async () => {
    const info = await Operation.create({ workspace: ws, label: "Workflow Args", kind: "pentest" })
    await Operation.writeWorkflow(ws, info.slug, {
      kind: "play",
      id: "arg-play",
      payload: {
        trace: [
          { kind: "tool", tool: "scanner", args: { mode: "crawl", target: "https://a.test" } },
          { kind: "tool", tool: "scanner", args: { mode: "js", target: "https://a.test" } },
        ],
        skipped: [],
      },
    })
    await Operation.setActiveWorkflow(ws, info.slug, { kind: "play", id: "arg-play" })

    const match = await Operation.recordWorkflowStep(ws, info.slug, {
      tool: "scanner",
      success: true,
      args: { mode: "js", target: "https://a.test" },
    })
    const workflow = await Operation.readWorkflow(ws, info.slug, { kind: "play", id: "arg-play" })
    const trace = workflow?.trace as Array<any>

    expect(match?.step_index).toBe(2)
    expect(trace[0]?.outcome).toBeUndefined()
    expect(trace[1]?.outcome).toBe("completed")
    expect(workflow?.completed_steps).toBe(1)
    expect(workflow?.pending_steps).toBe(1)
  })

  it("recordWorkflowStep marks bypassed non-tool steps as skipped when later tool steps complete", async () => {
    const info = await Operation.create({ workspace: ws, label: "Workflow Skips", kind: "pentest" })
    await Operation.writeWorkflow(ws, info.slug, {
      kind: "runbook",
      id: "skip-runbook",
      payload: {
        trace: [
          { kind: "skill", skill: "passive-osint", label: "enumerate passive subdomains" },
          { kind: "tool", tool: "scanner", args: { mode: "crawl" } },
        ],
        skipped: [],
      },
    })
    await Operation.setActiveWorkflow(ws, info.slug, { kind: "runbook", id: "skip-runbook" })

    const match = await Operation.recordWorkflowStep(ws, info.slug, {
      tool: "scanner",
      success: true,
      args: { mode: "crawl" },
    })
    const workflow = await Operation.readWorkflow(ws, info.slug, { kind: "runbook", id: "skip-runbook" })
    const trace = workflow?.trace as Array<any>

    expect(match?.step_index).toBe(2)
    expect(trace[0]?.outcome).toBe("skipped")
    expect(trace[1]?.outcome).toBe("completed")
    expect(Array.isArray(workflow?.skipped)).toBe(true)
    expect((workflow?.skipped as Array<any>).length).toBe(1)
    expect(workflow?.completed_steps).toBe(1)
    expect(workflow?.pending_steps).toBe(0)
  })

  it("writeContextPack persists a derived operation context artifact", async () => {
    const info = await Operation.create({ workspace: ws, label: "Context", kind: "appsec" })
    await Operation.writeContextPack(ws, info.slug, "# Active Operation Context\n\nhello")
    const content = await Operation.readContextPack(ws, info.slug)
    expect(content).toContain("# Active Operation Context")
    expect(content).toContain("hello")
  })

  it("read prefers projected operation_state from the cyber kernel when present", async () => {
    const info = await Operation.create({ workspace: ws, label: "Legacy", kind: "pentest" })
    const cyberDir = path.join(ws, ".numasec", "operation", info.slug, "cyber")
    await Bun.write(
      path.join(cyberDir, "facts.jsonl"),
      [
        JSON.stringify({
          entity_kind: "operation",
          entity_key: info.slug,
          fact_name: "operation_state",
          value_json: {
            label: "Projected",
            kind: "appsec",
            target: "https://api.target.test",
            opsec: "strict",
          },
        }),
        "",
      ].join("\n"),
    )

    const reread = await Operation.read(ws, info.slug)
    expect(reread?.label).toBe("Projected")
    expect(reread?.kind).toBe("appsec")
    expect(reread?.target).toBe("https://api.target.test")
    expect(reread?.opsec).toBe("strict")
  })

  it("reads projected scope and autonomy policy from the cyber kernel", async () => {
    const info = await Operation.create({ workspace: ws, label: "Projected Policies", kind: "appsec" })
    const cyberDir = path.join(ws, ".numasec", "operation", info.slug, "cyber")
    await Bun.write(
      path.join(cyberDir, "facts.jsonl"),
      [
        JSON.stringify({
          entity_kind: "operation",
          entity_key: info.slug,
          fact_name: "scope_policy",
          value_json: {
            default: "allow",
            in_scope: ["target.test"],
            out_of_scope: ["admin.target.test"],
          },
        }),
        JSON.stringify({
          entity_kind: "operation",
          entity_key: info.slug,
          fact_name: "autonomy_policy",
          value_json: {
            mode: "permissioned",
            session_id: "ses_123",
            rules: [{ tool: "browser", decision: "ask" }],
          },
        }),
        "",
      ].join("\n"),
    )

    const [scope, autonomy] = await Promise.all([
      Operation.readProjectedScopePolicy(ws, info.slug),
      Operation.readProjectedAutonomyPolicy(ws, info.slug),
    ])

    expect(scope).toEqual({
      default: "allow",
      in_scope: ["target.test"],
      out_of_scope: ["admin.target.test"],
    })
    expect(autonomy?.mode).toBe("permissioned")
    expect(autonomy?.session_id).toBe("ses_123")
    expect(autonomy?.rules).toEqual([{ tool: "browser", decision: "ask" }])
  })

  it("read and activeSlug still work when the legacy notebook is missing but the operation directory and projected state remain", async () => {
    const info = await Operation.create({ workspace: ws, label: "Kernel Only", kind: "appsec" })
    const dir = path.join(ws, ".numasec", "operation", info.slug)
    const cyberDir = path.join(dir, "cyber")
    await mkdir(cyberDir, { recursive: true })
    await Bun.write(
      path.join(cyberDir, "facts.jsonl"),
      [
        JSON.stringify({
          entity_kind: "operation",
          entity_key: info.slug,
          fact_name: "operation_state",
          value_json: {
            label: "Kernel Only Projected",
            kind: "osint",
            target: "https://kernel-only.test",
            opsec: "strict",
          },
        }),
        "",
      ].join("\n"),
    )
    await rm(path.join(dir, "numasec.md"), { force: true })

    const [active, reread] = await Promise.all([Operation.activeSlug(ws), Operation.read(ws, info.slug)])

    expect(active).toBe(info.slug)
    expect(reread?.label).toBe("Kernel Only Projected")
    expect(reread?.kind).toBe("osint")
    expect(reread?.target).toBe("https://kernel-only.test")
    expect(reread?.opsec).toBe("strict")
    expect(reread?.lines).toBe(0)
  })

  it("readMarkdown falls back to a derived kernel projection when the legacy notebook is missing", async () => {
    const info = await Operation.create({
      workspace: ws,
      label: "Projected Markdown",
      kind: "appsec",
      target: "https://api.target.test",
    })
    await Operation.writeContextPack(ws, info.slug, "# Active Operation Context\n\nkernel-first")
    await rm(path.join(ws, ".numasec", "operation", info.slug, "numasec.md"), { force: true })

    const markdown = await Operation.readMarkdown(ws, info.slug)

    expect(markdown).toContain("# Operation: Projected Markdown")
    expect(markdown).toContain("Derived markdown projection from the cyber kernel.")
    expect(markdown).toContain("## Context Pack")
    expect(markdown).toContain("kernel-first")
    expect(markdown).toContain("## Reportability")
    expect(markdown).toContain("## Identities")
    expect(markdown).toContain("## Knowledge")
    expect(markdown).toContain("## Tool Runtime")
    expect(markdown).toContain("## Exports")
  })

  it("readMarkdown regenerates a derived notebook projection when an on-disk derived file is stale", async () => {
    const info = await Operation.create({
      workspace: ws,
      label: "Stale Derived Notebook",
      kind: "pentest",
      target: "https://stale-derived.test",
    })
    const file = path.join(ws, ".numasec", "operation", info.slug, "numasec.md")
    await writeFile(
      file,
      [
        "# Operation: stale",
        "",
        "<!--",
        "Derived markdown projection from the cyber kernel.",
        "This file was generated because the legacy notebook is absent.",
        "-->",
        "",
        "stale projection content",
      ].join("\n"),
      "utf8",
    )

    const markdown = await Operation.readMarkdown(ws, info.slug)

    expect(markdown).toContain("# Operation: Stale Derived Notebook")
    expect(markdown).toContain("https://stale-derived.test")
    expect(markdown).not.toContain("stale projection content")
  })

  it("setOpsec does not rewrite an on-disk derived notebook projection", async () => {
    const info = await Operation.create({
      workspace: ws,
      label: "Derived Opsec Notebook",
      kind: "appsec",
    })
    const file = path.join(ws, ".numasec", "operation", info.slug, "numasec.md")
    const stale = [
      "# Operation: stale",
      "",
      "<!--",
      "Derived markdown projection from the cyber kernel.",
      "This file was generated because the legacy notebook is absent.",
      "-->",
      "",
      "stale projection content",
    ].join("\n")
    await writeFile(file, stale, "utf8")

    await Operation.setOpsec(ws, info.slug, "strict")

    const raw = await Bun.file(file).text()
    const reread = await Operation.read(ws, info.slug)
    expect(raw).toBe(stale)
    expect(reread?.opsec).toBe("strict")
  })

  it("touch updates operation updated_at via the operation activity marker, not the legacy notebook", async () => {
    const info = await Operation.create({ workspace: ws, label: "Touch Marker", kind: "appsec" })
    const dir = path.join(ws, ".numasec", "operation", info.slug)
    const before = await Operation.read(ws, info.slug)
    await rm(path.join(dir, "numasec.md"), { force: true })
    await new Promise((r) => setTimeout(r, 20))
    await Operation.touch(ws, info.slug)

    const after = await Operation.read(ws, info.slug)

    expect(before).toBeDefined()
    expect(after).toBeDefined()
    expect(after!.updated_at).toBeGreaterThan(before!.updated_at)
    expect(after!.lines).toBe(0)
  })

  it("setOpsec updates projected operation and scope state even without a legacy notebook", async () => {
    const info = await Operation.create({ workspace: ws, label: "Kernel Opsec", kind: "pentest", target: "https://target.test" })
    await rm(path.join(ws, ".numasec", "operation", info.slug, "numasec.md"), { force: true })

    await Operation.setOpsec(ws, info.slug, "strict")

    const reread = await Operation.read(ws, info.slug)
    const projectedState = await Operation.readProjectedState(ws, info.slug)
    const projectedScope = await Operation.readProjectedScopePolicy(ws, info.slug)

    expect(reread?.opsec).toBe("strict")
    expect(projectedState?.opsec).toBe("strict")
    expect(projectedScope?.default).toBe("ask")
    expect(projectedScope?.in_scope).toEqual(["target.test"])
  })
})
