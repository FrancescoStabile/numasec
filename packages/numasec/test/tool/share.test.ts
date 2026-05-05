import { describe, expect, test } from "bun:test"
import * as fs from "node:fs/promises"
import path from "node:path"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Cyber } from "../../src/core/cyber"
import { Operation } from "../../src/core/operation"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { MessageID, SessionID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { run as share, ShareTool } from "../../src/tool/share"
import { tmpdir } from "../fixture/fixture"

// tar-based share tests rely on POSIX tar behavior; skip on Windows.
const skipWindows = test.skipIf(process.platform === "win32")

const runtime = ManagedRuntime.make(
  Layer.mergeAll(
    AppFileSystem.defaultLayer,
    Format.defaultLayer,
    Bus.layer,
    Truncate.defaultLayer,
    Agent.defaultLayer,
  ),
)

const baseCtx = {
  sessionID: SessionID.make("ses_test"),
  messageID: MessageID.make(""),
  callID: "",
  agent: "security",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  extra: {},
  ask: () => Effect.succeed(undefined as any),
} as any

async function execShare(params: Record<string, unknown>) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* ShareTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/share", () => {
  skipWindows("default run emits a redacted, unsigned tarball with manifest inside", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({
          workspace: fixture.path,
          label: "Acme Assess",
          kind: "pentest",
          target: "https://acme.example.com",
        })
        const opDir = Operation.opDir(fixture.path, op.slug)

        const jwt =
          "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZyYW5jZXNjbyJ9.abcdefghijklmno"
        await fs.writeFile(
          path.join(opDir, "evidence", "notes.md"),
          `# probe\nfound token: ${jwt}\n`,
        )
        await fs.writeFile(
          path.join(opDir, "report-001.md"),
          `# Report\nleaked: ${jwt}\n`,
        )
        await fs.writeFile(
          path.join(opDir, "numasec.md"),
          [
            "# Operation: stale",
            "",
            "<!--",
            "Derived markdown projection from the cyber kernel.",
            "This file was generated because the legacy notebook is absent.",
            "-->",
            "",
            "stale share notebook",
          ].join("\n"),
        )
        await fs.mkdir(path.join(opDir, "cyber"), { recursive: true })
        await fs.mkdir(path.join(opDir, "context"), { recursive: true })
        await fs.writeFile(
          path.join(opDir, "cyber", "facts.jsonl"),
          JSON.stringify({
            entity_kind: "finding",
            entity_key: "share:test",
            fact_name: "record",
            status: "verified",
            value_json: { title: "Shared proof", summary: "included in share", replay_present: true },
          }) + "\n",
        )
        await fs.writeFile(
          path.join(opDir, "context", "active-context.md"),
          "# Active Operation Context\n\nshared context\n",
        )

        const result = await share({ workspace: fixture.path })

        expect(result.slug).toBe(op.slug)
        expect(result.signed).toBe(false)
        expect(result.redacted).toBe(true)
        expect(result.size).toBeGreaterThan(0)
        expect(result.sha256).toMatch(/^[0-9a-f]{64}$/)

        const st = await fs.stat(result.path)
        expect(st.isFile()).toBe(true)
        expect(st.size).toBe(result.size)

        const proc = Bun.spawn(["tar", "-tzf", result.path], { stdout: "pipe" })
        const listing = await new Response(proc.stdout).text()
        await proc.exited
        expect(listing).toContain("./manifest.json")
        expect(listing).toContain("./evidence/notes.md")
        expect(listing).toContain("./report-001.md")
        expect(listing).toContain("./numasec.md")
        expect(listing).toContain("./cyber/facts.jsonl")
        expect(listing).toContain("./context/active-context.md")

        const stagingDir = result.path.replace(/\.tar\.gz$/, "")
        const notebook = await fs.readFile(path.join(stagingDir, "numasec.md"), "utf8")
        const notes = await fs.readFile(path.join(stagingDir, "evidence", "notes.md"), "utf8")
        const report = await fs.readFile(path.join(stagingDir, "report-001.md"), "utf8")
        expect(notebook).toContain("# Operation: Acme Assess")
        expect(notebook).toContain("Derived markdown projection from the cyber kernel.")
        expect(notebook).toContain("## Scope")
        expect(notebook).not.toContain("stale share notebook")
        expect(notes).not.toContain(jwt)
        expect(notes).toContain("[redacted:jwt]")
        expect(report).not.toContain(jwt)

        const manifest = JSON.parse(
          await fs.readFile(path.join(stagingDir, "manifest.json"), "utf8"),
        )
        expect(manifest.operation).toBe(op.slug)
        expect(manifest.redacted).toBe(true)
        expect(Array.isArray(manifest.files)).toBe(true)
        expect(manifest.files.length).toBeGreaterThan(0)
        for (const f of manifest.files) {
          expect(f.sha256).toMatch(/^[0-9a-f]{64}$/)
          expect(typeof f.size).toBe("number")
        }

        const deliverable = JSON.parse(
          await fs.readFile(path.join(stagingDir, "deliverable-manifest.json"), "utf8"),
        )
        expect(deliverable.counts.cyber_findings).toBeGreaterThanOrEqual(1)

      },
    })
  })

  skipWindows("tool execution records share bundle state in the cyber kernel", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({
          workspace: fixture.path,
          label: "Kernel Share",
          kind: "pentest",
        })
        const result: any = await execShare({ redact: true, sign: false })
        expect(result.metadata.slug).toBe(op.slug)

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 200 }))
        const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 200 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "share_bundle" &&
              item.fact_name === "archive" &&
              item.status === "verified",
          ),
        ).toBe(true)
        expect(
          relations.some(
            (item) =>
              item.src_kind === "operation" &&
              item.src_key === op.slug &&
              item.relation === "shares" &&
              item.dst_kind === "share_bundle",
          ),
        ).toBe(true)

        const status: any = await execShare({ action: "status" })
        expect(status.metadata.slug).toBe(op.slug)
        expect(String(status.metadata.path)).toContain(".tar.gz")
        expect(status.output).toContain("sha256:")
      },
    })
  })

  skipWindows("sign:true without a key gracefully degrades (signed=false + warning)", async () => {
    await using fixture = await tmpdir()
    await Operation.create({
      workspace: fixture.path,
      label: "Ghost",
      kind: "pentest",
    })
    // Ensure no signing key env vars leak in from the host runner.
    const saved = {
      mk: process.env.NUMASEC_MINISIGN_KEY,
      mp: process.env.NUMASEC_MINISIGN_PASSWORD,
      ck: process.env.COSIGN_KEY,
    }
    delete process.env.NUMASEC_MINISIGN_KEY
    delete process.env.NUMASEC_MINISIGN_PASSWORD
    delete process.env.COSIGN_KEY

    try {
      const result = await share({ workspace: fixture.path, sign: true })
      expect(result.signed).toBe(false)
      expect(result.warning).toBeDefined()
      expect(result.warning!.toLowerCase()).toContain("signing")
      expect(result.size).toBeGreaterThan(0)
      // no sig side-car should be written when signing fails
      await expect(fs.stat(result.path + ".sig")).rejects.toBeDefined()
    } finally {
      if (saved.mk !== undefined) process.env.NUMASEC_MINISIGN_KEY = saved.mk
      if (saved.mp !== undefined) process.env.NUMASEC_MINISIGN_PASSWORD = saved.mp
      if (saved.ck !== undefined) process.env.COSIGN_KEY = saved.ck
    }
  })

  test("errors when there is no active operation", async () => {
    await using fixture = await tmpdir()
    await expect(share({ workspace: fixture.path })).rejects.toThrow(/no active operation/)
  })
})
