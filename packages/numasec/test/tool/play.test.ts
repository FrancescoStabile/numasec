import { describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { SessionID, MessageID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { PlayTool, _deps } from "../../src/tool/play"
import { Operation } from "../../src/core/operation"
import { Cyber } from "../../src/core/cyber"
import { AppRuntime } from "../../src/effect/app-runtime"
import path from "path"
import { tmpdir } from "../fixture/fixture"

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

async function exec(params: Record<string, unknown>) {
  await using fixture = await tmpdir()
  return await Instance.provide({
    directory: fixture.path,
    fn: () =>
      runtime.runPromise(
        Effect.gen(function* () {
          const info = yield* PlayTool
          const tool = yield* info.init()
          return yield* tool.execute(params as any, baseCtx)
        }) as any,
      ),
  })
}

async function init() {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* PlayTool
      return yield* info.init()
    }) as any,
  )
}

function fakeProbe(browserPresent: boolean, binaryNames: string[] = []) {
  return () =>
    Effect.succeed({
      runtime: { node: "0" },
      os: { platform: "linux", arch: "x64", release: "0" },
      binaries: binaryNames.map((name) => ({ name, present: true })),
      browser: { present: browserPresent },
      knowledge: { live_sources: [], local_sources: [], cache_path: "", api_keys_required: false },
      vault: { present: false, path: "" },
      workspace: { path: "", writable: true },
      capability: { plays: [], verticals: [] },
    } as any)
}

describe("tool/play", () => {
  // `_deps` is module-global state, so these tests must stay sequential.
  test("documents auth-surface in the tool description and id schema", async () => {
    const tool: any = await init()
    expect(tool.description).toContain("auth-surface")
    expect(tool.description).toContain("session-related browser signals")
    expect(tool.parameters.shape.id.description).toContain("auth-surface")
  })

  test("documents cloud-posture in the tool description and id schema", async () => {
    const tool: any = await init()
    expect(tool.description).toContain("cloud-posture")
    expect(tool.parameters.shape.id.description).toContain("cloud-posture")
  })

  test("documents appsec-web-triage in the tool description and id schema", async () => {
    const tool: any = await init()
    expect(tool.description).toContain("appsec-web-triage")
    expect(tool.parameters.shape.id.description).toContain("appsec-web-triage")
  })

  test("api-surface: skips browser step when browser runtime unavailable", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({ id: "api-surface", args: { target: "https://example.com" } })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(1)
      expect(result.metadata.degraded).toBe(true)
      expect(result.output).toContain("API Surface Map")
      expect(result.output).toContain("browser")
    } finally {
      _deps.probe = saved
    }
  })

  test("api-surface: includes browser step when browser runtime available", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(true) as any
    try {
      const result: any = await exec({ id: "api-surface", args: { target: "https://example.com" } })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(0)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("API Surface Map")
      expect(result.output).toContain("browser")
    } finally {
      _deps.probe = saved
    }
  })

  test("auth-surface: skips browser auth enrichment when browser runtime unavailable", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({ id: "auth-surface", args: { target: "https://example.com" } })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(1)
      expect(result.metadata.degraded).toBe(true)
      expect(result.output).toContain("Auth Surface Map")
      expect(result.output).toContain("browser runtime")
    } finally {
      _deps.probe = saved
    }
  })

  test("auth-surface: includes browser auth enrichment when browser runtime available", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(true) as any
    try {
      const result: any = await exec({ id: "auth-surface", args: { target: "https://example.com" } })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(0)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("Auth Surface Map")
      expect(result.output).toContain("browser auth/session passive findings")
    } finally {
      _deps.probe = saved
    }
  })

  test("web-surface: skips browser passive findings when browser runtime unavailable", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({
        id: "web-surface",
        args: { target: "https://example.com", domain: "example.com" },
      })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(1)
      expect(result.metadata.degraded).toBe(true)
      expect(result.output).toContain("Web Surface Map")
      expect(result.output).toContain("browser runtime")
    } finally {
      _deps.probe = saved
    }
  })

  test("web-surface: includes browser passive findings when browser runtime available", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(true) as any
    try {
      const result: any = await exec({
        id: "web-surface",
        args: { target: "https://example.com", domain: "example.com" },
      })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(0)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("Web Surface Map")
      expect(result.output).toContain("Browser passive findings")
    } finally {
      _deps.probe = saved
    }
  })

  test("network-surface: exposes normalized scanner behavior without degraded state", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({
        id: "network-surface",
        args: { target: "10.0.0.5" },
      })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(0)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("Network Surface Map")
      expect(result.output).toContain("Scan common TCP ports")
      expect(result.output).toContain("Probe common services on common ports")
      expect(result.output).toContain('"mode":"ports"')
      expect(result.output).toContain('"mode":"service"')
      expect(result.output).not.toContain('"kind":"portscan"')
    } finally {
      _deps.probe = saved
    }
  })

  test("osint-target: surfaces literal write content instead of instruction-shaped args", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({
        id: "osint-target",
        args: { target: "example.com" },
      })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(0)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("## Sources reviewed")
      expect(result.output).toContain('"filePath":"./osint-example.com.md"')
      expect(result.output).toContain("Fill in the synthesized profile for example.com here.")
      expect(result.output).not.toContain("{{target}}")
      expect(result.output).not.toContain("content_brief")
    } finally {
      _deps.probe = saved
    }
  })

  test("appsec-triage: exposes normalized repo-marker and grep steps without bash", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({
        id: "appsec-triage",
        args: { path: "./fixture-repo" },
      })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(0)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("Application Security Triage")
      expect(result.output).toContain("Detect Node markers")
      expect(result.output).toContain("Find hard-coded secrets")
      expect(result.output).toContain('tool: glob')
      expect(result.output).toContain('tool: grep')
      expect(result.output).not.toContain('tool: bash')
      expect(result.output).not.toContain('"description":"hard-coded secrets"')
    } finally {
      _deps.probe = saved
    }
  })

  test("appsec-web-triage: exposes semantic DAST probe step", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({
        id: "appsec-web-triage",
        args: { target: "https://example.com" },
      })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(0)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("AppSec Web Triage")
      expect(result.output).toContain("appsec_probe")
      expect(result.output).toContain("sqli_search")
    } finally {
      _deps.probe = saved
    }
  })

  test("ctf-warmup: reports degraded artifact enrichment when local binaries are unavailable", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({
        id: "ctf-warmup",
        args: { target: "./artifact.bin" },
      })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(2)
      expect(result.metadata.degraded).toBe(true)
      expect(result.output).toContain("CTF Warm-Up")
      expect(result.output).toContain("Primary artifact triage with forensics-kit")
      expect(result.output).toContain("missing optional capability: file binary")
      expect(result.output).toContain("missing optional capability: exiftool binary")
      expect(result.output).not.toContain("fallback if forensics-kit")
    } finally {
      _deps.probe = saved
    }
  })

  test("ctf-warmup: includes local enrichment steps when forensic binaries are present", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false, ["file", "strings", "exiftool"]) as any
    try {
      const result: any = await exec({
        id: "ctf-warmup",
        args: { target: "./artifact.bin" },
      })
      expect(result.metadata.available).toBe(true)
      expect(result.metadata.skipped).toBe(0)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("Local file and strings enrichment")
      expect(result.output).toContain("Exif metadata enrichment")
      expect(result.output).toContain("Map to MITRE artifact context")
      expect(result.output).not.toContain("fallback if forensics-kit")
    } finally {
      _deps.probe = saved
    }
  })

  test("cloud-posture: reports unavailable when required adapter binary is missing", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({
        id: "cloud-posture",
        args: { provider: "aws" },
      })
      expect(result.metadata.available).toBe(false)
      expect(result.metadata.skipped).toBe(1)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("missing required capability: prowler adapter")
      expect(result.output).toContain("Cloud Posture")
    } finally {
      _deps.probe = saved
    }
  })

  test("documents container-surface in the tool description and id schema", async () => {
    const tool: any = await init()
    expect(tool.description).toContain("container-surface")
    expect(tool.description).toContain("image-first container surface sweep")
    expect(tool.parameters.shape.id.description).toContain("container-surface")
  })

  test("container-surface: reports unavailable when required adapter binary is missing", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({
        id: "container-surface",
        args: { image: "nginx:latest" },
      })
      expect(result.metadata.available).toBe(false)
      expect(result.metadata.skipped).toBe(1)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("missing required capability: trivy adapter")
      expect(result.output).toContain("Container Surface")
    } finally {
      _deps.probe = saved
    }
  })

  test("documents iac-triage in the tool description and id schema", async () => {
    const tool: any = await init()
    expect(tool.description).toContain("iac-triage")
    expect(tool.description).toContain("path-first IaC triage sweep")
    expect(tool.parameters.shape.id.description).toContain("iac-triage")
  })

  test("iac-triage: reports unavailable when required adapter binary is missing", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({
        id: "iac-triage",
        args: { path: "./iac" },
      })
      expect(result.metadata.available).toBe(false)
      expect(result.metadata.skipped).toBe(1)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("missing required capability: checkov adapter")
      expect(result.output).toContain("IaC Triage")
    } finally {
      _deps.probe = saved
    }
  })

  test("documents binary-triage in the tool description and id schema", async () => {
    const tool: any = await init()
    expect(tool.description).toContain("binary-triage")
    expect(tool.description).toContain("single-binary hardening triage")
    expect(tool.parameters.shape.id.description).toContain("binary-triage")
  })

  test("binary-triage: reports unavailable when required adapter binary is missing", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(false) as any
    try {
      const result: any = await exec({
        id: "binary-triage",
        args: { path: "./chal.bin" },
      })
      expect(result.metadata.available).toBe(false)
      expect(result.metadata.skipped).toBe(1)
      expect(result.metadata.degraded).toBe(false)
      expect(result.output).toContain("missing required capability: checksec adapter")
      expect(result.output).toContain("Binary Triage")
    } finally {
      _deps.probe = saved
    }
  })

  test("writes play execution trace into the cyber kernel when an operation is active", async () => {
    const saved = _deps.probe
    _deps.probe = fakeProbe(true) as any
    await using fixture = await tmpdir({ git: true })
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const op = await Operation.create({ workspace: fixture.path, label: "Play Kernel", kind: "pentest" })
          const result: any = await runtime.runPromise(
            Effect.gen(function* () {
              const info = yield* PlayTool
              const tool = yield* info.init()
              return yield* tool.execute(
                { id: "web-surface", args: { target: "https://example.com", domain: "example.com" } } as any,
                baseCtx,
              )
            }) as any,
          )
          expect(result.metadata.play).toBe("web-surface")

          const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
          const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 100 }))
          const workflowProjection = path.join(
            fixture.path,
            ".numasec",
            "operation",
            op.slug,
            "workflow",
            "play-web-surface.json",
          )

        expect(
          facts.some(
            (item) =>
              item.entity_kind === "play" &&
              item.entity_key === "web-surface" &&
              item.fact_name === "capsule_readiness",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "play" &&
              item.entity_key === "web-surface" &&
              item.fact_name === "capsule_execution",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) =>
                item.entity_kind === "play" &&
                item.entity_key === "web-surface" &&
                item.fact_name === "execution_trace",
            ),
          ).toBe(true)
          expect(
            relations.some(
              (item) =>
                item.src_kind === "operation" &&
                item.src_key === op.slug &&
                item.relation === "uses_play" &&
                item.dst_kind === "play" &&
                item.dst_key === "web-surface",
            ),
          ).toBe(true)
          expect(
            facts.some(
              (item) =>
                item.entity_kind === "workflow_step" &&
                item.entity_key.startsWith("play:web-surface:planned:") &&
                item.fact_name === "planned_step",
            ),
          ).toBe(true)
          expect(
            relations.some(
              (item) =>
                item.src_kind === "play" &&
                item.src_key === "web-surface" &&
                item.relation === "has_step" &&
                item.dst_kind === "workflow_step",
            ),
          ).toBe(true)
          expect(await Bun.file(workflowProjection).exists()).toBe(true)
        },
      })
    } finally {
      _deps.probe = saved
    }
  })
})
