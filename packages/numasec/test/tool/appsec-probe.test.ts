import { afterEach, describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Cyber } from "../../src/core/cyber"
import { Evidence } from "../../src/core/evidence"
import { Observation } from "../../src/core/observation"
import { Operation } from "../../src/core/operation"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { MessageID, SessionID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { AppsecProbeTool, _deps } from "../../src/tool/appsec-probe"
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
  agent: "appsec",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  extra: {},
  ask: () => Effect.succeed(undefined as any),
} as any

async function exec(params: Record<string, unknown>) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* AppsecProbeTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

async function surfaceResponse(url: string, init: RequestInit) {
  const u = new URL(url)
  if (u.pathname === "/search") {
    const q = u.searchParams.get("q") ?? ""
    const body =
      q.includes("OR 1=1")
        ? { error: "SQL syntax near OR 1=1", route: "/search" }
        : { echo: q, reflected: q.includes("numasec-xss"), route: "/search" }
    return Response.json(body, { status: 200 })
  }
  if (u.pathname === "/session/login") {
    return Response.json({ error: "invalid credentials", token_type: "JWT bearer" }, { status: 401 })
  }
  if (u.pathname === "/accounts/7") {
    return Response.json({ id: 7, owner: "alice" }, { status: 200 })
  }
  const headers: Record<string, string> = { "Content-Type": "text/html" }
  const requestHeaders = new Headers(init.headers)
  if (requestHeaders.get("origin")) {
    headers["Access-Control-Allow-Origin"] = requestHeaders.get("origin")!
    headers["Access-Control-Allow-Credentials"] = "true"
  }
  return new Response("<html><body>ok</body></html>", { status: 200, headers })
}

afterEach(async () => {
  await Instance.disposeAll()
})

describe("tool/appsec-probe", () => {
  test("builds candidate probes from observed routes/forms instead of benchmark-specific paths", async () => {
    await using fixture = await tmpdir()
    const target = "https://app.test"
    const savedFetch = _deps.fetch
    _deps.fetch = surfaceResponse

    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const op = await Operation.create({ workspace: fixture.path, label: "AppSec Web", kind: "appsec", target })
          await AppRuntime.runPromise(
            Cyber.upsertFact({
              operation_slug: op.slug,
              entity_kind: "http_route",
              entity_key: "https://app.test/search?q=apple",
              fact_name: "discovered_by:test",
              value_json: { route: "/search?q=apple" },
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
            }),
          )
          await AppRuntime.runPromise(
            Cyber.upsertFact({
              operation_slug: op.slug,
              entity_kind: "http_route",
              entity_key: "https://app.test/accounts/7",
              fact_name: "discovered_by:test",
              value_json: { route: "/accounts/7" },
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
            }),
          )
          await AppRuntime.runPromise(
            Cyber.upsertFact({
              operation_slug: op.slug,
              entity_kind: "http_form",
              entity_key: "POST:https://app.test/session/login",
              fact_name: "shape",
              value_json: {
                action: "https://app.test/session/login",
                method: "post",
                source: "form",
                inputs: [
                  { name: "email", type: "email" },
                  { name: "password", type: "password" },
                ],
              },
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
            }),
          )

          const result: any = await exec({ target, timeout: 5_000 })
          const evidence = await Evidence.list(fixture.path, op.slug)
          const observations = await Observation.listProjected(fixture.path, op.slug)
          const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 500 }))
          const projected = await Cyber.readProjectedState(fixture.path, op.slug)

          expect(result.metadata.target).toBe(target)
          expect(result.metadata.candidates).toBeGreaterThanOrEqual(4)
          expect(result.output).toContain("/search")
          expect(result.output).toContain("/session/login")
          expect(result.output).toContain("/accounts/7")
          expect(result.output).not.toContain("/rest/products/search")
          expect(result.output).not.toContain("/rest/user/login")
          expect(result.output).not.toContain("/rest/basket/1")
          expect(evidence.some((item) => item.source === "appsec_probe")).toBe(true)
          expect(observations.length).toBeGreaterThan(0)
          expect(observations.every((item) => item.subtype !== "vuln")).toBe(true)
          expect(projected.summary.observations_projected).toBeGreaterThan(0)
          expect(projected.summary.candidate_findings).toBeGreaterThanOrEqual(4)
          expect(projected.summary.verified_findings).toBe(0)
          expect(projected.summary.reportable_findings).toBe(0)
          expect(
            facts.some(
              (item) =>
                item.entity_kind === "finding_candidate" &&
                item.fact_name === "sqli_search" &&
                Array.isArray(item.evidence_refs) &&
                item.evidence_refs.length > 0,
            ),
          ).toBe(true)
          expect(
            facts.some(
              (item) =>
                item.entity_kind === "identity" &&
                item.entity_key === "anonymous" &&
                item.fact_name === "descriptor",
            ),
          ).toBe(true)
        },
      })
    } finally {
      _deps.fetch = savedFetch
    }
  })

  test("degrades honestly when no observed routes or forms exist", async () => {
    await using fixture = await tmpdir()
    const target = "https://empty.test"
    const savedFetch = _deps.fetch
    _deps.fetch = surfaceResponse

    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const op = await Operation.create({ workspace: fixture.path, label: "Sparse AppSec", kind: "appsec", target })
          const result: any = await exec({ target, timeout: 5_000 })
          const projected = await Cyber.readProjectedState(fixture.path, op.slug)
          const observations = await Observation.listProjected(fixture.path, op.slug)

          expect(result.metadata.candidates).toBe(0)
          expect(result.output).toContain("skipped")
          expect(result.output).toContain("No observed reflective input surface")
          expect(projected.summary.candidate_findings).toBe(0)
          expect(projected.summary.verified_findings).toBe(0)
          expect(projected.summary.reportable_findings).toBe(0)
          expect(observations.every((item) => item.subtype !== "vuln")).toBe(true)
        },
      })
    } finally {
      _deps.fetch = savedFetch
    }
  })
})
