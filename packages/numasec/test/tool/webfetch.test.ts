import { describe, expect, test } from "bun:test"
import path from "path"
import { Effect, Layer } from "effect"
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import { Agent } from "../../src/agent/agent"
import { Operation } from "../../src/core/operation"
import { Cyber } from "../../src/core/cyber"
import { Evidence } from "../../src/core/evidence"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Truncate } from "../../src/tool"
import { Instance } from "../../src/project/instance"
import { WebFetchTool } from "../../src/tool/webfetch"
import { SessionID, MessageID } from "../../src/session/schema"
import { tmpdir } from "../fixture/fixture"

const projectRoot = path.join(import.meta.dir, "../..")

const ctx = {
  sessionID: SessionID.make("ses_test"),
  messageID: MessageID.make("message"),
  callID: "",
  agent: "security",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  ask: () => Effect.void,
}

function mockHttpClient(handler: (request: Request) => Response) {
  const client = HttpClient.make((request) =>
    Effect.flatMap(HttpClientRequest.toWeb(request), (webRequest) =>
      Effect.succeed(HttpClientResponse.fromWeb(request, handler(webRequest))),
    ).pipe(Effect.orDie),
  )
  return Layer.succeed(HttpClient.HttpClient, client)
}

function exec(
  args: { url: string; format: "text" | "markdown" | "html" },
  httpLayer: Layer.Layer<HttpClient.HttpClient>,
) {
  return WebFetchTool.pipe(
    Effect.flatMap((info) => info.init()),
    Effect.flatMap((tool) => tool.execute(args, ctx)),
    Effect.provide(Layer.mergeAll(httpLayer, Truncate.defaultLayer, Agent.defaultLayer)),
    Effect.runPromise,
  )
}

describe("tool.webfetch", () => {
  test("returns image responses as file attachments", async () => {
    const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])
    const httpLayer = mockHttpClient(() =>
      new Response(bytes, { status: 200, headers: { "content-type": "IMAGE/PNG; charset=binary" } }),
    )
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const result = await exec({ url: "https://target.test/image.png", format: "markdown" }, httpLayer)
        expect(result.output).toBe("Image fetched successfully")
        expect(result.attachments).toBeDefined()
        expect(result.attachments?.length).toBe(1)
        expect(result.attachments?.[0].type).toBe("file")
        expect(result.attachments?.[0].mime).toBe("image/png")
        expect(result.attachments?.[0].url.startsWith("data:image/png;base64,")).toBe(true)
        expect(result.attachments?.[0]).not.toHaveProperty("id")
        expect(result.attachments?.[0]).not.toHaveProperty("sessionID")
        expect(result.attachments?.[0]).not.toHaveProperty("messageID")
      },
    })
  })

  test("keeps svg as text output", async () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><text>hello</text></svg>'
    const httpLayer = mockHttpClient(() =>
      new Response(svg, {
        status: 200,
        headers: { "content-type": "image/svg+xml; charset=UTF-8" },
      }),
    )
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const result = await exec({ url: "https://target.test/image.svg", format: "html" }, httpLayer)
        expect(result.output).toContain("<svg")
        expect(result.attachments).toBeUndefined()
      },
    })
  })

  test("keeps text responses as text output", async () => {
    const httpLayer = mockHttpClient(() =>
      new Response("hello from webfetch", {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      }),
    )
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const result = await exec({ url: "https://target.test/file.txt", format: "text" }, httpLayer)
        expect(result.output).toBe("hello from webfetch")
        expect(result.attachments).toBeUndefined()
      },
    })
  })

  test("persists fetched pages into evidence and the cyber kernel when an operation is active", async () => {
    const httpLayer = mockHttpClient(() =>
      new Response("<html><body><h1>Hello</h1><p>from webfetch</p></body></html>", {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" },
      }),
    )
    await using fixture = await tmpdir({ git: true })
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "WebFetch", kind: "osint" })
        const fetchedUrl = "https://target.test/page"
        const result = await exec({ url: fetchedUrl, format: "markdown" }, httpLayer)
        const [facts, relations, evidence] = await Promise.all([
          AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 })),
          AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 100 })),
          Evidence.list(fixture.path, op.slug),
        ])

        expect(result.output).toContain("# Hello")
        expect(evidence.some((item) => item.label === `webfetch ${fetchedUrl}`)).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "web_page" &&
              item.entity_key === fetchedUrl &&
              item.fact_name === "fetch_result",
          ),
        ).toBe(true)
        expect(
          relations.some(
            (item) =>
              item.src_kind === "host" &&
              item.relation === "hosts" &&
              item.dst_kind === "web_page" &&
              item.dst_key === fetchedUrl,
          ),
        ).toBe(true)
      },
    })
  })
})
