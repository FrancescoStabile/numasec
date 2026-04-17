import { describe, expect, test } from "bun:test"
import type { MessageID, SessionID } from "../../src/session/schema"
import type { Tool } from "../../src/tool/tool"
import { AuthTestTool } from "../../src/security/tool/auth-test"
import { HttpRequestTool } from "../../src/security/tool/http-request"
import { ObserveSurfaceTool } from "../../src/security/tool/observe-surface"

function context(capture: { current?: Omit<any, "id" | "sessionID" | "tool"> }): Tool.Context {
  return {
    sessionID: "sess-permission-granularity" as SessionID,
    messageID: "msg-permission-granularity" as MessageID,
    agent: "test",
    abort: new AbortController().signal,
    extra: {},
    messages: [],
    metadata() {},
    ask: async (input) => {
      capture.current = input
      throw new Error("stop-after-ask")
    },
  }
}

async function captureRequest(tool: Tool.Info, args: Record<string, unknown>) {
  const capture: { current?: Omit<any, "id" | "sessionID" | "tool"> } = {}
  const impl = await tool.init()
  await expect(impl.execute(args as never, context(capture))).rejects.toThrow("stop-after-ask")
  return capture.current
}

describe("security permission granularity", () => {
  test("http_request no longer requests wildcard always-allow", async () => {
    const request = await captureRequest(HttpRequestTool, {
      url: "https://example.com/api",
      method: "GET",
    })

    expect(request?.always).toEqual([])
    expect(request?.patterns).toEqual(["https://example.com/api"])
  })

  test("observe_surface scopes approvals to the requested target", async () => {
    const request = await captureRequest(ObserveSurfaceTool, {
      target: "https://example.com",
      modes: ["recon"],
    })

    expect(request?.always).toEqual([])
    expect(request?.patterns).toEqual(["https://example.com"])
  })

  test("auth_test scopes approvals to the requested endpoint", async () => {
    const request = await captureRequest(AuthTestTool, {
      url: "https://example.com/login",
    })

    expect(request?.always).toEqual([])
    expect(request?.patterns).toEqual(["https://example.com/login"])
  })
})
