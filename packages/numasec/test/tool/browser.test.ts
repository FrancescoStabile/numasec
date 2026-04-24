import { describe, expect, test } from "bun:test"
import { Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Format } from "../../src/format"
import { Truncate } from "../../src/tool"
import { BrowserTool } from "../../src/tool/browser"

const runtime = ManagedRuntime.make(
  Layer.mergeAll(
    AppFileSystem.defaultLayer,
    Format.defaultLayer,
    Bus.layer,
    Truncate.defaultLayer,
    Agent.defaultLayer,
  ),
)

describe("tool/browser", () => {
  test("passive_appsec is a valid action in the public parameters schema", async () => {
    const info = await runtime.runPromise(BrowserTool)
    const tool: any = await runtime.runPromise(info.init())
    expect(() => tool.parameters.parse({ action: "passive_appsec", url: "https://example.com" })).not.toThrow()
  })
})
