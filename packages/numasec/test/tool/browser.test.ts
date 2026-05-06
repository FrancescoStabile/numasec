import { describe, expect, test } from "bun:test"
import { Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Cyber } from "../../src/core/cyber"
import { Operation } from "../../src/core/operation"
import { Observation } from "../../src/core/observation"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { MessageID, SessionID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { BrowserTool, persistBrowserObservation } from "../../src/tool/browser"
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

describe("tool/browser", () => {
  test("passive_appsec is a valid action in the public parameters schema", async () => {
    const info = await runtime.runPromise(BrowserTool)
    const tool: any = await runtime.runPromise(info.init())
    expect(() => tool.parameters.parse({ action: "passive_appsec", url: "https://example.com" })).not.toThrow()
  })

  test("passive_appsec persists projected forms and observations under an active operation", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({
          workspace: fixture.path,
          label: "Browser Passive",
          kind: "pentest",
          target: "https://app.example.test",
        })
        await runtime.runPromise(
          persistBrowserObservation(
            { action: "passive_appsec", url: "https://app.example.test/login" } as any,
            {
              title: "Passive AppSec -> Login",
              metadata: {
                url: "https://app.example.test/login",
                findings: 1,
                high: 0,
                medium: 1,
                low: 0,
                request_count: 4,
                script_urls: ["https://app.example.test/app.js"],
                forms: [
                  {
                    action: "https://app.example.test/rest/user/login",
                    method: "post",
                    source: "form",
                    inputs: [{ name: "email", type: "email" }, { name: "password", type: "password" }],
                  },
                ],
              },
              output: JSON.stringify({ findings: [{ id: "missing-security-header" }] }),
            },
            {
              sessionID: SessionID.make("ses_test"),
              messageID: MessageID.make(""),
            } as any,
          ),
        )

        const projected = await Cyber.readProjectedState(fixture.path, op.slug)
        const facts = await Cyber.readProjectedFacts(fixture.path, op.slug)
        const observations = await Observation.listProjected(fixture.path, op.slug)
        expect(projected.summary.http_forms).toBeGreaterThan(0)
        expect(projected.summary.observations_projected).toBeGreaterThan(0)
        expect(
          facts.some(
            (fact) =>
              fact.entity_kind === "http_form" &&
              fact.fact_name === "shape" &&
              (fact.value_json as Record<string, unknown> | null)?.source === "form",
          ),
        ).toBe(true)
        expect(observations.some((item) => item.evidence.length > 0)).toBe(true)
      },
    })
  })
})
