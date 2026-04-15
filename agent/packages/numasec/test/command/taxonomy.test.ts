import { describe, expect, test } from "bun:test"
import { Command } from "../../src/command/index"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"

describe("command taxonomy", () => {
  test("registers v2 command names", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const names = await Command.list().then((items) => items.map((item) => item.name))
        expect(names).toContain("scope set")
        expect(names).toContain("scope show")
        expect(names).toContain("hypothesis list")
        expect(names).toContain("verify next")
        expect(names).toContain("evidence list")
        expect(names).toContain("evidence show")
        expect(names).toContain("chains list")
        expect(names).toContain("finding list")
        expect(names).toContain("finding finalize")
        expect(names).toContain("remediation plan")
        expect(names).toContain("retest run")
        expect(names).toContain("report generate")
        expect(names).toContain("report finalize")
      },
    })
  })

  test("keeps legacy command aliases mapped to canonical behavior", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const scopeSet = await Command.get("scope set")
        const target = await Command.get("target")
        const findingList = await Command.get("finding list")
        const findingFinalize = await Command.get("finding finalize")
        const findings = await Command.get("findings")
        const reportGenerate = await Command.get("report generate")
        const reportFinalize = await Command.get("report finalize")
        const report = await Command.get("report")
        const evidence = await Command.get("evidence")

        expect(scopeSet).toBeDefined()
        expect(target).toBeDefined()
        expect(findingList).toBeDefined()
        expect(findingFinalize).toBeDefined()
        expect(findings).toBeDefined()
        expect(reportGenerate).toBeDefined()
        expect(reportFinalize).toBeDefined()
        expect(report).toBeDefined()
        expect(evidence).toBeDefined()

        expect(await target!.template).toBe(await scopeSet!.template)
        expect(await findings!.template).toBe(await findingList!.template)
        expect(await report!.template).toBe(await reportGenerate!.template)
        expect(await findingFinalize!.template).toContain("Call `finalize_finding`")
        expect(await reportFinalize!.template).toContain("Call `finalize_report`")
        expect(await evidence!.template).toContain("/evidence list")
        expect(await evidence!.template).toContain("/evidence show")
      },
    })
  })
})
