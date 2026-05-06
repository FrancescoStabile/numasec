import { afterEach, describe, expect } from "bun:test"
import path from "path"
import fs from "fs/promises"
import { Effect, Layer } from "effect"
import { Instance } from "../../src/project/instance"
import * as CrossSpawnSpawner from "../../src/effect/cross-spawn-spawner"
import { ToolRegistry } from "../../src/tool"
import { provideTmpdirInstance } from "../fixture/fixture"
import { testEffect } from "../lib/effect"

const node = CrossSpawnSpawner.defaultLayer

const it = testEffect(Layer.mergeAll(ToolRegistry.defaultLayer, node))

afterEach(async () => {
  await Instance.disposeAll()
})

describe("tool.registry", () => {
  it.live("includes semantic cyber surfaces in the built-in tool registry", () =>
    provideTmpdirInstance(() =>
      Effect.gen(function* () {
        const registry = yield* ToolRegistry.Service
        const ids = yield* registry.ids()
        expect(ids).toContain("workspace")
        expect(ids).toContain("evidence")
        expect(ids).toContain("runbook")
        expect(ids).toContain("scope")
        expect(ids).toContain("analyze")
        expect(ids).toContain("knowledge")
        expect(ids).toContain("autonomy")
        expect(ids).toContain("finding")
        expect(ids).toContain("identity")
        expect(ids).toContain("observation")
        expect(ids).toContain("report")
        expect(ids).toContain("appsec_probe")
      }),
    ),
  )

  it.live("orders semantic cyber surfaces ahead of lower-level raw tools", () =>
    provideTmpdirInstance(() =>
      Effect.gen(function* () {
        const registry = yield* ToolRegistry.Service
        const ids = yield* registry.ids()
        expect(ids.indexOf("identity")).toBeLessThan(ids.indexOf("vault"))
        expect(ids.indexOf("analyze")).toBeLessThan(ids.indexOf("cloud_posture"))
        expect(ids.indexOf("knowledge")).toBeLessThan(ids.indexOf("cve"))
        expect(ids.indexOf("runbook")).toBeLessThan(ids.indexOf("play"))
      }),
    ),
  )

  it.live("loads tools from .numasec/tool (singular)", () =>
    provideTmpdirInstance((dir) =>
      Effect.gen(function* () {
        const numasec = path.join(dir, ".numasec")
        const tool = path.join(numasec, "tool")
        yield* Effect.promise(() => fs.mkdir(tool, { recursive: true }))
        yield* Effect.promise(() =>
          Bun.write(
            path.join(tool, "hello.ts"),
            [
              "export default {",
              "  description: 'hello tool',",
              "  args: {},",
              "  execute: async () => {",
              "    return 'hello world'",
              "  },",
              "}",
              "",
            ].join("\n"),
          ),
        )
        const registry = yield* ToolRegistry.Service
        const ids = yield* registry.ids()
        expect(ids).toContain("hello")
      }),
    ),
  )

  it.live("loads tools from .numasec/tools (plural)", () =>
    provideTmpdirInstance((dir) =>
      Effect.gen(function* () {
        const numasec = path.join(dir, ".numasec")
        const tools = path.join(numasec, "tools")
        yield* Effect.promise(() => fs.mkdir(tools, { recursive: true }))
        yield* Effect.promise(() =>
          Bun.write(
            path.join(tools, "hello.ts"),
            [
              "export default {",
              "  description: 'hello tool',",
              "  args: {},",
              "  execute: async () => {",
              "    return 'hello world'",
              "  },",
              "}",
              "",
            ].join("\n"),
          ),
        )
        const registry = yield* ToolRegistry.Service
        const ids = yield* registry.ids()
        expect(ids).toContain("hello")
      }),
    ),
  )

  it.live("loads tools with external dependencies without crashing", () =>
    provideTmpdirInstance((dir) =>
      Effect.gen(function* () {
        const numasec = path.join(dir, ".numasec")
        const tools = path.join(numasec, "tools")
        yield* Effect.promise(() => fs.mkdir(tools, { recursive: true }))
        yield* Effect.promise(() =>
          Bun.write(
            path.join(numasec, "package.json"),
            JSON.stringify({
              name: "custom-tools",
              dependencies: {
                "@numasec/plugin": "^0.0.0",
                cowsay: "^1.6.0",
              },
            }),
          ),
        )
        yield* Effect.promise(() =>
          Bun.write(
            path.join(numasec, "package-lock.json"),
            JSON.stringify({
              name: "custom-tools",
              lockfileVersion: 3,
              packages: {
                "": {
                  dependencies: {
                    "@numasec/plugin": "^0.0.0",
                    cowsay: "^1.6.0",
                  },
                },
              },
            }),
          ),
        )

        const cowsay = path.join(numasec, "node_modules", "cowsay")
        yield* Effect.promise(() => fs.mkdir(cowsay, { recursive: true }))
        yield* Effect.promise(() =>
          Bun.write(
            path.join(cowsay, "package.json"),
            JSON.stringify({
              name: "cowsay",
              type: "module",
              exports: "./index.js",
            }),
          ),
        )
        yield* Effect.promise(() =>
          Bun.write(
            path.join(cowsay, "index.js"),
            ["export function say({ text }) {", "  return `moo ${text}`", "}", ""].join("\n"),
          ),
        )
        yield* Effect.promise(() =>
          Bun.write(
            path.join(tools, "cowsay.ts"),
            [
              "import { say } from 'cowsay'",
              "export default {",
              "  description: 'tool that imports cowsay at top level',",
              "  args: { text: { type: 'string' } },",
              "  execute: async ({ text }: { text: string }) => {",
              "    return say({ text })",
              "  },",
              "}",
              "",
            ].join("\n"),
          ),
        )
        const registry = yield* ToolRegistry.Service
        const ids = yield* registry.ids()
        expect(ids).toContain("cowsay")
      }),
    ),
  )
})
