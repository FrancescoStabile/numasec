import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import path from "path"
import { Effect } from "effect"
import { ModelID, ProviderID } from "../../src/provider/schema"
import { Instruction } from "../../src/session/instruction"
import type { MessageV2 } from "../../src/session/message-v2"
import { Instance } from "../../src/project/instance"
import { MessageID, PartID, SessionID } from "../../src/session/schema"
import { Global } from "../../src/global"
import { Operation } from "../../src/core/operation"
import { Cyber } from "../../src/core/cyber"
import { AppRuntime } from "../../src/effect/app-runtime"
import { tmpdir } from "../fixture/fixture"

const run = <A>(effect: Effect.Effect<A, any, Instruction.Service>) =>
  Effect.runPromise(effect.pipe(Effect.provide(Instruction.defaultLayer)))

function loaded(filepath: string): MessageV2.WithParts[] {
  const sessionID = SessionID.make("session-loaded-1")
  const messageID = MessageID.make("message-loaded-1")

  return [
    {
      info: {
        id: messageID,
        sessionID,
        role: "user",
        time: { created: 0 },
        agent: "security",
        model: {
          providerID: ProviderID.make("anthropic"),
          modelID: ModelID.make("claude-sonnet-4-20250514"),
        },
      },
      parts: [
        {
          id: PartID.make("part-loaded-1"),
          messageID,
          sessionID,
          type: "tool",
          callID: "call-loaded-1",
          tool: "read",
          state: {
            status: "completed",
            input: {},
            output: "done",
            title: "Read",
            metadata: { loaded: [filepath] },
            time: { start: 0, end: 1 },
          },
        },
      ],
    },
  ]
}

describe("Instruction.resolve", () => {
  test("returns empty when AGENTS.md is at project root (already in systemPaths)", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "AGENTS.md"), "# Root Instructions")
        await Bun.write(path.join(dir, "src", "file.ts"), "const x = 1")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: () =>
        run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const system = yield* svc.systemPaths()
              expect(system.has(path.join(tmp.path, "AGENTS.md"))).toBe(true)

              const results = yield* svc.resolve(
                [],
                path.join(tmp.path, "src", "file.ts"),
                MessageID.make("message-test-1"),
              )
              expect(results).toEqual([])
            }),
          ),
        ),
    })
  })

  test("returns AGENTS.md from subdirectory (not in systemPaths)", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "subdir", "AGENTS.md"), "# Subdir Instructions")
        await Bun.write(path.join(dir, "subdir", "nested", "file.ts"), "const x = 1")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: () =>
        run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const system = yield* svc.systemPaths()
              expect(system.has(path.join(tmp.path, "subdir", "AGENTS.md"))).toBe(false)

              const results = yield* svc.resolve(
                [],
                path.join(tmp.path, "subdir", "nested", "file.ts"),
                MessageID.make("message-test-2"),
              )
              expect(results.length).toBe(1)
              expect(results[0].filepath).toBe(path.join(tmp.path, "subdir", "AGENTS.md"))
            }),
          ),
        ),
    })
  })

  test("doesn't reload AGENTS.md when reading it directly", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "subdir", "AGENTS.md"), "# Subdir Instructions")
        await Bun.write(path.join(dir, "subdir", "nested", "file.ts"), "const x = 1")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: () =>
        run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const filepath = path.join(tmp.path, "subdir", "AGENTS.md")
              const system = yield* svc.systemPaths()
              expect(system.has(filepath)).toBe(false)

              const results = yield* svc.resolve([], filepath, MessageID.make("message-test-3"))
              expect(results).toEqual([])
            }),
          ),
        ),
    })
  })

  test("does not reattach the same nearby instructions twice for one message", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "subdir", "AGENTS.md"), "# Subdir Instructions")
        await Bun.write(path.join(dir, "subdir", "nested", "file.ts"), "const x = 1")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: () =>
        run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const filepath = path.join(tmp.path, "subdir", "nested", "file.ts")
              const id = MessageID.make("message-claim-1")

              const first = yield* svc.resolve([], filepath, id)
              const second = yield* svc.resolve([], filepath, id)

              expect(first).toHaveLength(1)
              expect(first[0].filepath).toBe(path.join(tmp.path, "subdir", "AGENTS.md"))
              expect(second).toEqual([])
            }),
          ),
        ),
    })
  })

  test("clear allows nearby instructions to be attached again for the same message", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "subdir", "AGENTS.md"), "# Subdir Instructions")
        await Bun.write(path.join(dir, "subdir", "nested", "file.ts"), "const x = 1")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: () =>
        run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const filepath = path.join(tmp.path, "subdir", "nested", "file.ts")
              const id = MessageID.make("message-claim-2")

              const first = yield* svc.resolve([], filepath, id)
              yield* svc.clear(id)
              const second = yield* svc.resolve([], filepath, id)

              expect(first).toHaveLength(1)
              expect(second).toHaveLength(1)
              expect(second[0].filepath).toBe(path.join(tmp.path, "subdir", "AGENTS.md"))
            }),
          ),
        ),
    })
  })

  test("skips instructions already reported by prior read metadata", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "subdir", "AGENTS.md"), "# Subdir Instructions")
        await Bun.write(path.join(dir, "subdir", "nested", "file.ts"), "const x = 1")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: () =>
        run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const agents = path.join(tmp.path, "subdir", "AGENTS.md")
              const filepath = path.join(tmp.path, "subdir", "nested", "file.ts")
              const id = MessageID.make("message-claim-3")

              const results = yield* svc.resolve(loaded(agents), filepath, id)
              expect(results).toEqual([])
            }),
          ),
        ),
    })
  })

  test.todo("fetches remote instructions from config URLs via HttpClient", () => {})
})

describe("Instruction.system", () => {
  test("loads both project and global AGENTS.md when both exist", async () => {
    const originalConfigDir = process.env["NUMASEC_CONFIG_DIR"]
    delete process.env["NUMASEC_CONFIG_DIR"]

    await using globalTmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "AGENTS.md"), "# Global Instructions")
      },
    })
    await using projectTmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "AGENTS.md"), "# Project Instructions")
      },
    })

    const originalGlobalConfig = Global.Path.config
    ;(Global.Path as { config: string }).config = globalTmp.path

    try {
      await Instance.provide({
        directory: projectTmp.path,
        fn: () =>
          run(
            Instruction.Service.use((svc) =>
              Effect.gen(function* () {
                const paths = yield* svc.systemPaths()
                expect(paths.has(path.join(projectTmp.path, "AGENTS.md"))).toBe(true)
                expect(paths.has(path.join(globalTmp.path, "AGENTS.md"))).toBe(true)

                const rules = yield* svc.system()
                expect(rules).toHaveLength(2)
                expect(rules).toContain(
                  `Instructions from: ${path.join(projectTmp.path, "AGENTS.md")}\n# Project Instructions`,
                )
                expect(rules).toContain(
                  `Instructions from: ${path.join(globalTmp.path, "AGENTS.md")}\n# Global Instructions`,
                )
              }),
            ),
          ),
      })
    } finally {
      ;(Global.Path as { config: string }).config = originalGlobalConfig
      if (originalConfigDir === undefined) {
        delete process.env["NUMASEC_CONFIG_DIR"]
      } else {
        process.env["NUMASEC_CONFIG_DIR"] = originalConfigDir
      }
    }
  })

  test("does not auto-load active operation numasec.md as an instruction file, but emits structured operation context", async () => {
    await using projectTmp = await tmpdir()

    await Instance.provide({
      directory: projectTmp.path,
      fn: async () => {
        const op = await Operation.create({
          workspace: projectTmp.path,
          label: "Target Review",
          kind: "appsec",
          target: "https://target.test",
          opsec: "strict",
        })
        const opFile = path.join(projectTmp.path, ".numasec", "operation", op.slug, "numasec.md")

        await run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const paths = yield* svc.systemPaths()
              expect(paths.has(opFile)).toBe(false)

              const rules = yield* svc.system()
              expect(rules.some((item) => item.includes("Active operation"))).toBe(true)
              expect(rules.some((item) => item.includes(`slug: ${op.slug}`))).toBe(true)
              expect(rules.some((item) => item.includes("opsec: strict"))).toBe(true)
              expect(rules.some((item) => item.includes("- in: target.test"))).toBe(true)
              const derived = yield* Effect.promise(() => Operation.readContextPack(projectTmp.path, op.slug))
              expect(derived).toContain("# Active Operation Context")
              expect(derived).toContain(`slug: ${op.slug}`)
            }),
          ),
        )
      },
    })
  })

  test("prefers projected scope_policy from the cyber kernel over legacy markdown scope in operation context", async () => {
    await using projectTmp = await tmpdir()

    await Instance.provide({
      directory: projectTmp.path,
      fn: async () => {
        const op = await Operation.create({
          workspace: projectTmp.path,
          label: "Projected Scope",
          kind: "appsec",
          target: "https://target.test",
        })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "operation",
            entity_key: op.slug,
            fact_name: "scope_policy",
            value_json: {
              default: "ask",
              in_scope: ["api.target.test"],
              out_of_scope: ["target.test"],
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )

        await run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const rules = yield* svc.system()
              const activeRule = rules.find((item) => item.includes("Active operation"))
              expect(activeRule).toBeDefined()
              expect(activeRule).toContain("- in: api.target.test")
              expect(activeRule).toContain("- out: target.test")
            }),
          ),
        )
      },
    })
  })
})

describe("Instruction .numasec.md", () => {
  test("loads .numasec.md from project root alongside AGENTS.md", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "AGENTS.md"), "# Agent Instructions")
        await Bun.write(path.join(dir, ".numasec.md"), "# Numasec Instructions")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: () =>
        run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const paths = yield* svc.systemPaths()
              expect(paths.has(path.join(tmp.path, "AGENTS.md"))).toBe(true)
              expect(paths.has(path.join(tmp.path, ".numasec.md"))).toBe(true)

              const rules = yield* svc.system()
              expect(rules).toContain(
                `Instructions from: ${path.join(tmp.path, ".numasec.md")}\n# Numasec Instructions`,
              )
            }),
          ),
        ),
    })
  })

  test("loads .numasec.md from .numasec/ directory", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, ".numasec", ".numasec.md"), "# Dotdir Instructions")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: () =>
        run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const paths = yield* svc.systemPaths()
              expect(paths.has(path.join(tmp.path, ".numasec", ".numasec.md"))).toBe(true)
            }),
          ),
        ),
    })
  })

  test("loads .numasec.md even when no AGENTS.md exists", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, ".numasec.md"), "# Only Numasec")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: () =>
        run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const paths = yield* svc.systemPaths()
              expect(paths.has(path.join(tmp.path, ".numasec.md"))).toBe(true)
            }),
          ),
        ),
    })
  })

  test("resolve picks up .numasec.md from subdirectory", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "subdir", ".numasec.md"), "# Subdir Numasec")
        await Bun.write(path.join(dir, "subdir", "nested", "file.ts"), "const x = 1")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: () =>
        run(
          Instruction.Service.use((svc) =>
            Effect.gen(function* () {
              const results = yield* svc.resolve(
                [],
                path.join(tmp.path, "subdir", "nested", "file.ts"),
                MessageID.make("message-numasec-1"),
              )
              expect(results.length).toBe(1)
              expect(results[0].filepath).toBe(path.join(tmp.path, "subdir", ".numasec.md"))
            }),
          ),
        ),
    })
  })
})

describe("Instruction.systemPaths NUMASEC_CONFIG_DIR", () => {
  let originalConfigDir: string | undefined

  beforeEach(() => {
    originalConfigDir = process.env["NUMASEC_CONFIG_DIR"]
  })

  afterEach(() => {
    if (originalConfigDir === undefined) {
      delete process.env["NUMASEC_CONFIG_DIR"]
    } else {
      process.env["NUMASEC_CONFIG_DIR"] = originalConfigDir
    }
  })

  test("prefers NUMASEC_CONFIG_DIR AGENTS.md over global when both exist", async () => {
    await using profileTmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "AGENTS.md"), "# Profile Instructions")
      },
    })
    await using globalTmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "AGENTS.md"), "# Global Instructions")
      },
    })
    await using projectTmp = await tmpdir()

    process.env["NUMASEC_CONFIG_DIR"] = profileTmp.path
    const originalGlobalConfig = Global.Path.config
    ;(Global.Path as { config: string }).config = globalTmp.path

    try {
      await Instance.provide({
        directory: projectTmp.path,
        fn: () =>
          run(
            Instruction.Service.use((svc) =>
              Effect.gen(function* () {
                const paths = yield* svc.systemPaths()
                expect(paths.has(path.join(profileTmp.path, "AGENTS.md"))).toBe(true)
                expect(paths.has(path.join(globalTmp.path, "AGENTS.md"))).toBe(false)
              }),
            ),
          ),
      })
    } finally {
      ;(Global.Path as { config: string }).config = originalGlobalConfig
    }
  })

  test("falls back to global AGENTS.md when NUMASEC_CONFIG_DIR has no AGENTS.md", async () => {
    await using profileTmp = await tmpdir()
    await using globalTmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "AGENTS.md"), "# Global Instructions")
      },
    })
    await using projectTmp = await tmpdir()

    process.env["NUMASEC_CONFIG_DIR"] = profileTmp.path
    const originalGlobalConfig = Global.Path.config
    ;(Global.Path as { config: string }).config = globalTmp.path

    try {
      await Instance.provide({
        directory: projectTmp.path,
        fn: () =>
          run(
            Instruction.Service.use((svc) =>
              Effect.gen(function* () {
                const paths = yield* svc.systemPaths()
                expect(paths.has(path.join(profileTmp.path, "AGENTS.md"))).toBe(false)
                expect(paths.has(path.join(globalTmp.path, "AGENTS.md"))).toBe(true)
              }),
            ),
          ),
      })
    } finally {
      ;(Global.Path as { config: string }).config = originalGlobalConfig
    }
  })

  test("uses global AGENTS.md when NUMASEC_CONFIG_DIR is not set", async () => {
    await using globalTmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "AGENTS.md"), "# Global Instructions")
      },
    })
    await using projectTmp = await tmpdir()

    delete process.env["NUMASEC_CONFIG_DIR"]
    const originalGlobalConfig = Global.Path.config
    ;(Global.Path as { config: string }).config = globalTmp.path

    try {
      await Instance.provide({
        directory: projectTmp.path,
        fn: () =>
          run(
            Instruction.Service.use((svc) =>
              Effect.gen(function* () {
                const paths = yield* svc.systemPaths()
                expect(paths.has(path.join(globalTmp.path, "AGENTS.md"))).toBe(true)
              }),
            ),
          ),
      })
    } finally {
      ;(Global.Path as { config: string }).config = originalGlobalConfig
    }
  })
})
