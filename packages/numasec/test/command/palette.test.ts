import { describe, expect } from "bun:test"
import { Effect, Layer } from "effect"
import { Command } from "../../src/command"
import * as CrossSpawnSpawner from "../../src/effect/cross-spawn-spawner"
import { provideTmpdirInstance } from "../fixture/fixture"
import { testEffect } from "../lib/effect"

const it = testEffect(Layer.mergeAll(Command.defaultLayer, CrossSpawnSpawner.defaultLayer))

const DEFAULT_NAMES = ["pwn", "play", "doctor", "opsec", "share", "remediate", "teach", "init", "review"] as const

describe("command palette", () => {
  it.live("registers all default commands with short descriptions and priorities", () =>
    provideTmpdirInstance(
      () =>
        Effect.gen(function* () {
          const command = yield* Command.Service
          const all = yield* command.list()
          const byName = new Map(all.map((c) => [c.name, c]))

          for (const name of DEFAULT_NAMES) {
            const info = byName.get(name)
            expect(info, `missing command /${name}`).toBeDefined()
            expect(info!.description, `/${name} missing description`).toBeTruthy()
            expect(info!.description!.length, `/${name} description too long`).toBeLessThanOrEqual(80)
            expect(typeof info!.priority, `/${name} missing priority`).toBe("number")
          }

          const defaults = DEFAULT_NAMES.map((n) => byName.get(n)!).sort(
            (a, b) => (a.priority ?? 100) - (b.priority ?? 100),
          )
          expect(defaults[0].name).toBe("pwn")
          expect(defaults[defaults.length - 1].name).toBe("review")

          const priorities = defaults.map((d) => d.priority!)
          for (let i = 1; i < priorities.length; i++) {
            expect(priorities[i]).toBeGreaterThan(priorities[i - 1])
          }
        }),
      { git: true },
    ),
  )
})
