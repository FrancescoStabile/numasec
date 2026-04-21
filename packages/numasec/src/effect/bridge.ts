import { Effect, Fiber } from "effect"
import { Instance, type InstanceContext } from "@/project/instance"
import { LocalContext } from "@/util"
import { InstanceRef } from "./instance-ref"
import { attachWith } from "./run-service"

export interface Shape {
  readonly promise: <A, E, R>(effect: Effect.Effect<A, E, R>) => Promise<A>
  readonly fork: <A, E, R>(effect: Effect.Effect<A, E, R>) => Fiber.Fiber<A, E>
}

function restore<R>(instance: InstanceContext | undefined, fn: () => R): R {
  if (instance) return Instance.restore(instance, fn)
  return fn()
}

export function make(): Effect.Effect<Shape> {
  return Effect.gen(function* () {
    const ctx = yield* Effect.context()
    const value = yield* InstanceRef
    const instance =
      value ??
      (() => {
        try {
          return Instance.current
        } catch (err) {
          if (!(err instanceof LocalContext.NotFound)) throw err
        }
      })()
    const attach = <A, E, R>(effect: Effect.Effect<A, E, R>) => attachWith(effect, { instance })
    const wrap = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
      attach(effect).pipe(Effect.provide(ctx)) as Effect.Effect<A, E, never>

    return {
      promise: <A, E, R>(effect: Effect.Effect<A, E, R>) =>
        restore(instance, () => Effect.runPromise(wrap(effect))),
      fork: <A, E, R>(effect: Effect.Effect<A, E, R>) =>
        restore(instance, () => Effect.runFork(wrap(effect))),
    } satisfies Shape
  })
}
