import { Effect, Layer, ManagedRuntime } from "effect"
import * as Context from "effect/Context"
import { Instance } from "@/project/instance"
import { LocalContext } from "@/util"
import { InstanceRef } from "./instance-ref"
import * as Observability from "./observability"
import type { InstanceContext } from "@/project/instance"

export const memoMap = Layer.makeMemoMapUnsafe()

type Refs = {
  instance?: InstanceContext
}

export function attachWith<A, E, R>(effect: Effect.Effect<A, E, R>, refs: Refs): Effect.Effect<A, E, R> {
  if (!refs.instance) return effect
  return effect.pipe(Effect.provideService(InstanceRef, refs.instance))
}

export function attach<A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, R> {
  try {
    return attachWith(effect, {
      instance: Instance.current,
    })
  } catch (err) {
    if (!(err instanceof LocalContext.NotFound)) throw err
  }
  return effect
}

export function makeRuntime<I, S, E>(service: Context.Service<I, S>, layer: Layer.Layer<I, E>) {
  let rt: ManagedRuntime.ManagedRuntime<I, E> | undefined
  const getRuntime = () => (rt ??= ManagedRuntime.make(Layer.provideMerge(layer, Observability.layer), { memoMap }))

  return {
    runSync: <A, Err>(fn: (svc: S) => Effect.Effect<A, Err, I>) => getRuntime().runSync(attach(service.use(fn))),
    runPromiseExit: <A, Err>(fn: (svc: S) => Effect.Effect<A, Err, I>, options?: Effect.RunOptions) =>
      getRuntime().runPromiseExit(attach(service.use(fn)), options),
    runPromise: <A, Err>(fn: (svc: S) => Effect.Effect<A, Err, I>, options?: Effect.RunOptions) =>
      getRuntime().runPromise(attach(service.use(fn)), options),
    runFork: <A, Err>(fn: (svc: S) => Effect.Effect<A, Err, I>) => getRuntime().runFork(attach(service.use(fn))),
    runCallback: <A, Err>(fn: (svc: S) => Effect.Effect<A, Err, I>) =>
      getRuntime().runCallback(attach(service.use(fn))),
  }
}
