import type * as Arr from "effect/Array"
import { NodeFileSystem, NodeSink, NodeStream } from "@effect/platform-node"
import * as NodePath from "@effect/platform-node/NodePath"
import * as Deferred from "effect/Deferred"
import * as Effect from "effect/Effect"
import * as Exit from "effect/Exit"
import * as FileSystem from "effect/FileSystem"
import * as Layer from "effect/Layer"
import * as Path from "effect/Path"
import * as PlatformError from "effect/PlatformError"
import * as Predicate from "effect/Predicate"
import * as Queue from "effect/Queue"
import * as Scope from "effect/Scope"
import * as Cause from "effect/Cause"
import * as Sink from "effect/Sink"
import * as Stream from "effect/Stream"
import * as ChildProcess from "effect/unstable/process/ChildProcess"
import type { ChildProcessHandle } from "effect/unstable/process/ChildProcessSpawner"
import {
  ChildProcessSpawner,
  ExitCode,
  make as makeSpawner,
  makeHandle,
  ProcessId,
} from "effect/unstable/process/ChildProcessSpawner"
import * as NodeChildProcess from "node:child_process"
import * as NodeFs from "node:fs"
import * as NodeFsPromises from "node:fs/promises"
import * as NodeOs from "node:os"
import * as NodePathModule from "node:path"
import { PassThrough } from "node:stream"
import launch from "cross-spawn"

const toError = (err: unknown): Error => (err instanceof globalThis.Error ? err : new globalThis.Error(String(err)))

const toTag = (err: NodeJS.ErrnoException): PlatformError.SystemErrorTag => {
  switch (err.code) {
    case "ENOENT":
      return "NotFound"
    case "EACCES":
      return "PermissionDenied"
    case "EEXIST":
      return "AlreadyExists"
    case "EISDIR":
      return "BadResource"
    case "ENOTDIR":
      return "BadResource"
    case "EBUSY":
      return "Busy"
    case "ELOOP":
      return "BadResource"
    default:
      return "Unknown"
  }
}

const flatten = (command: ChildProcess.Command) => {
  const commands: Array<ChildProcess.StandardCommand> = []
  const opts: Array<ChildProcess.PipeOptions> = []

  const walk = (cmd: ChildProcess.Command): void => {
    switch (cmd._tag) {
      case "StandardCommand":
        commands.push(cmd)
        return
      case "PipedCommand":
        walk(cmd.left)
        opts.push(cmd.options)
        walk(cmd.right)
        return
    }
  }

  walk(command)
  if (commands.length === 0) throw new Error("flatten produced empty commands array")
  const [head, ...tail] = commands
  return {
    commands: [head, ...tail] as Arr.NonEmptyReadonlyArray<ChildProcess.StandardCommand>,
    opts,
  }
}

const toPlatformError = (
  method: string,
  err: NodeJS.ErrnoException,
  command: ChildProcess.Command,
): PlatformError.PlatformError => {
  const cmd = flatten(command)
    .commands.map((x) => `${x.command} ${x.args.join(" ")}`)
    .join(" | ")
  return PlatformError.systemError({
    _tag: toTag(err),
    module: "ChildProcess",
    method,
    pathOrDescriptor: cmd,
    syscall: err.syscall,
    cause: err,
  })
}

type ExitSignal = Deferred.Deferred<readonly [code: number | null, signal: NodeJS.Signals | null]>
type SpawnedProcess = NodeChildProcess.ChildProcess & {
  __numasecAllRecorder?: OutputRecorder
  __numasecStdoutRecorder?: OutputRecorder
  __numasecStderrRecorder?: OutputRecorder
}

type OutputRecorder = {
  chunks: Array<Uint8Array>
  ended: boolean
  error?: PlatformError.PlatformError
  listeners: Set<(chunk: Uint8Array) => void>
  endListeners: Set<() => void>
  errorListeners: Set<(error: PlatformError.PlatformError) => void>
}

export const make = Effect.gen(function* () {
  const fs = yield* FileSystem.FileSystem
  const path = yield* Path.Path

  const cwd = Effect.fnUntraced(function* (opts: ChildProcess.CommandOptions) {
    if (Predicate.isUndefined(opts.cwd)) return undefined
    yield* fs.access(opts.cwd)
    return path.resolve(opts.cwd)
  })

  const env = (opts: ChildProcess.CommandOptions) =>
    opts.extendEnv ? { ...globalThis.process.env, ...opts.env } : opts.env

  const input = (x: ChildProcess.CommandInput | undefined): NodeChildProcess.IOType | undefined =>
    Stream.isStream(x) ? "pipe" : x

  const output = (x: ChildProcess.CommandOutput | undefined): NodeChildProcess.IOType | undefined =>
    Sink.isSink(x) ? "pipe" : x

  const stdin = (opts: ChildProcess.CommandOptions): ChildProcess.StdinConfig => {
    const cfg: ChildProcess.StdinConfig = { stream: "pipe", encoding: "utf-8", endOnDone: true }
    if (Predicate.isUndefined(opts.stdin)) return cfg
    if (typeof opts.stdin === "string") return { ...cfg, stream: opts.stdin }
    if (Stream.isStream(opts.stdin)) return { ...cfg, stream: opts.stdin }
    return {
      stream: opts.stdin.stream,
      encoding: opts.stdin.encoding ?? cfg.encoding,
      endOnDone: opts.stdin.endOnDone ?? cfg.endOnDone,
    }
  }

  const stdio = (opts: ChildProcess.CommandOptions, key: "stdout" | "stderr"): ChildProcess.StdoutConfig => {
    const cfg = opts[key]
    if (Predicate.isUndefined(cfg)) return { stream: "pipe" }
    if (typeof cfg === "string") return { stream: cfg }
    if (Sink.isSink(cfg)) return { stream: cfg }
    return { stream: cfg.stream }
  }

  const fds = (opts: ChildProcess.CommandOptions) => {
    if (Predicate.isUndefined(opts.additionalFds)) return []
    return Object.entries(opts.additionalFds)
      .flatMap(([name, config]) => {
        const fd = ChildProcess.parseFdName(name)
        return Predicate.isUndefined(fd) ? [] : [{ fd, config }]
      })
      .toSorted((a, b) => a.fd - b.fd)
  }

  const makeOutputRecorder = (): OutputRecorder => ({
    chunks: [],
    ended: false,
    listeners: new Set(),
    endListeners: new Set(),
    errorListeners: new Set(),
  })

  const recordOutput = (
    recorder: OutputRecorder,
    source: NodeJS.ReadableStream,
    onError: (error: Error) => PlatformError.PlatformError,
    combined?: OutputRecorder,
    onComplete?: () => void,
  ) => {
    source.on("data", (chunk) => {
      const value = chunk instanceof Uint8Array ? new Uint8Array(chunk) : new Uint8Array(Buffer.from(chunk))
      recorder.chunks.push(value)
      for (const listener of recorder.listeners) listener(value)
      if (combined) {
        combined.chunks.push(value)
        for (const listener of combined.listeners) listener(value)
      }
    })
    source.on("end", () => {
      recorder.ended = true
      for (const listener of recorder.endListeners) listener()
      onComplete?.()
    })
    source.on("error", (cause) => {
      recorder.error = onError(toError(cause))
      for (const listener of recorder.errorListeners) listener(recorder.error)
      if (combined && !combined.error) {
        combined.error = recorder.error
        for (const listener of combined.errorListeners) listener(combined.error)
      }
    })
    source.resume()
  }

  const outputStream = (recorder: OutputRecorder) =>
    Stream.suspend(() => {
      const replay = Stream.fromIterable(recorder.chunks)
      if (recorder.error) return Stream.concat(replay, Stream.fail(recorder.error))
      if (recorder.ended) return replay
      return Stream.callback<Uint8Array, PlatformError.PlatformError>((queue) =>
        Effect.sync(() => {
          const onChunk = (chunk: Uint8Array) => {
            Queue.offerUnsafe(queue, chunk)
          }
          const onEnd = () => {
            Queue.endUnsafe(queue)
          }
          const onError = (error: PlatformError.PlatformError) => {
            Queue.failCauseUnsafe(queue, Cause.fail(error))
          }
          recorder.listeners.add(onChunk)
          recorder.endListeners.add(onEnd)
          recorder.errorListeners.add(onError)
          for (const chunk of recorder.chunks) Queue.offerUnsafe(queue, chunk)
          if (recorder.error) {
            Queue.failCauseUnsafe(queue, Cause.fail(recorder.error))
          } else if (recorder.ended) {
            Queue.endUnsafe(queue)
          }
          return Effect.sync(() => {
            recorder.listeners.delete(onChunk)
            recorder.endListeners.delete(onEnd)
            recorder.errorListeners.delete(onError)
          })
        }),
      )
    })

  const stdios = (
    sin: ChildProcess.StdinConfig,
    sout: ChildProcess.StdoutConfig,
    serr: ChildProcess.StderrConfig,
    extra: ReadonlyArray<{ fd: number; config: ChildProcess.AdditionalFdConfig }>,
    stdinFd?: number,
  ): NodeChildProcess.StdioOptions => {
    const pipe = (x: NodeChildProcess.IOType | undefined) =>
      process.platform === "win32" && x === "pipe" ? "overlapped" : x
    const arr: Array<NodeChildProcess.IOType | number | undefined> = [
      stdinFd ?? pipe(input(sin.stream)),
      pipe(output(sout.stream)),
      pipe(output(serr.stream)),
    ]
    if (extra.length === 0) return arr as NodeChildProcess.StdioOptions
    const max = extra.reduce((acc, x) => Math.max(acc, x.fd), 2)
    for (let i = 3; i <= max; i++) arr[i] = "ignore"
    for (const x of extra) arr[x.fd] = pipe("pipe")
    return arr as NodeChildProcess.StdioOptions
  }

  const setupFds = Effect.fnUntraced(function* (
    command: ChildProcess.StandardCommand,
    proc: NodeChildProcess.ChildProcess,
    extra: ReadonlyArray<{ fd: number; config: ChildProcess.AdditionalFdConfig }>,
  ) {
    if (extra.length === 0) {
      return {
        getInputFd: () => Sink.drain,
        getOutputFd: () => Stream.empty,
      }
    }

    const ins = new Map<number, Sink.Sink<void, Uint8Array, never, PlatformError.PlatformError>>()
    const outs = new Map<number, Stream.Stream<Uint8Array, PlatformError.PlatformError>>()

    for (const x of extra) {
      const node = proc.stdio[x.fd]
      switch (x.config.type) {
        case "input": {
          let sink: Sink.Sink<void, Uint8Array, never, PlatformError.PlatformError> = Sink.drain
          if (node && "write" in node) {
            sink = NodeSink.fromWritable({
              evaluate: () => node,
              onError: (err) => toPlatformError(`fromWritable(fd${x.fd})`, toError(err), command),
              endOnDone: true,
            })
          }
          if (x.config.stream) yield* Effect.forkScoped(Stream.run(x.config.stream, sink))
          ins.set(x.fd, sink)
          break
        }
        case "output": {
          let stream: Stream.Stream<Uint8Array, PlatformError.PlatformError> = Stream.empty
          if (node && "read" in node) {
            const tap = new PassThrough()
            node.on("error", (err) => tap.destroy(toError(err)))
            node.pipe(tap)
            stream = NodeStream.fromReadable({
              evaluate: () => tap,
              onError: (err) => toPlatformError(`fromReadable(fd${x.fd})`, toError(err), command),
            })
          }
          if (x.config.sink) stream = Stream.transduce(stream, x.config.sink)
          outs.set(x.fd, stream)
          break
        }
      }
    }

    return {
      getInputFd: (fd: number) => ins.get(fd) ?? Sink.drain,
      getOutputFd: (fd: number) => outs.get(fd) ?? Stream.empty,
    }
  })

  const concatChunks = (chunks: ReadonlyArray<unknown>, encoding: BufferEncoding) => {
    const buffers = chunks.map((chunk) => {
      if (typeof chunk === "string") return Buffer.from(chunk, encoding)
      if (chunk instanceof Uint8Array) return Buffer.from(chunk)
      return Buffer.from(chunk as ArrayBuffer)
    })
    return Buffer.concat(buffers)
  }

  const stageStdin = Effect.fnUntraced(function* (stream: Stream.Stream<unknown, PlatformError.PlatformError>, encoding: BufferEncoding) {
    const chunks = yield* Stream.runCollect(stream)
    const data = concatChunks(Array.from(chunks), encoding)
    const dir = yield* Effect.tryPromise({
      try: () => NodeFsPromises.mkdtemp(NodePathModule.join(NodeOs.tmpdir(), "numasec-stdin-")),
      catch: (cause) => toPlatformError("mkdtemp(stdin)", toError(cause), ChildProcess.make("stdin-stage")),
    })
    const file = NodePathModule.join(dir, "stdin.bin")
    yield* Effect.tryPromise({
      try: () => NodeFsPromises.writeFile(file, data),
      catch: (cause) => toPlatformError("writeFile(stdin)", toError(cause), ChildProcess.make("stdin-stage")),
    })
    const fd = yield* Effect.try({
      try: () => NodeFs.openSync(file, "r"),
      catch: (cause) => toPlatformError("openSync(stdin)", toError(cause), ChildProcess.make("stdin-stage")),
    })
    const scope = yield* Scope.Scope
    yield* Scope.addFinalizer(scope, Effect.sync(() => {
      try {
        NodeFs.closeSync(fd)
      } catch {}
      NodeFsPromises.rm(dir, { recursive: true, force: true }).catch(() => {})
    }))
    return fd
  })

  const setupStdin = (
    command: ChildProcess.StandardCommand,
    proc: NodeChildProcess.ChildProcess,
    cfg: ChildProcess.StdinConfig,
  ) =>
    Effect.suspend(() => {
      let sink: Sink.Sink<void, unknown, never, PlatformError.PlatformError> = Sink.drain
      if (Predicate.isNotNull(proc.stdin) && Stream.isStream(cfg.stream)) {
        const stdin = proc.stdin
        const writeChunk = (chunk: unknown) =>
          Effect.tryPromise({
            try: () =>
              new Promise<void>((resolve, reject) => {
                const onWrite = (cause?: Error | null) => {
                  if (cause) {
                    reject(cause)
                    return
                  }
                  resolve()
                }
                if (typeof chunk === "string") {
                  stdin.write(chunk, cfg.encoding ?? "utf-8", onWrite)
                  return
                }
                stdin.write(chunk as Uint8Array, onWrite)
              }),
            catch: (cause) => toPlatformError("write(stdin)", toError(cause), command),
          })
        const endInput = cfg.endOnDone
          ? Effect.tryPromise({
              try: () =>
                new Promise<void>((resolve, reject) => {
                  stdin.end((cause?: Error | null) => {
                    if (cause) {
                      reject(cause)
                      return
                    }
                    resolve()
                  })
                }),
              catch: (cause) => toPlatformError("end(stdin)", toError(cause), command),
            })
          : Effect.void
        return Effect.as(
          Effect.forkScoped(Stream.runForEach(cfg.stream, writeChunk).pipe(Effect.andThen(endInput))),
          sink,
        )
      }
      if (Predicate.isNotNull(proc.stdin)) {
        const options: {
          evaluate: () => NodeJS.WritableStream
          onError: (err: unknown) => PlatformError.PlatformError
          endOnDone: boolean
          encoding?: BufferEncoding
        } = {
          evaluate: () => proc.stdin!,
          onError: (err) => toPlatformError("fromWritable(stdin)", toError(err), command),
          endOnDone: cfg.endOnDone ?? true,
        }
        if (!Stream.isStream(cfg.stream)) {
          options.encoding = cfg.encoding
        }
        sink = NodeSink.fromWritable({
          ...options,
        })
      }
      return Effect.succeed(sink)
    })

  const setupOutput = (
    command: ChildProcess.StandardCommand,
    proc: SpawnedProcess,
    out: ChildProcess.StdoutConfig,
    err: ChildProcess.StderrConfig,
  ) => {
    let stdout = proc.__numasecStdoutRecorder
      ? outputStream(proc.__numasecStdoutRecorder)
      : Stream.empty
    let stderr = proc.__numasecStderrRecorder
      ? outputStream(proc.__numasecStderrRecorder)
      : Stream.empty

    if (Sink.isSink(out.stream)) stdout = Stream.transduce(stdout, out.stream)
    if (Sink.isSink(err.stream)) stderr = Stream.transduce(stderr, err.stream)

    const all = proc.__numasecAllRecorder ? outputStream(proc.__numasecAllRecorder) : Stream.merge(stdout, stderr)
    return { stdout, stderr, all }
  }

  const spawn = (command: ChildProcess.StandardCommand, opts: NodeChildProcess.SpawnOptions) =>
    Effect.callback<readonly [NodeChildProcess.ChildProcess, ExitSignal], PlatformError.PlatformError>((resume) => {
      const signal = Deferred.makeUnsafe<readonly [code: number | null, signal: NodeJS.Signals | null]>()
      const proc = launch(command.command, command.args, opts) as SpawnedProcess
      const allRecorder = makeOutputRecorder()
      proc.__numasecAllRecorder = allRecorder
      let openOutputs = 0
      const onOutputComplete = () => {
        openOutputs -= 1
        if (openOutputs === 0 && !allRecorder.ended && !allRecorder.error) {
          allRecorder.ended = true
          for (const listener of allRecorder.endListeners) listener()
        }
      }
      if (proc.stdout) {
        openOutputs += 1
        const stdoutRecorder = makeOutputRecorder()
        recordOutput(
          stdoutRecorder,
          proc.stdout,
          (cause) => toPlatformError("fromReadable(stdout)", cause, command),
          allRecorder,
          onOutputComplete,
        )
        proc.__numasecStdoutRecorder = stdoutRecorder
      }
      if (proc.stderr) {
        openOutputs += 1
        const stderrRecorder = makeOutputRecorder()
        recordOutput(
          stderrRecorder,
          proc.stderr,
          (cause) => toPlatformError("fromReadable(stderr)", cause, command),
          allRecorder,
          onOutputComplete,
        )
        proc.__numasecStderrRecorder = stderrRecorder
      }
      if (openOutputs === 0) {
        allRecorder.ended = true
      }
      let end = false
      let exit: readonly [code: number | null, signal: NodeJS.Signals | null] | undefined
      proc.on("error", (err) => {
        resume(Effect.fail(toPlatformError("spawn", err, command)))
      })
      proc.on("exit", (...args) => {
        exit = args
      })
      proc.on("close", (...args) => {
        if (end) return
        end = true
        Deferred.doneUnsafe(signal, Exit.succeed(exit ?? args))
      })
      proc.on("spawn", () => {
        resume(Effect.succeed([proc, signal]))
      })
      return Effect.sync(() => {
        proc.kill("SIGTERM")
      })
    })

  const killGroup = (
    command: ChildProcess.StandardCommand,
    proc: NodeChildProcess.ChildProcess,
    signal: NodeJS.Signals,
  ) => {
    if (globalThis.process.platform === "win32") {
      return Effect.callback<void, PlatformError.PlatformError>((resume) => {
        NodeChildProcess.exec(`taskkill /pid ${proc.pid} /T /F`, { windowsHide: true }, (err) => {
          if (err) return resume(Effect.fail(toPlatformError("kill", toError(err), command)))
          resume(Effect.void)
        })
      })
    }

    return Effect.try({
      try: () => {
        globalThis.process.kill(-proc.pid!, signal)
      },
      catch: (err) => toPlatformError("kill", toError(err), command),
    })
  }

  const killOne = (
    command: ChildProcess.StandardCommand,
    proc: NodeChildProcess.ChildProcess,
    signal: NodeJS.Signals,
  ) =>
    Effect.suspend(() => {
      if (proc.kill(signal)) return Effect.void
      return Effect.fail(toPlatformError("kill", new Error("Failed to kill child process"), command))
    })

  const timeout =
    (
      proc: NodeChildProcess.ChildProcess,
      command: ChildProcess.StandardCommand,
      opts: ChildProcess.KillOptions | undefined,
    ) =>
    <A, E, R>(
      f: (
        command: ChildProcess.StandardCommand,
        proc: NodeChildProcess.ChildProcess,
        signal: NodeJS.Signals,
      ) => Effect.Effect<A, E, R>,
    ) => {
      const signal = opts?.killSignal ?? "SIGTERM"
      if (Predicate.isUndefined(opts?.forceKillAfter)) return f(command, proc, signal)
      return Effect.timeoutOrElse(f(command, proc, signal), {
        duration: opts.forceKillAfter,
        orElse: () => f(command, proc, "SIGKILL"),
      })
    }

  const source = (handle: ChildProcessHandle, from: ChildProcess.PipeFromOption | undefined) => {
    const opt = from ?? "stdout"
    switch (opt) {
      case "stdout":
        return handle.stdout
      case "stderr":
        return handle.stderr
      case "all":
        return handle.all
      default: {
        const fd = ChildProcess.parseFdName(opt)
        return Predicate.isNotUndefined(fd) ? handle.getOutputFd(fd) : handle.stdout
      }
    }
  }

  const spawnCommand: (
    command: ChildProcess.Command,
  ) => Effect.Effect<ChildProcessHandle, PlatformError.PlatformError, Scope.Scope> = Effect.fnUntraced(
    function* (command) {
      switch (command._tag) {
        case "StandardCommand": {
          const scope = yield* Scope.make()
          const parentScope = yield* Scope.Scope
          yield* Scope.addFinalizerExit(parentScope, (exit) => Scope.close(scope, exit))
          const sin = stdin(command.options)
          const sout = stdio(command.options, "stdout")
          const serr = stdio(command.options, "stderr")
          const extra = fds(command.options)
          const dir = yield* cwd(command.options)
          const stagedStdinFd =
            typeof Bun !== "undefined" && Stream.isStream(sin.stream)
              ? yield* stageStdin(sin.stream, sin.encoding ?? "utf-8")
              : undefined

          const [proc, signal] = yield* Effect.acquireRelease(
            spawn(command, {
              cwd: dir,
              env: env(command.options),
              stdio: stdios(sin, sout, serr, extra, stagedStdinFd),
              detached: command.options.detached ?? process.platform !== "win32",
              shell: command.options.shell,
              windowsHide: process.platform === "win32",
            }),
            Effect.fnUntraced(function* ([proc, signal]) {
              const done = yield* Deferred.isDone(signal)
              const kill = timeout(proc, command, command.options)
              if (done) {
                const [code] = yield* Deferred.await(signal)
                if (process.platform === "win32") return yield* Effect.void
                if (code !== 0 && Predicate.isNotNull(code)) return yield* Effect.ignore(kill(killGroup))
                return yield* Effect.void
              }
              const send = (s: NodeJS.Signals) =>
                Effect.catch(killGroup(command, proc, s), () => killOne(command, proc, s))
              const sig = command.options.killSignal ?? "SIGTERM"
              const attempt = send(sig).pipe(Effect.andThen(Deferred.await(signal)), Effect.asVoid)
              const escalated = command.options.forceKillAfter
                ? Effect.timeoutOrElse(attempt, {
                    duration: command.options.forceKillAfter,
                    orElse: () => send("SIGKILL").pipe(Effect.andThen(Deferred.await(signal)), Effect.asVoid),
                  })
                : attempt
              return yield* Effect.ignore(escalated)
            }),
          ).pipe(Scope.provide(scope))

          const fd = yield* setupFds(command, proc, extra)
          const out = setupOutput(command, proc, sout, serr)
          let ref = true
          return makeHandle({
            pid: ProcessId(proc.pid!),
            stdin: stagedStdinFd === undefined ? yield* setupStdin(command, proc, sin) : Sink.drain,
            stdout: out.stdout,
            stderr: out.stderr,
            all: out.all,
            getInputFd: fd.getInputFd,
            getOutputFd: fd.getOutputFd,
            isRunning: Effect.map(Deferred.isDone(signal), (done) => !done),
            exitCode: Effect.flatMap(Deferred.await(signal), ([code, signal]) => {
              if (Predicate.isNotNull(code)) return Effect.succeed(ExitCode(code))
              return Effect.fail(
                toPlatformError(
                  "exitCode",
                  new Error(`Process interrupted due to receipt of signal: '${signal}'`),
                  command,
                ),
              )
            }),
            kill: (opts?: ChildProcess.KillOptions) => {
              const sig = opts?.killSignal ?? "SIGTERM"
              const send = (s: NodeJS.Signals) =>
                Effect.catch(killGroup(command, proc, s), () => killOne(command, proc, s))
              const attempt = send(sig).pipe(Effect.andThen(Deferred.await(signal)), Effect.asVoid)
              if (!opts?.forceKillAfter) return attempt
              return Effect.timeoutOrElse(attempt, {
                duration: opts.forceKillAfter,
                orElse: () => send("SIGKILL").pipe(Effect.andThen(Deferred.await(signal)), Effect.asVoid),
              })
            },
            unref: Effect.sync(() => {
              if (ref) {
                proc.unref()
                ref = false
              }
              return Effect.sync(() => {
                if (!ref) {
                  proc.ref()
                  ref = true
                }
              })
            }),
          })
        }
        case "PipedCommand": {
          const flat = flatten(command)
          const [head, ...tail] = flat.commands
          let handle = spawnCommand(head)
          for (let i = 0; i < tail.length; i++) {
            const next = tail[i]
            const opts = flat.opts[i] ?? {}
            const sin = stdin(next.options)
            const stream = Stream.unwrap(Effect.map(handle, (x) => source(x, opts.from)))
            const to = opts.to ?? "stdin"
            if (to === "stdin") {
              handle = spawnCommand(
                ChildProcess.make(next.command, next.args, {
                  ...next.options,
                  stdin: { ...sin, stream },
                }),
              )
              continue
            }
            const fd = ChildProcess.parseFdName(to)
            if (Predicate.isUndefined(fd)) {
              handle = spawnCommand(
                ChildProcess.make(next.command, next.args, {
                  ...next.options,
                  stdin: { ...sin, stream },
                }),
              )
              continue
            }
            handle = spawnCommand(
              ChildProcess.make(next.command, next.args, {
                ...next.options,
                additionalFds: {
                  ...next.options.additionalFds,
                  [ChildProcess.fdName(fd) as `fd${number}`]: { type: "input", stream },
                },
              }),
            )
          }
          return yield* handle
        }
      }
    },
  )

  return makeSpawner(spawnCommand)
})

export const layer: Layer.Layer<ChildProcessSpawner, never, FileSystem.FileSystem | Path.Path> = Layer.effect(
  ChildProcessSpawner,
  make,
)

export const defaultLayer = layer.pipe(Layer.provide(NodeFileSystem.layer), Layer.provide(NodePath.layer))

import { lazy } from "@/util/lazy"

const rt = lazy(async () => {
  // Dynamic import to avoid circular dep: cross-spawn-spawner → run-service → Instance → project → cross-spawn-spawner
  const { makeRuntime } = await import("@/effect/run-service")
  return makeRuntime(ChildProcessSpawner, defaultLayer)
})

type RT = Awaited<ReturnType<typeof rt>>
export const runPromiseExit: RT["runPromiseExit"] = async (...args) => (await rt()).runPromiseExit(...(args as [any]))
