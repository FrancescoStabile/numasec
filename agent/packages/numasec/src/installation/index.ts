import { Effect, Layer, Schema, ServiceMap, Stream } from "effect"
import { FetchHttpClient, HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import * as CrossSpawnSpawner from "@/effect/cross-spawn-spawner"
import { makeRuntime } from "@/effect/run-service"
import { withTransientReadRetry } from "@/util/effect-http-client"
import { ChildProcess, ChildProcessSpawner } from "effect/unstable/process"
import path from "path"
import os from "os"
import fs from "fs/promises"
import z from "zod"
import { BusEvent } from "@/bus/bus-event"
import { Flag } from "../flag/flag"
import { Log } from "../util/log"

declare global {
  const NUMASEC_VERSION: string
  const NUMASEC_CHANNEL: string
}

import semver from "semver"

export namespace Installation {
  const log = Log.create({ service: "installation" })

  export type Method = "curl" | "source" | "npm" | "pnpm" | "bun" | "unknown"

  export type ReleaseType = "patch" | "minor" | "major"

  export const Event = {
    Updated: BusEvent.define(
      "installation.updated",
      z.object({
        version: z.string(),
      }),
    ),
    UpdateAvailable: BusEvent.define(
      "installation.update-available",
      z.object({
        version: z.string(),
      }),
    ),
  }

  export function getReleaseType(current: string, latest: string): ReleaseType {
    const currMajor = semver.major(current)
    const currMinor = semver.minor(current)
    const newMajor = semver.major(latest)
    const newMinor = semver.minor(latest)

    if (newMajor > currMajor) return "major"
    if (newMinor > currMinor) return "minor"
    return "patch"
  }

  export const Info = z
    .object({
      version: z.string(),
      latest: z.string(),
    })
    .meta({
      ref: "InstallationInfo",
    })
  export type Info = z.infer<typeof Info>

  export const VERSION = typeof NUMASEC_VERSION === "string" ? NUMASEC_VERSION : "local"
  export const CHANNEL = typeof NUMASEC_CHANNEL === "string" ? NUMASEC_CHANNEL : "local"
  export const USER_AGENT = `numasec/${CHANNEL}/${VERSION}/${Flag.NUMASEC_CLIENT}`

  export function isPreview() {
    return CHANNEL !== "latest"
  }

  export function isLocal() {
    return CHANNEL === "local"
  }

  export class UpgradeFailedError extends Schema.TaggedErrorClass<UpgradeFailedError>()("UpgradeFailedError", {
    stderr: Schema.String,
  }) {}

  // Response schemas for external version APIs
  const GitHubRelease = Schema.Struct({ tag_name: Schema.String })
  const NpmPackage = Schema.Struct({ version: Schema.String })
  function root(file: string) {
    let dir = file
    try {
      const stat = require("fs").statSync(file, { throwIfNoEntry: false })
      if (stat?.isFile()) dir = path.dirname(file)
    } catch {}
    while (true) {
      if (require("fs").existsSync(path.join(dir, "install.sh")) && require("fs").existsSync(path.join(dir, "agent", "package.json"))) {
        return dir
      }
      const parent = path.dirname(dir)
      if (parent === dir) return
      dir = parent
    }
  }

  function source(file: string) {
    if (file.includes(path.join(".numasec", "bin"))) return false
    const fsSync = require("fs")
    const stat = fsSync.lstatSync(file, { throwIfNoEntry: false })
    if (!stat) return false
    const next = stat.isSymbolicLink() ? fsSync.realpathSync(file) : file
    return !!root(next)
  }

  export interface Interface {
    readonly info: () => Effect.Effect<Info>
    readonly method: () => Effect.Effect<Method>
    readonly latest: (method?: Method) => Effect.Effect<string>
    readonly upgrade: (method: Method, target: string) => Effect.Effect<void, UpgradeFailedError>
  }

  export class Service extends ServiceMap.Service<Service, Interface>()("@numasec/Installation") {}

  export const layer: Layer.Layer<Service, never, HttpClient.HttpClient | ChildProcessSpawner.ChildProcessSpawner> =
    Layer.effect(
      Service,
      Effect.gen(function* () {
        const http = yield* HttpClient.HttpClient
        const httpOk = HttpClient.filterStatusOk(withTransientReadRetry(http))
        const spawner = yield* ChildProcessSpawner.ChildProcessSpawner

        const text = Effect.fnUntraced(
          function* (cmd: string[], opts?: { cwd?: string; env?: Record<string, string> }) {
            const proc = ChildProcess.make(cmd[0], cmd.slice(1), {
              cwd: opts?.cwd,
              env: opts?.env,
              extendEnv: true,
            })
            const handle = yield* spawner.spawn(proc)
            const out = yield* Stream.mkString(Stream.decodeText(handle.stdout))
            yield* handle.exitCode
            return out
          },
          Effect.scoped,
          Effect.catch(() => Effect.succeed("")),
        )

        const run = Effect.fnUntraced(
          function* (cmd: string[], opts?: { cwd?: string; env?: Record<string, string> }) {
            const proc = ChildProcess.make(cmd[0], cmd.slice(1), {
              cwd: opts?.cwd,
              env: opts?.env,
              extendEnv: true,
            })
            const handle = yield* spawner.spawn(proc)
            const [stdout, stderr] = yield* Effect.all(
              [Stream.mkString(Stream.decodeText(handle.stdout)), Stream.mkString(Stream.decodeText(handle.stderr))],
              { concurrency: 2 },
            )
            const code = yield* handle.exitCode
            return { code, stdout, stderr }
          },
          Effect.scoped,
          Effect.catch(() => Effect.succeed({ code: ChildProcessSpawner.ExitCode(1), stdout: "", stderr: "" })),
        )

        const upgradeCurl = Effect.fnUntraced(
          function* (target: string) {
            const response = yield* httpOk.execute(HttpClientRequest.get("https://numasec.ai/install"))
            const body = yield* response.text
            const bodyBytes = new TextEncoder().encode(body)
            const proc = ChildProcess.make("bash", [], {
              stdin: Stream.make(bodyBytes),
              env: { VERSION: target },
              extendEnv: true,
            })
            const handle = yield* spawner.spawn(proc)
            const [stdout, stderr] = yield* Effect.all(
              [Stream.mkString(Stream.decodeText(handle.stdout)), Stream.mkString(Stream.decodeText(handle.stderr))],
              { concurrency: 2 },
            )
            const code = yield* handle.exitCode
            return { code, stdout, stderr }
          },
          Effect.scoped,
          Effect.orDie,
        )

        const methodImpl = Effect.fn("Installation.method")(function* () {
          const execPaths = [process.execPath]
          // process.execPath resolves symlinks — also check symlink source and common locations
          yield* Effect.sync(() => {
            try {
              const fsSync = require("fs")
              const selfExe = fsSync.readlinkSync("/proc/self/exe")
              if (selfExe !== process.execPath) execPaths.push(selfExe)
            } catch {}
            const home = process.env.NUMASEC_TEST_HOME || os.homedir()
            for (const candidate of [
              path.join(home, ".bun", "bin", "numasec"),
              path.join(home, ".local", "bin", "numasec"),
              path.join(home, ".numasec", "bin", "numasec"),
            ]) {
              try {
                const fsSync = require("fs")
                const stat = fsSync.lstatSync(candidate)
                if (stat.isSymbolicLink() || stat.isFile()) execPaths.push(candidate)
              } catch {}
            }
          })

          for (const ep of execPaths) {
            if (ep.includes(path.join(".numasec", "bin"))) return "curl" as Method
            if (source(ep)) return "source" as Method
          }
          const exec = process.execPath.toLowerCase()

          const checks: Array<{ name: Method; command: () => Effect.Effect<string> }> = [
            { name: "npm", command: () => text(["npm", "list", "-g", "--depth=0"]) },
            { name: "pnpm", command: () => text(["pnpm", "list", "-g", "--depth=0"]) },
            { name: "bun", command: () => text(["bun", "pm", "ls", "-g"]) },
          ]

          checks.sort((a, b) => {
            const aMatches = exec.includes(a.name)
            const bMatches = exec.includes(b.name)
            if (aMatches && !bMatches) return -1
            if (!aMatches && bMatches) return 1
            return 0
          })

          for (const check of checks) {
            const output = yield* check.command()
            if (output.includes("numasec")) {
              return check.name
            }
          }

          return "unknown" as Method
        })

        const latestImpl = Effect.fn("Installation.latest")(function* (installMethod?: Method) {
          const detectedMethod = installMethod || (yield* methodImpl())

          if (detectedMethod === "npm" || detectedMethod === "bun" || detectedMethod === "pnpm") {
            const r = (yield* text(["npm", "config", "get", "registry"])).trim()
            const reg = r || "https://registry.npmjs.org"
            const registry = reg.endsWith("/") ? reg.slice(0, -1) : reg
            const channel = CHANNEL
            const response = yield* httpOk.execute(
              HttpClientRequest.get(`${registry}/numasec/${channel}`).pipe(HttpClientRequest.acceptJson),
            )
            const data = yield* HttpClientResponse.schemaBodyJson(NpmPackage)(response)
            return data.version
          }

          if (detectedMethod === "source") {
            return VERSION
          }

          const response = yield* httpOk.execute(
            HttpClientRequest.get("https://api.github.com/repos/FrancescoStabile/numasec/releases/latest").pipe(
              HttpClientRequest.acceptJson,
            ),
          )
          const data = yield* HttpClientResponse.schemaBodyJson(GitHubRelease)(response)
          return data.tag_name.replace(/^v/, "")
        }, Effect.orDie)

        const upgradeImpl = Effect.fn("Installation.upgrade")(function* (m: Method, target: string) {
          let result: { code: ChildProcessSpawner.ExitCode; stdout: string; stderr: string } | undefined
          switch (m) {
            case "curl":
              result = yield* upgradeCurl(target)
              break
            case "source":
              return yield* new UpgradeFailedError({
                stderr: "Source installs are managed from the repository checkout. Pull the desired revision and rerun `bash install.sh`.",
              })
            case "npm":
              result = yield* run(["npm", "install", "-g", `numasec@${target}`])
              break
            case "pnpm":
              result = yield* run(["pnpm", "install", "-g", `numasec@${target}`])
              break
            case "bun":
              result = yield* run(["bun", "install", "-g", `numasec@${target}`])
              break
            default:
              return yield* new UpgradeFailedError({ stderr: `Unknown method: ${m}` })
          }
          if (!result || result.code !== 0) {
            const stderr = result?.stderr || ""
            return yield* new UpgradeFailedError({ stderr })
          }
          log.info("upgraded", {
            method: m,
            target,
            stdout: result.stdout,
            stderr: result.stderr,
          })
          yield* text([process.execPath, "--version"])
        })

        return Service.of({
          info: Effect.fn("Installation.info")(function* () {
            return {
              version: VERSION,
              latest: yield* latestImpl(),
            }
          }),
          method: methodImpl,
          latest: latestImpl,
          upgrade: upgradeImpl,
        })
      }),
    )

  export const defaultLayer = layer.pipe(
    Layer.provide(FetchHttpClient.layer),
    Layer.provide(CrossSpawnSpawner.defaultLayer),
  )

  const { runPromise } = makeRuntime(Service, defaultLayer)

  export async function info(): Promise<Info> {
    return runPromise((svc) => svc.info())
  }

  export async function method(): Promise<Method> {
    return runPromise((svc) => svc.method())
  }

  export async function latest(installMethod?: Method): Promise<string> {
    return runPromise((svc) => svc.latest(installMethod))
  }

  export async function upgrade(m: Method, target: string): Promise<void> {
    return runPromise((svc) => svc.upgrade(m, target))
  }
}
