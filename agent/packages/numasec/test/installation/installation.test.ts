import { describe, expect, test } from "bun:test"
import { Effect, Layer, Stream } from "effect"
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import { ChildProcess, ChildProcessSpawner } from "effect/unstable/process"
import { Installation } from "../../src/installation"
import fs from "fs/promises"
import os from "os"
import path from "path"

const encoder = new TextEncoder()

function mockHttpClient(handler: (request: HttpClientRequest.HttpClientRequest) => Response) {
  const client = HttpClient.make((request) => Effect.succeed(HttpClientResponse.fromWeb(request, handler(request))))
  return Layer.succeed(HttpClient.HttpClient, client)
}

function mockSpawner(handler: (cmd: string, args: readonly string[]) => string = () => "") {
  const spawner = ChildProcessSpawner.make((command) => {
    const std = ChildProcess.isStandardCommand(command) ? command : undefined
    const output = handler(std?.command ?? "", std?.args ?? [])
    return Effect.succeed(
      ChildProcessSpawner.makeHandle({
        pid: ChildProcessSpawner.ProcessId(0),
        exitCode: Effect.succeed(ChildProcessSpawner.ExitCode(0)),
        isRunning: Effect.succeed(false),
        kill: () => Effect.void,
        stdin: { [Symbol.for("effect/Sink/TypeId")]: Symbol.for("effect/Sink/TypeId") } as any,
        stdout: output ? Stream.make(encoder.encode(output)) : Stream.empty,
        stderr: Stream.empty,
        all: Stream.empty,
        getInputFd: () => ({ [Symbol.for("effect/Sink/TypeId")]: Symbol.for("effect/Sink/TypeId") }) as any,
        getOutputFd: () => Stream.empty,
      }),
    )
  })
  return Layer.succeed(ChildProcessSpawner.ChildProcessSpawner, spawner)
}

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  })
}

function testLayer(
  httpHandler: (request: HttpClientRequest.HttpClientRequest) => Response,
  spawnHandler?: (cmd: string, args: readonly string[]) => string,
) {
  return Installation.layer.pipe(Layer.provide(mockHttpClient(httpHandler)), Layer.provide(mockSpawner(spawnHandler)))
}

describe("installation", () => {
  describe("latest", () => {
    test("reads release version from GitHub releases", async () => {
      const layer = testLayer(() => jsonResponse({ tag_name: "v1.2.3" }))

      const result = await Effect.runPromise(
        Installation.Service.use((svc) => svc.latest("unknown")).pipe(Effect.provide(layer)),
      )
      expect(result).toBe("1.2.3")
    })

    test("strips v prefix from GitHub release tag", async () => {
      const layer = testLayer(() => jsonResponse({ tag_name: "v4.0.0-beta.1" }))

      const result = await Effect.runPromise(
        Installation.Service.use((svc) => svc.latest("curl")).pipe(Effect.provide(layer)),
      )
      expect(result).toBe("4.0.0-beta.1")
    })

    test("reads npm registry versions", async () => {
      const layer = testLayer(
        () => jsonResponse({ version: "1.5.0" }),
        (cmd, args) => {
          if (cmd === "npm" && args.includes("registry")) return "https://registry.npmjs.org\n"
          return ""
        },
      )

      const result = await Effect.runPromise(
        Installation.Service.use((svc) => svc.latest("npm")).pipe(Effect.provide(layer)),
      )
      expect(result).toBe("1.5.0")
    })

    test("reads npm registry versions for bun method", async () => {
      const layer = testLayer(
        () => jsonResponse({ version: "1.6.0" }),
        () => "",
      )

      const result = await Effect.runPromise(
        Installation.Service.use((svc) => svc.latest("bun")).pipe(Effect.provide(layer)),
      )
      expect(result).toBe("1.6.0")
    })

    test("uses the current version for source installs", async () => {
      const layer = testLayer(() => jsonResponse({ tag_name: "v9.9.9" }), () => "")

      const result = await Effect.runPromise(
        Installation.Service.use((svc) => svc.latest("source")).pipe(Effect.provide(layer)),
      )
      expect(result).toBe(Installation.VERSION)
    })
  })

  describe("method", () => {
    test("detects source installs from a symlinked local binary", async () => {
      if (process.platform === "win32") return

      const prev = process.env.NUMASEC_TEST_HOME
      const home = await fs.mkdtemp(path.join(os.tmpdir(), "numasec-home-"))
      const repo = path.join(home, "repo")
      const target = path.join(repo, "agent", "packages", "numasec", "dist", "numasec-linux-x64", "bin", "numasec")
      const link = path.join(home, ".local", "bin", "numasec")
      try {
        process.env.NUMASEC_TEST_HOME = home
        await fs.mkdir(path.dirname(target), { recursive: true })
        await fs.mkdir(path.join(repo, "agent"), { recursive: true })
        await Bun.write(path.join(repo, "install.sh"), "#!/usr/bin/env bash\n")
        await Bun.write(path.join(repo, "agent", "package.json"), "{}\n")
        await Bun.write(target, "#!/usr/bin/env bash\n")
        await fs.mkdir(path.dirname(link), { recursive: true })
        await fs.symlink(target, link)

        const layer = testLayer(() => jsonResponse({ tag_name: "v1.2.3" }), () => "")
        const result = await Effect.runPromise(
          Installation.Service.use((svc) => svc.method()).pipe(Effect.provide(layer)),
        )

        expect(result).toBe("source")
      } finally {
        if (prev === undefined) delete process.env.NUMASEC_TEST_HOME
        else process.env.NUMASEC_TEST_HOME = prev
        await fs.rm(home, { recursive: true, force: true })
      }
    })

    test("treats unsupported package-manager installs as unknown", async () => {
      const layer = testLayer(
        () => jsonResponse({ tag_name: "v1.2.3" }),
        (cmd, args) => {
          if (cmd === "brew" && args.join(" ") === "list --formula numasec") return "numasec\n"
          if (cmd === "scoop" && args.join(" ") === "list numasec") return "Installed apps:\nnumasec 1.2.3\n"
          if (cmd === "choco" && args.join(" ") === "list --limit-output numasec") return "numasec|1.2.3\n"
          if (cmd === "yarn" && args.join(" ") === "global list") return "info\n└─ numasec@1.2.3\n"
          return ""
        },
      )

      const result = await Effect.runPromise(
        Installation.Service.use((svc) => svc.method()).pipe(Effect.provide(layer)),
      )

      expect(result).toBe("unknown")
    })
  })
})
