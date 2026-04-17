import z from "zod"
import { Effect } from "effect"
import fs from "node:fs/promises"
import path from "node:path"
import { spawn } from "node:child_process"
import { randomBytes } from "node:crypto"
import { Global } from "../global"
import { which } from "../util/which"
import * as Tool from "./tool"
import DESCRIPTION from "./interact.txt"

const parameters = z.object({
  op: z.enum(["generate", "poll", "close"]),
  id: z.string().optional(),
  max_wait_ms: z.number().int().min(100).max(30000).optional(),
})

type Params = z.infer<typeof parameters>
type Metadata = { op: string; id?: string; scheme?: string }

type Session = {
  id: string
  url: string
  scheme: "interactsh" | "webhook"
  pid?: number
  log_file?: string
}
type Store = Record<string, Session>

function storePath() {
  return path.join(Global.Path.state, "interact-sessions.json")
}

async function load(): Promise<Store> {
  try {
    return JSON.parse(await fs.readFile(storePath(), "utf-8")) as Store
  } catch {
    return {}
  }
}

async function save(s: Store) {
  await fs.mkdir(Global.Path.state, { recursive: true })
  await fs.writeFile(storePath(), JSON.stringify(s, null, 2), { mode: 0o600 })
}

function newId() {
  return "int_" + randomBytes(6).toString("hex")
}

function spawnInteractsh(id: string): Promise<{ url: string; pid: number; log_file: string }> {
  const logFile = path.join(Global.Path.log, `${id}.jsonl`)
  return new Promise((resolve, reject) => {
    const p = spawn("interactsh-client", ["-json", "-o", logFile, "-v"], { stdio: ["ignore", "pipe", "pipe"] })
    let urlFound: string | undefined
    const onData = (chunk: Buffer) => {
      const text = chunk.toString("utf-8")
      const m = text.match(/([a-z0-9]+\.oast\.(?:live|fun|me|site|pro|online))/i)
      if (m && !urlFound) {
        urlFound = `https://${m[1]}`
        resolve({ url: urlFound, pid: p.pid ?? 0, log_file: logFile })
      }
    }
    p.stdout.on("data", onData)
    p.stderr.on("data", onData)
    p.once("error", (e) => reject(e))
    p.once("exit", (code) => {
      if (!urlFound) reject(new Error(`interactsh-client exited with code ${code} before providing url`))
    })
    setTimeout(() => {
      if (!urlFound) {
        p.kill()
        reject(new Error("interactsh-client did not emit url within 10s"))
      }
    }, 10_000)
  })
}

function webhookUrl(id: string): string {
  const token = randomBytes(16).toString("hex")
  return `https://webhook.site/#!/${token}?id=${id}`
}

export const InteractTool = Tool.define<typeof parameters, Metadata, never>(
  "interact",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, _ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const store = yield* Effect.promise(() => load())
          if (params.op === "generate") {
            const id = newId()
            if (which("interactsh-client")) {
              const { url, pid, log_file } = yield* Effect.tryPromise({
                try: () => spawnInteractsh(id),
                catch: (e) => new Error(`interactsh: ${(e as Error).message}`),
              })
              store[id] = { id, url, scheme: "interactsh", pid, log_file }
              yield* Effect.promise(() => save(store))
              return {
                title: `interact generate (interactsh)`,
                output: JSON.stringify({ id, url, scheme: "interactsh" }, null, 2),
                metadata: { op: params.op, id, scheme: "interactsh" },
              }
            }
            const url = webhookUrl(id)
            store[id] = { id, url, scheme: "webhook" }
            yield* Effect.promise(() => save(store))
            return {
              title: `interact generate (webhook fallback)`,
              output: JSON.stringify(
                { id, url, scheme: "webhook", note: "install projectdiscovery interactsh-client for polling" },
                null,
                2,
              ),
              metadata: { op: params.op, id, scheme: "webhook" },
            }
          }
          if (params.op === "poll") {
            if (!params.id) throw new Error("poll requires id")
            const sess = store[params.id]
            if (!sess) throw new Error(`unknown session: ${params.id}`)
            if (sess.scheme !== "interactsh" || !sess.log_file) {
              return {
                title: `interact poll ${params.id}`,
                output: "webhook sessions cannot be polled via this tool; open the URL in a browser",
                metadata: { op: params.op, id: params.id, scheme: sess.scheme },
              }
            }
            const text = yield* Effect.promise(async () => {
              try {
                return await fs.readFile(sess.log_file!, "utf-8")
              } catch {
                return ""
              }
            })
            return {
              title: `interact poll ${params.id}`,
              output: text || "(no interactions yet)",
              metadata: { op: params.op, id: params.id, scheme: sess.scheme },
            }
          }
          if (params.op === "close") {
            if (!params.id) throw new Error("close requires id")
            const sess = store[params.id]
            if (!sess) throw new Error(`unknown session: ${params.id}`)
            if (sess.pid) {
              try {
                process.kill(sess.pid)
              } catch {
                /* already gone */
              }
            }
            delete store[params.id]
            yield* Effect.promise(() => save(store))
            return {
              title: `interact close ${params.id}`,
              output: `closed: ${params.id}`,
              metadata: { op: params.op, id: params.id },
            }
          }
          throw new Error(`unknown op: ${params.op}`)
        }).pipe(Effect.orDie),
    }
  }),
)
