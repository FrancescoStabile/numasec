import z from "zod"
import { Effect } from "effect"
import fs from "node:fs/promises"
import path from "node:path"
import os from "node:os"
import * as Tool from "./tool"
import DESCRIPTION from "./auth-as.txt"

const parameters = z.object({
  op: z.enum(["set", "get", "list", "remove"]),
  name: z.string().optional(),
  type: z.enum(["basic", "bearer", "cookie", "form"]).optional(),
  target_url: z.string().optional(),
  credentials: z.record(z.string(), z.unknown()).optional(),
})

type Params = z.infer<typeof parameters>
type Metadata = { op: string; name?: string; type?: string }

type Profile = {
  name: string
  type: string
  target_url?: string
  credentials: Record<string, unknown>
  updated_at: string
}
type Store = Record<string, Profile>

function configDir() {
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config")
  return path.join(base, "numasec")
}
function storePath() {
  return path.join(configDir(), "auth-profiles.json")
}

async function load(): Promise<Store> {
  try {
    const text = await fs.readFile(storePath(), "utf-8")
    return JSON.parse(text) as Store
  } catch {
    return {}
  }
}

async function save(s: Store) {
  await fs.mkdir(configDir(), { recursive: true })
  await fs.writeFile(storePath(), JSON.stringify(s, null, 2), { mode: 0o600 })
}

export const AuthAsTool = Tool.define<typeof parameters, Metadata, never>(
  "auth_as",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, _ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const store = yield* Effect.promise(() => load())
          if (params.op === "set") {
            if (!params.name || !params.type || !params.credentials)
              throw new Error("set requires name, type, credentials")
            store[params.name] = {
              name: params.name,
              type: params.type,
              target_url: params.target_url,
              credentials: params.credentials,
              updated_at: new Date().toISOString(),
            }
            yield* Effect.promise(() => save(store))
            return {
              title: `set ${params.name} (${params.type})`,
              output: `stored auth profile: ${params.name}`,
              metadata: { op: params.op, name: params.name, type: params.type },
            }
          }
          if (params.op === "get") {
            if (!params.name) throw new Error("get requires name")
            const p = store[params.name]
            if (!p) throw new Error(`unknown profile: ${params.name}`)
            return {
              title: `get ${params.name}`,
              output: JSON.stringify(p, null, 2),
              metadata: { op: params.op, name: params.name, type: p.type },
            }
          }
          if (params.op === "list") {
            const entries = Object.values(store).map((p) => `${p.name}\t${p.type}\t${p.target_url ?? "-"}`)
            return {
              title: `list (${entries.length})`,
              output: entries.length ? entries.join("\n") : "(no profiles)",
              metadata: { op: params.op },
            }
          }
          if (params.op === "remove") {
            if (!params.name) throw new Error("remove requires name")
            if (!(params.name in store)) throw new Error(`unknown profile: ${params.name}`)
            delete store[params.name]
            yield* Effect.promise(() => save(store))
            return {
              title: `remove ${params.name}`,
              output: `removed: ${params.name}`,
              metadata: { op: params.op, name: params.name },
            }
          }
          throw new Error(`unknown op: ${params.op}`)
        }).pipe(Effect.orDie),
    }
  }),
)
