import z from "zod"
import { Effect } from "effect"
import fs from "node:fs/promises"
import path from "node:path"
import os from "node:os"
import * as Tool from "./tool"
import DESCRIPTION from "./secrets.txt"

const parameters = z.object({
  op: z.enum(["set", "get", "list", "remove"]),
  name: z.string().optional(),
  value: z.string().optional(),
})

type Params = z.infer<typeof parameters>
type Metadata = { op: string; name?: string }

type Vault = Record<string, { value: string; updated_at: string }>

function configDir() {
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config")
  return path.join(base, "numasec")
}
function vaultPath() {
  return path.join(configDir(), "secrets.json")
}

async function loadVault(): Promise<Vault> {
  try {
    const text = await fs.readFile(vaultPath(), "utf-8")
    return JSON.parse(text) as Vault
  } catch {
    return {}
  }
}

async function saveVault(v: Vault) {
  await fs.mkdir(configDir(), { recursive: true })
  await fs.writeFile(vaultPath(), JSON.stringify(v, null, 2), { mode: 0o600 })
}

export const SecretsTool = Tool.define<typeof parameters, Metadata, never>(
  "secrets",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, _ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const vault = yield* Effect.promise(() => loadVault())
          if (params.op === "set") {
            if (!params.name || params.value === undefined) throw new Error("set requires name and value")
            vault[params.name] = { value: params.value, updated_at: new Date().toISOString() }
            yield* Effect.promise(() => saveVault(vault))
            return {
              title: `set ${params.name}`,
              output: `[REDACTED:${params.name}] (stored)`,
              metadata: { op: params.op, name: params.name },
            }
          }
          if (params.op === "get") {
            if (!params.name) throw new Error("get requires name")
            const entry = vault[params.name]
            if (!entry) throw new Error(`unknown secret: ${params.name}`)
            return {
              title: `get ${params.name}`,
              output: entry.value,
              metadata: { op: params.op, name: params.name },
            }
          }
          if (params.op === "list") {
            const names = Object.keys(vault).sort()
            return {
              title: `list (${names.length})`,
              output: names.length ? names.join("\n") : "(no secrets stored)",
              metadata: { op: params.op },
            }
          }
          if (params.op === "remove") {
            if (!params.name) throw new Error("remove requires name")
            if (!(params.name in vault)) throw new Error(`unknown secret: ${params.name}`)
            delete vault[params.name]
            yield* Effect.promise(() => saveVault(vault))
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
