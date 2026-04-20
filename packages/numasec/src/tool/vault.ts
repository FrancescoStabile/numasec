import z from "zod"
import { Effect } from "effect"
import fs from "node:fs/promises"
import path from "node:path"
import os from "node:os"
import * as Tool from "./tool"
import DESCRIPTION from "./vault.txt"

const parameters = z.object({
  action: z.enum(["set", "get", "list", "delete", "use_as"]),
  key: z.string().optional(),
  value: z.string().optional(),
  reveal: z.boolean().optional(),
})

type Params = z.infer<typeof parameters>
type Metadata = { action: string; key?: string }

type Entry = { value: string; updated_at: string }
type Vault = {
  secrets: Record<string, Entry>
  active_identity: string | null
  active_identity_set_at: string | null
}

const EMPTY_VAULT: Vault = { secrets: {}, active_identity: null, active_identity_set_at: null }

function configDir() {
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config")
  return path.join(base, "numasec")
}

function vaultPath() {
  return path.join(configDir(), "vault.json")
}

async function loadVault(): Promise<Vault> {
  try {
    const text = await fs.readFile(vaultPath(), "utf-8")
    const parsed = JSON.parse(text) as Partial<Vault>
    return {
      secrets: parsed.secrets ?? {},
      active_identity: parsed.active_identity ?? null,
      active_identity_set_at: parsed.active_identity_set_at ?? null,
    }
  } catch {
    return { ...EMPTY_VAULT, secrets: {} }
  }
}

async function saveVault(v: Vault) {
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 })
  const p = vaultPath()
  await fs.writeFile(p, JSON.stringify(v, null, 2), { mode: 0o600 })
  await fs.chmod(p, 0o600)
}

export const VaultTool = Tool.define<typeof parameters, Metadata, never>(
  "vault",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, _ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const vault = yield* Effect.promise(() => loadVault())

          if (params.action === "set") {
            if (!params.key || params.value === undefined) throw new Error("set requires key and value")
            vault.secrets[params.key] = { value: params.value, updated_at: new Date().toISOString() }
            yield* Effect.promise(() => saveVault(vault))
            return {
              title: `set ${params.key}`,
              output: `[REDACTED:${params.key}] (stored)`,
              metadata: { action: params.action, key: params.key },
            }
          }

          if (params.action === "get") {
            if (!params.key) throw new Error("get requires key")
            const entry = vault.secrets[params.key]
            if (!entry) throw new Error(`unknown key: ${params.key}`)
            if (params.reveal) {
              return {
                title: `get ${params.key} (revealed)`,
                output: entry.value,
                metadata: { action: params.action, key: params.key },
              }
            }
            return {
              title: `get ${params.key}`,
              output: JSON.stringify({ present: true, key: params.key, length: entry.value.length }),
              metadata: { action: params.action, key: params.key },
            }
          }

          if (params.action === "list") {
            const keys = Object.keys(vault.secrets).sort()
            const active = vault.active_identity ? `\nactive_identity: ${vault.active_identity}` : ""
            return {
              title: `list (${keys.length})`,
              output: (keys.length ? keys.join("\n") : "(vault empty)") + active,
              metadata: { action: params.action },
            }
          }

          if (params.action === "delete") {
            if (!params.key) throw new Error("delete requires key")
            if (!(params.key in vault.secrets)) throw new Error(`unknown key: ${params.key}`)
            delete vault.secrets[params.key]
            if (vault.active_identity === params.key) {
              vault.active_identity = null
              vault.active_identity_set_at = null
            }
            yield* Effect.promise(() => saveVault(vault))
            return {
              title: `delete ${params.key}`,
              output: `deleted: ${params.key}`,
              metadata: { action: params.action, key: params.key },
            }
          }

          if (params.action === "use_as") {
            if (!params.key) throw new Error("use_as requires key")
            if (!(params.key in vault.secrets))
              throw new Error(`unknown key: ${params.key} (store it first with action=set)`)
            vault.active_identity = params.key
            vault.active_identity_set_at = new Date().toISOString()
            yield* Effect.promise(() => saveVault(vault))
            return {
              title: `use_as ${params.key}`,
              output: `active identity: ${params.key} (http/browser traffic will carry this credential)`,
              metadata: { action: params.action, key: params.key },
            }
          }

          throw new Error(`unknown action: ${params.action}`)
        }).pipe(Effect.orDie),
    }
  }),
)
