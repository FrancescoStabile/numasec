import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./vault.txt"
import { Cyber } from "@/core/cyber"
import { resolveIdentityValue, loadVault, saveVault } from "@/core/vault"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

const parameters = z.object({
  action: z.enum(["set", "get", "list", "delete", "use_as"]),
  key: z.string().optional(),
  value: z.string().optional(),
  reveal: z.boolean().optional(),
})

type Params = z.infer<typeof parameters>
type Metadata = { action: string; key?: string }

function summarizeDescriptor(value: string) {
  const resolved = resolveIdentityValue("preview", value)
  return {
    mode: resolved.mode,
    header_keys: Object.keys(resolved.headers ?? {}),
    has_cookies: Boolean(resolved.cookies),
  }
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
            yield* Cyber.appendLedger({
              kind: "operation.note",
              source: "vault",
              summary: `vault set ${params.key}`,
              session_id: _ctx.sessionID,
              message_id: _ctx.messageID,
              data: { action: "set", key: params.key },
            }).pipe(Effect.catch(() => Effect.void))
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
            const descriptor = summarizeDescriptor(vault.secrets[params.key]!.value)
            delete vault.secrets[params.key]
            const wasActive = vault.active_identity === params.key
            if (vault.active_identity === params.key) {
              vault.active_identity = null
              vault.active_identity_set_at = null
            }
            yield* Effect.promise(() => saveVault(vault))
            const eventID = yield* Cyber.appendLedger({
              kind: "operation.note",
              source: "vault",
              summary: `vault delete ${params.key}`,
              session_id: _ctx.sessionID,
              message_id: _ctx.messageID,
              data: { action: "delete", key: params.key },
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertFact({
              entity_kind: "identity",
              entity_key: params.key,
              fact_name: "descriptor",
              value_json: descriptor,
              writer_kind: "operator",
              status: "stale",
              confidence: 1000,
              source_event_id: eventID || undefined,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            if (wasActive) {
              yield* Cyber.upsertFact({
                entity_kind: "identity",
                entity_key: params.key,
                fact_name: "active",
                value_json: false,
                writer_kind: "operator",
                status: "observed",
                confidence: 1000,
                source_event_id: eventID || undefined,
              }).pipe(Effect.catch(() => Effect.succeed("")))
            }
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
            const previous = vault.active_identity
            vault.active_identity = params.key
            vault.active_identity_set_at = new Date().toISOString()
            yield* Effect.promise(() => saveVault(vault))
            const descriptor = summarizeDescriptor(vault.secrets[params.key]!.value)
            const eventID = yield* Cyber.appendLedger({
              kind: "fact.observed",
              source: "vault",
              summary: `active identity set to ${params.key}`,
              session_id: _ctx.sessionID,
              message_id: _ctx.messageID,
              data: { action: "use_as", key: params.key, previous, mode: descriptor.mode },
            }).pipe(Effect.catch(() => Effect.succeed("")))
            if (previous && previous !== params.key) {
              yield* Cyber.upsertFact({
                entity_kind: "identity",
                entity_key: previous,
                fact_name: "active",
                value_json: false,
                writer_kind: "operator",
                status: "observed",
                confidence: 1000,
                source_event_id: eventID || undefined,
              }).pipe(Effect.catch(() => Effect.succeed("")))
            }
            yield* Cyber.upsertFact({
              entity_kind: "identity",
              entity_key: params.key,
              fact_name: "descriptor",
              value_json: descriptor,
              writer_kind: "operator",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID || undefined,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertFact({
              entity_kind: "identity",
              entity_key: params.key,
              fact_name: "active",
              value_json: true,
              writer_kind: "operator",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID || undefined,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            const slug = yield* Effect.promise(() => Operation.activeSlug(Instance.directory).catch(() => undefined)).pipe(
              Effect.catch(() => Effect.succeed(undefined)),
            )
            if (slug) {
              yield* Cyber.upsertRelation({
                operation_slug: slug,
                src_kind: "operation",
                src_key: slug,
                relation: "uses_identity",
                dst_kind: "identity",
                dst_key: params.key,
                writer_kind: "operator",
                status: "observed",
                confidence: 1000,
                source_event_id: eventID || undefined,
              }).pipe(Effect.catch(() => Effect.succeed("")))
            }
            return {
              title: `use_as ${params.key}`,
              output: `active identity: ${params.key} (${descriptor.mode}; http/browser traffic will carry this credential)`,
              metadata: { action: params.action, key: params.key },
            }
          }

          throw new Error(`unknown action: ${params.action}`)
        }).pipe(Effect.orDie),
    }
  }),
)
