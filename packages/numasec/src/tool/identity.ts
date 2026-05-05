import { Effect } from "effect"
import z from "zod"
import * as Tool from "./tool"
import DESCRIPTION from "./identity.txt"
import { Cyber } from "@/core/cyber"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"
import { loadVault, resolveIdentityValue, saveVault } from "@/core/vault"

const parameters = z.object({
  action: z.enum(["list", "status", "add", "use", "clear"]).default("status"),
  key: z.string().optional(),
  value: z.string().optional(),
})

type Params = z.infer<typeof parameters>
type Metadata = Record<string, unknown>

function summarizeDescriptor(value: string) {
  const resolved = resolveIdentityValue("preview", value)
  return {
    mode: resolved.mode,
    header_keys: Object.keys(resolved.headers ?? {}),
    has_cookies: Boolean(resolved.cookies),
  }
}

export const IdentityTool = Tool.define<typeof parameters, Metadata, never>(
  "identity",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context) =>
        Effect.gen(function* () {
          const vault = yield* Effect.promise(() => loadVault())

          if (params.action === "list") {
            const keys = Object.keys(vault.secrets).sort()
            const output =
              keys.length === 0
                ? "No identities stored."
                : keys
                    .map((key) => `${key === vault.active_identity ? "*" : "-"} ${key}`)
                    .join("\n")
            return {
              title: `identity · ${keys.length}`,
              output,
              metadata: {
                action: "list",
                count: keys.length,
                active_identity: vault.active_identity,
              },
            }
          }

          if (params.action === "status") {
            if (!vault.active_identity) {
              return {
                title: "identity · inactive",
                output: "No active identity.",
                metadata: { action: "status", active: false },
              }
            }
            const entry = vault.secrets[vault.active_identity]
            if (!entry) {
              return {
                title: "identity · stale",
                output: `Active identity ${vault.active_identity} is missing from the vault.`,
                metadata: { action: "status", active: false, stale: true, key: vault.active_identity },
              }
            }
            const descriptor = summarizeDescriptor(entry.value)
            return {
              title: `identity · ${vault.active_identity}`,
              output: [
                `Active identity: ${vault.active_identity}`,
                `Mode: ${descriptor.mode}`,
                `Headers: ${descriptor.header_keys.length > 0 ? descriptor.header_keys.join(", ") : "none"}`,
                `Cookies: ${descriptor.has_cookies ? "present" : "absent"}`,
              ].join("\n"),
              metadata: {
                action: "status",
                active: true,
                key: vault.active_identity,
                mode: descriptor.mode,
                header_keys: descriptor.header_keys,
                has_cookies: descriptor.has_cookies,
              },
            }
          }

          if (params.action === "clear") {
            const previous = vault.active_identity
            vault.active_identity = null
            vault.active_identity_set_at = null
            yield* Effect.promise(() => saveVault(vault))
            const eventID = yield* Cyber.appendLedger({
              kind: "fact.observed",
              source: "identity",
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              summary: previous ? `cleared active identity ${previous}` : "cleared active identity",
              data: { action: "clear", previous },
            }).pipe(Effect.catch(() => Effect.succeed("")))
            if (previous) {
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
            return {
              title: "identity · cleared",
              output: previous ? `Cleared active identity ${previous}.` : "No active identity to clear.",
              metadata: { action: "clear", previous },
            }
          }

          if (!params.key) {
            return {
              title: `identity ${params.action}`,
              output: "Provide key for this action.",
              metadata: { action: params.action },
            }
          }

          if (params.action === "add") {
            if (params.value === undefined) {
              return {
                title: "identity add",
                output: "Provide value when action = add.",
                metadata: { action: "add", key: params.key },
              }
            }
            vault.secrets[params.key] = { value: params.value, updated_at: new Date().toISOString() }
            yield* Effect.promise(() => saveVault(vault))
            const descriptor = summarizeDescriptor(params.value)
            const eventID = yield* Cyber.appendLedger({
              kind: "fact.observed",
              source: "identity",
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              summary: `stored identity ${params.key}`,
              data: {
                action: "add",
                key: params.key,
                mode: descriptor.mode,
                header_keys: descriptor.header_keys,
                has_cookies: descriptor.has_cookies,
              },
            }).pipe(Effect.catch(() => Effect.succeed("")))
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
            return {
              title: `identity · ${params.key}`,
              output: `Stored identity ${params.key} (${descriptor.mode}).`,
              metadata: {
                action: "add",
                key: params.key,
                mode: descriptor.mode,
                header_keys: descriptor.header_keys,
                has_cookies: descriptor.has_cookies,
              },
            }
          }

          if (!(params.key in vault.secrets)) {
            return {
              title: `identity use · ${params.key}`,
              output: `Unknown identity ${params.key}.`,
              metadata: { action: "use", key: params.key, found: false },
            }
          }
          const previous = vault.active_identity
          vault.active_identity = params.key
          vault.active_identity_set_at = new Date().toISOString()
          yield* Effect.promise(() => saveVault(vault))
          const descriptor = summarizeDescriptor(vault.secrets[params.key]!.value)
          const eventID = yield* Cyber.appendLedger({
            kind: "fact.observed",
            source: "identity",
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            summary: `active identity set to ${params.key}`,
            data: { action: "use", key: params.key, previous, mode: descriptor.mode },
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
            title: `identity · ${params.key}`,
            output: `Active identity: ${params.key} (${descriptor.mode}).`,
            metadata: {
              action: "use",
              key: params.key,
              previous,
              mode: descriptor.mode,
            },
          }
        }),
    }
  }),
)
