import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import { inferMode } from "./autonomy"
import { persistDoctorProjection } from "./doctor"
import { Instance } from "@/project/instance"
import { Operation, KIND_AGENT, type OperationKind, type OperationAgentID } from "@/core/operation"
import { Cyber } from "@/core/cyber"
import { Doctor } from "@/core/doctor"
import { Session } from "@/session"

const parameters = z.object({
  target: z.string().min(1).describe("raw target string — URL, IP, CIDR, or bare domain"),
})

type Shape = "url" | "ip" | "domain"

type Metadata = {
  target: string
  shape?: Shape
  kind?: OperationKind
  agent?: OperationAgentID
  play_id?: string
  slug?: string
  ok: boolean
  reason?: string
}

const URL_RE = /^https?:\/\//i
const IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/
const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]+(?<!-)(\.(?!-)[a-z0-9-]+(?<!-))+$/i

function classify(target: string): Shape | undefined {
  const t = target.trim()
  if (URL_RE.test(t)) return "url"
  if (IP_RE.test(t)) return "ip"
  if (DOMAIN_RE.test(t)) return "domain"
  return undefined
}

const PLAN: Record<Shape, { kind: OperationKind; playId: string }> = {
  url: { kind: "pentest", playId: "web-surface" },
  ip: { kind: "hacking", playId: "network-surface" },
  domain: { kind: "osint", playId: "osint-target" },
}

const DESCRIPTION = [
  "Bootstrap a one-shot offensive engagement from a single target string.",
  "",
  "Detects whether `target` is a URL, IP/CIDR, or bare domain, creates a new Operation with the right kind,",
  "activates it, and returns the default agent plus the play id the TUI should run next.",
  "",
  "Returns { slug, kind, agent, playId } on success, or an error payload if the target shape is unclear.",
].join("\n")

function anonymousIdentityDescriptor(target: string) {
  return {
    mode: "anonymous",
    header_keys: [],
    has_cookies: false,
    target,
    note: "Unauthenticated baseline identity for the bootstrapped operation. No secret material is stored.",
  }
}

export const PwnBootstrapTool = Tool.define<typeof parameters, Metadata, Session.Service>(
  "pwn_bootstrap",
  Effect.gen(function* () {
    const session = yield* Session.Service
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const shape = classify(params.target)
          if (!shape) {
            return {
              title: "pwn: target shape unclear",
              output: [
                `Could not classify target "${params.target}".`,
                "Expected one of: URL starting with http(s)://, IPv4 address or CIDR, or a bare domain like acme.com.",
              ].join(" "),
              metadata: {
                target: params.target,
                ok: false,
                reason: "target shape unclear",
              },
            }
          }

          const plan = PLAN[shape]
          const agent = KIND_AGENT[plan.kind]
          const workspace = Instance.directory
          const info = yield* Effect.promise(() =>
            Operation.create({
              workspace,
              label: `pwn ${params.target}`,
              kind: plan.kind,
              target: params.target,
            }),
          )
          yield* Effect.promise(() => Operation.activate(workspace, info.slug))
          const boundary =
            (yield* Effect.promise(() => Operation.readBoundary(workspace, info.slug).catch(() => undefined))) ?? {
              default: "allow" as const,
              in_scope: [],
              out_of_scope: [],
            }
          yield* Cyber.upsertOperationState({
            slug: info.slug,
            label: info.label,
            kind: info.kind,
            target: info.target,
            opsec: info.opsec,
            in_scope: boundary.in_scope,
            out_of_scope: boundary.out_of_scope,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            source: "pwn_bootstrap",
            summary: `bootstrapped operation ${info.slug}`,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertScopePolicy({
            operation_slug: info.slug,
            default: boundary.default === "allow" ? "allow" : "ask",
            in_scope: boundary.in_scope,
            out_of_scope: boundary.out_of_scope,
            opsec: info.opsec,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            source: "pwn_bootstrap",
            summary: `scope policy ${info.slug}`,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          const currentSession = yield* Effect.exit(session.get(ctx.sessionID))
          const permission = currentSession._tag === "Success" ? currentSession.value.permission : undefined
          yield* Cyber.upsertFact({
            operation_slug: info.slug,
            entity_kind: "operation",
            entity_key: info.slug,
            fact_name: "autonomy_policy",
            value_json: {
              mode: inferMode(permission),
              rules: permission,
              session_id: ctx.sessionID,
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          const identityEventID = yield* Cyber.appendLedger({
            operation_slug: info.slug,
            kind: "fact.observed",
            source: "pwn_bootstrap",
            status: "completed",
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            summary: "active identity set to anonymous",
            data: {
              action: "seed_anonymous_identity",
              key: "anonymous",
              mode: "anonymous",
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertFact({
            operation_slug: info.slug,
            entity_kind: "identity",
            entity_key: "anonymous",
            fact_name: "descriptor",
            value_json: anonymousIdentityDescriptor(params.target),
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: identityEventID || undefined,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertFact({
            operation_slug: info.slug,
            entity_kind: "identity",
            entity_key: "anonymous",
            fact_name: "active",
            value_json: true,
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: identityEventID || undefined,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertRelation({
            operation_slug: info.slug,
            src_kind: "operation",
            src_key: info.slug,
            relation: "uses_identity",
            dst_kind: "identity",
            dst_key: "anonymous",
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: identityEventID || undefined,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          const doctorReport = yield* Doctor.probe(workspace).pipe(Effect.catch(() => Effect.succeed(undefined)))
          if (doctorReport) {
            yield* persistDoctorProjection({ report: doctorReport })
          }

          return {
            title: `pwn: ${info.slug} · ${plan.kind} · ${plan.playId}`,
            output: JSON.stringify(
              { slug: info.slug, kind: plan.kind, agent, playId: plan.playId },
              null,
              2,
            ),
            metadata: {
              target: params.target,
              shape,
              kind: plan.kind,
              agent,
              play_id: plan.playId,
              slug: info.slug,
              ok: true,
            },
          }
        }),
    }
  }),
)
