import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import { Instance } from "@/project/instance"
import { Operation, KIND_AGENT, type OperationKind, type OperationAgentID } from "@/core/operation"

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

export const PwnBootstrapTool = Tool.define<typeof parameters, Metadata, never>(
  "pwn_bootstrap",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params, _ctx: Tool.Context<Metadata>) =>
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
