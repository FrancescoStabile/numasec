import { BusEvent } from "@/bus/bus-event"
import { InstanceState } from "@/effect"
import { EffectBridge } from "@/effect"
import type { InstanceContext } from "@/project/instance"
import { SessionID, MessageID } from "@/session/schema"
import { Effect, Layer, Context } from "effect"
import z from "zod"
import { Config } from "../config"
import { MCP } from "../mcp"
import { Skill } from "../skill"
import PROMPT_INITIALIZE from "./template/initialize.txt"
import PROMPT_REVIEW from "./template/review.txt"
import PROMPT_TEACH from "./template/teach.txt"
import PROMPT_DOCTOR from "./template/doctor.txt"
import PROMPT_PLAY from "./template/play.txt"
import PROMPT_PWN from "./template/pwn.txt"
import PROMPT_OPSEC from "./template/opsec.txt"
import PROMPT_SHARE from "./template/share.txt"
import PROMPT_REMEDIATE from "./template/remediate.txt"

type State = {
  commands: Record<string, Info>
}

export const Event = {
  Executed: BusEvent.define(
    "command.executed",
    z.object({
      name: z.string(),
      sessionID: SessionID.zod,
      arguments: z.string(),
      messageID: MessageID.zod,
    }),
  ),
}

export const Info = z
  .object({
    name: z.string(),
    description: z.string().optional(),
    agent: z.string().optional(),
    model: z.string().optional(),
    source: z.enum(["command", "mcp", "skill"]).optional(),
    // workaround for zod not supporting async functions natively so we use getters
    // https://zod.dev/v4/changelog?id=zfunction
    template: z.promise(z.string()).or(z.string()),
    subtask: z.boolean().optional(),
    hints: z.array(z.string()),
    priority: z.number().optional(),
  })
  .meta({
    ref: "Command",
  })

// for some reason zod is inferring `string` for z.promise(z.string()).or(z.string()) so we have to manually override it
export type Info = Omit<z.infer<typeof Info>, "template"> & { template: Promise<string> | string }

export function hints(template: string) {
  const result: string[] = []
  const numbered = template.match(/\$\d+/g)
  if (numbered) {
    for (const match of [...new Set(numbered)].sort()) result.push(match)
  }
  if (template.includes("$ARGUMENTS")) result.push("$ARGUMENTS")
  return result
}

export const Default = {
  INIT: "init",
  REVIEW: "review",
  TEACH: "teach",
  DOCTOR: "doctor",
  PLAY: "play",
  PWN: "pwn",
  OPSEC: "opsec",
  SHARE: "share",
  REMEDIATE: "remediate",
} as const

export interface Interface {
  readonly get: (name: string) => Effect.Effect<Info | undefined>
  readonly list: () => Effect.Effect<Info[]>
}

export class Service extends Context.Service<Service, Interface>()("@numasec/Command") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const config = yield* Config.Service
    const mcp = yield* MCP.Service
    const skill = yield* Skill.Service

    const init = Effect.fn("Command.state")(function* (ctx: InstanceContext) {
      const cfg = yield* config.get()
      const bridge = yield* EffectBridge.make()
      const commands: Record<string, Info> = {}

      commands[Default.PWN] = {
        name: Default.PWN,
        description: "one-shot recon + plan: pass a URL/IP/domain",
        source: "command",
        priority: 10,
        get template() {
          return PROMPT_PWN
        },
        hints: hints(PROMPT_PWN),
      }
      commands[Default.PLAY] = {
        name: Default.PLAY,
        description: "run a named play: web-surface, network-surface, appsec-triage, osint, ctf-warmup",
        source: "command",
        priority: 20,
        get template() {
          return PROMPT_PLAY
        },
        hints: hints(PROMPT_PLAY),
      }
      commands[Default.DOCTOR] = {
        name: Default.DOCTOR,
        description: "environment & tool probe — what's missing, what's ready",
        source: "command",
        priority: 30,
        get template() {
          return PROMPT_DOCTOR
        },
        hints: hints(PROMPT_DOCTOR),
      }
      commands[Default.OPSEC] = {
        name: Default.OPSEC,
        description: "toggle strict opsec for the active operation",
        source: "command",
        priority: 40,
        get template() {
          return PROMPT_OPSEC
        },
        hints: hints(PROMPT_OPSEC),
      }
      commands[Default.SHARE] = {
        name: Default.SHARE,
        description: "bundle & redact the active operation for handoff",
        source: "command",
        priority: 50,
        get template() {
          return PROMPT_SHARE
        },
        hints: hints(PROMPT_SHARE),
      }
      commands[Default.REMEDIATE] = {
        name: Default.REMEDIATE,
        description: "turn an observation into a patch on a disposable branch",
        source: "command",
        priority: 60,
        get template() {
          return PROMPT_REMEDIATE
        },
        hints: hints(PROMPT_REMEDIATE),
      }
      commands[Default.TEACH] = {
        name: Default.TEACH,
        description: "narrate every tool call — learn-by-watching mode",
        source: "command",
        priority: 70,
        get template() {
          return PROMPT_TEACH
        },
        hints: hints(PROMPT_TEACH),
      }
      commands[Default.INIT] = {
        name: Default.INIT,
        description: "guided AGENTS.md setup",
        source: "command",
        priority: 80,
        get template() {
          return PROMPT_INITIALIZE.replace("${path}", ctx.worktree)
        },
        hints: hints(PROMPT_INITIALIZE),
      }
      commands[Default.REVIEW] = {
        name: Default.REVIEW,
        description: "review changes [commit|branch|pr], defaults to uncommitted",
        source: "command",
        priority: 90,
        get template() {
          return PROMPT_REVIEW.replace("${path}", ctx.worktree)
        },
        subtask: true,
        hints: hints(PROMPT_REVIEW),
      }

      for (const [name, command] of Object.entries(cfg.command ?? {})) {
        commands[name] = {
          name,
          agent: command.agent,
          model: command.model,
          description: command.description,
          source: "command",
          get template() {
            return command.template
          },
          subtask: command.subtask,
          hints: hints(command.template),
        }
      }

      for (const [name, prompt] of Object.entries(yield* mcp.prompts())) {
        commands[name] = {
          name,
          source: "mcp",
          description: prompt.description,
          get template() {
            return bridge.promise(
              mcp
                .getPrompt(
                  prompt.client,
                  prompt.name,
                  prompt.arguments
                    ? Object.fromEntries(prompt.arguments.map((argument, i) => [argument.name, `$${i + 1}`]))
                    : {},
                )
                .pipe(
                  Effect.map(
                    (template) =>
                      template?.messages
                        .map((message) => (message.content.type === "text" ? message.content.text : ""))
                        .join("\n") || "",
                  ),
                ),
            )
          },
          hints: prompt.arguments?.map((_, i) => `$${i + 1}`) ?? [],
        }
      }

      for (const item of yield* skill.all()) {
        if (commands[item.name]) continue
        commands[item.name] = {
          name: item.name,
          description: item.description,
          source: "skill",
          get template() {
            return item.content
          },
          hints: [],
        }
      }

      return {
        commands,
      }
    })

    const state = yield* InstanceState.make<State>((ctx) => init(ctx))

    const get = Effect.fn("Command.get")(function* (name: string) {
      const s = yield* InstanceState.get(state)
      return s.commands[name]
    })

    const list = Effect.fn("Command.list")(function* () {
      const s = yield* InstanceState.get(state)
      return Object.values(s.commands)
    })

    return Service.of({ get, list })
  }),
)

export const defaultLayer = layer.pipe(
  Layer.provide(Config.defaultLayer),
  Layer.provide(MCP.defaultLayer),
  Layer.provide(Skill.defaultLayer),
)
