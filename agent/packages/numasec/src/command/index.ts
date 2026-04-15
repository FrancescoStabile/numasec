import { BusEvent } from "@/bus/bus-event"
import { InstanceState } from "@/effect/instance-state"
import { makeRuntime } from "@/effect/run-service"
import { SessionID, MessageID } from "@/session/schema"
import { Effect, Layer, ServiceMap } from "effect"
import z from "zod"
import { Config } from "../config/config"
import { MCP } from "../mcp"
import { Skill } from "../skill"
import { Log } from "../util/log"
import PROMPT_INITIALIZE from "./template/initialize.txt"
import PROMPT_REVIEW from "./template/review.txt"
import PROMPT_SCOPE_SET from "./template/target.txt"
import PROMPT_SCOPE_SHOW from "./template/scope-show.txt"
import PROMPT_HYPOTHESIS_LIST from "./template/hypothesis-list.txt"
import PROMPT_VERIFY_NEXT from "./template/verify-next.txt"
import PROMPT_EVIDENCE_LIST from "./template/evidence-list.txt"
import PROMPT_EVIDENCE_SHOW from "./template/evidence.txt"
import PROMPT_CHAINS_LIST from "./template/chains-list.txt"
import PROMPT_FINDING_LIST from "./template/findings.txt"
import PROMPT_FINDING_FINALIZE from "./template/finding-finalize.txt"
import PROMPT_REMEDIATION_PLAN from "./template/remediation-plan.txt"
import PROMPT_RETEST_RUN from "./template/retest-run.txt"
import PROMPT_REPORT_GENERATE from "./template/report.txt"
import PROMPT_REPORT_FINALIZE from "./template/report-finalize.txt"
import PROMPT_REPORT_STATUS from "./template/report-status.txt"
import PROMPT_COVERAGE from "./template/coverage.txt"
import PROMPT_CREDS from "./template/creds.txt"
import PROMPT_EVIDENCE_LEGACY from "./template/evidence-legacy.txt"

export namespace Command {
  const log = Log.create({ service: "command" })

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
    SCOPE_SET: "scope set",
    SCOPE_SHOW: "scope show",
    HYPOTHESIS_LIST: "hypothesis list",
    VERIFY_NEXT: "verify next",
    EVIDENCE_LIST: "evidence list",
    EVIDENCE_SHOW: "evidence show",
    CHAINS_LIST: "chains list",
    FINDING_LIST: "finding list",
    FINDING_FINALIZE: "finding finalize",
    REMEDIATION_PLAN: "remediation plan",
    RETEST_RUN: "retest run",
    REPORT_STATUS: "report status",
    REPORT_GENERATE: "report generate",
    REPORT_FINALIZE: "report finalize",
    TARGET: "target",
    FINDINGS: "findings",
    REPORT: "report",
    EVIDENCE: "evidence",
    COVERAGE: "coverage",
    CREDS: "creds",
  } as const

  export interface Interface {
    readonly get: (name: string) => Effect.Effect<Info | undefined>
    readonly list: () => Effect.Effect<Info[]>
  }

  export class Service extends ServiceMap.Service<Service, Interface>()("@numasec/Command") {}

  export const layer = Layer.effect(
    Service,
    Effect.gen(function* () {
      const config = yield* Config.Service
      const mcp = yield* MCP.Service
      const skill = yield* Skill.Service

      const init = Effect.fn("Command.state")(function* (ctx) {
        const cfg = yield* config.get()
        const commands: Record<string, Info> = {}
        const register = (
          name: string,
          command: {
            description: string
            template: string
            agent?: string
            subtask?: boolean
          },
        ) => {
          commands[name] = {
            name,
            description: command.description,
            source: "command",
            agent: command.agent,
            get template() {
              return command.template
            },
            subtask: command.subtask,
            hints: hints(command.template),
          }
        }

        commands[Default.INIT] = {
          name: Default.INIT,
          description: "analyze target app, create security AGENTS.md",
          source: "command",
          get template() {
            return PROMPT_INITIALIZE.replace("${path}", ctx.worktree)
          },
          hints: hints(PROMPT_INITIALIZE),
        }
        commands[Default.REVIEW] = {
          name: Default.REVIEW,
          description: "security review changes [commit|branch|pr], defaults to uncommitted",
          source: "command",
          get template() {
            return PROMPT_REVIEW.replace("${path}", ctx.worktree)
          },
          subtask: true,
          hints: hints(PROMPT_REVIEW),
        }

        // ── Security commands ──────────────────────────────────
        register(Default.SCOPE_SET, {
          description: "set pentest target and begin reconnaissance",
          template: PROMPT_SCOPE_SET,
          agent: "pentest",
        })
        register(Default.SCOPE_SHOW, {
          description: "show current engagement scope and observed surface",
          template: PROMPT_SCOPE_SHOW,
          subtask: true,
        })
        register(Default.HYPOTHESIS_LIST, {
          description: "list hypotheses from the evidence graph",
          template: PROMPT_HYPOTHESIS_LIST,
          subtask: true,
        })
        register(Default.VERIFY_NEXT, {
          description: "plan the next verification step",
          template: PROMPT_VERIFY_NEXT,
          subtask: true,
        })
        register(Default.EVIDENCE_LIST, {
          description: "list available evidence entries",
          template: PROMPT_EVIDENCE_LIST,
          subtask: true,
        })
        register(Default.EVIDENCE_SHOW, {
          description: "show evidence details for a finding",
          template: PROMPT_EVIDENCE_SHOW,
          subtask: true,
        })
        register(Default.CHAINS_LIST, {
          description: "list derived attack chains",
          template: PROMPT_CHAINS_LIST,
          subtask: true,
        })
        register(Default.FINDING_LIST, {
          description: "list all security findings",
          template: PROMPT_FINDING_LIST,
          subtask: true,
        })
        register(Default.FINDING_FINALIZE, {
          description: "finalize a finding through the closure path",
          template: PROMPT_FINDING_FINALIZE,
          agent: "pentest",
        })
        register(Default.REMEDIATION_PLAN, {
          description: "produce a prioritized remediation plan",
          template: PROMPT_REMEDIATION_PLAN,
          subtask: true,
        })
        register(Default.RETEST_RUN, {
          description: "run retest workflow for saved findings",
          template: PROMPT_RETEST_RUN,
          subtask: true,
        })
        register(Default.REPORT_STATUS, {
          description: "show report readiness and blockers",
          template: PROMPT_REPORT_STATUS,
          subtask: true,
        })
        register(Default.REPORT_GENERATE, {
          description: "generate pentest report [markdown|html|sarif]",
          template: PROMPT_REPORT_GENERATE,
          agent: "pentest",
        })
        register(Default.REPORT_FINALIZE, {
          description: "finalize pentest report with closure gating",
          template: PROMPT_REPORT_FINALIZE,
          agent: "pentest",
        })

        // Legacy aliases (progressive migration)
        register(Default.TARGET, {
          description: "alias for /scope set",
          template: PROMPT_SCOPE_SET,
          agent: "pentest",
        })
        register(Default.FINDINGS, {
          description: "alias for /finding list",
          template: PROMPT_FINDING_LIST,
          subtask: true,
        })
        register(Default.REPORT, {
          description: "alias for /report generate",
          template: PROMPT_REPORT_GENERATE,
          agent: "pentest",
        })
        register(Default.EVIDENCE, {
          description: "legacy /evidence command (maps to list/show behavior)",
          template: PROMPT_EVIDENCE_LEGACY,
          subtask: true,
        })
        commands[Default.COVERAGE] = {
          name: Default.COVERAGE,
          description: "show OWASP Top 10 coverage matrix",
          source: "command",
          get template() {
            return PROMPT_COVERAGE
          },
          subtask: true,
          hints: hints(PROMPT_COVERAGE),
        }
        commands[Default.CREDS] = {
          name: Default.CREDS,
          description: "list discovered credentials",
          source: "command",
          get template() {
            return PROMPT_CREDS
          },
          subtask: true,
          hints: hints(PROMPT_CREDS),
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
              return new Promise<string>(async (resolve, reject) => {
                const template = await MCP.getPrompt(
                  prompt.client,
                  prompt.name,
                  prompt.arguments
                    ? Object.fromEntries(prompt.arguments.map((argument, i) => [argument.name, `$${i + 1}`]))
                    : {},
                ).catch(reject)
                resolve(
                  template?.messages
                    .map((message) => (message.content.type === "text" ? message.content.text : ""))
                    .join("\n") || "",
                )
              })
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

      const cache = yield* InstanceState.make<State>((ctx) => init(ctx))

      const get = Effect.fn("Command.get")(function* (name: string) {
        const state = yield* InstanceState.get(cache)
        return state.commands[name]
      })

      const list = Effect.fn("Command.list")(function* () {
        const state = yield* InstanceState.get(cache)
        return Object.values(state.commands)
      })

      return Service.of({ get, list })
    }),
  )

  export const defaultLayer = layer.pipe(
    Layer.provide(Config.defaultLayer),
    Layer.provide(MCP.defaultLayer),
    Layer.provide(Skill.defaultLayer),
  )

  const { runPromise } = makeRuntime(Service, defaultLayer)

  export async function get(name: string) {
    return runPromise((svc) => svc.get(name))
  }

  export async function list() {
    return runPromise((svc) => svc.list())
  }
}
