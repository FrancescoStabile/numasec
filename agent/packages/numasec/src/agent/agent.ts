import { Config } from "../config/config"
import z from "zod"
import { Provider } from "../provider/provider"
import { ModelID, ProviderID } from "../provider/schema"
import { generateObject, streamObject, type ModelMessage } from "ai"
import { Instance } from "../project/instance"
import { Truncate } from "../tool/truncate"
import { Auth } from "../auth"
import { ProviderTransform } from "../provider/transform"

import PROMPT_GENERATE from "./generate.txt"
import PROMPT_PENTEST from "./prompt/pentest.txt"
import PROMPT_RECON from "./prompt/recon.txt"
import PROMPT_HUNT from "./prompt/hunt.txt"
import PROMPT_REVIEW from "./prompt/review.txt"
import PROMPT_REPORT from "./prompt/report.txt"
import PROMPT_SCANNER from "./prompt/scanner.txt"
import PROMPT_ANALYST from "./prompt/analyst.txt"
import PROMPT_COMPACTION from "./prompt/compaction.txt"
import PROMPT_EXPLORE from "./prompt/explore.txt"
import PROMPT_SUMMARY from "./prompt/summary.txt"
import PROMPT_TITLE from "./prompt/title.txt"
import { Permission } from "@/permission"
import { mergeDeep, pipe, sortBy, values } from "remeda"
import { Global } from "@/global"
import path from "path"
import { Plugin } from "@/plugin"
import { Skill } from "../skill"
import { Effect, ServiceMap, Layer } from "effect"
import { InstanceState } from "@/effect/instance-state"
import { makeRuntime } from "@/effect/run-service"

export namespace Agent {
  export const Info = z
    .object({
      name: z.string(),
      description: z.string().optional(),
      mode: z.enum(["subagent", "primary", "all"]),
      native: z.boolean().optional(),
      hidden: z.boolean().optional(),
      topP: z.number().optional(),
      temperature: z.number().optional(),
      color: z.string().optional(),
      permission: Permission.Ruleset,
      model: z
        .object({
          modelID: ModelID.zod,
          providerID: ProviderID.zod,
        })
        .optional(),
      variant: z.string().optional(),
      prompt: z.string().optional(),
      options: z.record(z.string(), z.any()),
      steps: z.number().int().positive().optional(),
    })
    .meta({
      ref: "Agent",
    })
  export type Info = z.infer<typeof Info>

  export interface Interface {
    readonly get: (agent: string) => Effect.Effect<Agent.Info>
    readonly list: () => Effect.Effect<Agent.Info[]>
    readonly defaultAgent: () => Effect.Effect<string>
    readonly generate: (input: {
      description: string
      model?: { providerID: ProviderID; modelID: ModelID }
    }) => Effect.Effect<{
      identifier: string
      whenToUse: string
      systemPrompt: string
    }>
  }

  type State = Omit<Interface, "generate">

  export class Service extends ServiceMap.Service<Service, Interface>()("@numasec/Agent") {}

  export const layer = Layer.effect(
    Service,
    Effect.gen(function* () {
      const config = yield* Config.Service
      const auth = yield* Auth.Service
      const skill = yield* Skill.Service

      const state = yield* InstanceState.make<State>(
        Effect.fn("Agent.state")(function* (ctx) {
          const cfg = yield* config.get()
          const skillDirs = yield* skill.dirs()
          const whitelistedDirs = [Truncate.GLOB, ...skillDirs.map((dir) => path.join(dir, "*"))]

          const defaults = Permission.fromConfig({
            "*": "allow",
            doom_loop: "ask",
            external_directory: {
              "*": "ask",
              ...Object.fromEntries(whitelistedDirs.map((dir) => [dir, "allow"])),
            },
            question: "deny",
            plan_enter: "deny",
            plan_exit: "deny",
            // mirrors github.com/github/gitignore Node.gitignore pattern for .env files
            read: {
              "*": "allow",
              "*.env": "ask",
              "*.env.*": "ask",
              "*.env.example": "allow",
            },
          })

          const user = Permission.fromConfig(cfg.permission ?? {})

          const agents: Record<string, Info> = {
            pentest: {
              name: "pentest",
              description:
                "Default penetration testing agent. Uses the v2 primitive cycle (scope → hypothesis → evidence → verification → finding → chains/report) with legacy compatibility.",
              options: {},
              prompt: PROMPT_PENTEST,
              color: "primary",
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  question: "allow",
                  bash: {
                    "*": "ask",
                    "curl *": "allow",
                    "nmap *": "allow",
                    "nikto *": "allow",
                    "dig *": "allow",
                    "whois *": "allow",
                    "nuclei *": "allow",
                    "sqlmap *": "ask",
                  },
                }),
                user,
              ),
              mode: "primary",
              native: true,
            },
            recon: {
              name: "recon",
              description:
                "Reconnaissance-only mode. Primitive-first surface observation and hypothesis seeding without exploitation payloads.",
              options: {},
              prompt: PROMPT_RECON,
              color: "info",
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  question: "allow",
                  bash: {
                    "*": "deny",
                    "nmap *": "allow",
                    "dig *": "allow",
                    "whois *": "allow",
                    "curl -I *": "allow",
                    "curl -sI *": "allow",
                  },
                }),
                user,
              ),
              mode: "primary",
              native: true,
            },
            hunt: {
              name: "hunt",
              description:
                "Vulnerability hunting mode. Aggressive primitive-first validation with OWASP prioritisation and compatibility aliases.",
              options: {},
              prompt: PROMPT_HUNT,
              color: "error",
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  question: "allow",
                  bash: {
                    "*": "ask",
                    "curl *": "allow",
                    "nmap *": "allow",
                    "nuclei *": "allow",
                    "sqlmap *": "ask",
                    "nikto *": "allow",
                    "ffuf *": "allow",
                    "gobuster *": "allow",
                    "wfuzz *": "allow",
                    "hydra *": "ask",
                  },
                }),
                user,
              ),
              mode: "primary",
              native: true,
            },
            review: {
              name: "review",
              description:
                "Secure code review mode. Static source analysis only (no runtime recon/exploitation primitives or legacy wrappers).",
              options: {},
              prompt: PROMPT_REVIEW,
              color: "warning",
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  question: "allow",
                  bash: {
                    "*": "deny",
                    "git *": "allow",
                  },
                  injection_test: "deny",
                  xss_test: "deny",
                  ssrf_test: "deny",
                  auth_test: "deny",
                  access_control_test: "deny",
                  dir_fuzz: "deny",
                  recon: "deny",
                  crawl: "deny",
                  js_analyze: "deny",
                  observe_surface: "deny",
                  plan_next: "deny",
                  upsert_hypothesis: "deny",
                  record_evidence: "deny",
                  link_evidence: "deny",
                  query_graph: "deny",
                  upsert_finding: "deny",
                  derive_attack_paths: "deny",
                  exec_command: "deny",
                  batch_replay: "deny",
                  mutate_input: "deny",
                  extract_observation: "deny",
                  verify_assertion: "deny",
                  browser: "deny",
                  http_request: "deny",
                  security_shell: "deny",
                  create_session: "deny",
                  save_finding: "deny",
                }),
                user,
              ),
              mode: "primary",
              native: true,
            },
            report: {
              name: "report",
              description:
                "Report generation mode. Derive attack paths, review projected findings, and generate deliverables without active testing.",
              options: {},
              prompt: PROMPT_REPORT,
              color: "success",
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  question: "allow",
                  bash: "deny",
                  injection_test: "deny",
                  xss_test: "deny",
                  ssrf_test: "deny",
                  auth_test: "deny",
                  access_control_test: "deny",
                  dir_fuzz: "deny",
                  recon: "deny",
                  crawl: "deny",
                  js_analyze: "deny",
                  observe_surface: "deny",
                  plan_next: "deny",
                  upsert_hypothesis: "deny",
                  record_evidence: "deny",
                  link_evidence: "deny",
                  upsert_finding: "deny",
                  exec_command: "deny",
                  batch_replay: "deny",
                  mutate_input: "deny",
                  extract_observation: "deny",
                  verify_assertion: "deny",
                  browser: "deny",
                  security_shell: "deny",
                }),
                user,
              ),
              mode: "primary",
              native: true,
            },
            general: {
              name: "general",
              description: `General-purpose agent for researching complex questions and executing multi-step tasks. Use this agent to execute multiple units of work in parallel.`,
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  todowrite: "deny",
                }),
                user,
              ),
              options: {},
              mode: "subagent",
              native: true,
            },
            scanner: {
              name: "scanner",
              description:
                "Security scanner agent. Executes delegated tests, records evidence, and returns verification-ready output (no final finding persistence).",
              prompt: PROMPT_SCANNER,
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  question: "deny",
                  todowrite: "deny",
                }),
                user,
              ),
              options: {},
              mode: "subagent",
              native: true,
            },
            analyst: {
              name: "analyst",
              description:
                "Security analyst agent. Validates evidence, prunes false positives, and prepares graph-backed chains for reporting.",
              prompt: PROMPT_ANALYST,
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  bash: "deny",
                  question: "deny",
                  todowrite: "deny",
                }),
                user,
              ),
              options: {},
              mode: "subagent",
              native: true,
            },
            reporter: {
              name: "reporter",
              description: `Report generation agent. Creates structured security reports from findings in SARIF, Markdown, or HTML format.`,
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  bash: "deny",
                  todowrite: "deny",
                }),
                user,
              ),
              options: {},
              mode: "subagent",
              native: true,
            },
            explore: {
              name: "explore",
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  "*": "deny",
                  grep: "allow",
                  glob: "allow",
                  list: "allow",
                  bash: "allow",
                  webfetch: "allow",
                  websearch: "allow",
                  read: "allow",
                  kb_search: "allow",
                  external_directory: {
                    "*": "ask",
                    ...Object.fromEntries(whitelistedDirs.map((dir) => [dir, "allow"])),
                  },
                }),
                user,
              ),
              description: `Research agent for exploring targets and gathering intelligence. Use for CVE research, exploit documentation, and target analysis. Specify thoroughness: "quick", "medium", or "very thorough".`,
              prompt: PROMPT_EXPLORE,
              options: {},
              mode: "subagent",
              native: true,
            },
            compaction: {
              name: "compaction",
              mode: "primary",
              native: true,
              hidden: true,
              prompt: PROMPT_COMPACTION,
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  "*": "deny",
                }),
                user,
              ),
              options: {},
            },
            title: {
              name: "title",
              mode: "primary",
              options: {},
              native: true,
              hidden: true,
              temperature: 0.5,
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  "*": "deny",
                }),
                user,
              ),
              prompt: PROMPT_TITLE,
            },
            summary: {
              name: "summary",
              mode: "primary",
              options: {},
              native: true,
              hidden: true,
              permission: Permission.merge(
                defaults,
                Permission.fromConfig({
                  "*": "deny",
                }),
                user,
              ),
              prompt: PROMPT_SUMMARY,
            },
          }

          for (const [key, value] of Object.entries(cfg.agent ?? {})) {
            if (value.disable) {
              delete agents[key]
              continue
            }
            let item = agents[key]
            if (!item)
              item = agents[key] = {
                name: key,
                mode: "all",
                permission: Permission.merge(defaults, user),
                options: {},
                native: false,
              }
            if (value.model) item.model = Provider.parseModel(value.model)
            item.variant = value.variant ?? item.variant
            item.prompt = value.prompt ?? item.prompt
            item.description = value.description ?? item.description
            item.temperature = value.temperature ?? item.temperature
            item.topP = value.top_p ?? item.topP
            item.mode = value.mode ?? item.mode
            item.color = value.color ?? item.color
            item.hidden = value.hidden ?? item.hidden
            item.name = value.name ?? item.name
            item.steps = value.steps ?? item.steps
            item.options = mergeDeep(item.options, value.options ?? {})
            item.permission = Permission.merge(item.permission, Permission.fromConfig(value.permission ?? {}))
          }

          // Ensure Truncate.GLOB is allowed unless explicitly configured
          for (const name in agents) {
            const agent = agents[name]
            const explicit = agent.permission.some((r) => {
              if (r.permission !== "external_directory") return false
              if (r.action !== "deny") return false
              return r.pattern === Truncate.GLOB
            })
            if (explicit) continue

            agents[name].permission = Permission.merge(
              agents[name].permission,
              Permission.fromConfig({ external_directory: { [Truncate.GLOB]: "allow" } }),
            )
          }

          const get = Effect.fnUntraced(function* (agent: string) {
            return agents[agent]
          })

          const list = Effect.fnUntraced(function* () {
            const cfg = yield* config.get()
            return pipe(
              agents,
              values(),
              sortBy(
                [(x) => (cfg.default_agent ? x.name === cfg.default_agent : x.name === "pentest"), "desc"],
                [(x) => x.name, "asc"],
              ),
            )
          })

          const defaultAgent = Effect.fnUntraced(function* () {
            const c = yield* config.get()
            if (c.default_agent) {
              const agent = agents[c.default_agent]
              if (!agent) throw new Error(`default agent "${c.default_agent}" not found`)
              if (agent.mode === "subagent") throw new Error(`default agent "${c.default_agent}" is a subagent`)
              if (agent.hidden === true) throw new Error(`default agent "${c.default_agent}" is hidden`)
              return agent.name
            }
            const visible = Object.values(agents).find((a) => a.mode !== "subagent" && a.hidden !== true)
            if (!visible) throw new Error("no primary visible agent found")
            return visible.name
          })

          return {
            get,
            list,
            defaultAgent,
          } satisfies State
        }),
      )

      return Service.of({
        get: Effect.fn("Agent.get")(function* (agent: string) {
          return yield* InstanceState.useEffect(state, (s) => s.get(agent))
        }),
        list: Effect.fn("Agent.list")(function* () {
          return yield* InstanceState.useEffect(state, (s) => s.list())
        }),
        defaultAgent: Effect.fn("Agent.defaultAgent")(function* () {
          return yield* InstanceState.useEffect(state, (s) => s.defaultAgent())
        }),
        generate: Effect.fn("Agent.generate")(function* (input: {
          description: string
          model?: { providerID: ProviderID; modelID: ModelID }
        }) {
          const cfg = yield* config.get()
          const model = input.model ?? (yield* Effect.promise(() => Provider.defaultModel()))
          const resolved = yield* Effect.promise(() => Provider.getModel(model.providerID, model.modelID))
          const language = yield* Effect.promise(() => Provider.getLanguage(resolved))

          const system = [PROMPT_GENERATE]
          yield* Effect.promise(() =>
            Plugin.trigger("experimental.chat.system.transform", { model: resolved }, { system }),
          )
          const existing = yield* InstanceState.useEffect(state, (s) => s.list())

          const params = {
            experimental_telemetry: {
              isEnabled: cfg.experimental?.openTelemetry,
              metadata: {
                userId: cfg.username ?? "unknown",
              },
            },
            temperature: 0.3,
            messages: [
              ...system.map(
                (item): ModelMessage => ({
                  role: "system",
                  content: item,
                }),
              ),
              {
                role: "user",
                content: `Create an agent configuration based on this request: \"${input.description}\".\n\nIMPORTANT: The following identifiers already exist and must NOT be used: ${existing.map((i) => i.name).join(", ")}\n  Return ONLY the JSON object, no other text, do not wrap in backticks`,
              },
            ],
            model: language,
            schema: z.object({
              identifier: z.string(),
              whenToUse: z.string(),
              systemPrompt: z.string(),
            }),
          } satisfies Parameters<typeof generateObject>[0]

          // TODO: clean this up so provider specific logic doesnt bleed over
          const authInfo = yield* auth.get(model.providerID).pipe(Effect.orDie)
          if (model.providerID === "openai" && authInfo?.type === "oauth") {
            return yield* Effect.promise(async () => {
              const result = streamObject({
                ...params,
                providerOptions: ProviderTransform.providerOptions(resolved, {
                  store: false,
                }),
                onError: () => {},
              })
              for await (const part of result.fullStream) {
                if (part.type === "error") throw part.error
              }
              return result.object
            })
          }

          return yield* Effect.promise(() => generateObject(params).then((r) => r.object))
        }),
      })
    }),
  )

  export const defaultLayer = layer.pipe(
    Layer.provide(Auth.layer),
    Layer.provide(Config.defaultLayer),
    Layer.provide(Skill.defaultLayer),
  )

  const { runPromise } = makeRuntime(Service, defaultLayer)

  export async function get(agent: string) {
    return runPromise((svc) => svc.get(agent))
  }

  export async function list() {
    return runPromise((svc) => svc.list())
  }

  export async function defaultAgent() {
    return runPromise((svc) => svc.defaultAgent())
  }

  export async function generate(input: { description: string; model?: { providerID: ProviderID; modelID: ModelID } }) {
    return runPromise((svc) => svc.generate(input))
  }
}
