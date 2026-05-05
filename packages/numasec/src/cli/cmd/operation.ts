import type { Argv } from "yargs"
import { cmd } from "./cmd"
import { UI } from "../ui"
import { Cyber } from "@/core/cyber"
import { Operation, KINDS, type OperationKind } from "@/core/operation"

function workspace(): string {
  return process.cwd()
}

function formatTable(ops: Awaited<ReturnType<typeof Operation.list>>): string {
  if (ops.length === 0) return "no operations yet — create one with `numasec operation new`"
  return ops
    .map((o) => {
      const mark = o.active ? "◆" : "·"
      const target = o.target ? ` · ${o.target}` : ""
      return `${mark}  ${o.slug}  [${o.kind}]  ${o.label}${target}  (${o.lines} lines)`
    })
    .join("\n")
}

export const OperationListCommand = cmd({
  command: "list",
  describe: "list operations in this workspace",
  builder: (yargs: Argv) =>
    yargs.option("format", {
      describe: "output format",
      type: "string",
      choices: ["table", "json"],
      default: "table",
    }),
  handler: async (args) => {
    const ops = await Operation.list(workspace())
    if (args.format === "json") {
      UI.println(JSON.stringify(ops, null, 2))
      return
    }
    UI.println(formatTable(ops))
  },
})

export const OperationNewCommand = cmd({
  command: "new [label]",
  describe: "create a new operation",
  builder: (yargs: Argv) =>
    yargs
      .positional("label", { type: "string", describe: "human label" })
      .option("kind", {
        alias: "k",
        describe: "kind of engagement",
        type: "string",
        choices: KINDS as unknown as string[],
        default: "pentest",
      })
      .option("target", { type: "string", describe: "optional target URL" }),
  handler: async (args) => {
    const label = args.label ?? `new ${args.kind} op`
    const info = await Operation.create({
      workspace: workspace(),
      label,
      kind: args.kind as OperationKind,
      target: args.target,
    })
    UI.println(
      UI.Style.TEXT_SUCCESS_BOLD +
        `created ${info.slug} [${info.kind}] ${info.label}` +
        UI.Style.TEXT_NORMAL,
    )
    UI.println(`operation: .numasec/operation/${info.slug}`)
  },
})

export const OperationShowCommand = cmd({
  command: "show [slug]",
  describe: "show operation state (defaults to active)",
  builder: (yargs: Argv) =>
    yargs
      .positional("slug", { type: "string" })
      .option("format", {
        describe: "output format",
        type: "string",
        choices: ["summary", "json", "context", "markdown"],
        default: "summary",
      }),
  handler: async (args) => {
    const slug = args.slug ?? (await Operation.activeSlug(workspace()))
    if (!slug) {
      UI.error("no active operation")
      process.exit(1)
    }
    const info = await Operation.read(workspace(), slug)
    if (!info) {
      UI.error(`operation not found: ${slug}`)
      process.exit(1)
    }

    if (args.format === "markdown") {
      const content = await Operation.readMarkdown(workspace(), slug)
      if (!content) {
        UI.error(`operation notebook not found: ${slug}`)
        process.exit(1)
      }
      UI.println(content)
      return
    }

    const [scope, autonomy, context, projected] = await Promise.all([
      Operation.readProjectedScopePolicy(workspace(), slug).catch(() => undefined),
      Operation.readProjectedAutonomyPolicy(workspace(), slug).catch(() => undefined),
      Operation.readContextPack(workspace(), slug).catch(() => undefined),
      Cyber.readProjectedState(workspace(), slug).catch(() => undefined),
    ])

    if (args.format === "context") {
      if (!context) {
        UI.error(`context pack not found: ${slug}`)
        process.exit(1)
      }
      UI.println(context)
      return
    }

    if (args.format === "json") {
      UI.println(
        JSON.stringify(
          {
            operation: info,
            scope_policy: scope,
            autonomy_policy: autonomy,
            projected: projected
              ? {
                  summary: projected.summary,
                  findings: projected.findings,
                  knowledge: projected.knowledge,
                  capsules: projected.capsules,
                  workflows: projected.workflows,
                  workflow_steps: projected.workflow_steps,
                  relations: projected.relations,
                  timeline: projected.timeline,
                }
              : undefined,
            context_pack: context,
          },
          null,
          2,
        ),
      )
      return
    }

    const summary = projected?.summary
    const lines = [
      `${info.slug} [${info.kind}] ${info.label}`,
      `target: ${info.target ?? "-"}`,
      `opsec: ${info.opsec}`,
      `active: ${info.active ? "yes" : "no"}`,
      `autonomy: ${autonomy?.mode ?? "-"}`,
      `scope_default: ${scope?.default ?? "-"}`,
      `in_scope: ${scope?.in_scope?.join(", ") || "-"}`,
      `out_of_scope: ${scope?.out_of_scope?.join(", ") || "-"}`,
      summary
        ? `kernel: routes=${summary.route_facts} findings=${summary.findings} candidates=${summary.candidate_findings} observations=${summary.observations_projected} workflows=${projected?.workflows.length ?? 0} relations=${projected?.relations.length ?? 0}`
        : "kernel: -",
      summary
        ? `reportability: reportable=${summary.reportable_findings} suspected=${summary.suspected_findings} rejected=${summary.rejected_findings} replay_backed=${summary.replay_backed_findings} replay_exempt=${summary.replay_exempt_findings}`
        : "reportability: -",
    ]
    if (context) {
      lines.push("")
      lines.push(context)
    }
    UI.println(lines.join("\n"))
  },
})

export const OperationUseCommand = cmd({
  command: "use <slug>",
  describe: "set the active operation",
  builder: (yargs: Argv) => yargs.positional("slug", { type: "string", demandOption: true }),
  handler: async (args) => {
    const info = await Operation.read(workspace(), args.slug)
    if (!info) {
      UI.error(`operation not found: ${args.slug}`)
      process.exit(1)
    }
    await Operation.activate(workspace(), info.slug)
    UI.println(`active → ${info.slug} [${info.kind}] ${info.label}`)
  },
})

export const OperationArchiveCommand = cmd({
  command: "archive <slug>",
  describe: "deactivate an operation (files remain on disk)",
  builder: (yargs: Argv) => yargs.positional("slug", { type: "string", demandOption: true }),
  handler: async (args) => {
    const info = await Operation.read(workspace(), args.slug)
    if (!info) {
      UI.error(`operation not found: ${args.slug}`)
      process.exit(1)
    }
    await Operation.archive(workspace(), args.slug)
    UI.println(`archived ${args.slug}`)
  },
})

export const OperationCommand = cmd({
  command: "operation",
  aliases: ["op"],
  describe: "manage operations (engagements, reviews, investigations)",
  builder: (yargs: Argv) =>
    yargs
      .command(OperationListCommand)
      .command(OperationNewCommand)
      .command(OperationShowCommand)
      .command(OperationUseCommand)
      .command(OperationArchiveCommand)
      .demandCommand(),
  async handler() {},
})
