import type { Argv } from "yargs"
import { cmd } from "./cmd"
import { UI } from "../ui"
import { Plan } from "@/core/plan"
import { OperationActive } from "@/core/operation"

function workspace(): string {
  return process.cwd()
}

async function requireActive(): Promise<string> {
  const slug = await OperationActive.getActiveSlug(workspace())
  if (!slug) {
    UI.error("no active operation — run `numasec operation use <slug>` first")
    process.exit(1)
  }
  return slug
}

const STATUS_GLYPH: Record<string, string> = {
  planned: "◌",
  running: "◐",
  done: "●",
  blocked: "✕",
  skipped: "◇",
}

export const PlanListCommand = cmd({
  command: "list",
  describe: "list plan nodes for the active operation",
  builder: (y: Argv) =>
    y.option("format", { type: "string", choices: ["tree", "json"], default: "tree" }),
  handler: async (args) => {
    const slug = await requireActive()
    const nodes = await Plan.list(workspace(), slug)
    if (args.format === "json") return UI.println(JSON.stringify(nodes, null, 2))
    if (nodes.length === 0) return UI.println("plan is empty — add a node with `numasec plan add`")
    const byParent = new Map<string | undefined, typeof nodes>()
    for (const n of nodes) {
      const p = n.parent_id
      if (!byParent.has(p)) byParent.set(p, [])
      byParent.get(p)!.push(n)
    }
    const render = (parent: string | undefined, depth: number): string[] =>
      (byParent.get(parent) ?? []).flatMap((n) => [
        `${"  ".repeat(depth)}${STATUS_GLYPH[n.status] ?? "·"} ${n.title}  ${UI.Style.TEXT_DIM}(${n.id.slice(0, 10)})${UI.Style.TEXT_NORMAL}`,
        ...render(n.id, depth + 1),
      ])
    UI.println(render(undefined, 0).join("\n"))
    const p = Plan.progress(nodes)
    UI.println(`\n${p.done}/${p.total} done · ${p.running} running · ${p.blocked} blocked`)
  },
})

export const PlanAddCommand = cmd({
  command: "add <title>",
  describe: "add a plan node",
  builder: (y: Argv) =>
    y
      .positional("title", { type: "string", demandOption: true })
      .option("parent", { type: "string", describe: "parent node id" })
      .option("note", { type: "string" }),
  handler: async (args) => {
    const slug = await requireActive()
    const n = await Plan.add(workspace(), slug, {
      title: args.title as string,
      parent_id: args.parent as string | undefined,
      note: args.note as string | undefined,
    })
    UI.println(`added ${n.id} ${n.title}`)
  },
})

export const PlanSetCommand = cmd({
  command: "set <id> <status>",
  describe: "set status (planned|running|done|blocked|skipped)",
  builder: (y: Argv) =>
    y
      .positional("id", { type: "string", demandOption: true })
      .positional("status", {
        type: "string",
        choices: ["planned", "running", "done", "blocked", "skipped"],
        demandOption: true,
      })
      .option("note", { type: "string" }),
  handler: async (args) => {
    const slug = await requireActive()
    await Plan.update(workspace(), slug, args.id as string, {
      status: args.status as Plan.NodeStatus,
      note: args.note as string | undefined,
    })
    UI.println(`updated ${args.id} → ${args.status}`)
  },
})

export const PlanRemoveCommand = cmd({
  command: "remove <id>",
  describe: "remove a plan node",
  builder: (y: Argv) => y.positional("id", { type: "string", demandOption: true }),
  handler: async (args) => {
    const slug = await requireActive()
    await Plan.remove(workspace(), slug, args.id as string)
    UI.println(`removed ${args.id}`)
  },
})

export const PlanCommand = cmd({
  command: "plan",
  describe: "manage the active operation's plan tree",
  builder: (y: Argv) =>
    y
      .command(PlanListCommand)
      .command(PlanAddCommand)
      .command(PlanSetCommand)
      .command(PlanRemoveCommand)
      .demandCommand(),
  async handler() {},
})
