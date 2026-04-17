import type { Argv } from "yargs"
import { cmd } from "./cmd"
import { UI } from "../ui"
import { Observation } from "@/core/observation"
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

const SEV_GLYPH: Record<string, string> = {
  info: "◇",
  low: "◈",
  medium: "◆",
  high: "◆",
  critical: "◆",
}

export const ObservationListCommand = cmd({
  command: "list",
  describe: "list observations for the active operation",
  builder: (y: Argv) =>
    y
      .option("format", { type: "string", choices: ["table", "json"], default: "table" })
      .option("subtype", { type: "string" })
      .option("severity", { type: "string" }),
  handler: async (args) => {
    const slug = await requireActive()
    let items = await Observation.list(workspace(), slug)
    if (args.subtype) items = items.filter((o) => o.subtype === args.subtype)
    if (args.severity) items = items.filter((o) => o.severity === args.severity)
    if (args.format === "json") return UI.println(JSON.stringify(items, null, 2))
    if (items.length === 0) return UI.println("no observations — add one with `numasec observation add`")
    for (const o of items) {
      const sev = o.severity ? `${SEV_GLYPH[o.severity]} ${o.severity}` : "  -"
      UI.println(
        `${sev.padEnd(12)} ${o.subtype.padEnd(12)} ${o.status.padEnd(10)} ${o.title}  ${UI.Style.TEXT_DIM}(${o.id.slice(0, 14)}, ev=${o.evidence.length})${UI.Style.TEXT_NORMAL}`,
      )
    }
    const counts = Observation.severityCounts(items)
    UI.println(
      `\n${counts.critical} critical · ${counts.high} high · ${counts.medium} medium · ${counts.low} low · ${counts.info} info · ${counts.none} unrated`,
    )
  },
})

export const ObservationAddCommand = cmd({
  command: "add <title>",
  describe: "add an observation",
  builder: (y: Argv) =>
    y
      .positional("title", { type: "string", demandOption: true })
      .option("subtype", {
        type: "string",
        choices: ["vuln", "code-smell", "intel-fact", "flag", "ioc", "control-gap", "risk"],
        default: "risk",
      })
      .option("severity", {
        type: "string",
        choices: ["info", "low", "medium", "high", "critical"],
      })
      .option("confidence", { type: "number" })
      .option("note", { type: "string" })
      .option("tag", { type: "array" }),
  handler: async (args) => {
    const slug = await requireActive()
    const o = await Observation.add(workspace(), slug, {
      title: args.title as string,
      subtype: args.subtype as any,
      severity: args.severity as any,
      confidence: args.confidence as number | undefined,
      note: args.note as string | undefined,
      tags: (args.tag as string[] | undefined)?.map(String),
    })
    UI.println(`added ${o.id} ${o.title}`)
  },
})

export const ObservationSetCommand = cmd({
  command: "set <id>",
  describe: "update an observation",
  builder: (y: Argv) =>
    y
      .positional("id", { type: "string", demandOption: true })
      .option("title", { type: "string" })
      .option("severity", {
        type: "string",
        choices: ["info", "low", "medium", "high", "critical"],
      })
      .option("confidence", { type: "number" })
      .option("status", {
        type: "string",
        choices: ["open", "triaged", "confirmed", "resolved", "false-positive"],
      })
      .option("note", { type: "string" }),
  handler: async (args) => {
    const slug = await requireActive()
    await Observation.update(workspace(), slug, args.id as string, {
      title: args.title as string | undefined,
      severity: args.severity as any,
      confidence: args.confidence as number | undefined,
      status: args.status as any,
      note: args.note as string | undefined,
    })
    UI.println(`updated ${args.id}`)
  },
})

export const ObservationRemoveCommand = cmd({
  command: "remove <id>",
  describe: "remove an observation",
  builder: (y: Argv) => y.positional("id", { type: "string", demandOption: true }),
  handler: async (args) => {
    const slug = await requireActive()
    await Observation.remove(workspace(), slug, args.id as string)
    UI.println(`removed ${args.id}`)
  },
})

export const ObservationLinkCommand = cmd({
  command: "link <id> <evidence>",
  describe: "link evidence (SHA-256 hash) to an observation",
  builder: (y: Argv) =>
    y
      .positional("id", { type: "string", demandOption: true })
      .positional("evidence", { type: "string", demandOption: true }),
  handler: async (args) => {
    const slug = await requireActive()
    await Observation.linkEvidence(
      workspace(),
      slug,
      args.id as string,
      args.evidence as string,
    )
    UI.println(`linked ${args.evidence} → ${args.id}`)
  },
})

export const ObservationCommand = cmd({
  command: "observation",
  aliases: ["obs"],
  describe: "manage observations (vuln/flag/intel/risk/…) for the active operation",
  builder: (y: Argv) =>
    y
      .command(ObservationListCommand)
      .command(ObservationAddCommand)
      .command(ObservationSetCommand)
      .command(ObservationRemoveCommand)
      .command(ObservationLinkCommand)
      .demandCommand(),
  async handler() {},
})
