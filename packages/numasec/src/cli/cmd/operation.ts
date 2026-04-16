import type { Argv } from "yargs"
import { cmd } from "./cmd"
import { UI } from "../ui"
import { Operation, OperationActive } from "@/core/operation"
import { Kind, type KindId } from "@/core/kind"

function workspace(): string {
  return process.cwd()
}

function formatTable(ops: Awaited<ReturnType<typeof Operation.list>>): string {
  if (ops.length === 0) return "no operations yet — create one with `numasec operation new`"
  const rows = ops.map((o) => {
    const pack = Kind.byId(o.kind)
    const glyph = pack?.glyph ?? "·"
    const status = o.status === "archived" ? "archived" : "active"
    const sessions = o.sessions.length
    return [glyph, o.slug, pack?.short ?? o.kind, o.label, `${sessions} sess`, status].join("  ")
  })
  return rows.join("\n")
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
    const active = await OperationActive.getActiveSlug(workspace())
    UI.println(formatTable(ops))
    if (active) UI.println(`\nactive: ${active}`)
  },
})

export const OperationNewCommand = cmd({
  command: "new [label]",
  describe: "create a new operation",
  builder: (yargs: Argv) =>
    yargs
      .positional("label", { type: "string", describe: "human label (defaults to slug)" })
      .option("kind", {
        alias: "k",
        describe: "kind pack",
        type: "string",
        choices: ["security", "pentest", "appsec", "osint", "hacking"],
        default: "security",
      })
      .option("slug", { type: "string", describe: "slug override" })
      .option("activate", {
        type: "boolean",
        default: true,
        describe: "set as active operation",
      }),
  handler: async (args) => {
    const label = args.label ?? args.slug ?? `new ${args.kind} op`
    const info = await Operation.create(workspace(), {
      label,
      kind: args.kind as KindId,
      slug: args.slug,
    })
    if (args.activate) await OperationActive.setActive(workspace(), info.slug)
    UI.println(
      UI.Style.TEXT_SUCCESS_BOLD +
        `created ${info.slug} [${info.kind}] ${info.label}` +
        UI.Style.TEXT_NORMAL,
    )
  },
})

export const OperationShowCommand = cmd({
  command: "show [slug]",
  describe: "show operation details (defaults to active)",
  builder: (yargs: Argv) => yargs.positional("slug", { type: "string" }),
  handler: async (args) => {
    const slug = args.slug ?? (await OperationActive.getActiveSlug(workspace()))
    if (!slug) {
      UI.error("no active operation")
      process.exit(1)
    }
    const info = await Operation.get(workspace(), slug)
    if (!info) {
      UI.error(`operation not found: ${slug}`)
      process.exit(1)
    }
    UI.println(JSON.stringify(info, null, 2))
  },
})

export const OperationUseCommand = cmd({
  command: "use <slug>",
  describe: "set the active operation",
  builder: (yargs: Argv) => yargs.positional("slug", { type: "string", demandOption: true }),
  handler: async (args) => {
    const info = await Operation.get(workspace(), args.slug)
    if (!info) {
      UI.error(`operation not found: ${args.slug}`)
      process.exit(1)
    }
    await OperationActive.setActive(workspace(), info.slug)
    UI.println(`active → ${info.slug} [${info.kind}] ${info.label}`)
  },
})

export const OperationArchiveCommand = cmd({
  command: "archive <slug>",
  describe: "archive an operation",
  builder: (yargs: Argv) => yargs.positional("slug", { type: "string", demandOption: true }),
  handler: async (args) => {
    const info = await Operation.get(workspace(), args.slug)
    if (!info) {
      UI.error(`operation not found: ${args.slug}`)
      process.exit(1)
    }
    await Operation.archive(workspace(), args.slug)
    const active = await OperationActive.getActiveSlug(workspace())
    if (active === args.slug) await OperationActive.clearActive(workspace())
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
