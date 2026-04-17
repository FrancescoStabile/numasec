import type { Argv } from "yargs"
import { readFile } from "fs/promises"
import { cmd } from "./cmd"
import { UI } from "../ui"
import { Evidence } from "@/core/evidence"
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

export const EvidenceListCommand = cmd({
  command: "list",
  describe: "list evidence manifest for the active operation",
  builder: (y: Argv) =>
    y.option("format", { type: "string", choices: ["table", "json"], default: "table" }),
  handler: async (args) => {
    const slug = await requireActive()
    const items = await Evidence.list(workspace(), slug)
    if (args.format === "json") return UI.println(JSON.stringify(items, null, 2))
    if (items.length === 0)
      return UI.println("no evidence — add one with `numasec evidence add <path>`")
    for (const e of items) {
      UI.println(
        `${e.sha256.slice(0, 16)}…  ${String(e.size).padStart(8)}B  ${(e.mime ?? "-").padEnd(24)} ${e.label ?? ""}  ${UI.Style.TEXT_DIM}${e.source ?? ""}${UI.Style.TEXT_NORMAL}`,
      )
    }
    UI.println(`\n${items.length} entr${items.length === 1 ? "y" : "ies"}`)
  },
})

export const EvidenceAddCommand = cmd({
  command: "add <path>",
  describe: "store a file as evidence (content-addressed by SHA-256)",
  builder: (y: Argv) =>
    y
      .positional("path", { type: "string", demandOption: true })
      .option("mime", { type: "string" })
      .option("label", { type: "string" })
      .option("source", { type: "string" })
      .option("ext", { type: "string" }),
  handler: async (args) => {
    const slug = await requireActive()
    const entry = await Evidence.put(
      workspace(),
      slug,
      { path: args.path as string },
      {
        mime: args.mime as string | undefined,
        label: args.label as string | undefined,
        source: (args.source as string | undefined) ?? (args.path as string),
        ext: args.ext as string | undefined,
      },
    )
    UI.println(`stored ${entry.sha256} (${entry.size}B, ${entry.ext})`)
  },
})

export const EvidenceShowCommand = cmd({
  command: "show <hash>",
  describe: "print evidence metadata (and bytes as text if --print)",
  builder: (y: Argv) =>
    y
      .positional("hash", { type: "string", demandOption: true })
      .option("print", { type: "boolean", default: false }),
  handler: async (args) => {
    const slug = await requireActive()
    const got = await Evidence.get(workspace(), slug, args.hash as string)
    if (!got) {
      UI.error(`not found: ${args.hash}`)
      process.exit(1)
    }
    UI.println(JSON.stringify(got.entry, null, 2))
    if (args.print) {
      UI.println("")
      UI.println(Buffer.from(got.bytes).toString("utf8"))
    }
  },
})

export const EvidenceCommand = cmd({
  command: "evidence",
  aliases: ["ev"],
  describe: "manage the evidence locker for the active operation",
  builder: (y: Argv) =>
    y
      .command(EvidenceListCommand)
      .command(EvidenceAddCommand)
      .command(EvidenceShowCommand)
      .demandCommand(),
  async handler() {},
})

void readFile
