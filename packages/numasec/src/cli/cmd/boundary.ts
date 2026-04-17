import type { Argv } from "yargs"
import { cmd } from "./cmd"
import { UI } from "../ui"
import { evaluate } from "@/core/boundary"
import { Operation, OperationActive } from "@/core/operation"

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

function currentBoundary(info: Awaited<ReturnType<typeof Operation.get>>): {
  default: "allow" | "deny" | "ask"
  in_scope: string[]
  out_of_scope: string[]
} {
  const raw = info?.boundary ?? {}
  return {
    default: (raw["default"] as "allow" | "deny" | "ask" | undefined) ?? "ask",
    in_scope: Array.isArray(raw["in_scope"]) ? (raw["in_scope"] as string[]) : [],
    out_of_scope: Array.isArray(raw["out_of_scope"]) ? (raw["out_of_scope"] as string[]) : [],
  }
}

export const BoundaryShowCommand = cmd({
  command: "show",
  describe: "show the active operation's boundary",
  builder: (y: Argv) => y,
  handler: async () => {
    const slug = await requireActive()
    const info = await Operation.get(workspace(), slug)
    const b = currentBoundary(info)
    UI.println(`default: ${b.default}`)
    UI.println(`in_scope (${b.in_scope.length}):`)
    b.in_scope.forEach((p) => UI.println(`  + ${p}`))
    UI.println(`out_of_scope (${b.out_of_scope.length}):`)
    b.out_of_scope.forEach((p) => UI.println(`  - ${p}`))
  },
})

export const BoundarySetCommand = cmd({
  command: "set <bucket> <pattern>",
  describe: "add a pattern to in|out scope",
  builder: (y: Argv) =>
    y
      .positional("bucket", { type: "string", choices: ["in", "out", "default"], demandOption: true })
      .positional("pattern", { type: "string", demandOption: true })
      .option("remove", { type: "boolean", describe: "remove the pattern instead of adding", default: false }),
  handler: async (args) => {
    const slug = await requireActive()
    const info = await Operation.get(workspace(), slug)
    const b = currentBoundary(info)
    const pattern = args.pattern as string
    if (args.bucket === "default") {
      if (!["allow", "deny", "ask"].includes(pattern)) {
        UI.error(`default must be one of allow|deny|ask`)
        process.exit(1)
      }
      b.default = pattern as "allow" | "deny" | "ask"
    } else {
      const list = args.bucket === "in" ? b.in_scope : b.out_of_scope
      const i = list.indexOf(pattern)
      if (args.remove) {
        if (i >= 0) list.splice(i, 1)
      } else if (i < 0) {
        list.push(pattern)
      }
    }
    await Operation.setBoundary(workspace(), slug, b as unknown as Record<string, unknown>)
    UI.println(`${args.remove ? "removed" : "updated"} ${args.bucket}: ${pattern}`)
  },
})

export const BoundaryCheckCommand = cmd({
  command: "check <kind> <value>",
  describe: "evaluate a request against the active boundary",
  builder: (y: Argv) =>
    y
      .positional("kind", { type: "string", choices: ["url", "path", "host", "raw"], demandOption: true })
      .positional("value", { type: "string", demandOption: true }),
  handler: async (args) => {
    const slug = await requireActive()
    const info = await Operation.get(workspace(), slug)
    const d = evaluate(info?.boundary ?? {}, {
      kind: args.kind as "url" | "path" | "host" | "raw",
      value: args.value as string,
    })
    UI.println(`${d.mode.toUpperCase()}  ${d.reason}${d.matched ? `  [${d.matched}]` : ""}`)
    if (d.mode === "deny") process.exit(2)
  },
})

export const BoundaryCommand = cmd({
  command: "boundary",
  describe: "view and manage the active operation's scope boundary",
  builder: (y: Argv) =>
    y
      .command(BoundaryShowCommand)
      .command(BoundarySetCommand)
      .command(BoundaryCheckCommand)
      .demandCommand(),
  async handler() {},
})
