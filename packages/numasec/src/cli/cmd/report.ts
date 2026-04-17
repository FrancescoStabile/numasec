import type { Argv } from "yargs"
import { cmd } from "./cmd"
import { UI } from "../ui"
import { Deliverable } from "@/core/deliverable"
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

export const ReportBuildCommand = cmd({
  command: "build",
  describe: "build a signed deliverable bundle (report.md + report.json + manifest.json)",
  builder: (y: Argv) =>
    y.option("format", { type: "string", choices: ["md", "json"], describe: "skip one of the two" }),
  handler: async (args) => {
    const slug = await requireActive()
    const result = await Deliverable.build(workspace(), slug, {
      format: args.format as "md" | "json" | undefined,
    })
    UI.println(`bundle: ${result.bundleDir}`)
    UI.println(`manifest: ${result.manifestPath}`)
    for (const f of result.manifest.files) {
      UI.println(`  ${f.sha256.slice(0, 16)}…  ${String(f.size).padStart(8)}B  ${f.path}`)
    }
    UI.println(
      `\ncounts: plan=${result.manifest.counts.plan} · observations=${result.manifest.counts.observations} · evidence=${result.manifest.counts.evidence}`,
    )
  },
})

export const ReportCommand = cmd({
  command: "report",
  describe: "generate deliverables for the active operation",
  builder: (y: Argv) => y.command(ReportBuildCommand).demandCommand(),
  async handler() {},
})
