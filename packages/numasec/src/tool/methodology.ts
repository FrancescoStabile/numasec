import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./methodology.txt"
import { Methodology, type Framework, type FrameworkID } from "../core/methodology"

const parameters = z.object({
  framework: z.enum(["mitre", "ptes", "wstg"]).describe("which methodology to query"),
  phase: z.string().optional().describe("phase/tactic/category id or name (e.g. TA0001, Reconnaissance, WSTG-ATHN)"),
  query: z.string().optional().describe("free-text filter against technique id, name, description"),
})

type Params = z.infer<typeof parameters>
type Metadata = { framework: FrameworkID; phase?: string; query?: string; matches: number }

function fmtTechnique(t: { id: string; name: string; description: string }) {
  return `  - [${t.id}] ${t.name} — ${t.description}`
}

function fmtPhase(phase: Framework["phases"][number], techniques: Framework["phases"][number]["techniques"]) {
  const header = `## [${phase.id}] ${phase.name}`
  const desc = phase.description ? `${phase.description}\n` : ""
  if (techniques.length === 0) return `${header}\n${desc}  (no matching techniques)`
  return [header, desc + techniques.map(fmtTechnique).join("\n")].join("\n")
}

function render(p: Params): { output: string; matches: number } {
  const fw = Methodology.get(p.framework)
  const q = p.query?.trim().toLowerCase()

  const phases = p.phase ? [Methodology.findPhase(p.framework, p.phase)].filter((x) => !!x) : fw.phases

  if (p.phase && phases.length === 0) {
    return {
      output: `No phase "${p.phase}" in ${fw.name}. Available: ${fw.phases.map((x) => `${x.id} (${x.name})`).join(", ")}`,
      matches: 0,
    }
  }

  const blocks: string[] = []
  let total = 0
  for (const phase of phases) {
    const techniques = q
      ? phase.techniques.filter(
          (t) =>
            t.id.toLowerCase().includes(q) ||
            t.name.toLowerCase().includes(q) ||
            t.description.toLowerCase().includes(q),
        )
      : phase.techniques
    if (q && techniques.length === 0) continue
    total += techniques.length
    blocks.push(fmtPhase(phase, techniques))
  }

  const header = `# ${fw.name} (${fw.version})`
  const body = blocks.length ? blocks.join("\n\n") : `No techniques match query "${p.query}".`
  return { output: [header, body].join("\n\n"), matches: total }
}

export const MethodologyTool = Tool.define<typeof parameters, Metadata, never>(
  "methodology",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, _ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const { output, matches } = render(params)
          const fw = Methodology.get(params.framework)
          const scope = [params.phase, params.query].filter(Boolean).join(" / ")
          return {
            title: scope ? `${fw.name}: ${scope}` : fw.name,
            output,
            metadata: { framework: params.framework, phase: params.phase, query: params.query, matches },
          }
        }),
    }
  }),
)
