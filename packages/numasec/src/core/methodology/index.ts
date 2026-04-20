import mitre from "./data/mitre-attack.json" with { type: "json" }
import ptes from "./data/ptes.json" with { type: "json" }
import wstg from "./data/wstg.json" with { type: "json" }
import type { Framework, FrameworkID } from "./framework"

export namespace Methodology {
  export const frameworks: Record<FrameworkID, Framework> = {
    mitre: mitre as Framework,
    ptes: ptes as Framework,
    wstg: wstg as Framework,
  }

  export const ids = Object.keys(frameworks) as FrameworkID[]

  export function get(id: FrameworkID): Framework {
    return frameworks[id]
  }

  export function findPhase(id: FrameworkID, phaseId: string) {
    const needle = phaseId.toLowerCase()
    return frameworks[id].phases.find(
      (p) => p.id.toLowerCase() === needle || p.name.toLowerCase() === needle,
    )
  }

  export function search(id: FrameworkID, query: string) {
    const q = query.toLowerCase()
    const fw = frameworks[id]
    const matches: { phase: Framework["phases"][number]; technique: Framework["phases"][number]["techniques"][number] }[] = []
    for (const phase of fw.phases) {
      for (const technique of phase.techniques) {
        if (
          technique.id.toLowerCase().includes(q) ||
          technique.name.toLowerCase().includes(q) ||
          technique.description.toLowerCase().includes(q)
        ) {
          matches.push({ phase, technique })
        }
      }
    }
    return matches
  }
}

export type { Framework, FrameworkID, Phase, Technique } from "./framework"
