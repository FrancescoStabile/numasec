// Scope parser for numasec.md — regex on the `## Scope` section.
//
// Rules:
//   Under `## Scope`, lines like `- in: <pattern>` add to in_scope.
//   Lines like `- out: <pattern>` add to out_of_scope.
//   Empty pattern (`- in:` alone) is ignored.
//   Section ends at the next `## ` heading.
//
// The output is shaped as a Boundary (see core/boundary/schema) so it can be
// fed directly into the existing matcher.

import type { Boundary } from "../boundary/schema"

const HEADING_RE = /^##\s+/

export function parseScope(markdown: string): Boundary {
  const lines = markdown.split("\n")
  const inScope: string[] = []
  const outOfScope: string[] = []
  let inside = false

  for (const raw of lines) {
    const line = raw.trimEnd()
    if (/^##\s+scope\b/i.test(line)) {
      inside = true
      continue
    }
    if (inside && HEADING_RE.test(line)) break
    if (!inside) continue

    const inMatch = line.match(/^\s*-\s*in\s*:\s*(.*)$/i)
    const outMatch = line.match(/^\s*-\s*out\s*:\s*(.*)$/i)
    if (inMatch) {
      const v = inMatch[1].trim()
      if (v) inScope.push(v)
    } else if (outMatch) {
      const v = outMatch[1].trim()
      if (v) outOfScope.push(v)
    }
  }

  return {
    default: inScope.length === 0 && outOfScope.length === 0 ? "allow" : "ask",
    in_scope: inScope,
    out_of_scope: outOfScope,
  }
}
