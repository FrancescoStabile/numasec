import type { Play } from "../play"

const play: Play = {
  id: "binary-triage",
  name: "Binary Triage",
  description:
    "Run a single-binary hardening triage through the optional checksec adapter and surface honest readiness when the adapter is unavailable.",
  args: [{ name: "path", required: true, type: "string", description: "local binary file path for this slice" }],
  steps: [
    {
      kind: "tool",
      label: "Run binary scan with checksec",
      tool: "binary_triage",
      args: {
        path: "{{path}}",
      },
      requires: [{ kind: "binary", id: "checksec", label: "checksec adapter", missingAs: "required" }],
    },
  ],
}

export default play
