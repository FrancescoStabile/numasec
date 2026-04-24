import type { Play } from "../play"

const play: Play = {
  id: "iac-triage",
  name: "IaC Triage",
  description:
    "Run a path-first IaC triage sweep through the optional checkov adapter and surface honest readiness when the adapter is unavailable.",
  args: [{ name: "path", required: true, type: "string", description: "local IaC file or directory path for this slice" }],
  steps: [
    {
      kind: "tool",
      label: "Run IaC scan with checkov",
      tool: "iac_triage",
      args: {
        path: "{{path}}",
        mode: "quick",
      },
      requires: [{ kind: "binary", id: "checkov", label: "checkov adapter", missingAs: "required" }],
    },
  ],
}

export default play
