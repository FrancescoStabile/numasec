import type { Play } from "../play"

const play: Play = {
  id: "container-surface",
  name: "Container Surface",
  description:
    "Run an image-first container surface sweep through the optional trivy adapter and surface honest readiness when the adapter is unavailable.",
  args: [{ name: "image", required: true, type: "string", description: "fully-qualified container image reference (e.g., nginx:latest, ghcr.io/org/app:sha-abc123)" }],
  steps: [
    {
      kind: "tool",
      label: "Run container image triage with trivy",
      tool: "container_surface",
      args: {
        image: "{{image}}",
        mode: "quick",
      },
      requires: [{ kind: "binary", id: "trivy", label: "trivy adapter", missingAs: "required" }],
    },
  ],
}

export default play
