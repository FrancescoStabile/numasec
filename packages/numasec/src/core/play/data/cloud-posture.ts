import type { Play } from "../play"

const play: Play = {
  id: "cloud-posture",
  name: "Cloud Posture",
  description:
    "Run an AWS-first cloud posture sweep through the optional prowler adapter and surface honest readiness when the adapter is unavailable.",
  args: [
    { name: "provider", required: true, type: "string", description: "cloud provider for this slice (aws only)" },
    { name: "profile", required: false, type: "string", description: "optional AWS profile name" },
    { name: "region", required: false, type: "string", description: "optional AWS region" },
  ],
  steps: [
    {
      kind: "tool",
      label: "Run AWS posture sweep with prowler",
      tool: "cloud_posture",
      args: {
        provider: "{{provider}}",
        mode: "quick",
        profile: "{{profile}}",
        region: "{{region}}",
      },
      requires: [{ kind: "binary", id: "prowler", label: "prowler adapter", missingAs: "required" }],
    },
  ],
}

export default play
