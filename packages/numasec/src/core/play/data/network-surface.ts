import type { Play } from "../play"

const play: Play = {
  id: "network-surface",
  name: "Network Surface Map",
  description:
    "Portscan, service-probe, and banner-collect an IP or CIDR. Produces open ports, detected services, and raw banners.",
  args: [
    { name: "target", required: true, type: "string", description: "IP or CIDR to scan (e.g. 10.0.0.0/24)" },
    {
      name: "ports",
      required: false,
      type: "string",
      description: 'port spec (default "top-1000")',
    },
  ],
  steps: [
    {
      tool: "scanner",
      args: {
        kind: "portscan",
        target: "{{target}}",
        ports: "{{ports|top-1000}}",
        profile: "tcp-syn",
      },
    },
    {
      tool: "scanner",
      args: {
        kind: "service-probe",
        target: "{{target}}",
        follow_up: "portscan",
        note: "version detection on open ports only",
      },
    },
    {
      tool: "scanner",
      args: {
        kind: "banner",
        target: "{{target}}",
        note: "grab banners from open ports for manual triage",
      },
    },
    {
      tool: "methodology",
      args: { framework: "ptes", phase: "Intelligence Gathering" },
    },
  ],
}

export default play
