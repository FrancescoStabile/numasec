import type { Play } from "../play"

const play: Play = {
  id: "network-surface",
  name: "Network Surface Map",
  description:
    "Map the network surface of a host: scan common TCP ports, probe likely services, and align findings to PTES intelligence gathering. Produces open ports, detected services, and captured banners where available.",
  args: [
    { name: "target", required: true, type: "string", description: "host or IP to scan (e.g. 10.0.0.5)" },
  ],
  steps: [
    {
      kind: "tool",
      label: "Scan common TCP ports",
      tool: "scanner",
      args: {
        mode: "ports",
        target: "{{target}}",
        options: {
          concurrency: 50,
          timeout: 3_000,
        },
      },
    },
    {
      kind: "tool",
      label: "Probe common services on common ports",
      tool: "scanner",
      args: {
        mode: "service",
        target: "{{target}}",
        options: {
          ports: [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 2049, 3000, 3001, 3306, 3389, 4000, 5000, 5173, 5432, 5900,
            6379, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 27017,
          ],
          concurrency: 10,
          timeout: 5_000,
        },
      },
    },
    {
      kind: "tool",
      label: "Map to PTES intelligence gathering",
      tool: "methodology",
      args: { framework: "ptes", phase: "Intelligence Gathering" },
    },
  ],
}

export default play
