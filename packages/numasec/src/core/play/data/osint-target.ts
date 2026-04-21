import type { Play } from "../play"

const play: Play = {
  id: "osint-target",
  name: "OSINT Target Profile",
  description:
    "Passive OSINT sweep for a domain or person: crt.sh, wayback, theHarvester, holehe via the passive-osint skill; synthesize a profile.",
  args: [
    {
      name: "target",
      required: true,
      type: "string",
      description: "domain (example.com), email, or handle to profile",
    },
  ],
  steps: [
    {
      skill: "passive-osint",
      brief:
        "run the full passive-osint workflow against {{target}}: crt.sh subdomains, wayback URLs, theHarvester emails/hosts, holehe for account presence",
    },
    {
      tool: "methodology",
      args: { framework: "mitre", phase: "Reconnaissance" },
    },
    {
      tool: "write",
      args: {
        path: "./osint-{{target}}.md",
        content_brief:
          "synthesize the collected OSINT into a markdown profile: subdomains, emails, account hits, wayback highlights, suggested next moves",
      },
    },
  ],
}

export default play
