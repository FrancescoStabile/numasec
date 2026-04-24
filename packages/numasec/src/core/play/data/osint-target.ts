import type { Play } from "../play"

const play: Play = {
  id: "osint-target",
  name: "OSINT Target Profile",
  description:
    "Passive OSINT sweep for a domain or person: crt.sh, wayback, theHarvester, holehe via the passive-osint skill, then seed a markdown profile scaffold for analyst synthesis.",
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
        filePath: "./osint-{{target}}.md",
        content: `# OSINT Target Profile: {{target}}

## Sources reviewed

- Passive OSINT workflow executed for {{target}}
- crt.sh results
- Wayback URLs
- theHarvester findings
- holehe account hits

## Summary

Fill in the synthesized profile for {{target}} here.

## Suggested next moves

- Prioritize the most interesting subdomains
- Highlight notable account hits
- Capture high-value archived endpoints
`,
      },
    },
  ],
}

export default play
