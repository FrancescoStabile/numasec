import type { Play } from "../play"

const play: Play = {
  id: "web-surface",
  name: "Web Surface Map",
  description:
    "Map the attack surface of a URL: crawl the site, analyse loaded JS, run a light dir-fuzz, and enumerate subdomains via passive OSINT. Produces endpoints, forms, JS secrets, subdomains.",
  args: [
    { name: "target", required: true, type: "string", description: "root URL to survey (e.g. https://example.com)" },
    {
      name: "domain",
      required: false,
      type: "string",
      description: "apex domain for subdomain enumeration (defaults to hostname of target)",
    },
  ],
  steps: [
    {
      skill: "passive-osint",
      brief:
        "enumerate subdomains of {{domain}} using crt.sh, wayback, theHarvester, holehe — no active probes, passive only",
    },
    {
      tool: "browser",
      args: {
        action: "crawl",
        url: "{{target}}",
        depth: 2,
        note: "collect endpoints, forms, and referenced JS URLs",
      },
    },
    {
      tool: "bash",
      args: {
        command:
          "echo 'js-analyze: fetch each JS URL from crawl, grep for secrets (AWS_|API_KEY|TOKEN|password|bearer), endpoints (/api/, fetch\\(, axios)'",
        description: "JS secrets & endpoint extraction guidance",
      },
    },
    {
      tool: "scanner",
      args: {
        kind: "dir-fuzz",
        target: "{{target}}",
        profile: "light",
        note: "top-1k wordlist, 10 req/s, no recursion",
      },
    },
    {
      tool: "methodology",
      args: { framework: "wstg", phase: "WSTG-INFO" },
    },
  ],
}

export default play
