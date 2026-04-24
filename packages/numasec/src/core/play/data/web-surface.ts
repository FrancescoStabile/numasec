import type { Play } from "../play"

const play: Play = {
  id: "web-surface",
  name: "Web Surface Map",
  description:
    "Map the attack surface of a URL: crawl the site, analyse loaded JS, run a light dir-fuzz, enumerate subdomains via passive OSINT, and optionally capture browser passive findings. Produces endpoints, forms, JS secrets, subdomains.",
  args: [
    { name: "target", required: true, type: "string", description: "root URL to survey (e.g. https://example.com)" },
    {
      name: "domain",
      required: false,
      type: "string",
      description: "apex domain for subdomain enumeration (optional)",
    },
  ],
  steps: [
    {
      kind: "skill",
      label: "enumerate passive subdomains",
      skill: "passive-osint",
      brief: "enumerate subdomains of {{domain|target hostname}} using crt.sh, wayback, theHarvester, holehe — no active probes, passive only",
    },
    {
      kind: "tool",
      label: "crawl target",
      tool: "scanner",
      args: {
        mode: "crawl",
        target: "{{target}}",
        options: {
          maxUrls: 50,
          maxDepth: 2,
          timeout: 10_000,
        },
      },
    },
    {
      kind: "tool",
      label: "JavaScript endpoint extraction",
      tool: "scanner",
      args: {
        mode: "js",
        target: "{{target}}",
        options: {
          maxFiles: 20,
          timeout: 10_000,
        },
      },
    },
    {
      kind: "tool",
      label: "Light web dir-fuzz",
      tool: "scanner",
      args: {
        mode: "dir-fuzz",
        target: "{{target}}",
        options: {
          concurrency: 10,
          timeout: 10_000,
          wordlist: ["common"],
          extensions: ["php", "txt", "js"],
          filterStatus: [200, 201, 204, 301, 302, 307, 308, 401, 403],
        },
      },
    },
    {
      kind: "tool",
      label: "Browser passive findings",
      tool: "browser",
      args: {
        action: "passive_appsec",
        url: "{{target}}",
      },
      requires: [{ kind: "runtime", id: "browser", label: "browser runtime", missingAs: "optional" }],
    },
  ],
}

export default play
