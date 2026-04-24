import type { Play } from "../play"

const play: Play = {
  id: "api-surface",
  name: "API Surface Map",
  description:
    "Surface likely API routes and lightweight passive findings: HTTP probe, JS endpoint extraction, light API dir-fuzz, and optional browser passive capture. Produces candidate routes, response patterns, and surface-level passive findings.",
  args: [
    {
      name: "target",
      required: true,
      type: "string",
      description: "absolute root URL to survey (e.g. https://api.example.com)",
    },
  ],
  steps: [
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
      label: "Light API dir-fuzz",
      tool: "scanner",
      args: {
        mode: "dir-fuzz",
        target: "{{target}}",
        options: {
          concurrency: 10,
          timeout: 10_000,
          wordlist: ["common", "api"],
          extensions: ["json", "txt"],
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
