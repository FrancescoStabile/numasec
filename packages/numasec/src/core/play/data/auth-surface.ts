import type { Play } from "../play"

const play: Play = {
  id: "auth-surface",
  name: "Auth Surface Map",
  description:
    "Discovery and mapping of authentication entry points: crawl auth-shaped routes, extract auth hints from JavaScript, and optionally capture passive auth/session findings with a browser. No active verification.",
  args: [
    {
      name: "target",
      required: true,
      type: "string",
      description: "absolute root URL to survey (e.g. https://auth.example.com)",
    },
  ],
  steps: [
    {
      kind: "tool",
      label: "crawl auth entrypoints",
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
      label: "extract auth hints from javascript",
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
      label: "browser auth/session passive findings",
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
