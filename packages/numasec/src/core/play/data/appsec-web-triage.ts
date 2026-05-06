import type { Play } from "../play"

const play: Play = {
  id: "appsec-web-triage",
  name: "AppSec Web Triage",
  description:
    "Run an evidence-first DAST triage against a live web application: environment readiness, AppSec methodology context, surface crawl, JS extraction, and semantic candidate-finding probes.",
  args: [
    { name: "target", required: true, type: "string", description: "root HTTP(S) URL to triage" },
  ],
  steps: [
    {
      kind: "tool",
      label: "Refresh local cyber tool readiness",
      tool: "doctor",
      args: {},
    },
    {
      kind: "tool",
      label: "Anchor to AppSec methodology knowledge",
      tool: "knowledge",
      args: {
        intent: "methodology",
        action: "safe_next_actions",
        query: "OWASP WSTG SQL injection XSS JWT IDOR CORS",
        mode: "offline",
        limit: 10,
      },
    },
    {
      kind: "tool",
      label: "Crawl target routes",
      tool: "scanner",
      args: {
        mode: "crawl",
        target: "{{target}}",
        options: {
          maxUrls: 80,
          maxDepth: 2,
          timeout: 10_000,
        },
      },
    },
    {
      kind: "tool",
      label: "Extract JavaScript endpoints and secret-shaped values",
      tool: "scanner",
      args: {
        mode: "js",
        target: "{{target}}",
        options: {
          maxFiles: 30,
          timeout: 10_000,
        },
      },
    },
    {
      kind: "tool",
      label: "Run semantic AppSec DAST candidate probes",
      tool: "appsec_probe",
      args: {
        target: "{{target}}",
        checks: ["sqli_search", "xss_search", "broken_auth_jwt", "idor_basket", "weak_cors"],
        timeout: 15_000,
      },
    },
  ],
}

export default play
