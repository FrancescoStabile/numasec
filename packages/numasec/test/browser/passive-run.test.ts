import { describe, expect, test } from "bun:test"
import { runInNewContext } from "node:vm"
import {
  buildPassiveAppSecResult,
  collectPassiveInput,
  formatPassiveAppSecResult,
} from "../../src/browser/passive-run"

class FakeHTMLInputElement {
  name: string
  type: string
  value: string

  constructor(name: string, type: string, value: string) {
    this.name = name
    this.type = type
    this.value = value
  }
}

class FakeHTMLTextAreaElement {
  name: string
  value: string

  constructor(name: string, value: string) {
    this.name = name
    this.value = value
  }
}

class FakeHTMLSelectElement {
  name: string
  type: string
  value: string

  constructor(name: string, value: string) {
    this.name = name
    this.type = "select-one"
    this.value = value
  }
}

function makeStorage(entries: Record<string, string>) {
  const keys = Object.keys(entries)

  return {
    get length() {
      return keys.length
    },
    getItem(key: string) {
      return entries[key] ?? null
    },
    key(index: number) {
      return keys[index] ?? null
    },
    ...entries,
  }
}

function makeBrowserSandbox() {
  const form = {
    getAttribute(name: string) {
      return name === "name" ? "transfer" : null
    },
    action: "https://app.example.test/transfer",
    method: "post",
    querySelectorAll(selector: string) {
      if (selector !== "input,textarea,select") return []
      return [
        new FakeHTMLInputElement("amount", "text", "100"),
        new FakeHTMLTextAreaElement("memo", "rent"),
        new FakeHTMLSelectElement("priority", "high"),
      ]
    },
  }

  const script = {
    getAttribute(name: string) {
      return name === "src" ? null : null
    },
  }

  return {
    HTMLInputElement: FakeHTMLInputElement,
    HTMLTextAreaElement: FakeHTMLTextAreaElement,
    HTMLSelectElement: FakeHTMLSelectElement,
    document: {
      querySelectorAll(selector: string) {
        if (selector === "form") return [form]
        if (selector === "script") return [script]
        return []
      },
    },
    localStorage: makeStorage({ authToken: "abc123" }),
    window: { sessionStorage: makeStorage({ draft: "1" }) },
  }
}

describe("browser passive appsec run", () => {
  test("collects passive browser input from page, context, and session state", async () => {
    const input = await collectPassiveInput(
      {
        url: () => "https://app.example.test/dashboard",
        evaluate: async (fn) => runInNewContext(`(${fn.toString()})()`, makeBrowserSandbox()),
      },
      {
        cookies: async () => [
          {
            name: "session",
            value: "cookie",
            domain: "app.example.test",
            path: "/",
            secure: true,
            httpOnly: true,
            sameSite: "Strict",
          },
        ],
      },
      {
        network: [
          {
            method: "GET",
            url: "https://app.example.test/api/me",
            status: 200,
            content_type: "application/json",
          },
        ],
        console: [{ level: "error", text: "boom" }],
      },
      { "content-security-policy": "default-src 'self'" },
    )

    expect(input).toMatchObject({
      url: "https://app.example.test/dashboard",
      headers: { "content-security-policy": "default-src 'self'" },
      cookies: [{ name: "session" }],
      storage: {
        local: { authToken: "abc123" },
        session: { draft: "1" },
      },
      forms: [
        {
          name: "transfer",
          action: "https://app.example.test/transfer",
          method: "post",
          inputs: [
            { name: "amount", type: "text", value: "100" },
            { name: "memo", value: "rent" },
            { name: "priority", type: "select-one", value: "high" },
          ],
        },
      ],
      requests: [{ url: "https://app.example.test/api/me", status: 200 }],
      console: [{ level: "error", text: "boom" }],
      scripts: {
        inline_count: 1,
        external: [],
      },
    })
    expect(input.forms?.[0]?.inputs).toEqual([
      { name: "amount", type: "text", value: "100" },
      { name: "memo", value: "rent" },
      { name: "priority", type: "select-one", value: "high" },
    ])
  })

  test("formats passive findings as a structured tool result", () => {
    const result = formatPassiveAppSecResult({
      title: "Example App",
      report: {
        findings: [
          {
            id: "missing-security-header",
            severity: "low",
            title: "Missing security headers",
            evidence: ["content-security-policy"],
          },
        ],
        summary: {
          high: 0,
          medium: 0,
          low: 1,
          total_findings: 1,
          console_errors: 0,
          request_count: 2,
        },
      },
    })

    expect(result.title).toBe("Passive AppSec → Example App")
    expect(result.metadata.findings).toBe(1)
    expect(result.output).toContain("missing-security-header")
  })

  test("truncates output to 65536 bytes by default when max_bytes is omitted", () => {
    const largeEvidence = Array.from({ length: 5000 }, (_, i) => `evidence-item-${i}`)
    const result = formatPassiveAppSecResult({
      title: "Example App",
      report: {
        findings: [
          {
            id: "missing-security-header",
            severity: "low",
            title: "Missing security headers",
            evidence: largeEvidence,
          },
        ],
        summary: { high: 0, medium: 0, low: 1, total_findings: 1, console_errors: 0, request_count: 0 },
      },
    })

    // +100 allows for the truncation suffix appended after the byte slice
    expect(Buffer.byteLength(result.output)).toBeLessThanOrEqual(65536 + 100)
    expect(result.output).toContain("truncated")
  })

  test("buildPassiveAppSecResult scopes analysis to the current run and clears buffers", async () => {
    const page = {
      url: () => "https://app.example.test/dashboard",
      evaluate: async () => ({
        storage: { local: {}, session: {} },
        forms: [],
        scripts: { inline_count: 0, external: [] },
      }),
    }
    const context = {
      cookies: async () => [],
    }
    const session = {
      network: [
        {
          method: "GET",
          url: "http://cdn.example.test/stale.js",
          status: 200,
          content_type: "application/javascript",
        },
        {
          method: "GET",
          url: "http://cdn.example.test/current.js",
          status: 200,
          content_type: "application/javascript",
        },
      ],
      console: [
        { level: "error", text: "stale warning" },
        { level: "error", text: "current warning" },
      ],
    }

    const first = await buildPassiveAppSecResult({
      title: "Example App",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      page,
      context,
      session,
      startIndexes: {
        network: 1,
        console: 1,
      },
      clear: true,
    })

    expect(first.metadata).toMatchObject({
      findings: 1,
      console_errors: 1,
      request_count: 1,
    })
    expect(first.output).toContain("http://cdn.example.test/current.js")
    expect(first.output).not.toContain("stale.js")
    expect(session.console).toHaveLength(0)
    expect(session.network).toHaveLength(0)
  })
})
