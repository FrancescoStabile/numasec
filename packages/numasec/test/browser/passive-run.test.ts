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
  id = ""
  placeholder = ""
  autocomplete = ""
  required = false

  constructor(name: string, type: string, value: string) {
    this.name = name
    this.type = type
    this.value = value
  }

  getAttribute(name: string) {
    return name === "aria-label" ? null : null
  }
}

class FakeHTMLTextAreaElement {
  name: string
  value: string
  id = ""
  placeholder = ""
  required = false

  constructor(name: string, value: string) {
    this.name = name
    this.value = value
  }

  getAttribute(name: string) {
    return name === "aria-label" ? null : null
  }
}

class FakeHTMLSelectElement {
  name: string
  type: string
  id = ""
  required = false

  constructor(name: string) {
    this.name = name
    this.type = "select-one"
  }

  getAttribute(name: string) {
    return name === "aria-label" ? null : null
  }
}

class FakeHTMLButtonElement {
  id: string
  type: string
  textContent: string
  required: boolean

  constructor(id: string, type: string, textContent: string) {
    this.id = id
    this.type = type
    this.textContent = textContent
    this.required = false
  }

  getAttribute(name: string) {
    if (name === "aria-label") return "submit login"
    return null
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
      if (selector !== "input,textarea,select,button") return []
      return [
        new FakeHTMLInputElement("amount", "text", "100"),
        new FakeHTMLTextAreaElement("memo", "rent"),
        new FakeHTMLSelectElement("priority"),
      ]
    },
  }

  const standaloneInput = new FakeHTMLInputElement("search", "search", "query")
  Object.assign(standaloneInput, {
    id: "search-box",
    placeholder: "Search catalog",
    autocomplete: "off",
    required: false,
    getAttribute(name: string) {
      if (name === "aria-label") return "site search"
      return null
    },
  })

  const standaloneButton = new FakeHTMLButtonElement("login-submit", "submit", "Log In")

  const script = {
    getAttribute(name: string) {
      return name === "src" ? null : null
    },
  }

  return {
    HTMLInputElement: FakeHTMLInputElement,
    HTMLTextAreaElement: FakeHTMLTextAreaElement,
    HTMLSelectElement: FakeHTMLSelectElement,
    HTMLButtonElement: FakeHTMLButtonElement,
    document: {
      location: { href: "https://app.example.test/dashboard" },
      querySelectorAll(selector: string) {
        if (selector === "form") return [form]
        if (selector === "input,textarea,select,button") return [standaloneInput, standaloneButton]
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
      cookies: [{ name: "session", value: "cookie", domain: "app.example.test", path: "/", secure: true, httpOnly: true, sameSite: "Strict" }],
      storage: {
        local: { authToken: "abc123" },
        session: { draft: "1" },
      },
      forms: [
        {
          name: "transfer",
          action: "https://app.example.test/transfer",
          method: "post",
          source: "form",
          inputs: [
            { name: "amount", type: "text", required: false },
            { name: "memo", required: false },
            { name: "priority", type: "select-one", required: false },
          ],
        },
        {
          name: "search",
          action: "https://app.example.test/dashboard",
          method: "get",
          source: "standalone_control",
          inputs: [
            {
              name: "search",
              type: "search",
              id: "search-box",
              placeholder: "Search catalog",
              aria_label: "site search",
              autocomplete: "off",
              required: false,
            },
          ],
        },
        {
          name: "Log In",
          action: "https://app.example.test/dashboard",
          method: "get",
          source: "standalone_control",
          inputs: [
            {
              name: "Log In",
              type: "submit",
              id: "login-submit",
              aria_label: "submit login",
              required: false,
            },
          ],
        },
      ],
      requests: [{ method: "GET", url: "https://app.example.test/api/me", status: 200, content_type: "application/json" }],
      console: [{ level: "error", text: "boom" }],
      scripts: {
        inline_count: 1,
        external: [],
      },
    })
    expect(input.forms?.[0]?.inputs).toEqual([
      { name: "amount", type: "text", id: undefined, placeholder: undefined, aria_label: undefined, autocomplete: undefined, required: false },
      { name: "memo", type: undefined, id: undefined, placeholder: undefined, aria_label: undefined, autocomplete: undefined, required: false },
      { name: "priority", type: "select-one", id: undefined, placeholder: undefined, aria_label: undefined, autocomplete: undefined, required: false },
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
      passive: {
        url: "https://app.example.test/login",
        forms: [
          {
            name: "login",
            action: "https://app.example.test/rest/user/login",
            method: "post",
            source: "form",
            inputs: [
              { name: "email", type: "email", placeholder: "Email" },
              { name: "password", type: "password", placeholder: "Password" },
            ],
          },
        ],
      },
    })

    expect(result.title).toBe("Passive AppSec → Example App")
    expect(result.metadata.findings).toBe(1)
    expect(result.output).toContain("missing-security-header")
    expect(result.output).toContain("\"forms\"")
    expect(result.output).toContain("\"name\": \"email\"")
    expect(result.output).toContain("\"placeholder\": \"Password\"")
    expect(result.output).not.toContain("supersecret")
    expect((result.metadata as any).forms[0].inputs[0].value).toBeUndefined()
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
