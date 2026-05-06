import { describe, expect, test } from "bun:test"
import { analyzePassiveAppSec } from "../../src/browser/passive"

describe("browser passive appsec analysis", () => {
  test("flags passive web findings from a normalized snapshot", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-type": "text/html",
        "x-frame-options": "DENY",
      },
      cookies: [
        {
          name: "session",
          value: "abc123",
          domain: "app.example.test",
          path: "/",
          secure: false,
          httpOnly: false,
          sameSite: "Lax",
        },
      ],
      storage: {
        local: {
          authToken: "sk_live_1234567890abcdef",
        },
        session: {},
      },
      forms: [
        {
          action: "https://app.example.test/transfer",
          method: "post",
          inputs: [{ name: "amount", type: "text" }],
        },
      ],
      requests: [
        {
          method: "GET",
          url: "http://cdn.example.test/app.js",
          status: 200,
          content_type: "application/javascript",
        },
      ],
      console: [{ level: "error", text: "Failed to fetch /api/me" }],
      scripts: {
        inline_count: 2,
        external: ["http://cdn.example.test/app.js"],
      },
    })

    expect(report.findings.some((item) => item.id === "storage-secret")).toBe(true)
    expect(report.findings.some((item) => item.id === "weak-cookie")).toBe(true)
    expect(report.findings.some((item) => item.id === "missing-security-header")).toBe(true)
    expect(report.findings.some((item) => item.id === "csrf-form")).toBe(true)
    expect(report.findings.some((item) => item.id === "mixed-content")).toBe(true)
    expect(report.summary.console_errors).toBe(1)
    expect(report.summary.total_findings).toBeGreaterThanOrEqual(5)
  })

  test("flags a POST form when no input name matches a CSRF field", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      forms: [
        {
          action: "https://app.example.test/update",
          method: "post",
          inputs: [{ name: "note", type: "text" }],
        },
      ],
    })

    expect(report.findings.some((item) => item.id === "csrf-form")).toBe(true)
  })

  test("deduplicates mixed-content evidence across requests and scripts", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      requests: [
        {
          method: "GET",
          url: "http://cdn.example.test/app.js",
          status: 200,
          content_type: "application/javascript",
        },
      ],
      scripts: {
        external: ["http://cdn.example.test/app.js"],
      },
    })

    expect(report.findings.find((item) => item.id === "mixed-content")?.evidence).toEqual([
      "request: http://cdn.example.test/app.js",
    ])
  })

  test("flags insecure form actions on HTTPS pages as mixed content", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      forms: [
        {
          action: "http://app.example.test/transfer",
          method: "post",
          inputs: [{ name: "amount", type: "text" }],
        },
      ],
    })

    expect(report.findings.find((item) => item.id === "mixed-content")?.evidence).toEqual([
      "form: http://app.example.test/transfer",
    ])
  })

  test("still flags a POST form with a non-csrf *_token field name", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      forms: [
        {
          action: "https://app.example.test/checkout",
          method: "post",
          inputs: [{ name: "discount_token", type: "hidden" }],
        },
      ],
    })

    expect(report.findings.some((item) => item.id === "csrf-form")).toBe(true)
  })

  test("handles security headers case-insensitively", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin",
      },
      cookies: [
        {
          name: "session",
          value: "abc123",
          domain: "app.example.test",
          path: "/",
          secure: true,
          httpOnly: true,
          sameSite: "Strict",
        },
      ],
      storage: {
        local: {},
        session: {},
      },
      forms: [],
      requests: [],
      console: [],
      scripts: {
        inline_count: 0,
        external: [],
      },
    })

    expect(report.findings).toHaveLength(0)
    expect(report.summary.total_findings).toBe(0)
  })

  test("does not flag SameSite=Lax as a weakness on its own", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      cookies: [
        {
          name: "session",
          value: "abc123",
          domain: "app.example.test",
          path: "/",
          secure: true,
          httpOnly: true,
          sameSite: "Lax",
        },
      ],
      storage: {
        local: {},
        session: {},
      },
      forms: [],
      requests: [],
      console: [],
      scripts: {
        inline_count: 0,
        external: [],
      },
    })

    expect(report.findings.some((item) => item.id === "weak-cookie")).toBe(false)
  })

  test("flags SameSite=None without Secure as a weak cookie attribute", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      cookies: [
        {
          name: "session",
          value: "abc123",
          domain: "app.example.test",
          path: "/",
          secure: false,
          httpOnly: true,
          sameSite: "None",
        },
      ],
    })

    expect(report.findings.some((item) => item.id === "weak-cookie")).toBe(true)
    expect(report.findings.find((item) => item.id === "weak-cookie")?.evidence).toEqual(
      expect.arrayContaining(["session: SameSite=None without Secure"]),
    )
  })

  test("does not flag SameSite=None with Secure as a weakness for SameSite alone", () => {
    // Cookie has SameSite=None + Secure (valid), but is missing HttpOnly — so
    // a weak-cookie finding exists for the HttpOnly gap, not for the SameSite pair.
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      cookies: [
        {
          name: "session",
          value: "abc123",
          domain: "app.example.test",
          path: "/",
          secure: true,
          httpOnly: false,
          sameSite: "None",
        },
      ],
    })

    expect(report.findings.some((item) => item.id === "weak-cookie")).toBe(true)
    const evidence = report.findings.find((item) => item.id === "weak-cookie")?.evidence ?? []
    expect(evidence).toEqual(expect.arrayContaining(["session: missing HttpOnly"]))
    expect(evidence).not.toEqual(expect.arrayContaining(["session: SameSite=None without Secure"]))
  })

  test("preserves structured evidence for secret storage findings", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      storage: {
        local: {
          authToken: "sk_live_1234567890abcdef",
        },
        session: {},
      },
    })

    const finding = report.findings.find((item) => item.id === "storage-secret")

    expect(finding).toBeDefined()
    expect(finding?.evidence).toEqual(
      expect.arrayContaining(["local.authToken", "local.authToken value matches token pattern"]),
    )
  })

  test("only flags genuinely secret-like storage keys", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      storage: {
        local: {
          authToken: "abc123",
          tokenCount: "12",
          sessionDuration: "3600",
          passwordStrength: "strong",
        },
        session: {},
      },
    })

    expect(report.findings.some((item) => item.id === "storage-secret")).toBe(true)
    expect(report.findings.find((item) => item.id === "storage-secret")?.evidence).toEqual(
      expect.arrayContaining(["local.authToken"]),
    )
    expect(report.findings.find((item) => item.id === "storage-secret")?.evidence).not.toEqual(
      expect.arrayContaining([
        "local.tokenCount",
        "local.sessionDuration",
        "local.passwordStrength",
      ]),
    )
  })

  test("does not flag benign storage keys without secret values", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      storage: {
        local: {
          authorName: "Alice",
        },
        session: {},
      },
    })

    expect(report.findings.some((item) => item.id === "storage-secret")).toBe(false)
  })

  test("flags aws-style access keys as secrets", () => {
    const report = analyzePassiveAppSec({
      url: "https://app.example.test/dashboard",
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
      storage: {
        local: {
          serviceKey: "AKIA1234567890ABCDEF",
        },
        session: {},
      },
    })

    expect(report.findings.some((item) => item.id === "storage-secret")).toBe(true)
    expect(report.findings.find((item) => item.id === "storage-secret")?.evidence).toEqual(
      expect.arrayContaining(["local.serviceKey value matches token pattern"]),
    )
  })
})
