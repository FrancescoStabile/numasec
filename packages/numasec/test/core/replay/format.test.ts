import { describe, expect, test } from "bun:test"
import { buildReplay, parseReplay, verifyBody, FORMAT } from "@/core/replay/format"
import { redactValue } from "@/core/replay/redact"
import type { Session } from "@/session"
import type { MessageV2 } from "@/session/message-v2"

function mkSession(): Session.Info {
  return {
    id: "ses_test01" as Session.Info["id"],
    slug: "test",
    projectID: "prj_x" as Session.Info["projectID"],
    directory: "/tmp",
    title: "test session",
    version: "1.1.5",
    time: { created: 1_700_000_000_000, updated: 1_700_000_005_000 },
  } as unknown as Session.Info
}

function mkMessages(): MessageV2.WithParts[] {
  return [
    {
      info: {
        id: "msg_user01",
        sessionID: "ses_test01",
        role: "user",
        time: { created: 1_700_000_000_000 },
        agent: "pentest",
        model: { providerID: "anthropic", modelID: "claude-opus-4.7" },
      } as unknown as MessageV2.User,
      parts: [
        { id: "prt_u1", messageID: "msg_user01", sessionID: "ses_test01", type: "text", text: "scan example.com" } as unknown as MessageV2.Part,
      ],
    },
    {
      info: {
        id: "msg_asst01",
        sessionID: "ses_test01",
        role: "assistant",
        parentID: "msg_user01",
        modelID: "claude-opus-4.7",
        providerID: "anthropic",
        agent: "pentest",
        mode: "build",
        path: { cwd: "/tmp", root: "/tmp" },
        cost: 0,
        tokens: { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } },
        time: { created: 1_700_000_001_000, completed: 1_700_000_004_000 },
      } as unknown as MessageV2.Assistant,
      parts: [
        { id: "prt_a1", messageID: "msg_asst01", sessionID: "ses_test01", type: "text", text: "running probe" } as unknown as MessageV2.Part,
        {
          id: "prt_a2",
          messageID: "msg_asst01",
          sessionID: "ses_test01",
          type: "tool",
          tool: "bash",
          callID: "tc_1",
          state: {
            status: "completed",
            input: {
              command:
                "curl -H 'Authorization: Bearer eyJabcdefgh.ijklmnopqrst.uvwxyz12345' https://example.com",
            },
            output: "200 OK",
            time: { start: 1_700_000_002_000, end: 1_700_000_003_000 },
            metadata: {},
            title: "curl",
          },
        } as unknown as MessageV2.Part,
      ],
    },
  ]
}

describe("core/replay format", () => {
  test("round-trip: build, parse, verify", () => {
    const built = buildReplay({ info: mkSession(), messages: mkMessages(), redact: "off" })
    const text = built.lines.join("\n") + "\n"
    const parsed = parseReplay(text)
    expect(parsed.header.format).toBe(FORMAT)
    expect(parsed.header.kind).toBe("pentest")
    expect(parsed.header.model?.id).toBe("claude-opus-4.7")
    expect(parsed.events.length).toBe(4)
    expect(parsed.events[0].event).toBe("message")
    expect(parsed.events[2].event).toBe("tool_call")
    expect(parsed.events[3].event).toBe("tool_result")
    expect(parsed.trailer.events).toBe(4)
    const v = verifyBody(text)
    expect(v.ok).toBe(true)
  })

  test("redact: strips JWT-shaped tokens in tool input", () => {
    const built = buildReplay({ info: mkSession(), messages: mkMessages(), redact: "on" })
    const text = built.lines.join("\n")
    expect(text).not.toContain("eyJabcdefgh.ijklmnopqrst.uvwxyz12345")
    expect(text).toContain("[redacted:jwt]")
    expect(built.header.redacted).toBe(true)
  })

  test("verifyBody detects tampering", () => {
    const built = buildReplay({ info: mkSession(), messages: mkMessages(), redact: "off" })
    const tampered =
      built.lines.map((l, i) => (i === 1 ? l.replace("scan example.com", "scan evil.com") : l)).join("\n") + "\n"
    expect(verifyBody(tampered).ok).toBe(false)
  })
})

describe("core/replay redact helpers", () => {
  test("redacts header keys by name", () => {
    const out = redactValue({ headers: { Authorization: "Bearer abc", "X-Other": "fine" } }, "on") as {
      headers: Record<string, string>
    }
    expect(out.headers.Authorization).toBe("[redacted:header:Authorization]")
    expect(out.headers["X-Other"]).toBe("fine")
  })
  test("redacts secret-named keys", () => {
    const out = redactValue({ password: "hunter2", note: "ok" }, "on") as Record<string, string>
    expect(out.password).toBe("[redacted:secret:password]")
    expect(out.note).toBe("ok")
  })
  test("off mode is identity", () => {
    const v = { headers: { Authorization: "x" }, password: "p" }
    expect(redactValue(v, "off")).toEqual(v)
  })
})
