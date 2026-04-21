import { describe, expect, test } from "bun:test"
import { SessionPrompt } from "../../src/session/prompt"
import { SystemPrompt } from "../../src/session/system"

function model(id: string) {
  return { api: { id } } as unknown as Parameters<typeof SessionPrompt.needsPlanningReminder>[0]
}

describe("plan injection", () => {
  test("Claude models are classified as anthropic and skip injection", () => {
    const m = model("claude-3-5-sonnet-20241022")
    expect(SystemPrompt.kind(m)).toBe("anthropic")
    expect(SessionPrompt.needsPlanningReminder(m)).toBe(false)
  })

  test("GPT models need the planning reminder", () => {
    const m = model("gpt-4o")
    expect(SystemPrompt.kind(m)).toBe("openai")
    expect(SessionPrompt.needsPlanningReminder(m)).toBe(true)
  })

  test("Gemini models need the planning reminder", () => {
    const m = model("gemini-2.0-flash")
    expect(SystemPrompt.kind(m)).toBe("google")
    expect(SessionPrompt.needsPlanningReminder(m)).toBe(true)
  })

  test("Other models need the planning reminder", () => {
    const m = model("trinity-core")
    expect(SystemPrompt.kind(m)).toBe("other")
    expect(SessionPrompt.needsPlanningReminder(m)).toBe(true)
  })

  test("planning reminder mentions TodoWrite and is within the token budget", () => {
    const text = SessionPrompt.PLANNING_REMINDER
    expect(text).toContain("TodoWrite")
    expect(text).toContain("in_progress")
    expect(text).toContain("done")
    expect(text.length).toBeLessThanOrEqual(800)
  })

  test("anthropic system prompt already covers TodoWrite (no duplicate injection needed)", () => {
    const [anthropic] = SystemPrompt.provider({
      api: { id: "claude-3-5-sonnet-20241022" },
    } as unknown as Parameters<typeof SystemPrompt.provider>[0])
    expect(anthropic).toContain("TodoWrite")
  })
})
