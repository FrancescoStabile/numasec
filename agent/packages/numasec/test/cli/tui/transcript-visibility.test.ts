import { describe, expect, test } from "bun:test"
import {
  showDetailedToolView,
  TRANSCRIPT_VISIBILITY_DEFAULTS,
  TRANSCRIPT_VISIBILITY_KEYS,
} from "../../../src/cli/cmd/tui/transcript-visibility"

describe("transcript visibility", () => {
  test("uses versioned keys to reset broken persisted defaults", () => {
    expect(TRANSCRIPT_VISIBILITY_KEYS.thinking).toBe("thinking_visibility_v2")
    expect(TRANSCRIPT_VISIBILITY_KEYS.tool_details).toBe("tool_details_visibility_v2")
    expect(TRANSCRIPT_VISIBILITY_KEYS.assistant_metadata).toBe("assistant_metadata_visibility_v2")
  })

  test("restores transparent defaults", () => {
    expect(TRANSCRIPT_VISIBILITY_DEFAULTS.thinking).toBe(true)
    expect(TRANSCRIPT_VISIBILITY_DEFAULTS.tool_details).toBe(true)
    expect(TRANSCRIPT_VISIBILITY_DEFAULTS.assistant_metadata).toBe(true)
  })

  test("keeps running and failed tools visible even when details are hidden", () => {
    expect(showDetailedToolView("pending", false)).toBe(true)
    expect(showDetailedToolView("running", false)).toBe(true)
    expect(showDetailedToolView("error", false)).toBe(true)
  })

  test("collapses only completed tools when details are hidden", () => {
    expect(showDetailedToolView("completed", false)).toBe(false)
    expect(showDetailedToolView("completed", true)).toBe(true)
  })
})
