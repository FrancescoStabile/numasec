import { describe, expect, test } from "bun:test"
import { shouldEnableMouseMovement } from "../../../src/cli/cmd/tui/util/mouse"

describe("shouldEnableMouseMovement", () => {
  test("disables mouse movement on WSL by kernel release", () => {
    expect(
      shouldEnableMouseMovement({
        platform: "linux",
        release: "5.15.167.4-microsoft-standard-WSL2",
        env: {},
      }),
    ).toBe(false)
  })

  test("disables mouse movement on WSL by lowercase kernel release", () => {
    expect(
      shouldEnableMouseMovement({
        platform: "linux",
        release: "5.15.167.4-microsoft-standard-wsl2",
        env: {},
      }),
    ).toBe(false)
  })

  test("disables mouse movement on WSL by environment", () => {
    expect(
      shouldEnableMouseMovement({
        platform: "linux",
        release: "6.6.87.2-microsoft-standard",
        env: { WSL_DISTRO_NAME: "Kali-Linux" },
      }),
    ).toBe(false)
  })

  test("keeps mouse movement enabled outside WSL", () => {
    expect(
      shouldEnableMouseMovement({
        platform: "linux",
        release: "6.8.0-60-generic",
        env: {},
      }),
    ).toBe(true)
  })
})
