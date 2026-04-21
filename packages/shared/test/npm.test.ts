import { describe, expect, test } from "bun:test"
import { Npm } from "@numasec/shared/npm"

const win = process.platform === "win32"

describe("Npm.sanitize", () => {
  test("keeps normal scoped package specs unchanged", () => {
    expect(Npm.sanitize("@numasec/acme")).toBe("@numasec/acme")
    expect(Npm.sanitize("@numasec/acme@1.0.0")).toBe("@numasec/acme@1.0.0")
    expect(Npm.sanitize("prettier")).toBe("prettier")
  })

  test("handles git https specs", () => {
    const spec = "acme@git+https://github.com/numasec/acme.git"
    const expected = win ? "acme@git+https_//github.com/numasec/acme.git" : spec
    expect(Npm.sanitize(spec)).toBe(expected)
  })
})
