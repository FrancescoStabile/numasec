import { describe, expect, test } from "bun:test"
import { securityChildEnv } from "../../src/security/child-env"

function withEnv(values: Record<string, string | undefined>, fn: () => void) {
  const prev = new Map<string, string | undefined>()
  for (const key of Object.keys(values)) {
    prev.set(key, process.env[key])
    const value = values[key]
    if (value === undefined) {
      delete process.env[key]
      continue
    }
    process.env[key] = value
  }
  try {
    fn()
  } finally {
    for (const [key, value] of prev) {
      if (value === undefined) {
        delete process.env[key]
        continue
      }
      process.env[key] = value
    }
  }
}

describe("security child env", () => {
  test("strips unrelated host secrets while keeping runtime basics", () => {
    withEnv(
      {
        PATH: "/usr/bin",
        HOME: "/tmp/home",
        HTTP_PROXY: "http://proxy.local",
        OPENAI_API_KEY: "secret",
      },
      () => {
        const env = securityChildEnv()
        expect(env.PATH).toBe("/usr/bin")
        expect(env.HOME).toBe("/tmp/home")
        expect(env.HTTP_PROXY).toBe("http://proxy.local")
        expect(env.OPENAI_API_KEY).toBeUndefined()
        expect(env.TERM).toBe("dumb")
      },
    )
  })

  test("allows explicit env overrides through the security allowlist input", () => {
    withEnv({ PATH: "/usr/bin", TERM: "xterm-256color" }, () => {
      const env = securityChildEnv({
        CUSTOM_TOKEN: "present",
        TERM: "vt100",
      })
      expect(env.PATH).toBe("/usr/bin")
      expect(env.CUSTOM_TOKEN).toBe("present")
      expect(env.TERM).toBe("vt100")
    })
  })
})
