import { describe, expect, test } from "bun:test"
import { httpRequestTls, insecureTlsEnabled } from "../../src/security/http-client"

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

describe("security http client TLS policy", () => {
  test("keeps TLS verification enabled by default", () => {
    withEnv({ NUMASEC_SECURITY_INSECURE_TLS: undefined }, () => {
      expect(insecureTlsEnabled()).toBe(false)
      expect(httpRequestTls()).toBeUndefined()
    })
  })

  test("enables insecure TLS only when explicitly requested", () => {
    withEnv({ NUMASEC_SECURITY_INSECURE_TLS: "1" }, () => {
      expect(insecureTlsEnabled()).toBe(true)
      expect(httpRequestTls()).toEqual({ rejectUnauthorized: false })
      expect(insecureTlsEnabled({ insecureTls: false })).toBe(false)
      expect(httpRequestTls({ insecureTls: false })).toBeUndefined()
      expect(insecureTlsEnabled({ insecureTls: true })).toBe(true)
      expect(httpRequestTls({ insecureTls: true })).toEqual({ rejectUnauthorized: false })
    })
  })
})
