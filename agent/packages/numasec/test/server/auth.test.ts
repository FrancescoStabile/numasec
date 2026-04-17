import { describe, expect, test } from "bun:test"
import {
  configuredServerAuth,
  resolveServerAuthPolicy,
  serverAuthorizationHeader,
} from "../../src/server/auth"

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

describe("server auth policy", () => {
  test("allows loopback binds without auth by default", () => {
    withEnv(
      {
        NUMASEC_SERVER_PASSWORD: undefined,
        NUMASEC_SERVER_USERNAME: undefined,
        NUMASEC_SERVER_INSECURE_NO_AUTH: undefined,
      },
      () => {
        const policy = resolveServerAuthPolicy("127.0.0.1")
        expect(policy.external).toBe(false)
        expect(policy.auth).toBeUndefined()
        expect(policy.explicitInsecureNoAuth).toBe(false)
      },
    )
  })

  test("requires auth on non-loopback binds by default", () => {
    withEnv(
      {
        NUMASEC_SERVER_PASSWORD: undefined,
        NUMASEC_SERVER_USERNAME: undefined,
        NUMASEC_SERVER_INSECURE_NO_AUTH: undefined,
      },
      () => {
        expect(() => resolveServerAuthPolicy("0.0.0.0")).toThrow("NUMASEC_SERVER_PASSWORD")
      },
    )
  })

  test("uses configured credentials when provided", () => {
    withEnv(
      {
        NUMASEC_SERVER_PASSWORD: "secret-password",
        NUMASEC_SERVER_USERNAME: "operator",
        NUMASEC_SERVER_INSECURE_NO_AUTH: undefined,
      },
      () => {
        const auth = configuredServerAuth()
        expect(auth).toEqual({
          username: "operator",
          password: "secret-password",
        })
        const policy = resolveServerAuthPolicy("0.0.0.0")
        expect(policy.auth).toEqual(auth)
        expect(serverAuthorizationHeader()).toMatch(/^Basic /)
      },
    )
  })

  test("allows explicit insecure opt-out for external binds", () => {
    withEnv(
      {
        NUMASEC_SERVER_PASSWORD: undefined,
        NUMASEC_SERVER_USERNAME: undefined,
        NUMASEC_SERVER_INSECURE_NO_AUTH: "1",
      },
      () => {
        const policy = resolveServerAuthPolicy("0.0.0.0")
        expect(policy.external).toBe(true)
        expect(policy.auth).toBeUndefined()
        expect(policy.explicitInsecureNoAuth).toBe(true)
      },
    )
  })
})
