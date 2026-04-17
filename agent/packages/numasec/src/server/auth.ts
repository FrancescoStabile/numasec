export interface ServerBasicAuth {
  username: string
  password: string
}

export interface ServerAuthPolicy {
  auth?: ServerBasicAuth
  external: boolean
  explicitInsecureNoAuth: boolean
}

function truthy(value?: string) {
  const next = value?.toLowerCase()
  return next === "true" || next === "1"
}

export function isLoopbackHost(hostname: string) {
  return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "::1"
}

export function configuredServerAuth(input: {
  password?: string
  username?: string
} = {}): ServerBasicAuth | undefined {
  const password = input.password ?? process.env["NUMASEC_SERVER_PASSWORD"]
  if (!password) return
  return {
    username: input.username ?? process.env["NUMASEC_SERVER_USERNAME"] ?? "numasec",
    password,
  }
}

export function serverAuthorizationHeader(input: {
  password?: string
  username?: string
} = {}) {
  const auth = configuredServerAuth(input)
  if (!auth) return
  return `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString("base64")}`
}

export function resolveServerAuthPolicy(hostname: string): ServerAuthPolicy {
  const auth = configuredServerAuth()
  const external = !isLoopbackHost(hostname)
  if (!external) {
    return {
      auth,
      external,
      explicitInsecureNoAuth: false,
    }
  }
  if (auth) {
    return {
      auth,
      external,
      explicitInsecureNoAuth: false,
    }
  }
  if (truthy(process.env["NUMASEC_SERVER_INSECURE_NO_AUTH"])) {
    return {
      auth: undefined,
      external,
      explicitInsecureNoAuth: true,
    }
  }
  throw new Error(
    "NUMASEC_SERVER_PASSWORD is required when listening on a non-loopback interface. Set NUMASEC_SERVER_PASSWORD or explicitly opt out with NUMASEC_SERVER_INSECURE_NO_AUTH=1.",
  )
}
