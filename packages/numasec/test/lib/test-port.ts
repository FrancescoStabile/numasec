const key = Symbol.for("numasec.test.port.counter")

type State = { next: number }

function state(): State {
  const bag = globalThis as typeof globalThis & { [key]?: State }
  if (bag[key]) return bag[key]

  const worker = Number(process.env.BUN_WORKER_ID ?? process.env.JEST_WORKER_ID ?? "0")
  const base = 30000 + ((process.pid + worker * 997) % 20000)
  const value = { next: base }
  bag[key] = value
  return value
}

export function nextTestPort() {
  const ports = state()
  const port = ports.next
  ports.next += 1
  if (ports.next > 65000) ports.next = 30000
  return port
}

export function serveOnTestPort(options: Omit<Parameters<typeof Bun.serve>[0], "port">) {
  let lastError: unknown
  for (let attempt = 0; attempt < 32; attempt++) {
    try {
      return Bun.serve({ ...(options as any), port: nextTestPort() } as any)
    } catch (error) {
      const code = typeof error === "object" && error && "code" in error ? (error as { code?: string }).code : undefined
      if (code !== "EADDRINUSE") throw error
      lastError = error
    }
  }
  throw lastError ?? new Error("failed to bind test server")
}
