import { createHash } from "crypto"

type User = {
  id: number
  email: string
  password: string
  role: string
  password_hash: string
}

function hash(value: string) {
  return createHash("md5").update(value).digest("hex")
}

function encode(value: unknown) {
  return Buffer.from(JSON.stringify(value)).toString("base64url")
}

function token(user: User) {
  const header = encode({
    alg: "none",
    typ: "JWT",
  })
  const payload = encode({
    status: "success",
    data: {
      id: user.id,
      email: user.email,
      password: user.password_hash,
      role: user.role,
    },
    iat: Math.floor(Date.now() / 1000),
  })
  return `${header}.${payload}.`
}

function parseToken(value: string) {
  const parts = value.split(".")
  const body = parts[1] ?? ""
  if (!body) return
  try {
    const text = Buffer.from(body, "base64url").toString("utf8")
    const payload = JSON.parse(text) as {
      data?: {
        id?: number
        email?: string
        role?: string
      }
    }
    const data = payload.data
    if (!data) return
    return data
  } catch {
    return
  }
}

function readJson(req: Request) {
  return req
    .text()
    .then((text) => {
      if (!text) return {} as Record<string, unknown>
      return JSON.parse(text) as Record<string, unknown>
    })
    .catch(() => ({}) as Record<string, unknown>)
}

function readBearer(req: Request) {
  const value = req.headers.get("authorization") ?? ""
  if (!value.toLowerCase().startsWith("bearer ")) return ""
  return value.slice(7).trim()
}

function readCookie(req: Request, key: string) {
  const value = req.headers.get("cookie") ?? ""
  const parts = value.split(";").map((item) => item.trim())
  for (const item of parts) {
    if (!item.startsWith(`${key}=`)) continue
    return item.slice(key.length + 1)
  }
  return ""
}

function sqliBody() {
  return `<!DOCTYPE html>
<html><body><pre>SequelizeDatabaseError: SQLITE_ERROR: near "UNION": syntax error
    at Query.run (/workspace/node_modules/sequelize/lib/dialects/sqlite/query.js:185:27)
    at Database.<anonymous> (/workspace/node_modules/sequelize/lib/dialects/sqlite/query.js:183:50)
</pre></body></html>`
}

function loginResponse(user: User) {
  const jwt = token(user)
  return Response.json(
    {
      status: "success",
      authentication: {
        token: jwt,
      },
      data: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    },
    {
      headers: {
        "set-cookie": `session=auth-${user.id}; Path=/; HttpOnly`,
        "access-control-allow-origin": "*",
      },
    },
  )
}

export interface SecurityTargetFixture {
  readonly server: ReturnType<typeof Bun.serve>
  readonly baseUrl: string
  readonly admin: User
  readonly stop: () => void
  readonly tokenFor: (id: number) => string
  readonly cookieFor: (id: number) => string
}

export function startSecurityTarget(): SecurityTargetFixture {
  const users = new Map<number, User>()
  let next = 2
  const admin = {
    id: 1,
    email: "admin@fixture.local",
    password: "admin123!",
    role: "admin",
    password_hash: hash("admin123!"),
  }
  users.set(admin.id, admin)

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url)
      const path = url.pathname
      const origin = req.headers.get("origin") ?? ""

      if (path === "/") {
        return new Response("<html><body>fixture</body></html>", {
          headers: {
            "content-type": "text/html",
          },
        })
      }

      if (path === "/metrics") {
        return new Response(
          [
            "# HELP process_cpu_user_seconds_total Total user CPU time spent in seconds.",
            "# TYPE process_cpu_user_seconds_total counter",
            "process_cpu_user_seconds_total 1.23",
            "nodejs_eventloop_lag_seconds 0.01",
          ].join("\n"),
          {
            headers: {
              "content-type": "text/plain; version=0.0.4",
            },
          },
        )
      }

      if (path === "/api/Users" && req.method === "POST") {
        const body = await readJson(req)
        const email = String(body.email ?? "")
        const password = String(body.password ?? "")
        const role = String(body.role ?? "customer")
        const user = {
          id: next++,
          email,
          password,
          role,
          password_hash: hash(password),
        }
        users.set(user.id, user)
        return Response.json(
          {
            status: "success",
            data: {
              id: user.id,
              email: user.email,
              role: user.role,
              profileImage: user.role === "admin" ? "/assets/public/images/uploads/defaultAdmin.png" : "/assets/public/images/uploads/default.svg",
            },
          },
          {
            status: 201,
          },
        )
      }

      if (path === "/rest/user/login" && req.method === "POST") {
        const body = await readJson(req)
        const email = String(body.email ?? "")
        const password = String(body.password ?? "")
        if (email.includes("'--")) {
          const candidate = email.split("'--")[0] ?? ""
          const user = Array.from(users.values()).find((item) => item.email === candidate)
          if (user) return loginResponse(user)
        }
        if (email.includes("' UNION SELECT") || email.includes("')) OR (") || email.includes("' OR '1'='1")) {
          return new Response(sqliBody(), {
            status: 500,
            headers: {
              "content-type": "text/html",
              "access-control-allow-origin": "*",
            },
          })
        }
        const user = Array.from(users.values()).find((item) => item.email === email && item.password === password)
        if (!user) {
          return Response.json(
            {
              status: "error",
              error: "Invalid email or password.",
            },
            { status: 401 },
          )
        }
        return loginResponse(user)
      }

      if (path === "/api/private/profile") {
        const cookie = readCookie(req, "session")
        if (!cookie.startsWith("auth-")) {
          return Response.json(
            {
              status: "error",
            },
            { status: 401 },
          )
        }
        const id = Number(cookie.slice(5))
        const user = users.get(id)
        if (!user) {
          return Response.json(
            {
              status: "error",
            },
            { status: 401 },
          )
        }
        return Response.json(
          {
            id: user.id,
            email: user.email,
            role: user.role,
            secret: `private-${user.id}`,
          },
          {
            headers: {
              "access-control-allow-origin": origin || "https://evil.example",
              "access-control-allow-credentials": "true",
            },
          },
        )
      }

      if (path === "/api/profile") {
        const jwt = readBearer(req)
        const data = parseToken(jwt)
        if (!data) {
          return Response.json(
            {
              status: "error",
            },
            { status: 401 },
          )
        }
        const id = Number(url.searchParams.get("id") ?? data.id ?? 0)
        const user = users.get(id)
        if (!user) {
          return Response.json(
            {
              status: "error",
            },
            { status: 404 },
          )
        }
        return Response.json({
          id: user.id,
          email: user.email,
          role: user.role,
        })
      }

      if (path.startsWith("/api/Users/")) {
        const jwt = readBearer(req)
        const data = parseToken(jwt)
        if (!data) {
          return Response.json(
            {
              status: "error",
            },
            { status: 401 },
          )
        }
        const id = Number(path.split("/").at(-1) ?? "0")
        const user = users.get(id)
        if (!user) {
          return Response.json(
            {
              status: "error",
            },
            { status: 404 },
          )
        }
        return Response.json({
          id: user.id,
          email: user.email,
          role: user.role,
        })
      }

      return new Response("not-found", { status: 404 })
    },
  })

  return {
    server,
    baseUrl: server.url.origin,
    admin,
    stop() {
      server.stop()
    },
    tokenFor(id: number) {
      const user = users.get(id)
      if (!user) throw new Error(`Unknown user ${id}`)
      return token(user)
    },
    cookieFor(id: number) {
      const user = users.get(id)
      if (!user) throw new Error(`Unknown user ${id}`)
      return `session=auth-${user.id}`
    },
  }
}
