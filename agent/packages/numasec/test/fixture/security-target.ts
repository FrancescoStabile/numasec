import { createHash } from "crypto"

type User = {
  id: number
  email: string
  password: string
  role: string
  password_hash: string
}

type Project = {
  id: number
  owner_id: number
  tenant_id: string
  name: string
  state: string
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
  const projects = new Map<number, Project>()
  let next = 2
  let nextProject = 2
  const admin = {
    id: 1,
    email: "admin@fixture.local",
    password: "admin123!",
    role: "admin",
    password_hash: hash("admin123!"),
  }
  users.set(admin.id, admin)
  projects.set(1, {
    id: 1,
    owner_id: admin.id,
    tenant_id: `tenant-${admin.id}`,
    name: "admin-roadmap",
    state: "draft",
  })

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url)
      const path = url.pathname
      const origin = req.headers.get("origin") ?? ""

      if (path === "/") {
        return new Response(
          `<html><head><script src="/app.js"></script></head><body><a href="/app/projects/1">Project</a><form method="POST" action="/api/Projects/1/approve"><input name="confirm" type="hidden" value="1" /></form>fixture</body></html>`,
          {
            headers: {
              "content-type": "text/html",
            },
          },
        )
      }

      if (path === "/app.js") {
        return new Response(
          `fetch('/api/Projects/1/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ confirm: '1', filters: { owner: { id: '1' } } }) });`,
          {
            headers: {
              "content-type": "application/javascript",
            },
          },
        )
      }

      if (path === "/app/projects/1") {
        return new Response("<html><body>project</body></html>", {
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

      if (path === "/api/Users" && req.method === "GET") {
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
        return Response.json({
          data: Array.from(users.values()).map((item) => ({
            id: item.id,
            email: item.email,
            role: item.role,
          })),
        })
      }

      if (path === "/api/Projects" && req.method === "POST") {
        const jwt = readBearer(req)
        const data = parseToken(jwt)
        if (!data?.id) {
          return Response.json(
            {
              status: "error",
            },
            { status: 401 },
          )
        }
        const body = await readJson(req)
        const project = {
          id: nextProject++,
          owner_id: data.id,
          tenant_id: `tenant-${data.id}`,
          name: String(body.name ?? `project-${data.id}`),
          state: String(body.state ?? "draft"),
        }
        projects.set(project.id, project)
        return Response.json(
          {
            status: "success",
            data: project,
          },
          { status: 201 },
        )
      }

      if (path === "/api/Projects" && req.method === "GET") {
        const jwt = readBearer(req)
        const data = parseToken(jwt)
        if (!data?.id) {
          return Response.json(
            {
              status: "error",
            },
            { status: 401 },
          )
        }
        return Response.json({
          data: Array.from(projects.values()),
        })
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

      if (path.startsWith("/api/Projects/")) {
        const jwt = readBearer(req)
        const data = parseToken(jwt)
        if (!data?.id) {
          return Response.json(
            {
              status: "error",
            },
            { status: 401 },
          )
        }
        const parts = path.split("/").filter(Boolean)
        const tail = parts.at(-1) ?? ""
        const action = parts.length > 3 ? tail : ""
        const raw = action ? parts.at(-2) ?? "0" : tail
        const id = Number(raw)
        const project = projects.get(id)
        if (!project) {
          return Response.json(
            {
              status: "error",
            },
            { status: 404 },
          )
        }
        if (action && req.method === "POST") {
          if (action === "approve") project.state = "approved"
          if (action === "claim") project.state = "claimed"
          if (action === "close") project.state = "closed"
          if (action === "complete") project.state = "completed"
          if (action === "delete") {
            projects.delete(project.id)
            return Response.json({
              status: "success",
              data: {
                id: project.id,
                deleted: true,
              },
            })
          }
          if (action === "publish") project.state = "published"
          if (action === "verify") project.state = "verified"
          if (action === "activate") project.state = "active"
          if (action === "archive") project.state = "archived"
          projects.set(project.id, project)
          return Response.json({
            status: "success",
            data: project,
          })
        }
        if (req.method === "PUT" || req.method === "PATCH") {
          const body = await readJson(req)
          project.name = String(body.name ?? project.name)
          project.state = String(body.state ?? project.state)
          if (typeof body.owner_id === "number") project.owner_id = body.owner_id
          if (typeof body.tenant_id === "string" && body.tenant_id) project.tenant_id = body.tenant_id
          projects.set(project.id, project)
        }
        return Response.json({
          data: project,
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
