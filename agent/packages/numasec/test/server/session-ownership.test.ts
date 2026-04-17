import { describe, expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { Server } from "../../src/server/server"
import { Session } from "../../src/session"
import { tmpdir } from "../fixture/fixture"

describe("server session ownership", () => {
  test("session routes reject cross-project session ids", async () => {
    await using owner = await tmpdir({ git: true })
    await using other = await tmpdir({ git: true })

    const session = await Instance.provide({
      directory: owner.path,
      fn: async () => Session.create({}),
    })

    const app = Server.Default()

    const owned = await app.request(`/session/${session.id}`, {
      headers: { "x-numasec-directory": owner.path },
    })
    expect(owned.status).toBe(200)

    const foreign = await app.request(`/session/${session.id}`, {
      headers: { "x-numasec-directory": other.path },
    })
    expect(foreign.status).toBe(404)

    await Instance.provide({
      directory: owner.path,
      fn: async () => {
        await Session.remove(session.id)
      },
    })
  })

  test("security routes reject cross-project session ids", async () => {
    await using owner = await tmpdir({ git: true })
    await using other = await tmpdir({ git: true })

    const session = await Instance.provide({
      directory: owner.path,
      fn: async () => Session.create({}),
    })

    const app = Server.Default()

    const owned = await app.request(`/security/${session.id}/read`, {
      headers: { "x-numasec-directory": owner.path },
    })
    expect(owned.status).toBe(200)

    const foreign = await app.request(`/security/${session.id}/read`, {
      headers: { "x-numasec-directory": other.path },
    })
    expect(foreign.status).toBe(404)

    await Instance.provide({
      directory: owner.path,
      fn: async () => {
        await Session.remove(session.id)
      },
    })
  })
})
