import { describe, expect, test } from "bun:test"
import path from "path"
import { Server } from "../../src/server/server"
import { Config } from "../../src/config/config"
import { Auth } from "../../src/auth"
import { Global } from "../../src/global"
import { Filesystem } from "../../src/util/filesystem"
import { tmpdir } from "../fixture/fixture"

describe("server global admin boundaries", () => {
  test("global config routes stay global regardless of project directory", async () => {
    await using first = await tmpdir({
      init: async (dir) => {
        await Bun.write(
          path.join(dir, "numasec.json"),
          JSON.stringify({
            $schema: "https://numasec.ai/config.json",
            model: "anthropic/claude-sonnet-4-20250514",
          }),
        )
      },
    })
    await using second = await tmpdir({
      init: async (dir) => {
        await Bun.write(
          path.join(dir, "numasec.json"),
          JSON.stringify({
            $schema: "https://numasec.ai/config.json",
            model: "openai/gpt-5",
          }),
        )
      },
    })

    const app = Server.Default()
    const original = await Config.getGlobal()

    try {
      const patch = await app.request("/global/config", {
        method: "PATCH",
        headers: {
          "content-type": "application/json",
          "x-numasec-directory": first.path,
        },
        body: JSON.stringify({
          ...original,
          model: "github-copilot/gpt-5-mini",
        }),
      })
      expect(patch.status).toBe(200)

      const fromFirst = await app.request("/global/config", {
        headers: { "x-numasec-directory": first.path },
      })
      const firstBody = (await fromFirst.json()) as any

      const fromSecond = await app.request("/global/config", {
        headers: { "x-numasec-directory": second.path },
      })
      const secondBody = (await fromSecond.json()) as any

      expect(firstBody.model).toBe("github-copilot/gpt-5-mini")
      expect(secondBody.model).toBe("github-copilot/gpt-5-mini")
    } finally {
      await Config.updateGlobal(original)
    }
  })

  test("auth routes operate on the global auth store across project directories", async () => {
    await using first = await tmpdir()
    await using second = await tmpdir()

    const authPath = path.join(Global.Path.data, "auth.json")
    const original = await Filesystem.readText(authPath).catch(() => undefined)
    const app = Server.Default()

    try {
      const put = await app.request("/auth/anthropic", {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          "x-numasec-directory": first.path,
        },
        body: JSON.stringify({
          type: "api",
          key: "shared-secret",
        }),
      })
      expect(put.status).toBe(200)
      const saved = await Auth.get("anthropic")
      expect(saved?.type).toBe("api")
      if (saved?.type === "api") {
        expect(saved.key).toBe("shared-secret")
      }

      const del = await app.request("/auth/anthropic", {
        method: "DELETE",
        headers: {
          "x-numasec-directory": second.path,
        },
      })
      expect(del.status).toBe(200)
      expect(await Auth.get("anthropic")).toBeUndefined()
    } finally {
      if (original === undefined) {
        await import("fs/promises").then((fs) => fs.unlink(authPath)).catch(() => undefined)
      }
      if (original !== undefined) {
        await Filesystem.write(authPath, original, 0o600)
      }
    }
  })
})
