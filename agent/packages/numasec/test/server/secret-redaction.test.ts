import { describe, expect, test } from "bun:test"
import path from "path"
import { Env } from "../../src/env"
import { Instance } from "../../src/project/instance"
import { Server } from "../../src/server/server"
import { Log } from "../../src/util/log"
import { tmpdir } from "../fixture/fixture"

Log.init({ print: false })

function secretConfig() {
  return {
    $schema: "https://numasec.ai/config.json",
    provider: {
      "custom-provider": {
        name: "Custom Provider",
        npm: "@ai-sdk/openai-compatible",
        api: "https://api.example.com/v1",
        env: ["CUSTOM_PROVIDER_KEY"],
        options: {
          apiKey: "inline-secret",
          destination: {
            url: "https://api.example.com",
            clientSecret: "destination-secret",
            tokenServiceUrl: "https://auth.example.com/oauth/token",
          },
          headers: {
            Authorization: "Bearer secret-token",
            "X-Trace": "keep-me",
          },
        },
        models: {
          "custom-model": {
            name: "Custom Model",
            headers: {
              Authorization: "Bearer model-secret",
              "X-Model": "keep-model",
            },
          },
        },
      },
    },
  }
}

async function dispose(directory: string) {
  await Instance.provide({
    directory,
    fn: () => Instance.dispose(),
  }).catch(() => undefined)
}

describe("server secret redaction", () => {
  test("config routes redact provider secrets from responses", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "numasec.json"), JSON.stringify(secretConfig()))
      },
    })

    const app = Server.Default()

    const get = await app.request("/config", {
      headers: { "x-numasec-directory": tmp.path },
    })
    expect(get.status).toBe(200)
    const body = (await get.json()) as any
    const provider = body.provider["custom-provider"]
    expect(provider.options.apiKey).toBeUndefined()
    expect(provider.options.destination.clientSecret).toBeUndefined()
    expect(provider.options.destination.tokenServiceUrl).toBe("https://auth.example.com/oauth/token")
    expect(provider.options.headers.Authorization).toBeUndefined()
    expect(provider.options.headers["X-Trace"]).toBe("keep-me")
    expect(provider.models["custom-model"].headers.Authorization).toBeUndefined()
    expect(provider.models["custom-model"].headers["X-Model"]).toBe("keep-model")

    const patch = await app.request("/config", {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        "x-numasec-directory": tmp.path,
      },
      body: JSON.stringify(secretConfig()),
    })
    expect(patch.status).toBe(200)
    const updated = (await patch.json()) as any
    expect(updated.provider["custom-provider"].options.apiKey).toBeUndefined()
    expect(updated.provider["custom-provider"].options.destination.clientSecret).toBeUndefined()
    expect(updated.provider["custom-provider"].options.headers.Authorization).toBeUndefined()
    expect(updated.provider["custom-provider"].models["custom-model"].headers.Authorization).toBeUndefined()

    await dispose(tmp.path)
  })

  test("provider routes redact connected provider secrets from responses", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "numasec.json"), JSON.stringify(secretConfig()))
      },
    })

    await Instance.provide({
      directory: tmp.path,
      init: async () => {
        Env.set("ANTHROPIC_API_KEY", "env-secret")
      },
      fn: async () => undefined,
    })

    const app = Server.Default()

    const provider = await app.request("/provider", {
      headers: { "x-numasec-directory": tmp.path },
    })
    expect(provider.status).toBe(200)
    const providerBody = (await provider.json()) as any
    const anthropic = providerBody.all.find((item: any) => item.id === "anthropic")
    const custom = providerBody.all.find((item: any) => item.id === "custom-provider")
    expect(anthropic.key).toBeUndefined()
    expect(custom.options.apiKey).toBeUndefined()
    expect(custom.options.destination.clientSecret).toBeUndefined()
    expect(custom.options.destination.tokenServiceUrl).toBe("https://auth.example.com/oauth/token")
    expect(custom.options.headers.Authorization).toBeUndefined()
    expect(custom.options.headers["X-Trace"]).toBe("keep-me")
    expect(custom.models["custom-model"].headers.Authorization).toBeUndefined()

    const configProviders = await app.request("/config/providers", {
      headers: { "x-numasec-directory": tmp.path },
    })
    expect(configProviders.status).toBe(200)
    const configBody = (await configProviders.json()) as any
    const customConfig = configBody.providers.find((item: any) => item.id === "custom-provider")
    expect(customConfig.options.apiKey).toBeUndefined()
    expect(customConfig.options.destination.clientSecret).toBeUndefined()
    expect(customConfig.options.headers.Authorization).toBeUndefined()
    expect(customConfig.models["custom-model"].headers.Authorization).toBeUndefined()

    await dispose(tmp.path)
  })
})
