import { expect, test } from "bun:test"
import { Config } from "../../src/config/config"
import { ProviderID } from "../../src/provider/schema"

test("ProviderID.zod accepts the provider id contract used by custom providers", () => {
  expect(String(ProviderID.zod.parse("anthropic"))).toBe("anthropic")
  expect(String(ProviderID.zod.parse("custom-provider_2"))).toBe("custom-provider_2")
})

test("ProviderID.zod rejects arbitrary strings outside the provider id contract", () => {
  expect(ProviderID.zod.safeParse("https://example.com").success).toBe(false)
  expect(ProviderID.zod.safeParse("../escape").success).toBe(false)
  expect(ProviderID.zod.safeParse("UpperCase").success).toBe(false)
})

test("Config.Info rejects invalid custom provider ids", () => {
  const result = Config.Info.safeParse({
    provider: {
      "bad/provider": {
        name: "Bad Provider",
        npm: "@ai-sdk/openai-compatible",
        api: "https://api.example.com/v1",
        env: ["BAD_PROVIDER_KEY"],
        models: {},
      },
    },
  })

  expect(result.success).toBe(false)
})

test("Config.Info accepts valid custom provider ids", () => {
  const result = Config.Info.safeParse({
    provider: {
      "custom-provider": {
        name: "Custom Provider",
        npm: "@ai-sdk/openai-compatible",
        api: "https://api.example.com/v1",
        env: ["CUSTOM_PROVIDER_KEY"],
        models: {},
      },
    },
    disabled_providers: ["custom-provider"],
    enabled_providers: ["custom-provider"],
  })

  expect(result.success).toBe(true)
})
