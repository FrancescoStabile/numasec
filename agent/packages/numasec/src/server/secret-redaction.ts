import { Config } from "@/config/config"
import { Provider } from "@/provider/provider"

const headerPattern = /^(authorization|proxy-authorization|x-api-key|api-key|api_key|x-auth-token)$/i
const fieldPattern = /^(api[-_]?key|access[-_]?token|refresh[-_]?token|client[-_]?secret|token|secret|password|authorization)$/i

function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value)
}

function redactHeaders(input: Record<string, string> | undefined) {
  if (!input) return input
  const out: Record<string, string> = {}
  for (const key of Object.keys(input)) {
    if (headerPattern.test(key)) continue
    out[key] = input[key]!
  }
  return out
}

function redactValue(input: unknown): unknown {
  if (Array.isArray(input)) return input.map((item) => redactValue(item))
  if (!record(input)) return input
  const out: Record<string, unknown> = {}
  for (const key of Object.keys(input)) {
    const value = input[key]
    if (key === "headers" && record(value)) {
      const next = redactHeaders(value as Record<string, string>)
      if (next && Object.keys(next).length > 0) out[key] = next
      continue
    }
    if (fieldPattern.test(key)) continue
    out[key] = redactValue(value)
  }
  return out
}

export function redactProviderInfo(input: Provider.Info): Provider.Info {
  const models: Record<string, Provider.Model> = {}
  for (const id of Object.keys(input.models)) {
    const model = input.models[id]
    if (!model) continue
    models[id] = {
      ...model,
      options: (redactValue(model.options) ?? {}) as Record<string, any>,
      headers: redactHeaders(model.headers) ?? {},
    }
  }
  return {
    ...input,
    key: undefined,
    options: (redactValue(input.options) ?? {}) as Record<string, any>,
    models,
  }
}

export function redactConfigInfo(input: Config.Info): Config.Info {
  if (!input.provider) return input
  const providers = {} as NonNullable<Config.Info["provider"]>
  for (const id of Object.keys(input.provider)) {
    const item = input.provider[id]
    if (!item) continue
    const next = {
      ...item,
      options: item.options ? ((redactValue(item.options) ?? {}) as Record<string, any>) : item.options,
    }
    if (item.models) {
      const models = {} as NonNullable<typeof item.models>
      for (const modelID of Object.keys(item.models)) {
        const model = item.models[modelID]
        if (!model) continue
        models[modelID] = {
          ...model,
          options: model.options ? ((redactValue(model.options) ?? {}) as Record<string, any>) : model.options,
          headers: model.headers ? redactHeaders(model.headers) : model.headers,
        }
      }
      next.models = models
    }
    providers[id] = next
  }
  return {
    ...input,
    provider: providers,
  }
}
