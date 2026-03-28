import { Config } from "effect"

function truthy(key: string) {
  const value = process.env[key]?.toLowerCase()
  return value === "true" || value === "1"
}

function falsy(key: string) {
  const value = process.env[key]?.toLowerCase()
  return value === "false" || value === "0"
}

export namespace Flag {
  export const NUMASEC_AUTO_SHARE = truthy("NUMASEC_AUTO_SHARE")
  export const NUMASEC_GIT_BASH_PATH = process.env["NUMASEC_GIT_BASH_PATH"]
  export const NUMASEC_CONFIG = process.env["NUMASEC_CONFIG"]
  export declare const NUMASEC_TUI_CONFIG: string | undefined
  export declare const NUMASEC_CONFIG_DIR: string | undefined
  export const NUMASEC_CONFIG_CONTENT = process.env["NUMASEC_CONFIG_CONTENT"]
  export const NUMASEC_DISABLE_AUTOUPDATE = truthy("NUMASEC_DISABLE_AUTOUPDATE")
  export const NUMASEC_ALWAYS_NOTIFY_UPDATE = truthy("NUMASEC_ALWAYS_NOTIFY_UPDATE")
  export const NUMASEC_DISABLE_PRUNE = truthy("NUMASEC_DISABLE_PRUNE")
  export const NUMASEC_DISABLE_TERMINAL_TITLE = truthy("NUMASEC_DISABLE_TERMINAL_TITLE")
  export const NUMASEC_PERMISSION = process.env["NUMASEC_PERMISSION"]
  export const NUMASEC_DISABLE_DEFAULT_PLUGINS = truthy("NUMASEC_DISABLE_DEFAULT_PLUGINS")
  export const NUMASEC_DISABLE_LSP_DOWNLOAD = truthy("NUMASEC_DISABLE_LSP_DOWNLOAD")
  export const NUMASEC_ENABLE_EXPERIMENTAL_MODELS = truthy("NUMASEC_ENABLE_EXPERIMENTAL_MODELS")
  export const NUMASEC_DISABLE_AUTOCOMPACT = truthy("NUMASEC_DISABLE_AUTOCOMPACT")
  export const NUMASEC_DISABLE_MODELS_FETCH = truthy("NUMASEC_DISABLE_MODELS_FETCH")
  export const NUMASEC_DISABLE_EXTERNAL_SKILLS = truthy("NUMASEC_DISABLE_EXTERNAL_SKILLS")
  export declare const NUMASEC_DISABLE_PROJECT_CONFIG: boolean
  export const NUMASEC_FAKE_VCS = process.env["NUMASEC_FAKE_VCS"]
  export declare const NUMASEC_CLIENT: string
  export const NUMASEC_SERVER_PASSWORD = process.env["NUMASEC_SERVER_PASSWORD"]
  export const NUMASEC_SERVER_USERNAME = process.env["NUMASEC_SERVER_USERNAME"]
  export const NUMASEC_ENABLE_QUESTION_TOOL = truthy("NUMASEC_ENABLE_QUESTION_TOOL")

  // Experimental
  export const NUMASEC_EXPERIMENTAL = truthy("NUMASEC_EXPERIMENTAL")
  export const NUMASEC_EXPERIMENTAL_FILEWATCHER = Config.boolean("NUMASEC_EXPERIMENTAL_FILEWATCHER").pipe(
    Config.withDefault(false),
  )
  export const NUMASEC_EXPERIMENTAL_DISABLE_FILEWATCHER = Config.boolean(
    "NUMASEC_EXPERIMENTAL_DISABLE_FILEWATCHER",
  ).pipe(Config.withDefault(false))
  export const NUMASEC_EXPERIMENTAL_ICON_DISCOVERY =
    NUMASEC_EXPERIMENTAL || truthy("NUMASEC_EXPERIMENTAL_ICON_DISCOVERY")

  const copy = process.env["NUMASEC_EXPERIMENTAL_DISABLE_COPY_ON_SELECT"]
  export const NUMASEC_EXPERIMENTAL_DISABLE_COPY_ON_SELECT =
    copy === undefined ? process.platform === "win32" : truthy("NUMASEC_EXPERIMENTAL_DISABLE_COPY_ON_SELECT")
  export const NUMASEC_ENABLE_EXA =
    truthy("NUMASEC_ENABLE_EXA") || NUMASEC_EXPERIMENTAL || truthy("NUMASEC_EXPERIMENTAL_EXA")
  export const NUMASEC_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS = number("NUMASEC_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS")
  export const NUMASEC_EXPERIMENTAL_OUTPUT_TOKEN_MAX = number("NUMASEC_EXPERIMENTAL_OUTPUT_TOKEN_MAX")
  export const NUMASEC_EXPERIMENTAL_OXFMT = NUMASEC_EXPERIMENTAL || truthy("NUMASEC_EXPERIMENTAL_OXFMT")
  export const NUMASEC_EXPERIMENTAL_LSP_TY = truthy("NUMASEC_EXPERIMENTAL_LSP_TY")
  export const NUMASEC_EXPERIMENTAL_LSP_TOOL = NUMASEC_EXPERIMENTAL || truthy("NUMASEC_EXPERIMENTAL_LSP_TOOL")
  export const NUMASEC_DISABLE_FILETIME_CHECK = Config.boolean("NUMASEC_DISABLE_FILETIME_CHECK").pipe(
    Config.withDefault(false),
  )
  export const NUMASEC_EXPERIMENTAL_PLAN_MODE = NUMASEC_EXPERIMENTAL || truthy("NUMASEC_EXPERIMENTAL_PLAN_MODE")
  export const NUMASEC_EXPERIMENTAL_WORKSPACES = NUMASEC_EXPERIMENTAL || truthy("NUMASEC_EXPERIMENTAL_WORKSPACES")
  export const NUMASEC_EXPERIMENTAL_MARKDOWN = !falsy("NUMASEC_EXPERIMENTAL_MARKDOWN")
  export const NUMASEC_MODELS_URL = process.env["NUMASEC_MODELS_URL"]
  export const NUMASEC_MODELS_PATH = process.env["NUMASEC_MODELS_PATH"]
  export const NUMASEC_DISABLE_EMBEDDED_WEB_UI = truthy("NUMASEC_DISABLE_EMBEDDED_WEB_UI")
  export const NUMASEC_DB = process.env["NUMASEC_DB"]
  export const NUMASEC_DISABLE_CHANNEL_DB = truthy("NUMASEC_DISABLE_CHANNEL_DB")
  export const NUMASEC_SKIP_MIGRATIONS = truthy("NUMASEC_SKIP_MIGRATIONS")
  export const NUMASEC_STRICT_CONFIG_DEPS = truthy("NUMASEC_STRICT_CONFIG_DEPS")

  function number(key: string) {
    const value = process.env[key]
    if (!value) return undefined
    const parsed = Number(value)
    return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined
  }
}

// Dynamic getter for NUMASEC_DISABLE_PROJECT_CONFIG
// This must be evaluated at access time, not module load time,
// because external tooling may set this env var at runtime
Object.defineProperty(Flag, "NUMASEC_DISABLE_PROJECT_CONFIG", {
  get() {
    return truthy("NUMASEC_DISABLE_PROJECT_CONFIG")
  },
  enumerable: true,
  configurable: false,
})

// Dynamic getter for NUMASEC_TUI_CONFIG
// This must be evaluated at access time, not module load time,
// because tests and external tooling may set this env var at runtime
Object.defineProperty(Flag, "NUMASEC_TUI_CONFIG", {
  get() {
    return process.env["NUMASEC_TUI_CONFIG"]
  },
  enumerable: true,
  configurable: false,
})

// Dynamic getter for NUMASEC_CONFIG_DIR
// This must be evaluated at access time, not module load time,
// because external tooling may set this env var at runtime
Object.defineProperty(Flag, "NUMASEC_CONFIG_DIR", {
  get() {
    return process.env["NUMASEC_CONFIG_DIR"]
  },
  enumerable: true,
  configurable: false,
})

// Dynamic getter for NUMASEC_CLIENT
// This must be evaluated at access time, not module load time,
// because some commands override the client at runtime
Object.defineProperty(Flag, "NUMASEC_CLIENT", {
  get() {
    return process.env["NUMASEC_CLIENT"] ?? "cli"
  },
  enumerable: true,
  configurable: false,
})
