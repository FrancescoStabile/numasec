import type { HttpResponse } from "../http-client"

export type ExecutionFailureCode =
  | "browser_dependency_missing"
  | "out_of_scope"
  | "origin_uninitialized"
  | "auth_stale"
  | "csrf_missing"
  | "selector_missing"
  | "navigation_timeout"
  | "rate_limited"
  | "waf_suspected"
  | "transient_network"
  | "schema_rejected"
  | "unexpected_redirect"
  | "page_crashed"
  | "browser_action_failed"

export type RecoveryStrategy =
  | "none"
  | "retry_same_request"
  | "reload_last_origin"
  | "reload_requested_url"

export interface ExecutionFailure {
  code: ExecutionFailureCode
  message: string
  retryable: boolean
  strategy: RecoveryStrategy
  status?: number
}

export interface RecoveryTelemetry {
  initial_code: ExecutionFailureCode
  attempts: number
  strategy: RecoveryStrategy
  recovered: boolean
}

function text(input: unknown) {
  if (input instanceof Error && input.message) return input.message
  return String(input ?? "")
}

function code(input: unknown) {
  if (!input || typeof input !== "object" || !("code" in input)) return ""
  return String((input as { code?: unknown }).code ?? "")
}

function body(input: string) {
  return input.toLowerCase()
}

function loginURL(input: string) {
  const value = input.toLowerCase()
  return value.includes("/login") || value.includes("/signin") || value.includes("/auth")
}

function waf(input: HttpResponse) {
  const payload = body(input.body)
  if (payload.includes("attention required")) return true
  if (payload.includes("access denied")) return true
  if (payload.includes("temporarily blocked")) return true
  if (payload.includes("security challenge")) return true
  if (payload.includes("captcha")) return true
  if (payload.includes("cloudflare")) return true
  if (payload.includes("akamai")) return true
  if (payload.includes("perimeterx")) return true
  if (payload.includes("incapsula")) return true
  if (payload.includes("blocked by waf")) return true
  if (input.headers["cf-ray"]) return true
  if (input.headers["x-sucuri-id"]) return true
  if (input.headers["server"]?.toLowerCase().includes("cloudflare")) return true
  return false
}

function csrf(input: HttpResponse) {
  const payload = body(input.body)
  return payload.includes("csrf") || payload.includes("xsrf")
}

function schema(input: HttpResponse) {
  const payload = body(input.body)
  if (payload.includes("validation")) return true
  if (payload.includes("invalid input")) return true
  if (payload.includes("schema")) return true
  if (payload.includes("unprocessable")) return true
  return false
}

export function classifyBrowserFailure(error: unknown): ExecutionFailure {
  const message = text(error) || "Browser action failed"
  const tag = code(error)
  if (tag === "playwright_missing" || tag === "playwright_browser_missing") {
    return {
      code: "browser_dependency_missing",
      message,
      retryable: false,
      strategy: "none",
    }
  }
  if (tag === "browser_page_failed" || /page crashed|target page, context or browser has been closed/i.test(message)) {
    return {
      code: "page_crashed",
      message,
      retryable: false,
      strategy: "none",
    }
  }
  if (/out of scope|err_blocked_by_client/i.test(message)) {
    return {
      code: "out_of_scope",
      message,
      retryable: false,
      strategy: "none",
    }
  }
  if (/net::err_name_not_resolved|net::err_connection_refused|net::err_connection_reset|net::err_connection_closed|net::err_internet_disconnected|net::err_network_changed|net::err_address_unreachable|chrome-error:\/\/chromewebdata/i.test(message)) {
    return {
      code: "transient_network",
      message,
      retryable: true,
      strategy: "reload_requested_url",
    }
  }
  if (/timeout/i.test(message)) {
    return {
      code: "navigation_timeout",
      message,
      retryable: true,
      strategy: "reload_requested_url",
    }
  }
  if (/selector|required/i.test(message)) {
    return {
      code: "selector_missing",
      message,
      retryable: false,
      strategy: "none",
    }
  }
  if (/about:blank|localstorage|sessionstorage|securityerror/i.test(message)) {
    return {
      code: "origin_uninitialized",
      message,
      retryable: true,
      strategy: "reload_last_origin",
    }
  }
  return {
    code: "browser_action_failed",
    message,
    retryable: false,
    strategy: "none",
  }
}

export function classifyHttpFailure(input: {
  response: HttpResponse
  actorSessionID?: string
}) {
  const response = input.response
  if (response.status === 0) {
    if (/^Out of scope:/i.test(response.statusText) || /not in scope|No scope defined/i.test(response.statusText)) {
      return {
        code: "out_of_scope",
        message: response.statusText.replace(/^Out of scope:\s*/i, "") || "Target is out of scope",
        retryable: false,
        strategy: "none",
        status: response.status,
      } satisfies ExecutionFailure
    }
    return {
      code: "transient_network",
      message: response.statusText || "HTTP request failed",
      retryable: true,
      strategy: "retry_same_request",
      status: response.status,
    } satisfies ExecutionFailure
  }
  if (response.status === 429) {
    return {
      code: "rate_limited",
      message: "Target responded with rate limiting",
      retryable: false,
      strategy: "none",
      status: response.status,
    } satisfies ExecutionFailure
  }
  if (waf(response) && [403, 406, 423, 429, 503].includes(response.status)) {
    return {
      code: "waf_suspected",
      message: "Response matched WAF or blocking fingerprints",
      retryable: false,
      strategy: "none",
      status: response.status,
    } satisfies ExecutionFailure
  }
  if (input.actorSessionID && (response.status === 401 || response.status === 403)) {
    return {
      code: csrf(response)
        ? "csrf_missing"
        : "auth_stale",
      message: csrf(response)
        ? "Authenticated request appears to be missing CSRF material"
        : "Authenticated request appears to have stale auth state",
      retryable: false,
      strategy: "none",
      status: response.status,
    } satisfies ExecutionFailure
  }
  if (input.actorSessionID && response.redirectChain.length > 0 && loginURL(response.url)) {
    return {
      code: "unexpected_redirect",
      message: "Authenticated request redirected to a login-like endpoint",
      retryable: false,
      strategy: "none",
      status: response.status,
    } satisfies ExecutionFailure
  }
  if ([400, 422].includes(response.status) && schema(response)) {
    return {
      code: "schema_rejected",
      message: "Request rejected by schema or validation checks",
      retryable: false,
      strategy: "none",
      status: response.status,
    } satisfies ExecutionFailure
  }
  return
}

export function failureObservation(input: ExecutionFailure) {
  return {
    key: `execution-failure-${input.code}`,
    family: "execution_failure",
    kind: input.code,
    status: input.status ?? 0,
    retryable: input.retryable,
    recovery_strategy: input.strategy,
    message: input.message,
  } satisfies Record<string, unknown>
}

export function recoveryObservation(input: RecoveryTelemetry) {
  return {
    key: `execution-recovery-${input.initial_code}`,
    family: "execution_recovery",
    kind: input.initial_code,
    attempts: input.attempts,
    recovery_strategy: input.strategy,
    recovered: input.recovered,
  } satisfies Record<string, unknown>
}
