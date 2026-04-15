import type { SessionID } from "../../session/schema"
import { httpRequest, type HttpRequestOptions } from "../http-client"
import { Scope } from "../scope"
import {
  classifyHttpFailure,
  type ExecutionFailureCode,
  type ExecutionFailure,
  type RecoveryTelemetry,
} from "./execution-failure"
import { recordExecutionAttempt } from "./execution-attempt"
import {
  applyTargetProfile,
  noteTargetSignal,
  type TargetExecutionProfile,
} from "./target-profile-store"

export interface HttpExecutionInput {
  sessionID: SessionID
  toolName: string
  action: string
  url: string
  actorSessionID?: string
  request: HttpRequestOptions
  attemptBudget?: number
}

export interface HttpExecutionResult {
  response: Awaited<ReturnType<typeof httpRequest>>
  failure?: ExecutionFailure
  recovery?: RecoveryTelemetry
  profile?: TargetExecutionProfile
}

function failureResponse(url: string, code: ExecutionFailureCode, message: string) {
  return {
    status: 0,
    statusText: code === "out_of_scope" ? `Out of scope: ${message}` : message,
    headers: {},
    setCookies: [],
    body: "",
    url,
    redirectChain: [],
    elapsed: 0,
  } satisfies Awaited<ReturnType<typeof httpRequest>>
}

function scopeFailure(error: Scope.ScopeViolationError): ExecutionFailure {
  return {
    code: "out_of_scope",
    message: error.message,
    retryable: false,
    strategy: "none",
    status: 0,
  }
}

async function sendRequest(input: HttpExecutionInput) {
  try {
    const response = await httpRequest(input.url, {
      ...input.request,
      sessionID: input.sessionID,
    })
    return { response }
  } catch (error) {
    if (!(error instanceof Scope.ScopeViolationError)) throw error
    return {
      response: failureResponse(input.url, "out_of_scope", error.message),
      failure: scopeFailure(error),
    }
  }
}

export async function executeHttpWithRecovery(input: HttpExecutionInput): Promise<HttpExecutionResult> {
  const profile = await applyTargetProfile(input.sessionID, input.url)
  const budget = Math.max(0, input.attemptBudget ?? profile?.retry_budget ?? 1)
  const firstRequest = await sendRequest(input)
  const first = firstRequest.response
  const initial = firstRequest.failure ?? classifyHttpFailure({
    response: first,
    actorSessionID: input.actorSessionID,
  })
  if (initial) {
    await noteTargetSignal(input.sessionID, input.url, initial.code).catch(() => undefined)
  }
  if (!initial) {
    await noteTargetSignal(input.sessionID, input.url, "success").catch(() => undefined)
  }
  await recordExecutionAttempt({
    sessionID: input.sessionID,
    toolName: input.toolName,
    action: input.action,
    status: initial ? "error" : "ok",
    errorCode: initial?.code,
    actorSessionID: input.actorSessionID,
    notes: {
      status: first.status,
      elapsed: first.elapsed,
      url: first.url,
      redirects: first.redirectChain.length,
    },
  }).catch(() => undefined)
  if (!initial) return { response: first, profile }
  if (!initial.retryable || budget <= 0) {
    return {
      response: first,
      failure: initial,
      profile,
    }
  }

  let count = 1
  let failure: ExecutionFailure = initial
  let response = first
  while (count <= budget && failure.retryable && failure.strategy === "retry_same_request") {
    count += 1
    const nextRequest = await sendRequest(input)
    response = nextRequest.response
    const next = nextRequest.failure ?? classifyHttpFailure({
      response,
      actorSessionID: input.actorSessionID,
    })
    if (next) {
      await noteTargetSignal(input.sessionID, input.url, next.code).catch(() => undefined)
    }
    if (!next) {
      await noteTargetSignal(input.sessionID, input.url, "success").catch(() => undefined)
    }
    await recordExecutionAttempt({
      sessionID: input.sessionID,
      toolName: input.toolName,
      action: input.action,
      status: next ? "retry_error" : "recovered",
      errorCode: next?.code ?? "",
      actorSessionID: input.actorSessionID,
      notes: {
        attempt: count,
        status: response.status,
        elapsed: response.elapsed,
        url: response.url,
        redirects: response.redirectChain.length,
        recovery_strategy: initial.strategy,
      },
    }).catch(() => undefined)
    if (!next) {
      return {
        response,
        profile,
        recovery: {
          initial_code: initial.code,
          attempts: count,
          strategy: initial.strategy,
          recovered: true,
        },
      }
    }
    failure = next
  }

  return {
    response,
    failure,
    profile,
    recovery: {
      initial_code: initial.code,
      attempts: count,
      strategy: initial.strategy,
      recovered: false,
    },
  }
}
