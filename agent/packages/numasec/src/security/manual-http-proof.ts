import { hasAuthSuccessSignal, hasSqliPayloadSignal, hasVerboseErrorSignal } from "./http-signals"
import { makeToolResultEnvelope, type ToolResultEnvelope } from "./tool/result-envelope"

type ParsedRequest = {
  command: string
  url: string
  method: string
  headers: Record<string, string>
  body: string
  cookies: string
}

type ParsedResponse = {
  status: number
  statusText: string
  headers: Record<string, string>
  setCookies: string[]
  body: string
}

const TOKEN_REGEX = /"(?:\\"|[^"])*"|'(?:\\'|[^'])*'|[^\s]+/g
const STATUS_REGEX = /^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$/i

function unquote(input: string) {
  if (input.startsWith('"') && input.endsWith('"')) return input.slice(1, -1).replaceAll('\\"', '"')
  if (input.startsWith("'") && input.endsWith("'")) return input.slice(1, -1).replaceAll("\\'", "'")
  return input
}

function tokens(input: string) {
  return (input.match(TOKEN_REGEX) ?? []).map((item) => unquote(item))
}

function parseHeaderLine(input: string) {
  const index = input.indexOf(":")
  if (index <= 0) return undefined
  return {
    name: input.slice(0, index).trim().toLowerCase(),
    value: input.slice(index + 1).trim(),
  }
}

function parseCurlCommand(input: string): ParsedRequest | undefined {
  const args = tokens(input.trim())
  if ((args[0] ?? "").toLowerCase() !== "curl") return undefined
  let url = ""
  let method = ""
  let body = ""
  let cookies = ""
  const headers: Record<string, string> = {}
  for (let i = 1; i < args.length; i++) {
    const arg = args[i] ?? ""
    if (arg === "-X" || arg === "--request") {
      method = (args[++i] ?? "").toUpperCase()
      continue
    }
    if (arg.startsWith("-X") && arg.length > 2) {
      method = arg.slice(2).toUpperCase()
      continue
    }
    if (arg.startsWith("--request=")) {
      method = arg.slice("--request=".length).toUpperCase()
      continue
    }
    if (arg === "-H" || arg === "--header") {
      const header = parseHeaderLine(args[++i] ?? "")
      if (header) headers[header.name] = header.value
      continue
    }
    if (arg.startsWith("--header=")) {
      const header = parseHeaderLine(arg.slice("--header=".length))
      if (header) headers[header.name] = header.value
      continue
    }
    if (arg === "-d" || arg === "--data" || arg === "--data-raw" || arg === "--data-binary" || arg === "--data-urlencode") {
      const value = args[++i] ?? ""
      body = body ? `${body}\n${value}` : value
      continue
    }
    if (
      arg.startsWith("--data=") ||
      arg.startsWith("--data-raw=") ||
      arg.startsWith("--data-binary=") ||
      arg.startsWith("--data-urlencode=")
    ) {
      const value = arg.slice(arg.indexOf("=") + 1)
      body = body ? `${body}\n${value}` : value
      continue
    }
    if (arg === "-b" || arg === "--cookie") {
      cookies = args[++i] ?? ""
      continue
    }
    if (arg.startsWith("--cookie=")) {
      cookies = arg.slice("--cookie=".length)
      continue
    }
    if (arg === "--url") {
      url = args[++i] ?? ""
      continue
    }
    if (arg.startsWith("--url=")) {
      url = arg.slice("--url=".length)
      continue
    }
    if (arg.startsWith("-")) continue
    if (!url && /^https?:\/\//i.test(arg)) {
      url = arg
      continue
    }
  }
  if (!url) return undefined
  if (!method) method = body ? "POST" : "GET"
  return {
    command: input,
    url,
    method,
    headers,
    body,
    cookies,
  }
}

function cleanedLine(input: string) {
  return input.trimStart().replace(/^<\s?/, "")
}

function parseCurlOutput(input: string): ParsedResponse | undefined {
  const output = input.replaceAll("\r\n", "\n").trim()
  if (!output) return undefined
  const lines = output.split("\n")
  const statusIndexes: number[] = []
  for (let i = 0; i < lines.length; i++) {
    if (STATUS_REGEX.test(cleanedLine(lines[i] ?? ""))) statusIndexes.push(i)
  }
  if (statusIndexes.length === 0) {
    return {
      status: 0,
      statusText: "",
      headers: {},
      setCookies: [],
      body: output,
    }
  }
  const start = statusIndexes[statusIndexes.length - 1]!
  const statusMatch = STATUS_REGEX.exec(cleanedLine(lines[start] ?? ""))
  if (!statusMatch) return undefined
  const headers: Record<string, string> = {}
  const setCookies: string[] = []
  let cursor = start + 1
  for (; cursor < lines.length; cursor++) {
    const line = cleanedLine(lines[cursor] ?? "")
    if (!line.trim()) {
      cursor += 1
      break
    }
    const header = parseHeaderLine(line)
    if (!header) continue
    if (!(header.name in headers)) headers[header.name] = header.value
    if (header.name === "set-cookie") setCookies.push(header.value)
  }
  return {
    status: Number(statusMatch[1] ?? 0),
    statusText: statusMatch[2] ?? "",
    headers,
    setCookies,
    body: lines.slice(cursor).join("\n").trimStart(),
  }
}

function verifications(request: ParsedRequest, response: ParsedResponse) {
  const out: Record<string, any>[] = []
  const lower = response.body.toLowerCase()
  const origin = request.headers["origin"] ?? ""
  const acao = response.headers["access-control-allow-origin"] ?? ""
  const acac = response.headers["access-control-allow-credentials"] ?? ""
  if (origin && acao === origin && acac === "true") {
    out.push({
      key: "cors-dangerous-reflection",
      family: "cors",
      kind: "credentialed_reflection",
      title: "Credentialed CORS origin reflection on sensitive endpoint",
      technical_severity: "high",
      passed: true,
      control: "positive",
      url: request.url,
      method: request.method,
      evidence_keys: ["exchange"],
    })
  }
  if (acao === "*" && acac === "true") {
    out.push({
      key: "cors-dangerous-wildcard",
      family: "cors",
      kind: "wildcard_with_credentials",
      title: "Wildcard CORS with credentials enabled",
      technical_severity: "high",
      passed: true,
      control: "positive",
      url: request.url,
      method: request.method,
      evidence_keys: ["exchange"],
    })
  }
  if (
    response.status === 200 &&
    (request.url.endsWith("/metrics") || lower.includes("process_cpu_user_seconds_total") || lower.includes("# help"))
  ) {
    out.push({
      key: "metrics-public",
      family: "metrics",
      kind: "prometheus_public",
      title: "Prometheus metrics exposed without authentication",
      technical_severity: "medium",
      passed: true,
      control: "positive",
      url: request.url,
      method: request.method,
      evidence_keys: ["exchange"],
    })
  }
  const payload = `${request.url}\n${request.body}`.toLowerCase()
  if (
    response.status >= 500 &&
    (lower.includes("sqlite") || lower.includes("mysql") || lower.includes("postgres") || lower.includes("oracle") || lower.includes("sql")) &&
    hasSqliPayloadSignal(payload)
  ) {
    out.push({
      key: "sqli-db-error",
      family: "sql_injection",
      kind: "db_error_signature",
      title: "SQL injection indicated by database error after crafted request",
      technical_severity: "high",
      passed: true,
      control: "positive",
      url: request.url,
      method: request.method,
      parameter: "",
      payload: request.body,
      evidence_keys: ["exchange"],
    })
  }
  const successful = response.status === 0 || (response.status >= 200 && response.status < 300)
  if (successful && hasSqliPayloadSignal(payload) && hasAuthSuccessSignal(response.body)) {
    out.push({
      key: "sqli-auth-bypass",
      family: "sql_injection",
      kind: "auth_bypass",
      title: "SQL injection payload yielded authentication success",
      technical_severity: "critical",
      passed: true,
      control: "positive",
      url: request.url,
      method: request.method,
      parameter: "",
      payload: request.body,
      evidence_keys: ["exchange"],
    })
  }
  if (response.status >= 500 && hasVerboseErrorSignal(response.body)) {
    out.push({
      key: "error-disclosure-stacktrace",
      family: "error_disclosure",
      kind: "stacktrace",
      title: "Verbose server error details exposed in HTTP response",
      technical_severity: "medium",
      passed: true,
      control: "positive",
      url: request.url,
      method: request.method,
      evidence_keys: ["exchange"],
    })
  }
  return out
}

export function mergeToolEnvelopes(base: ToolResultEnvelope, extra: ToolResultEnvelope) {
  const text = [base.text, extra.text].filter(Boolean).join("\n\n")
  return makeToolResultEnvelope({
    status: base.status,
    artifacts: [...base.artifacts, ...extra.artifacts],
    observations: [...base.observations, ...extra.observations],
    verifications: [...base.verifications, ...extra.verifications],
    links: [...base.links, ...extra.links],
    metrics: {
      ...base.metrics,
      ...extra.metrics,
    },
    error: base.error ?? extra.error,
    text: text || undefined,
  })
}

export function manualCommandEnvelope(input: {
  tool: string
  command: string
  output: string
  exitCode?: number
}): ToolResultEnvelope | undefined {
  const request = parseCurlCommand(input.command)
  if (!request) return undefined
  const response = parseCurlOutput(input.output)
  if (!response) return undefined
  return makeToolResultEnvelope({
    status: input.exitCode === 0 || response.status > 0 ? "ok" : "inconclusive",
    artifacts: [
      {
        key: "exchange",
        subtype: "manual_http_exchange",
        source_tool: input.tool,
        command: input.command,
        request: {
          url: request.url,
          method: request.method,
          headers: request.headers,
          body: request.body,
          cookies: request.cookies,
        },
        response: {
          url: request.url,
          status: response.status,
          status_text: response.statusText,
          headers: response.headers,
          set_cookies: response.setCookies,
          body: response.body,
        },
        replay: request.command,
      },
    ],
    observations: [
      {
        key: "manual-curl-proof",
        family: "manual_http",
        kind: "curl_capture",
        source_tool: input.tool,
        url: request.url,
        method: request.method,
        exit_code: input.exitCode ?? 0,
      },
    ],
    verifications: verifications(request, response),
    metrics: {
      status: response.status,
      exit_code: input.exitCode ?? 0,
      response_bytes: response.body.length,
    },
    text: "Manual curl proof captured as canonical evidence.",
  })
}
