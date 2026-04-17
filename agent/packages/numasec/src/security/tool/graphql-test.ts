/**
 * Tool: graphql_test
 *
 * GraphQL-specific vulnerability testing.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { testGraphql } from "../scanner/graphql-tester"

const DESCRIPTION = `Test a GraphQL endpoint for common vulnerabilities:
- Introspection enabled (full schema leak)
- Query depth attacks (denial of service)
- Batching attacks (bypass rate limits)
- Field suggestion exploitation
- Injection in GraphQL arguments

Requires: GraphQL endpoint URL.

NEXT STEPS with findings:
- If introspection enabled: dump full schema, find mutations with side effects
- If query depth unlimited: report DoS risk
- For each mutation: test with injection_test on input fields
- For auth mutations: test with auth_test`

export const GraphqlTestTool = Tool.define("graphql_test", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("GraphQL endpoint URL"),
    headers: z.record(z.string(), z.string()).optional().describe("Headers (e.g., auth tokens)"),
    cookies: z.string().optional().describe("Cookies"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "graphql_test",
      patterns: [params.url],
      always: [] as string[],
      metadata: { url: params.url } as Record<string, any>,
    })

    ctx.metadata({ title: "Testing GraphQL endpoint..." })
    const result = await testGraphql(params.url, {
      headers: params.headers,
      cookies: params.cookies,
      sessionID: ctx.sessionID,
    })

    const parts: string[] = [`── GraphQL Analysis ──`]

    if (result.schema) {
      parts.push("")
      parts.push("⚠ INTROSPECTION ENABLED — Schema exposed")
      if (result.schema.queryType) parts.push(`Query type: ${result.schema.queryType}`)
      if (result.schema.mutationType) parts.push(`Mutation type: ${result.schema.mutationType}`)
    }

    if (result.findings.length > 0) {
      parts.push("")
      for (const f of result.findings) {
        parts.push(`[${f.severity.toUpperCase()}] ${f.type}: ${f.description}`)
        parts.push(`  Evidence: ${f.evidence}`)
      }
    } else {
      parts.push("No GraphQL vulnerabilities found.")
    }

    return {
      title: result.vulnerable ? `⚠ ${result.findings.length} GraphQL issue(s)` : "GraphQL: no issues",
      metadata: {
        vulnerable: result.vulnerable,
        findings: result.findings.length,
        hasSchema: !!result.schema,
      } as any,
      output: parts.join("\n"),
    }
  },
})
