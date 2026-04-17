/**
 * Scanner: GraphQL tester
 *
 * Tests GraphQL endpoints for: introspection, query depth attacks,
 * batching attacks, field injection, and information disclosure.
 */

import { httpRequest } from "../http-client"
import type { SessionID } from "../../session/schema"

export interface GraphqlResult {
  vulnerable: boolean
  findings: GraphqlFinding[]
  schema?: GraphqlSchema
}

export interface GraphqlFinding {
  type: string
  severity: "critical" | "high" | "medium" | "low"
  description: string
  evidence: string
}

export interface GraphqlSchema {
  queryType?: string
  mutationType?: string
  types: string[]
  queries: string[]
  mutations: string[]
}

const INTROSPECTION_QUERY = `{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name } }
        type { name kind ofType { name } }
      }
    }
  }
}`

async function graphqlRequest(
  url: string,
  query: string,
  options: { headers?: Record<string, string>; cookies?: string; timeout?: number; sessionID?: SessionID | string } = {},
): Promise<{ data: unknown; errors?: unknown[]; status: number; body: string }> {
  const resp = await httpRequest(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
    body: JSON.stringify({ query }),
    cookies: options.cookies,
    timeout: options.timeout ?? 15_000,
    sessionID: options.sessionID,
  })

  let data: unknown
  let errors: unknown[] | undefined
  try {
    const parsed = JSON.parse(resp.body)
    data = parsed.data
    errors = parsed.errors
  } catch {
    data = null
  }

  return { data, errors, status: resp.status, body: resp.body }
}

/**
 * Test introspection — if enabled, full schema is exposed.
 */
async function testIntrospection(
  url: string,
  options: { headers?: Record<string, string>; cookies?: string; timeout?: number; sessionID?: SessionID | string },
): Promise<{ finding?: GraphqlFinding; schema?: GraphqlSchema }> {
  const resp = await graphqlRequest(url, INTROSPECTION_QUERY, options)

  if (resp.data && typeof resp.data === "object" && "__schema" in (resp.data as Record<string, unknown>)) {
    const schema = (resp.data as Record<string, unknown>).__schema as Record<string, unknown>
    const types = Array.isArray(schema.types) ? schema.types : []

    const typeNames = types
      .map((t: Record<string, unknown>) => String(t.name))
      .filter((n: string) => !n.startsWith("__"))

    const queries: string[] = []
    const mutations: string[] = []
    for (const type of types) {
      const t = type as Record<string, unknown>
      const fields = Array.isArray(t.fields) ? t.fields : []
      if (t.name === (schema.queryType as Record<string, string>)?.name) {
        queries.push(...fields.map((f: Record<string, string>) => f.name))
      }
      if (t.name === (schema.mutationType as Record<string, string>)?.name) {
        mutations.push(...fields.map((f: Record<string, string>) => f.name))
      }
    }

    return {
      finding: {
        type: "introspection_enabled",
        severity: "medium",
        description: "GraphQL introspection is enabled — full schema exposed to attackers",
        evidence: `Found ${typeNames.length} types, ${queries.length} queries, ${mutations.length} mutations`,
      },
      schema: {
        queryType: (schema.queryType as Record<string, string>)?.name,
        mutationType: (schema.mutationType as Record<string, string>)?.name,
        types: typeNames,
        queries,
        mutations,
      },
    }
  }

  return {}
}

/**
 * Test query depth attack — deeply nested query to cause DoS.
 */
async function testDepthAttack(
  url: string,
  options: { headers?: Record<string, string>; cookies?: string; timeout?: number; sessionID?: SessionID | string },
): Promise<GraphqlFinding | undefined> {
  // Build a deeply nested query
  let query = "{ __typename"
  const depth = 20
  for (let i = 0; i < depth; i++) {
    query = `{ __schema { types { fields { type { ofType ${query} } } } } }`
  }

  const resp = await graphqlRequest(url, query, options)

  // If server doesn't reject deep queries, it's vulnerable to DoS
  if (resp.status === 200 && !resp.errors) {
    return {
      type: "no_depth_limit",
      severity: "medium",
      description: "No query depth limit — vulnerable to resource exhaustion via nested queries",
      evidence: `Depth-${depth} query returned 200 without error`,
    }
  }

  return undefined
}

/**
 * Test batching attack — multiple queries in a single request.
 */
async function testBatching(
  url: string,
  options: { headers?: Record<string, string>; cookies?: string; timeout?: number; sessionID?: SessionID | string },
): Promise<GraphqlFinding | undefined> {
  const batchQuery = JSON.stringify([
    { query: "{ __typename }" },
    { query: "{ __typename }" },
    { query: "{ __typename }" },
    { query: "{ __typename }" },
    { query: "{ __typename }" },
  ])

  const resp = await httpRequest(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...options.headers },
    body: batchQuery,
    cookies: options.cookies,
    timeout: options.timeout ?? 15_000,
    sessionID: options.sessionID,
  })

  try {
    const parsed = JSON.parse(resp.body)
    if (Array.isArray(parsed) && parsed.length === 5) {
      return {
        type: "batching_enabled",
        severity: "low",
        description: "GraphQL batching is enabled — can be used for brute-force or DoS",
        evidence: `Batch of 5 queries returned ${parsed.length} results`,
      }
    }
  } catch {
    // Not JSON array response
  }

  return undefined
}

/**
 * Test GraphQL endpoint for all known weaknesses.
 */
export async function testGraphql(
  url: string,
  options: {
    headers?: Record<string, string>
    cookies?: string
    timeout?: number
    sessionID?: SessionID | string
  } = {},
): Promise<GraphqlResult> {
  const findings: GraphqlFinding[] = []
  let schema: GraphqlSchema | undefined

  // Test introspection
  const introResult = await testIntrospection(url, options)
  if (introResult.finding) findings.push(introResult.finding)
  if (introResult.schema) schema = introResult.schema

  // Test depth attack
  const depthFinding = await testDepthAttack(url, options)
  if (depthFinding) findings.push(depthFinding)

  // Test batching
  const batchFinding = await testBatching(url, options)
  if (batchFinding) findings.push(batchFinding)

  return {
    vulnerable: findings.length > 0,
    findings,
    schema,
  }
}
