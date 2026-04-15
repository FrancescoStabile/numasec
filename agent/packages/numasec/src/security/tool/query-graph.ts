import z from "zod"
import { and, eq, inArray } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { EvidenceEdgeTable, EvidenceNodeTable } from "../evidence.sql"
import { Database } from "../../storage/db"
import { canonicalSecuritySessionID } from "../security-session"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Query the canonical evidence graph for nodes, edges, and aggregates.
Supports typed filtering, optional neighborhood traversal, and cursor pagination.`

const QueryGraphParameters = z.object({
  node_types: z.array(z.string()).optional().describe("Filter node types"),
  statuses: z.array(z.string()).optional().describe("Filter node statuses"),
  relations: z.array(z.string()).optional().describe("Filter edge relations"),
  root_node_id: z.string().optional().describe("Optional root node for neighborhood traversal"),
  depth: z.number().min(1).max(6).optional().describe("Traversal depth from root node"),
  cursor: z.number().min(0).optional().describe("Offset cursor"),
  limit: z.number().min(1).max(200).optional().describe("Max nodes per page"),
  include_edges: z.boolean().optional().describe("Include edge list in response"),
})

type NodeRow = (typeof EvidenceNodeTable)["$inferSelect"]
type EdgeRow = (typeof EvidenceEdgeTable)["$inferSelect"]

function filterNeighborhood(nodes: NodeRow[], edges: EdgeRow[], rootNodeID: string, depth: number) {
  const known = new Set<string>()
  const queue: Array<{ node_id: string; depth: number }> = []
  const picked = new Set<string>()

  known.add(rootNodeID)
  queue.push({ node_id: rootNodeID, depth: 0 })

  while (queue.length > 0) {
    const item = queue.shift()
    if (!item) continue
    if (item.depth >= depth) continue
    for (const edge of edges) {
      if (edge.from_node_id !== item.node_id && edge.to_node_id !== item.node_id) continue
      picked.add(edge.id)
      const nextID = edge.from_node_id === item.node_id ? edge.to_node_id : edge.from_node_id
      if (known.has(nextID)) continue
      known.add(nextID)
      queue.push({ node_id: nextID, depth: item.depth + 1 })
    }
  }

  const filteredNodes = nodes.filter((item) => known.has(item.id))
  const filteredEdges = edges.filter((item) => picked.has(item.id))
  return {
    nodes: filteredNodes,
    edges: filteredEdges,
  }
}

export const QueryGraphTool = Tool.define("query_graph", {
  description: DESCRIPTION,
  parameters: QueryGraphParameters,
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const nodeConditions = [eq(EvidenceNodeTable.session_id, sessionID)]
    if (params.node_types && params.node_types.length > 0) {
      nodeConditions.push(inArray(EvidenceNodeTable.type, params.node_types))
    }
    if (params.statuses && params.statuses.length > 0) {
      nodeConditions.push(inArray(EvidenceNodeTable.status, params.statuses))
    }

    const edgeConditions = [eq(EvidenceEdgeTable.session_id, sessionID)]
    if (params.relations && params.relations.length > 0) {
      edgeConditions.push(inArray(EvidenceEdgeTable.relation, params.relations))
    }

    const allNodes = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(nodeConditions.length === 1 ? nodeConditions[0] : and(...nodeConditions))
        .orderBy(EvidenceNodeTable.time_created)
        .all(),
    )
    const allEdges = Database.use((db) =>
      db
        .select()
        .from(EvidenceEdgeTable)
        .where(edgeConditions.length === 1 ? edgeConditions[0] : and(...edgeConditions))
        .orderBy(EvidenceEdgeTable.time_created)
        .all(),
    )

    const includeEdges = params.include_edges !== false
    const depth = params.depth ?? 1
    const graph = params.root_node_id
      ? filterNeighborhood(allNodes, allEdges, params.root_node_id, depth)
      : { nodes: allNodes, edges: allEdges }

    const cursor = params.cursor ?? 0
    const limit = params.limit ?? 50
    const pageNodes = graph.nodes.slice(cursor, cursor + limit)
    const nextCursor = cursor + pageNodes.length < graph.nodes.length ? cursor + pageNodes.length : null

    const pageNodeIDs = new Set<string>()
    for (const item of pageNodes) {
      pageNodeIDs.add(item.id)
    }

    const pageEdges = includeEdges
      ? graph.edges.filter((item) => pageNodeIDs.has(item.from_node_id) && pageNodeIDs.has(item.to_node_id))
      : []

    const nodeTypeCounts = new Map<string, number>()
    for (const item of graph.nodes) {
      const value = nodeTypeCounts.get(item.type) ?? 0
      nodeTypeCounts.set(item.type, value + 1)
    }

    const lines: string[] = []
    lines.push(`Nodes: ${graph.nodes.length} total | page ${pageNodes.length}`)
    lines.push(`Edges: ${includeEdges ? pageEdges.length : 0}`)
    if (params.root_node_id) {
      lines.push(`Traversal root: ${params.root_node_id} (depth ${depth})`)
    }
    if (nextCursor !== null) {
      lines.push(`Next cursor: ${nextCursor}`)
    }

    for (const entry of nodeTypeCounts.entries()) {
      lines.push(`Type ${entry[0]}: ${entry[1]}`)
    }

    return {
      title: `Graph query: ${pageNodes.length}/${graph.nodes.length} nodes`,
      metadata: {
        nodeCount: graph.nodes.length,
        edgeCount: includeEdges ? graph.edges.length : 0,
        pageCount: pageNodes.length,
        nextCursor,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: [
          {
            type: "graph_query",
            node_count: graph.nodes.length,
            edge_count: includeEdges ? graph.edges.length : 0,
            page_count: pageNodes.length,
            next_cursor: nextCursor,
          },
        ],
        metrics: {
          node_count: graph.nodes.length,
          edge_count: includeEdges ? graph.edges.length : 0,
          page_count: pageNodes.length,
        },
      }),
      output: [
        lines.join("\n"),
        "",
        JSON.stringify(
          {
            nodes: pageNodes,
            edges: pageEdges,
            aggregates: {
              node_types: Array.from(nodeTypeCounts.entries()).map((item) => ({ type: item[0], count: item[1] })),
            },
            cursor: nextCursor,
          },
          null,
          2,
        ),
      ].join("\n"),
    }
  },
})
