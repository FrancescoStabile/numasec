import { describe, expect, test } from "bun:test"
import path from "path"
import { Instance } from "../../src/project/instance"
import { Server } from "../../src/server/server"
import { CoverageTable, FindingTable, TargetTable } from "../../src/security/security.sql"
import { EvidenceEdgeTable, EvidenceNodeTable, type EvidenceEdgeID, type EvidenceNodeID } from "../../src/security/evidence.sql"
import { persistEngagementTarget } from "../../src/security/target-store"
import type { FindingID, TargetID } from "../../src/security/security.sql"
import { Session } from "../../src/session"
import { MessageTable, PartTable } from "../../src/session/session.sql"
import { Database, eq } from "../../src/storage/db"
import { Log } from "../../src/util/log"

const root = path.join(__dirname, "../..")
Log.init({ print: false })

type SyncMeta = {
  limit: number
  cursor: string | null
  since: number | null
  next_cursor: string | null
  has_more: boolean
}

type FindingSyncBody = {
  items: Array<{ id: string; severity: string; time_updated: number }>
  sync: SyncMeta
}

type ChainSyncBody = {
  items: Array<{
    chain_id: string
    severity: string
    finding_count: number
    finding_ids: string[]
    urls: string[]
    time_created: number
    time_updated: number
  }>
  sync: SyncMeta
}

type EvidenceSyncBody = {
  enabled: boolean
  items: Array<{ id: string; time_updated: number }>
  sync: SyncMeta
}

type SummaryBody = {
  session_id: string
  graph_enabled: boolean
  summary: {
    scope_count: number
    hypothesis_count: number
    evidence_node_count: number
    evidence_edge_count: number
    finding_count: number
    chain_count: number
    coverage_count: number
  }
  checkpoints: {
    scope: { count: number; latest_time_updated: number | null; changed: boolean }
    hypotheses: { count: number; latest_time_updated: number | null; changed: boolean }
    findings: { count: number; latest_time_updated: number | null; changed: boolean }
    chains: { count: number; latest_time_updated: number | null; changed: boolean }
    coverage: { count: number; latest_time_updated: number | null; changed: boolean }
    engagement: { count: number; latest_time_updated: number | null; changed: boolean }
    evidence_nodes: { enabled: boolean; count: number; latest_time_updated: number | null; changed: boolean }
    evidence_edges: { enabled: boolean; count: number; latest_time_updated: number | null; changed: boolean }
  }
  sync: { since: number | null }
}

describe("security read model routes", () => {
  test("returns canonical read model from scope/findings/chains projections", async () => {
    await Instance.provide({
      directory: root,
      fn: async () => {
        const session = await Session.create({})

        Database.use((db) =>
          db
            .insert(TargetTable)
            .values({
              id: "target-1" as TargetID,
              session_id: session.id,
              url: "https://example.com",
              scope: ["https://example.com/api/*"],
            })
            .run(),
        )

        Database.use((db) =>
          db
            .insert(FindingTable)
            .values([
              {
                id: "SSEC-READ000001" as FindingID,
                session_id: session.id,
                title: "SQL injection in search",
                severity: "high",
                url: "https://example.com/api/search",
                chain_id: "CHAIN-001",
              },
              {
                id: "SSEC-READ000002" as FindingID,
                session_id: session.id,
                title: "Privilege escalation in admin endpoint",
                severity: "critical",
                url: "https://example.com/api/admin",
                chain_id: "CHAIN-001",
              },
            ])
            .run(),
        )

        const app = Server.Default()
        const response = await app.request(`/security/${session.id}/read`)
        expect(response.status).toBe(200)
        const body = (await response.json()) as {
          session_id: string
          graph_enabled: boolean
          scope: string[]
          findings: unknown[]
          chains: Array<{ chain_id: string }>
          summary: { finding_count: number; chain_count: number }
          engagement: {
            engagement_target_url: string | null
            current_endpoint_url: string | null
            last_tested_url: string | null
            findings: {
              total: number
              verified: number
              provisional: number
              suppressed: number
              severity: { critical: number; high: number; medium: number; low: number; info: number }
            }
            report: {
              state: string
              working_ready: boolean
              final_ready: boolean
              final_blocked: boolean
              final_snapshot: {
                state: string
                exported_at: number | null
                exported_revision: number | null
              }
              verification_debt: {
                promotion_gaps: number
                open_hypotheses: number
                open_critical_hypotheses: number
              }
            }
          }
        }

        expect(body.session_id).toBe(session.id)
        expect(body.graph_enabled).toBe(false)
        expect(body.scope).toContain("https://example.com")
        expect(body.scope).toContain("https://example.com/api/*")
        expect(body.findings.length).toBe(2)
        expect(body.chains.length).toBe(1)
        expect(body.chains[0].chain_id).toBe("CHAIN-001")
        expect(body.summary.finding_count).toBe(2)
        expect(body.summary.chain_count).toBe(1)
        expect(body.engagement.engagement_target_url).toBe("https://example.com")
        expect(body.engagement.current_endpoint_url).toBe("https://example.com/api/admin")
        expect(body.engagement.last_tested_url).toBe("https://example.com/api/admin")
        expect(body.engagement.findings.total).toBe(2)
        expect(body.engagement.findings.severity.critical).toBe(1)
        expect(body.engagement.findings.severity.high).toBe(1)
        expect(body.engagement.report.state).toBe("final_ready")
        expect(body.engagement.report.working_ready).toBe(true)
        expect(body.engagement.report.final_ready).toBe(true)
        expect(body.engagement.report.final_snapshot.state).toBe("absent")

        await Session.remove(session.id)
      },
    })
  })

  test("marks a stale final snapshot as reopened when security state changes afterwards", async () => {
    await Instance.provide({
      directory: root,
      fn: async () => {
        const session = await Session.create({})

        Database.use((db) =>
          db
            .insert(FindingTable)
            .values({
              id: "SSEC-READ-REOPEN" as FindingID,
              session_id: session.id,
              title: "Verified finding",
              severity: "high",
              description: "before reopen",
              confirmed: true,
              state: "verified",
              reportable: true,
              manual_override: true,
              url: "https://example.com/api/search",
              method: "GET",
              confidence: 0.9,
              tool_used: "test",
              time_created: 1,
              time_updated: 1,
            })
            .run(),
        )

        Database.use((db) =>
          db
            .insert(MessageTable)
            .values({
              id: "msg-read-reopen" as any,
              session_id: session.id,
              data: {
                role: "assistant",
              } as any,
              time_created: 2,
              time_updated: 2,
            })
            .run(),
        )
        Database.use((db) =>
          db
            .insert(PartTable)
            .values({
              id: "part-read-reopen" as any,
              message_id: "msg-read-reopen" as any,
              session_id: session.id,
              data: {
                type: "tool",
                callID: "call-read-reopen",
                tool: "generate_report",
                state: {
                  status: "completed",
                  input: {
                    format: "markdown",
                  },
                  output: "# Security Assessment Report",
                  output_v2: {},
                  title: "Report (markdown): 1 verified, risk 20/100",
                  metadata: {
                    reportRendered: "final",
                    engagementRevision: 1,
                  },
                  time: {
                    start: 1,
                    end: 2,
                  },
                },
              } as any,
              time_created: 2,
              time_updated: 2,
            })
            .run(),
        )
        Database.use((db) =>
          db
            .update(FindingTable)
            .set({
              description: "after reopen",
              time_updated: 3,
            })
            .where(eq(FindingTable.id, "SSEC-READ-REOPEN" as any))
            .run(),
        )

        const app = Server.Default()
        const response = await app.request(`/security/${session.id}/read`)
        expect(response.status).toBe(200)
        const body = (await response.json()) as {
          engagement: {
            report: {
              state: string
              final_snapshot: {
                state: string
                exported_revision: number | null
              }
              updated_at: number | null
            }
            revision: number
          }
        }

        expect(body.engagement.report.state).toBe("final_ready")
        expect(body.engagement.report.final_snapshot.state).toBe("reopened")
        expect(body.engagement.report.final_snapshot.exported_revision).toBe(1)
        expect(body.engagement.revision).toBe(3)

        await Session.remove(session.id)
      },
    })
  })

  test("uses persisted engagement target when findings point at a deeper endpoint", async () => {
    await Instance.provide({
      directory: root,
      fn: async () => {
        const session = await Session.create({})
        persistEngagementTarget({
          sessionID: session.id,
          url: "http://localhost:3000/rest/user/security-question",
          source: "observe_surface",
        })

        Database.use((db) =>
          db
            .insert(FindingTable)
            .values({
              id: "SSEC-READ-TARGET01" as FindingID,
              session_id: session.id,
              title: "Endpoint finding",
              severity: "high",
              url: "http://localhost:3000/api/Users",
            })
            .run(),
        )

        const app = Server.Default()
        const response = await app.request(`/security/${session.id}/read`)
        expect(response.status).toBe(200)
        const body = (await response.json()) as {
          engagement: {
            engagement_target_url: string | null
            current_endpoint_url: string | null
            last_tested_url: string | null
          }
        }

        expect(body.engagement.engagement_target_url).toBe("http://localhost:3000")
        expect(body.engagement.current_endpoint_url).toBe("http://localhost:3000/api/Users")
        expect(body.engagement.last_tested_url).toBe("http://localhost:3000/api/Users")

        await Session.remove(session.id)
      },
    })
  })

  test("returns evidence nodes when graph read flag is enabled", async () => {
    await Instance.provide({
      directory: root,
      fn: async () => {
        const session = await Session.create({})
        process.env["NUMASEC_SECURITY_GRAPH_READ"] = "1"

        Database.use((db) =>
          db
            .insert(EvidenceNodeTable)
            .values({
              id: "ENOD-READTEST0001" as EvidenceNodeID,
              session_id: session.id,
              type: "observation",
              fingerprint: "fp-read-1",
              payload: { note: "node-1" },
            })
            .run(),
        )

        const app = Server.Default()
        const response = await app.request(`/security/${session.id}/evidence/nodes`)
        expect(response.status).toBe(200)
        const body = (await response.json()) as {
          enabled: boolean
          items: Array<{ id: string }>
        }

        expect(body.enabled).toBe(true)
        expect(body.items.length).toBe(1)
        expect(body.items[0].id).toBe("ENOD-READTEST0001")

        delete process.env["NUMASEC_SECURITY_GRAPH_READ"]
        await Session.remove(session.id)
      },
    })
  })

  test("supports findings sync pagination, cursor and since filters", async () => {
    await Instance.provide({
      directory: root,
      fn: async () => {
        const session = await Session.create({})

        Database.use((db) =>
          db
            .insert(FindingTable)
            .values([
              {
                id: "SSEC-SYNCFIND001" as FindingID,
                session_id: session.id,
                title: "Info finding",
                severity: "info",
                url: "https://example.com/a",
                time_created: 1_000,
                time_updated: 1_000,
              },
              {
                id: "SSEC-SYNCFIND002" as FindingID,
                session_id: session.id,
                title: "High finding 1",
                severity: "high",
                url: "https://example.com/b",
                time_created: 2_000,
                time_updated: 2_000,
              },
              {
                id: "SSEC-SYNCFIND003" as FindingID,
                session_id: session.id,
                title: "High finding 2",
                severity: "high",
                url: "https://example.com/c",
                time_created: 3_000,
                time_updated: 3_000,
              },
            ])
            .run(),
        )

        const app = Server.Default()
        const first = await app.request(`/security/${session.id}/findings/sync?limit=2`)
        expect(first.status).toBe(200)
        const firstBody = (await first.json()) as FindingSyncBody
        expect(firstBody.items.map((item) => item.id)).toEqual(["SSEC-SYNCFIND001", "SSEC-SYNCFIND002"])
        expect(firstBody.sync.limit).toBe(2)
        expect(firstBody.sync.has_more).toBe(true)
        expect(firstBody.sync.next_cursor).toBeTruthy()
        expect(first.headers.get("x-next-cursor")).toBe(firstBody.sync.next_cursor)

        const cursor = firstBody.sync.next_cursor!
        const second = await app.request(`/security/${session.id}/findings/sync?limit=2&cursor=${encodeURIComponent(cursor)}`)
        expect(second.status).toBe(200)
        const secondBody = (await second.json()) as FindingSyncBody
        expect(secondBody.items.map((item) => item.id)).toEqual(["SSEC-SYNCFIND003"])
        expect(secondBody.sync.has_more).toBe(false)

        const filtered = await app.request(`/security/${session.id}/findings/sync?since=2000&severity=high`)
        expect(filtered.status).toBe(200)
        const filteredBody = (await filtered.json()) as FindingSyncBody
        expect(filteredBody.items.map((item) => item.id)).toEqual(["SSEC-SYNCFIND002", "SSEC-SYNCFIND003"])
        expect(filteredBody.sync.since).toBe(2_000)

        const invalid = await app.request(`/security/${session.id}/findings/sync?cursor=bad`)
        expect(invalid.status).toBe(400)

        await Session.remove(session.id)
      },
    })
  })

  test("supports chain sync pagination and incremental retrieval", async () => {
    await Instance.provide({
      directory: root,
      fn: async () => {
        const session = await Session.create({})

        Database.use((db) =>
          db
            .insert(FindingTable)
            .values([
              {
                id: "SSEC-SYNCCHAIN001" as FindingID,
                session_id: session.id,
                title: "Chain B finding",
                severity: "low",
                url: "https://example.com/b",
                chain_id: "CHAIN-B",
                time_created: 1_000,
                time_updated: 1_000,
              },
              {
                id: "SSEC-SYNCCHAIN002" as FindingID,
                session_id: session.id,
                title: "Chain A finding 1",
                severity: "medium",
                url: "https://example.com/a/1",
                chain_id: "CHAIN-A",
                time_created: 2_000,
                time_updated: 2_000,
              },
              {
                id: "SSEC-SYNCCHAIN003" as FindingID,
                session_id: session.id,
                title: "Chain A finding 2",
                severity: "critical",
                url: "https://example.com/a/2",
                chain_id: "CHAIN-A",
                time_created: 3_000,
                time_updated: 3_000,
              },
            ])
            .run(),
        )

        const app = Server.Default()
        const first = await app.request(`/security/${session.id}/chains/sync?limit=1`)
        expect(first.status).toBe(200)
        const firstBody = (await first.json()) as ChainSyncBody
        expect(firstBody.items.length).toBe(1)
        expect(firstBody.items[0].chain_id).toBe("CHAIN-B")
        expect(firstBody.items[0].time_updated).toBe(1_000)
        expect(firstBody.sync.has_more).toBe(true)
        expect(first.headers.get("x-next-cursor")).toBe(firstBody.sync.next_cursor)

        const cursor = firstBody.sync.next_cursor!
        const second = await app.request(`/security/${session.id}/chains/sync?limit=1&cursor=${encodeURIComponent(cursor)}`)
        expect(second.status).toBe(200)
        const secondBody = (await second.json()) as ChainSyncBody
        expect(secondBody.items.length).toBe(1)
        expect(secondBody.items[0].chain_id).toBe("CHAIN-A")
        expect(secondBody.items[0].severity).toBe("critical")
        expect(secondBody.items[0].finding_count).toBe(2)
        expect(secondBody.items[0].finding_ids).toContain("SSEC-SYNCCHAIN002")
        expect(secondBody.items[0].finding_ids).toContain("SSEC-SYNCCHAIN003")
        expect(secondBody.sync.has_more).toBe(false)

        const filtered = await app.request(`/security/${session.id}/chains/sync?since=2500`)
        expect(filtered.status).toBe(200)
        const filteredBody = (await filtered.json()) as ChainSyncBody
        expect(filteredBody.items.length).toBe(1)
        expect(filteredBody.items[0].chain_id).toBe("CHAIN-A")
        expect(filteredBody.sync.since).toBe(2_500)

        await Session.remove(session.id)
      },
    })
  })

  test("supports evidence sync pagination and graph flag interactions", async () => {
    await Instance.provide({
      directory: root,
      fn: async () => {
        const session = await Session.create({})
        const app = Server.Default()

        const disabled = await app.request(`/security/${session.id}/evidence/nodes/sync?limit=2`)
        expect(disabled.status).toBe(200)
        const disabledBody = (await disabled.json()) as EvidenceSyncBody
        expect(disabledBody.enabled).toBe(false)
        expect(disabledBody.items.length).toBe(0)
        expect(disabledBody.sync.has_more).toBe(false)

        process.env["NUMASEC_SECURITY_GRAPH_READ"] = "1"

        Database.use((db) =>
          db
            .insert(EvidenceNodeTable)
            .values([
              {
                id: "ENOD-SYNC-0001" as EvidenceNodeID,
                session_id: session.id,
                type: "observation",
                fingerprint: "fp-sync-1",
                payload: { note: "node-1" },
                time_created: 1_000,
                time_updated: 1_000,
              },
              {
                id: "ENOD-SYNC-0002" as EvidenceNodeID,
                session_id: session.id,
                type: "hypothesis",
                fingerprint: "fp-sync-2",
                payload: { note: "node-2" },
                time_created: 2_000,
                time_updated: 2_000,
              },
            ])
            .run(),
        )

        Database.use((db) =>
          db
            .insert(EvidenceEdgeTable)
            .values({
              id: "EEDG-SYNC-0001" as EvidenceEdgeID,
              session_id: session.id,
              from_node_id: "ENOD-SYNC-0001" as EvidenceNodeID,
              to_node_id: "ENOD-SYNC-0002" as EvidenceNodeID,
              relation: "supports",
              time_created: 2_500,
              time_updated: 2_500,
            })
            .run(),
        )

        const first = await app.request(`/security/${session.id}/evidence/nodes/sync?limit=1`)
        expect(first.status).toBe(200)
        const firstBody = (await first.json()) as EvidenceSyncBody
        expect(firstBody.enabled).toBe(true)
        expect(firstBody.items.length).toBe(1)
        expect(firstBody.items[0].id).toBe("ENOD-SYNC-0001")
        expect(firstBody.sync.has_more).toBe(true)
        expect(first.headers.get("x-next-cursor")).toBe(firstBody.sync.next_cursor)

        const cursor = firstBody.sync.next_cursor!
        const second = await app.request(
          `/security/${session.id}/evidence/nodes/sync?limit=1&cursor=${encodeURIComponent(cursor)}`,
        )
        expect(second.status).toBe(200)
        const secondBody = (await second.json()) as EvidenceSyncBody
        expect(secondBody.items.length).toBe(1)
        expect(secondBody.items[0].id).toBe("ENOD-SYNC-0002")
        expect(secondBody.sync.has_more).toBe(false)

        const edge = await app.request(`/security/${session.id}/evidence/edges/sync?since=1000`)
        expect(edge.status).toBe(200)
        const edgeBody = (await edge.json()) as EvidenceSyncBody
        expect(edgeBody.enabled).toBe(true)
        expect(edgeBody.items.length).toBe(1)
        expect(edgeBody.items[0].id).toBe("EEDG-SYNC-0001")
        expect(edgeBody.sync.since).toBe(1_000)

        delete process.env["NUMASEC_SECURITY_GRAPH_READ"]
        await Session.remove(session.id)
      },
    })
  })

  test("returns unified summary checkpoints for sync polling", async () => {
    await Instance.provide({
      directory: root,
      fn: async () => {
        const session = await Session.create({})
        process.env["NUMASEC_SECURITY_GRAPH_READ"] = "1"

        Database.use((db) =>
          db
            .insert(TargetTable)
            .values({
              id: "target-summary" as TargetID,
              session_id: session.id,
              url: "https://example.com",
              scope: ["https://example.com/api/*"],
              time_created: 500,
              time_updated: 500,
            })
            .run(),
        )

        Database.use((db) =>
          db
            .insert(FindingTable)
            .values([
              {
                id: "SSEC-SUMMARY001" as FindingID,
                session_id: session.id,
                title: "Summary finding 1",
                severity: "high",
                url: "https://example.com/a",
                chain_id: "CHAIN-SUM",
                time_created: 1_000,
                time_updated: 1_000,
              },
              {
                id: "SSEC-SUMMARY002" as FindingID,
                session_id: session.id,
                title: "Summary finding 2",
                severity: "medium",
                url: "https://example.com/b",
                chain_id: "CHAIN-SUM",
                time_created: 2_000,
                time_updated: 2_000,
              },
            ])
            .run(),
        )

        Database.use((db) =>
          db
            .insert(CoverageTable)
            .values({
              session_id: session.id,
              category: "A01:2021",
              tested: true,
              finding_count: 2,
              time_created: 2_100,
              time_updated: 2_100,
            })
            .run(),
        )

        Database.use((db) =>
          db
            .insert(EvidenceNodeTable)
            .values([
              {
                id: "ENOD-SUMMARY-1" as EvidenceNodeID,
                session_id: session.id,
                type: "observation",
                fingerprint: "fp-summary-1",
                payload: { note: "obs" },
                time_created: 1_500,
                time_updated: 1_500,
              },
              {
                id: "ENOD-SUMMARY-2" as EvidenceNodeID,
                session_id: session.id,
                type: "hypothesis",
                fingerprint: "fp-summary-2",
                payload: { note: "hyp" },
                time_created: 2_500,
                time_updated: 2_500,
              },
            ])
            .run(),
        )

        Database.use((db) =>
          db
            .insert(EvidenceEdgeTable)
            .values({
              id: "EEDG-SUMMARY-1" as EvidenceEdgeID,
              session_id: session.id,
              from_node_id: "ENOD-SUMMARY-1" as EvidenceNodeID,
              to_node_id: "ENOD-SUMMARY-2" as EvidenceNodeID,
              relation: "supports",
              time_created: 2_600,
              time_updated: 2_600,
            })
            .run(),
        )

        const app = Server.Default()
        const enabled = await app.request(`/security/${session.id}/read/summary?since=2400`)
        expect(enabled.status).toBe(200)
        const enabledBody = (await enabled.json()) as SummaryBody
        expect(enabledBody.session_id).toBe(session.id)
        expect(enabledBody.graph_enabled).toBe(true)
        expect(enabledBody.summary.scope_count).toBe(2)
        expect(enabledBody.summary.hypothesis_count).toBe(1)
        expect(enabledBody.summary.evidence_node_count).toBe(2)
        expect(enabledBody.summary.evidence_edge_count).toBe(1)
        expect(enabledBody.summary.finding_count).toBe(2)
        expect(enabledBody.summary.chain_count).toBe(1)
        expect(enabledBody.summary.coverage_count).toBe(1)
        expect(enabledBody.checkpoints.scope.latest_time_updated).toBe(500)
        expect(enabledBody.checkpoints.scope.changed).toBe(false)
        expect(enabledBody.checkpoints.findings.latest_time_updated).toBe(2_000)
        expect(enabledBody.checkpoints.findings.changed).toBe(false)
        expect(enabledBody.checkpoints.chains.latest_time_updated).toBe(2_000)
        expect(enabledBody.checkpoints.chains.changed).toBe(false)
        expect(enabledBody.checkpoints.hypotheses.latest_time_updated).toBe(2_500)
        expect(enabledBody.checkpoints.hypotheses.changed).toBe(true)
        expect(enabledBody.checkpoints.evidence_nodes.enabled).toBe(true)
        expect(enabledBody.checkpoints.evidence_nodes.latest_time_updated).toBe(2_500)
        expect(enabledBody.checkpoints.evidence_nodes.changed).toBe(true)
        expect(enabledBody.checkpoints.evidence_edges.enabled).toBe(true)
        expect(enabledBody.checkpoints.evidence_edges.latest_time_updated).toBe(2_600)
        expect(enabledBody.checkpoints.evidence_edges.changed).toBe(true)
        expect(enabledBody.checkpoints.coverage.latest_time_updated).toBe(2_100)
        expect(enabledBody.checkpoints.coverage.changed).toBe(false)
        expect(enabledBody.checkpoints.engagement.count).toBe(1)
        expect(enabledBody.checkpoints.engagement.latest_time_updated).toBe(2_600)
        expect(enabledBody.checkpoints.engagement.changed).toBe(true)
        expect(enabledBody.sync.since).toBe(2_400)

        delete process.env["NUMASEC_SECURITY_GRAPH_READ"]

        const disabled = await app.request(`/security/${session.id}/read/summary?since=2400`)
        expect(disabled.status).toBe(200)
        const disabledBody = (await disabled.json()) as SummaryBody
        expect(disabledBody.graph_enabled).toBe(false)
        expect(disabledBody.summary.evidence_node_count).toBe(0)
        expect(disabledBody.summary.evidence_edge_count).toBe(0)
        expect(disabledBody.checkpoints.evidence_nodes.enabled).toBe(false)
        expect(disabledBody.checkpoints.evidence_nodes.count).toBe(0)
        expect(disabledBody.checkpoints.evidence_edges.enabled).toBe(false)
        expect(disabledBody.checkpoints.evidence_edges.count).toBe(0)
        expect(disabledBody.checkpoints.engagement.count).toBe(1)

        await Session.remove(session.id)
      },
    })
  })
})
