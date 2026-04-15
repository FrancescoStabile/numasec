import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SessionTable } from "../../src/session/session.sql"
import { Database, eq } from "../../src/storage/db"
import { FindingTable } from "../../src/security/security.sql"
import { CreateControlCaseTool } from "../../src/security/tool/create-control-case"
import { FinalizeFindingTool } from "../../src/security/tool/finalize-finding"
import { RecordEvidenceTool } from "../../src/security/tool/record-evidence"
import { UpsertHypothesisTool } from "../../src/security/tool/upsert-hypothesis"
import { startSecurityTarget, type SecurityTargetFixture } from "../fixture/security-target"

let app: SecurityTargetFixture

beforeAll(() => {
  app = startSecurityTarget()
})

afterAll(() => {
  app.stop()
})

function seedSession(sessionID: SessionID) {
  const projectID = ProjectID.make(`project-${sessionID}`)
  Database.use((db) =>
    db
      .insert(ProjectTable)
      .values({
        id: projectID,
        worktree: "/tmp",
        sandboxes: [],
      })
      .onConflictDoNothing()
      .run(),
  )
  Database.use((db) =>
    db
      .insert(SessionTable)
      .values({
        id: sessionID,
        project_id: projectID,
        slug: "semantic-closure-tests",
        directory: "/tmp",
        title: "semantic-closure-tests",
        version: "1",
      })
      .onConflictDoNothing()
      .run(),
  )
}

function toolContext(sessionID: SessionID): Tool.Context {
  return {
    sessionID,
    messageID: `msg-${sessionID}` as MessageID,
    agent: "test",
    abort: new AbortController().signal,
    callID: "call-test",
    extra: {},
    messages: [],
    metadata() {},
    ask: async () => {},
  }
}

async function runTool(tool: Tool.Info, args: Record<string, unknown>, sessionID: SessionID) {
  const impl = await tool.init()
  return impl.execute(args as never, toolContext(sessionID))
}

describe("semantic closure tools", () => {
  test("create_control_case returns replay artifact ids and a verification node in one call", async () => {
    const sessionID = "sess-semantic-control-case" as SessionID
    seedSession(sessionID)

    const out = await runTool(
      CreateControlCaseTool,
      {
        requests: [
          {
            url: `${app.baseUrl}/api/Products`,
            method: "GET",
          },
        ],
        assertion: {
          typed: {
            kind: "http_status",
            equals: 401,
          },
          control: "negative",
        },
      },
      sessionID,
    )

    const body = JSON.parse(out.output)
    expect(body.artifact_node_ids).toHaveLength(1)
    expect(body.verification.passed).toBe(true)
    expect(body.verification_node_id).toContain("ENOD-")
  })

  test("finalize_finding can create a negative control case inline before confirmation", async () => {
    const sessionID = "sess-semantic-finalize-finding" as SessionID
    seedSession(sessionID)

    const hypothesis = await runTool(
      UpsertHypothesisTool,
      {
        statement: "Crafted login request yields authenticated success",
        predicate: "crafted login returns 200 and token material",
        asset_ref: `${app.baseUrl}/rest/user/login`,
      },
      sessionID,
    )
    const hypothesisID = (hypothesis.metadata as any).nodeID as string

    const positive = await runTool(
      RecordEvidenceTool,
      {
        type: "artifact",
        payload_text: "crafted login returned token-like material",
        request: {
          url: `${app.baseUrl}/rest/user/login`,
          method: "POST",
        },
        response: {
          status: 200,
          body: "{\"authentication\":{\"token\":\"ey.fake.token\"}}",
        },
        hypothesis_id: hypothesisID,
        assertions: [
          {
            typed: {
              kind: "http_status",
              equals: 200,
            },
            control: "positive",
          },
        ],
      },
      sessionID,
    )

    const out = await runTool(
      FinalizeFindingTool,
      {
        hypothesis_id: hypothesisID,
        title: "SQL injection authentication bypass",
        severity: "high",
        impact: "Unauthenticated users can obtain authenticated session state",
        evidence_refs: (positive.metadata as any).assertionVerificationIDs,
        impact_refs: [(positive.metadata as any).id],
        url: `${app.baseUrl}/rest/user/login`,
        method: "POST",
        parameter: "email",
        control_case: {
          requests: [
            {
              url: `${app.baseUrl}/rest/user/login`,
              method: "POST",
              headers: {
                "content-type": "application/json",
              },
              body: JSON.stringify({
                email: "nobody@example.com",
                password: "wrong",
              }),
            },
          ],
          assertion: {
            typed: {
              kind: "http_status",
              equals: 200,
            },
            control: "negative",
          },
        },
      },
      sessionID,
    )

    expect((out.metadata as any).findingID).toContain("SSEC-")
    expect((out.metadata as any).controlCase.verification_node_id).toContain("ENOD-")

    const row = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.id, ((out.metadata as any).findingID) as any))
        .get(),
    )

    expect(row?.state).toBe("verified")
    expect(row?.confirmed).toBe(true)
  })

  test("finalize_finding can hydrate closure fields from an existing finding id", async () => {
    const sessionID = "sess-semantic-finalize-finding-id" as SessionID
    seedSession(sessionID)

    const hypothesis = await runTool(
      UpsertHypothesisTool,
      {
        statement: "Profile endpoint leaks another user's data",
        predicate: "profile read returns victim record",
        asset_ref: `${app.baseUrl}/api/profile/1`,
      },
      sessionID,
    )
    const hypothesisID = (hypothesis.metadata as any).nodeID as string

    const positive = await runTool(
      RecordEvidenceTool,
      {
        type: "artifact",
        payload_text: "victim profile data returned",
        request: {
          url: `${app.baseUrl}/api/profile/1`,
          method: "GET",
        },
        response: {
          status: 200,
          body: "{\"id\":1,\"email\":\"victim@example.com\"}",
        },
        hypothesis_id: hypothesisID,
        assertions: [
          {
            typed: {
              kind: "http_status",
              equals: 200,
            },
            control: "positive",
          },
        ],
      },
      sessionID,
    )

    Database.use((db) =>
      db
        .insert(FindingTable)
        .values({
          id: "SSEC-FINALIZE-BY-ID" as any,
          session_id: sessionID,
          title: "Foreign profile read",
          severity: "high",
          description: "Victim profile data is readable",
          evidence: "",
          confirmed: false,
          state: "provisional",
          family: "",
          source_hypothesis_id: hypothesisID,
          root_cause_key: "profile-idor",
          suppression_reason: "",
          reportable: true,
          manual_override: true,
          url: `${app.baseUrl}/api/profile/1`,
          method: "GET",
          parameter: "",
          payload: "",
          confidence: 0.8,
          tool_used: "manual",
          remediation_summary: "Enforce ownership checks",
          owasp_category: "A01:2021 - Broken Access Control",
        })
        .run(),
    )

    const out = await runTool(
      FinalizeFindingTool,
      {
        finding_id: "SSEC-FINALIZE-BY-ID",
        evidence_refs: (positive.metadata as any).assertionVerificationIDs,
        impact_refs: [(positive.metadata as any).id],
        control_case: {
          requests: [
            {
              url: `${app.baseUrl}/api/profile`,
              method: "GET",
            },
          ],
          assertion: {
            typed: {
              kind: "http_status",
              equals: 200,
            },
            control: "negative",
          },
        },
      },
      sessionID,
    )

    expect((out.metadata as any).findingID).toBe("SSEC-FINALIZE-BY-ID")

    const row = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.id, "SSEC-FINALIZE-BY-ID" as any))
        .get(),
    )

    expect(row?.state).toBe("verified")
    expect(row?.confirmed).toBe(true)
  })
})
