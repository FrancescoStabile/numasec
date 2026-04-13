import { describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { SessionID, MessageID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SessionTable } from "../../src/session/session.sql"
import { Database, eq } from "../../src/storage/db"
import { Global } from "../../src/global"
import { EvidenceNodeTable } from "../../src/security/evidence.sql"
import { FindingTable } from "../../src/security/security.sql"
import { MutateInputTool } from "../../src/security/tool/mutate-input"
import { ExtractObservationTool } from "../../src/security/tool/extract-observation"
import { VerifyAssertionTool } from "../../src/security/tool/verify-assertion"
import { RecordEvidenceTool } from "../../src/security/tool/record-evidence"
import { SaveFindingTool } from "../../src/security/tool/save-finding"
import { UpsertHypothesisTool } from "../../src/security/tool/upsert-hypothesis"
import { UpsertFindingTool } from "../../src/security/tool/upsert-finding"
import { ConfirmFindingTool } from "../../src/security/tool/confirm-finding"
import { QueryGraphTool } from "../../src/security/tool/query-graph"
import { DeriveAttackPathsTool } from "../../src/security/tool/derive-attack-paths"
import path from "path"

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
        slug: "primitive-tests",
        directory: "/tmp",
        title: "primitive-tests",
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

describe("primitive tools", () => {
  test("mutate_input returns deterministic variants", async () => {
    const sessionID = "sess-primitive-mutate" as SessionID
    seedSession(sessionID)
    const out = await runTool(
      MutateInputTool,
      {
        base: "admin",
        strategy: "sqli",
        max_variants: 3,
      },
      sessionID,
    )

    const body = JSON.parse(out.output)
    expect(body.variants.length).toBe(3)
    expect(body.variants[0]).toContain("admin")
  })

  test("extract_observation + verify_assertion workflow", async () => {
    const sessionID = "sess-primitive-extract-verify" as SessionID
    seedSession(sessionID)
    const extract = await runTool(
      ExtractObservationTool,
      {
        text: "HTTP 200 OK https://example.com/api/users",
        extractors: ["status_code", "url"],
        persist: true,
      },
      sessionID,
    )

    const extractBody = JSON.parse(extract.output)
    const refs = extractBody.node_ids as string[]
    expect(refs.length).toBeGreaterThan(0)

    const verify = await runTool(
      VerifyAssertionTool,
      {
        predicate: "example.com/api/users",
        evidence_refs: refs,
        mode: "substring",
        require_all: false,
      },
      sessionID,
    )

    const verifyBody = JSON.parse(verify.output)
    expect(verifyBody.passed).toBe(true)
    expect(verifyBody.matches).toBeGreaterThan(0)

    const control = await runTool(
      VerifyAssertionTool,
      {
        predicate: "no-such-token",
        evidence_refs: refs,
        mode: "substring",
        control: "negative",
      },
      sessionID,
    )
    const controlBody = JSON.parse(control.output)
    expect(controlBody.passed).toBe(true)
    expect(controlBody.control).toBe("negative")
  })

  test("verify_assertion typed modes validate status, headers, json paths, and jwt claims", async () => {
    const sessionID = "sess-primitive-typed-verify" as SessionID
    seedSession(sessionID)

    const token =
      "eyJhbGciOiJub25lIn0.eyJhdWQiOiJteWFkanJhbmsiLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vbXlhZGpyYW5rIn0."
    const node = await runTool(
      RecordEvidenceTool,
      {
        type: "artifact",
        payload: {
          response: {
            status: 200,
            headers: {
              "access-control-allow-origin": "https://attacker-controlled.example.com",
            },
            body: {
              idToken: token,
            },
          },
        },
      },
      sessionID,
    )
    const ref = (node.metadata as any).id as string

    const status = await runTool(
      VerifyAssertionTool,
      {
        evidence_refs: [ref],
        typed: {
          kind: "http_status",
          equals: 200,
        },
      },
      sessionID,
    )
    expect(JSON.parse(status.output).passed).toBe(true)

    const header = await runTool(
      VerifyAssertionTool,
      {
        evidence_refs: [ref],
        typed: {
          kind: "header",
          name: "Access-Control-Allow-Origin",
          contains: "attacker-controlled.example.com",
        },
      },
      sessionID,
    )
    expect(JSON.parse(header.output).passed).toBe(true)

    const jsonPath = await runTool(
      VerifyAssertionTool,
      {
        evidence_refs: [ref],
        typed: {
          kind: "json_path",
          path: "response.body.idToken",
          op: "exists",
        },
      },
      sessionID,
    )
    expect(JSON.parse(jsonPath.output).passed).toBe(true)

    const claim = await runTool(
      VerifyAssertionTool,
      {
        evidence_refs: [ref],
        typed: {
          kind: "jwt_claim",
          token_path: "response.body.idToken",
          claim: "aud",
          equals: "myadjrank",
        },
      },
      sessionID,
    )
    expect(JSON.parse(claim.output).passed).toBe(true)
  })

  test("upsert_hypothesis + upsert_finding + query_graph + derive_attack_paths", async () => {
    const sessionID = "sess-primitive-finding-flow" as SessionID
    seedSession(sessionID)

    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values({
          id: "ENOD-VERIFY-0001" as any,
          session_id: sessionID,
          type: "verification",
          fingerprint: "verify-0001",
          payload: {
            predicate: "idor confirmed",
            passed: true,
          },
          confidence: 0.9,
          source_tool: "test",
          status: "confirmed",
        })
        .onConflictDoNothing()
        .run(),
    )

    const hypothesis = await runTool(
      UpsertHypothesisTool,
      {
        statement: "IDOR in user profile endpoint",
        predicate: "user_id mismatch still returns 200",
        asset_ref: "https://example.com/api/users",
      },
      sessionID,
    )
    const hypothesisID = (hypothesis.metadata as any).nodeID as string
    expect(hypothesisID.length).toBeGreaterThan(0)

    const first = await runTool(
      UpsertFindingTool,
      {
        hypothesis_id: hypothesisID,
        title: "IDOR in profile endpoint",
        severity: "high",
        impact: "Unauthorized access to user data",
        evidence_refs: ["ENOD-VERIFY-0001"],
        url: "https://example.com/api/users/1",
        method: "GET",
        confidence: 0.95,
      },
      sessionID,
    )
    expect((first.metadata as any).findingID).toContain("SSEC-")
    expect((first.metadata as any).assertionContract.required).toBe(true)
    expect((first.metadata as any).assertionContract.status).toBe("incomplete")

    await runTool(
      UpsertFindingTool,
      {
        hypothesis_id: hypothesisID,
        title: "Privilege escalation via profile update",
        severity: "medium",
        impact: "User role can be changed without authorization",
        evidence_refs: ["ENOD-VERIFY-0001"],
        url: "https://example.com/api/users/2",
        method: "PUT",
        confidence: 0.9,
      },
      sessionID,
    )

    const graph = await runTool(
      QueryGraphTool,
      {
        node_types: ["finding"],
        limit: 10,
        include_edges: true,
      },
      sessionID,
    )
    expect((graph.envelope as any).metrics.node_count).toBeGreaterThanOrEqual(1)

    const derive = await runTool(
      DeriveAttackPathsTool,
      {
        confidence_threshold: 0.5,
      },
      sessionID,
    )
    expect((derive.metadata as any).chains).toBeGreaterThanOrEqual(1)

    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all(),
    )
    expect(rows.some((item) => item.chain_id.startsWith("CHAIN-"))).toBe(true)
  })

  test("upsert_hypothesis reuses an existing ENOD node id instead of creating a duplicate", async () => {
    const sessionID = "sess-primitive-hypothesis-reuse" as SessionID
    seedSession(sessionID)

    const first = await runTool(
      UpsertHypothesisTool,
      {
        statement: "SQL injection in login",
        predicate: "crafted payload returns authenticated response",
        asset_ref: "https://example.com/rest/user/login",
        confidence: 0.5,
      },
      sessionID,
    )
    const hypothesisID = (first.metadata as any).nodeID as string

    const second = await runTool(
      UpsertHypothesisTool,
      {
        statement: "SQL injection in login",
        predicate: "crafted payload returns authenticated response",
        asset_ref: "https://example.com/rest/user/login",
        confidence: 1,
        status: "confirmed",
        hypothesis_id: hypothesisID,
      },
      sessionID,
    )

    expect((second.metadata as any).nodeID).toBe(hypothesisID)
    const rows = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(eq(EvidenceNodeTable.session_id, sessionID))
        .all(),
    )
    const hypotheses = rows.filter((item) => item.type === "hypothesis")
    expect(hypotheses).toHaveLength(1)
    expect(hypotheses[0]?.status).toBe("confirmed")
  })

  test("record_evidence externalizes large payloads with local artifact references", async () => {
    const sessionID = "sess-primitive-record-evidence" as SessionID
    seedSession(sessionID)
    const big = "A".repeat(20_000)

    const out = await runTool(
      RecordEvidenceTool,
      {
        type: "artifact",
        payload: {
          source: "http_response",
          body: big,
        },
        artifact_mode: "auto",
        max_inline_bytes: 2048,
        source_tool: "test",
      },
      sessionID,
    )

    expect((out.metadata as any).artifactStored).toBe(true)
    const nodeID = (out.metadata as any).id as string
    const row = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(eq(EvidenceNodeTable.id, nodeID as any))
        .get(),
    )
    expect(row).toBeDefined()
    expect((row?.payload as any).artifact_id).toContain("EART-")
    const rel = (row?.payload as any).relative_path as string
    const file = Bun.file(path.join(Global.Path.data, rel))
    expect(await file.exists()).toBe(true)
  })

  test("record_evidence supports payload_text and payload_json with canonical request/response blocks", async () => {
    const sessionID = "sess-primitive-record-canonical" as SessionID
    seedSession(sessionID)

    const out = await runTool(
      RecordEvidenceTool,
      {
        type: "artifact",
        payload_text: "raw exchange note",
        payload_json: JSON.stringify({
          trace_id: "abc-123",
          marker: "integration",
        }),
        request: {
          url: "https://example.com/api/test",
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: "Bearer redacted",
          },
          body: "{\"x\":1}",
        },
        response: {
          status: 200,
          headers: {
            "Access-Control-Allow-Origin": "https://attacker.example",
          },
          body: "{\"ok\":true}",
        },
      },
      sessionID,
    )

    const nodeID = (out.metadata as any).id as string
    const row = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(eq(EvidenceNodeTable.id, nodeID as any))
        .get(),
    )
    expect(row).toBeDefined()
    expect((row?.payload as any).schema_version).toBe("evidence_payload_v2")
    expect((row?.payload as any).request.headers["authorization"]).toBe("Bearer redacted")
    expect((row?.payload as any).response.headers["access-control-allow-origin"]).toContain("attacker")
    expect(typeof (row?.payload as any).replay).toBe("string")
  })

  test("upsert_finding keeps high severity when assertion contract is complete", async () => {
    const sessionID = "sess-primitive-assertion-complete" as SessionID
    seedSession(sessionID)

    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values([
          {
            id: "ENOD-VERIFY-POSITIVE" as any,
            session_id: sessionID,
            type: "verification",
            fingerprint: "verify-positive",
            payload: {
              predicate: "idor confirmed",
              passed: true,
              control: "positive",
            },
            confidence: 0.9,
            source_tool: "test",
            status: "confirmed",
          },
          {
            id: "ENOD-VERIFY-NEGATIVE" as any,
            session_id: sessionID,
            type: "verification",
            fingerprint: "verify-negative",
            payload: {
              predicate: "idor absent on control account",
              passed: true,
              control: "negative",
            },
            confidence: 0.8,
            source_tool: "test",
            status: "confirmed",
          },
          {
            id: "ENOD-IMPACT-0001" as any,
            session_id: sessionID,
            type: "observation",
            fingerprint: "impact-0001",
            payload: {
              leaked_records: 25,
            },
            confidence: 0.8,
            source_tool: "test",
            status: "active",
          },
        ])
        .run(),
    )

    const hypothesis = await runTool(
      UpsertHypothesisTool,
      {
        statement: "IDOR in account API",
        predicate: "cross-account access",
      },
      sessionID,
    )

    const out = await runTool(
      UpsertFindingTool,
      {
        hypothesis_id: (hypothesis.metadata as any).nodeID,
        title: "IDOR in account API",
        severity: "high",
        impact: "Cross-account data exposure",
        evidence_refs: ["ENOD-VERIFY-POSITIVE"],
        negative_control_refs: ["ENOD-VERIFY-NEGATIVE"],
        impact_refs: ["ENOD-IMPACT-0001"],
        confidence: 0.9,
      },
      sessionID,
    )

    expect((out.metadata as any).severity).toBe("high")
    expect((out.metadata as any).assertionContract.status).toBe("complete")
  })

  test("upsert_finding calibrates confidence down for speculative impact without strong impact evidence", async () => {
    const sessionID = "sess-primitive-confidence-calibration" as SessionID
    seedSession(sessionID)

    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values([
          {
            id: "ENOD-CAL-POS" as any,
            session_id: sessionID,
            type: "verification",
            fingerprint: "cal-pos",
            payload: {
              predicate: "signup accepted",
              passed: true,
              control: "positive",
            },
            confidence: 0.9,
            source_tool: "test",
            status: "confirmed",
          },
          {
            id: "ENOD-CAL-NEG" as any,
            session_id: sessionID,
            type: "verification",
            fingerprint: "cal-neg",
            payload: {
              predicate: "invalid key denied",
              passed: true,
              control: "negative",
            },
            confidence: 0.8,
            source_tool: "test",
            status: "confirmed",
          },
          {
            id: "ENOD-CAL-IMPACT" as any,
            session_id: sessionID,
            type: "artifact",
            fingerprint: "cal-impact",
            payload: {
              response: {
                status: 403,
                body: "PERMISSION_DENIED",
              },
            },
            confidence: 0.8,
            source_tool: "test",
            status: "confirmed",
          },
        ])
        .run(),
    )

    const hypothesis = await runTool(
      UpsertHypothesisTool,
      {
        statement: "Speculative future abuse",
        predicate: "future billing risk",
      },
      sessionID,
    )

    const out = await runTool(
      UpsertFindingTool,
      {
        hypothesis_id: (hypothesis.metadata as any).nodeID,
        title: "Speculative quota abuse",
        severity: "high",
        impact: "This could potentially cause future billing impact",
        evidence_refs: ["ENOD-CAL-POS"],
        negative_control_refs: ["ENOD-CAL-NEG"],
        impact_refs: ["ENOD-CAL-IMPACT"],
        confidence: 0.95,
      },
      sessionID,
    )

    expect((out.metadata as any).confidence).toBeLessThanOrEqual(0.75)
  })

  test("extract_observation ignores non-http numeric noise for status code", async () => {
    const sessionID = "sess-primitive-extract-noise" as SessionID
    seedSession(sessionID)

    const out = await runTool(
      ExtractObservationTool,
      {
        text: "command failed with exit code 127 and then HTTP/1.1 200 OK",
        extractors: ["status_code"],
        persist: false,
      },
      sessionID,
    )
    const body = JSON.parse(out.output)
    const values = (body.observations as Array<{ value: string }>).map((item) => item.value)
    expect(values).toContain("200")
    expect(values).not.toContain("127")
  })

  test("save_finding follows assertion contract path and cannot bypass high severity policy", async () => {
    const sessionID = "sess-primitive-save-finding-wrapper" as SessionID
    seedSession(sessionID)

    const out = await runTool(
      SaveFindingTool,
      {
        title: "JWT none accepted",
        severity: "high",
        description: "Server accepts unsigned JWT tokens",
        url: "https://example.com/rest/user/whoami",
        method: "GET",
        parameter: "Authorization",
        payload: "alg:none token",
        evidence: "HTTP/1.1 200 OK with forged token",
        confidence: 0.95,
        tool_used: "manual",
        remediation: "Reject alg none",
        confirmed: true,
      },
      sessionID,
    )

    expect((out.metadata as any).wrappedBy).toBe("save_finding")
    const findingID = (out.metadata as any).id as string
    const row = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.id, findingID as any))
        .get(),
    )
    expect(row).toBeDefined()
    expect(row?.severity).toBe("high")
    expect(row?.state).toBe("provisional")
  })

  test("confirm_finding auto-selects verification, control, and impact evidence", async () => {
    const sessionID = "sess-primitive-confirm-finding" as SessionID
    seedSession(sessionID)

    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values([
          {
            id: "ENOD-CONFIRM-POS" as any,
            session_id: sessionID,
            type: "verification",
            fingerprint: "confirm-pos",
            payload: {
              predicate: "token issued",
              passed: true,
              control: "positive",
            },
            confidence: 0.9,
            source_tool: "test",
            status: "confirmed",
          },
          {
            id: "ENOD-CONFIRM-NEG" as any,
            session_id: sessionID,
            type: "verification",
            fingerprint: "confirm-neg",
            payload: {
              predicate: "control denied",
              passed: true,
              control: "negative",
            },
            confidence: 0.8,
            source_tool: "test",
            status: "confirmed",
          },
          {
            id: "ENOD-CONFIRM-IMPACT" as any,
            session_id: sessionID,
            type: "artifact",
            fingerprint: "confirm-impact",
            payload: {
              response: {
                status: 200,
                body: "idToken issued",
              },
            },
            confidence: 0.8,
            source_tool: "test",
            status: "confirmed",
          },
        ])
        .run(),
    )

    const hypothesis = await runTool(
      UpsertHypothesisTool,
      {
        statement: "Anonymous signup can be abused",
        predicate: "token issued to arbitrary caller",
      },
      sessionID,
    )

    const out = await runTool(
      ConfirmFindingTool,
      {
        hypothesis_id: (hypothesis.metadata as any).nodeID,
        title: "Anonymous signup abuse",
        severity: "high",
        impact: "Quota and billing abuse with token issuance",
        url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
        method: "POST",
      },
      sessionID,
    )

    expect((out.metadata as any).findingID).toContain("SSEC-")
    expect((out.metadata as any).auto_selected.evidence_refs.length).toBeGreaterThan(0)
    expect((out.metadata as any).auto_selected.negative_control_refs.length).toBeGreaterThan(0)
    expect((out.metadata as any).auto_selected.impact_refs.length).toBeGreaterThan(0)
  })
})
