import { describe, expect, test } from "bun:test"
import { buildChainGroups } from "../../src/security/chain-builder"
import type { FindingTable } from "../../src/security/security.sql"

type Finding = typeof FindingTable.$inferSelect

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: overrides.id ?? ("SSEC-TEST000001" as any),
    session_id: "test-session" as any,
    target_id: null,
    title: overrides.title ?? "Test Finding",
    severity: overrides.severity ?? "medium",
    description: overrides.description ?? "",
    evidence: overrides.evidence ?? "",
    confirmed: overrides.confirmed ?? false,
    false_positive: false,
    url: overrides.url ?? "http://example.com/api/users",
    method: overrides.method ?? "GET",
    parameter: overrides.parameter ?? "",
    payload: overrides.payload ?? "",
    request_dump: overrides.request_dump ?? "",
    response_status: overrides.response_status ?? null,
    cwe_id: overrides.cwe_id ?? "",
    cvss_score: overrides.cvss_score ?? 5.0,
    cvss_vector: overrides.cvss_vector ?? "",
    owasp_category: overrides.owasp_category ?? "",
    attack_technique: overrides.attack_technique ?? "",
    rule_id: overrides.rule_id ?? "",
    wstg_id: overrides.wstg_id ?? "",
    confidence: overrides.confidence ?? 0.8,
    chain_id: overrides.chain_id ?? "",
    related_finding_ids: overrides.related_finding_ids ?? null,
    tool_used: overrides.tool_used ?? "",
    remediation_summary: overrides.remediation_summary ?? "",
    time_created: Date.now(),
    time_updated: Date.now(),
  } as Finding
}

describe("buildChainGroups", () => {
  test("returns empty for no findings", () => {
    expect(buildChainGroups([])).toEqual([])
  })

  test("returns empty for single finding (no chain possible)", () => {
    const findings = [makeFinding({ id: "SSEC-001" as any })]
    expect(buildChainGroups(findings)).toEqual([])
  })

  test("groups findings by URL base path", () => {
    const findings = [
      makeFinding({ id: "SSEC-001" as any, url: "http://example.com/api/users?id=1", title: "SQLi in users", severity: "critical" }),
      makeFinding({ id: "SSEC-002" as any, url: "http://example.com/api/users/profile", title: "IDOR in users", severity: "high" }),
    ]

    const chains = buildChainGroups(findings)
    expect(chains.length).toBe(1)
    expect(chains[0].findings.length).toBe(2)
    expect(chains[0].id).toBe("CHAIN-001")
  })

  test("does NOT group findings from different paths", () => {
    const findings = [
      makeFinding({ id: "SSEC-001" as any, url: "http://example.com/api/users", title: "SQLi" }),
      makeFinding({ id: "SSEC-002" as any, url: "http://example.com/admin/dashboard", title: "IDOR" }),
    ]

    const chains = buildChainGroups(findings)
    expect(chains.length).toBe(0)
  })

  test("chain title joins unique finding titles with →", () => {
    const findings = [
      makeFinding({ id: "SSEC-001" as any, url: "http://example.com/api/v1/login", title: "SQL Injection in login", severity: "critical" }),
      makeFinding({ id: "SSEC-002" as any, url: "http://example.com/api/v1/token", title: "Weak JWT in token endpoint", severity: "high" }),
    ]

    const chains = buildChainGroups(findings)
    expect(chains.length).toBe(1)
    expect(chains[0].title).toContain("→")
  })

  test("chain severity is the highest severity finding", () => {
    const findings = [
      makeFinding({ id: "SSEC-001" as any, url: "http://example.com/api/data", title: "Info leak", severity: "low" }),
      makeFinding({ id: "SSEC-002" as any, url: "http://example.com/api/data/export", title: "SQLi", severity: "critical" }),
    ]

    const chains = buildChainGroups(findings)
    expect(chains[0].severity).toBe("critical")
  })

  test("merges via related_finding_ids for findings on different paths", () => {
    const findings = [
      makeFinding({
        id: "SSEC-001" as any,
        url: "http://a.com/path1",
        title: "Finding A",
        related_finding_ids: ["SSEC-002"],
      }),
      makeFinding({
        id: "SSEC-002" as any,
        url: "http://b.com/path2",
        title: "Finding B",
      }),
    ]

    const chains = buildChainGroups(findings)
    expect(chains.length).toBe(1)
    expect(chains[0].findings.length).toBe(2)
  })

  test("handles invalid URLs gracefully", () => {
    const findings = [
      makeFinding({ id: "SSEC-001" as any, url: "not-a-url", title: "A" }),
      makeFinding({ id: "SSEC-002" as any, url: "also-not-a-url", title: "B" }),
    ]

    const chains = buildChainGroups(findings)
    expect(chains.length).toBe(1)
  })

  test("multiple chains from different path groups", () => {
    // basePath = hostname + first 2 path segments: /api/users and /admin/panel
    const findings = [
      makeFinding({ id: "SSEC-001" as any, url: "http://example.com/api/users/1", title: "SQLi" }),
      makeFinding({ id: "SSEC-002" as any, url: "http://example.com/api/users/2", title: "IDOR" }),
      makeFinding({ id: "SSEC-003" as any, url: "http://example.com/admin/panel/settings", title: "CSRF" }),
      makeFinding({ id: "SSEC-004" as any, url: "http://example.com/admin/panel/config", title: "Info Disclosure" }),
    ]

    const chains = buildChainGroups(findings)
    expect(chains.length).toBe(2)
  })

  test("chain IDs are sequential", () => {
    const findings = [
      makeFinding({ id: "SSEC-001" as any, url: "http://example.com/api/users/a", title: "A" }),
      makeFinding({ id: "SSEC-002" as any, url: "http://example.com/api/users/b", title: "B" }),
      makeFinding({ id: "SSEC-003" as any, url: "http://example.com/admin/panel/c", title: "C" }),
      makeFinding({ id: "SSEC-004" as any, url: "http://example.com/admin/panel/d", title: "D" }),
    ]

    const chains = buildChainGroups(findings)
    expect(chains[0].id).toBe("CHAIN-001")
    expect(chains[1].id).toBe("CHAIN-002")
  })

  test("does not create a chain from duplicate default-credential variants on one endpoint", () => {
    const findings = [
      makeFinding({
        id: "SSEC-001" as any,
        url: "http://example.com/rest/user/login",
        title: "Default credentials work for admin",
        severity: "high",
        cwe_id: "CWE-798",
        tool_used: "auth_test",
      }),
      makeFinding({
        id: "SSEC-002" as any,
        url: "http://example.com/rest/user/login",
        title: "Default credentials work for user",
        severity: "high",
        cwe_id: "CWE-798",
        tool_used: "auth_test",
      }),
    ]

    expect(buildChainGroups(findings)).toEqual([])
  })

  test("does not create a chain from duplicate common-credential variants on one endpoint", () => {
    const findings = [
      makeFinding({
        id: "SSEC-101" as any,
        url: "http://example.com/rest/user/login",
        title: "Common credentials work for admin@admin.com",
        severity: "high",
        cwe_id: "CWE-521",
        tool_used: "auth_test",
      }),
      makeFinding({
        id: "SSEC-102" as any,
        url: "http://example.com/rest/user/login",
        title: "Common credentials work for test",
        severity: "high",
        cwe_id: "CWE-521",
        tool_used: "auth_test",
      }),
    ]

    expect(buildChainGroups(findings)).toEqual([])
  })

  test("still chains distinct finding families on the same endpoint cluster", () => {
    const findings = [
      makeFinding({
        id: "SSEC-001" as any,
        url: "http://example.com/api/users",
        title: "Default credentials work for admin",
        severity: "high",
        cwe_id: "CWE-798",
        tool_used: "auth_test",
      }),
      makeFinding({
        id: "SSEC-002" as any,
        url: "http://example.com/api/users",
        title: "Mass assignment accepted protected field role",
        severity: "high",
        cwe_id: "CWE-915",
        tool_used: "access_control_test",
      }),
    ]

    const chains = buildChainGroups(findings)
    expect(chains.length).toBe(1)
    expect(chains[0].findings.length).toBe(2)
    expect(chains[0].title).toContain("→")
  })
})
