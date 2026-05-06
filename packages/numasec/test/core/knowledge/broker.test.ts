import { describe, expect, test } from "bun:test"
import { KnowledgeBroker } from "../../../src/core/knowledge"

function response(json: unknown, status = 200) {
  return new Response(JSON.stringify(json), {
    status,
    headers: { "content-type": "application/json" },
  })
}

describe("core/knowledge/broker", () => {
  test("builds vuln intel cards from no-key structured sources", async () => {
    const fetch = async (url: string, init?: RequestInit) => {
      if (url.includes("services.nvd.nist.gov")) {
        return response({
          vulnerabilities: [
            {
              cve: {
                id: "CVE-2026-1000",
                descriptions: [{ lang: "en", value: "Test vulnerability" }],
                lastModified: "2026-01-01T00:00:00.000",
                metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8 }, baseSeverity: "CRITICAL" }] },
                references: [{ url: "https://vendor.example/advisory" }],
              },
            },
          ],
        })
      }
      if (url.includes("known_exploited_vulnerabilities")) {
        return response({ vulnerabilities: [{ cveID: "CVE-2026-1000", dueDate: "2026-03-01" }] })
      }
      if (url.includes("api.first.org")) {
        return response({ data: [{ cve: "CVE-2026-1000", epss: "0.91", percentile: "0.99" }] })
      }
      if (url.includes("api.osv.dev")) return response({ vulns: [] })
      if (url.includes("api.github.com")) return response([])
      throw new Error(`unexpected fetch ${url} ${init?.method ?? "GET"}`)
    }

    const result = await KnowledgeBroker.query(
      {
        intent: "vuln_intel",
        action: "lookup",
        query: "CVE-2026-1000",
        mode: "live",
        limit: 10,
      },
      { fetch, now: () => 1_000 },
    )

    expect(result.cards).toHaveLength(1)
    const card = result.cards[0]
    expect(card?.kind).toBe("vuln_intel")
    if (card?.kind === "vuln_intel") {
      expect(card.id).toBe("CVE-2026-1000")
      expect(card.exploitation.kev).toBe(true)
      expect(card.exploitation.epss).toBe(0.91)
      expect(card.severity.cvss_v3).toBe(9.8)
    }
  })

  test("match_component evaluates NVD version ranges for nginx instead of keyword-only lookup", async () => {
    const fetch = async (url: string) => {
      if (url.includes("services.nvd.nist.gov")) {
        expect(url).toContain("virtualMatchString")
        return response({
          vulnerabilities: [
            {
              cve: {
                id: "CVE-2021-23017",
                descriptions: [{ lang: "en", value: "A security issue in nginx resolver could cause a one-byte memory overwrite." }],
                lastModified: "2021-06-01T00:00:00.000",
                metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.7 }, baseSeverity: "HIGH" }] },
                configurations: {
                  nodes: [
                    {
                      cpeMatch: [
                        {
                          vulnerable: true,
                          criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                          versionStartIncluding: "0.6.18",
                          versionEndIncluding: "1.20.0",
                        },
                      ],
                    },
                  ],
                },
                references: [{ url: "https://nginx.org/en/security_advisories.html" }],
              },
            },
          ],
        })
      }
      if (url.includes("known_exploited_vulnerabilities")) return response({ vulnerabilities: [] })
      if (url.includes("api.first.org")) return response({ data: [{ cve: "CVE-2021-23017", epss: "0.73166", percentile: "0.9732" }] })
      if (url.includes("api.osv.dev")) return response({ vulns: [] })
      if (url.includes("api.github.com")) return response([])
      throw new Error(`unexpected fetch ${url}`)
    }

    const result = await KnowledgeBroker.query(
      {
        intent: "vuln_intel",
        action: "match_component",
        query: "nginx 1.18.0",
        mode: "live",
        limit: 10,
      },
      { fetch, now: () => 1_000 },
    )

    expect(result.cards).toHaveLength(1)
    expect(result.operator_summary).toContain("conditional=1")
    const card = result.cards[0]
    expect(card?.kind).toBe("vuln_intel")
    if (card?.kind === "vuln_intel") {
      expect(card.id).toBe("CVE-2021-23017")
      expect(card.applicability.state).toBe("conditional")
      expect(card.applicability.matched_component).toBe("nginx")
      expect(card.applicability.matched_version).toBe("1.18.0")
      expect(card.applicability.version_match).toBe(true)
      expect(card.applicability.preconditions?.some((item) => item.includes("resolver"))).toBe(true)
      expect(card.exploitation.kev).toBe(false)
      expect(card.exploitation.epss_probability).toBe(0.73166)
      expect(card.exploitation.epss_percentile).toBe(0.9732)
      expect(card.safe_next_actions.some((item) => item.includes("backport"))).toBe(true)
    }
  })

  test("match_component does not mark fixed nginx versions as applicable", async () => {
    const fetch = async (url: string) => {
      if (url.includes("services.nvd.nist.gov")) {
        return response({
          vulnerabilities: [
            {
              cve: {
                id: "CVE-2021-23017",
                descriptions: [{ lang: "en", value: "nginx resolver one-byte memory overwrite" }],
                metrics: {},
                configurations: {
                  nodes: [
                    {
                      cpeMatch: [
                        {
                          vulnerable: true,
                          criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                          versionStartIncluding: "0.6.18",
                          versionEndIncluding: "1.20.0",
                        },
                      ],
                    },
                  ],
                },
                references: [],
              },
            },
          ],
        })
      }
      if (url.includes("known_exploited_vulnerabilities")) return response({ vulnerabilities: [] })
      if (url.includes("api.first.org")) return response({ data: [] })
      if (url.includes("api.osv.dev")) return response({ vulns: [] })
      if (url.includes("api.github.com")) return response([])
      throw new Error(`unexpected fetch ${url}`)
    }

    const result = await KnowledgeBroker.query(
      {
        intent: "vuln_intel",
        action: "match_component",
        query: "nginx 1.20.1",
        mode: "live",
        limit: 10,
      },
      { fetch },
    )

    const card = result.cards[0]
    expect(card?.kind).toBe("vuln_intel")
    if (card?.kind === "vuln_intel") {
      expect(card.applicability.state).toBe("not_applicable")
      expect(card.applicability.version_match).toBe(false)
    }
  })

  test("opsec_strict blocks target-specific external vuln queries", async () => {
    const result = await KnowledgeBroker.query(
      {
        intent: "vuln_intel",
        action: "enrich_observed",
        query: "https://client.example/internal/admin",
        mode: "opsec_strict",
        limit: 5,
      },
      {
        fetch: async () => {
          throw new Error("fetch should not be called")
        },
      },
    )

    expect(result.degraded).toBe(true)
    expect(result.cards).toHaveLength(0)
    expect(result.errors[0]).toContain("opsec_strict")
  })

  test("uses workspace cache for offline vulnerability intelligence", async () => {
    const cache = new Map<string, any>()
    const fetch = async (url: string) => {
      if (url.includes("services.nvd.nist.gov")) {
        return response({
          vulnerabilities: [
            {
              cve: {
                id: "CVE-2026-2000",
                descriptions: [{ lang: "en", value: "Cached vulnerability" }],
                metrics: {},
                references: [],
              },
            },
          ],
        })
      }
      if (url.includes("known_exploited_vulnerabilities")) return response({ vulnerabilities: [] })
      if (url.includes("api.first.org")) return response({ data: [] })
      if (url.includes("api.osv.dev")) return response({ vulns: [] })
      if (url.includes("api.github.com")) return response([])
      throw new Error(`unexpected fetch ${url}`)
    }
    const request = {
      intent: "vuln_intel" as const,
      action: "lookup" as const,
      query: "CVE-2026-2000",
      mode: "live" as const,
      limit: 5,
    }

    await KnowledgeBroker.query(request, {
      fetch,
      now: () => 2_000,
      readCache: async (key) => cache.get(key),
      writeCache: async (key, result) => {
        cache.set(key, result)
      },
    })

    const offline = await KnowledgeBroker.query(
      { ...request, mode: "offline" },
      {
        fetch: async () => {
          throw new Error("offline mode should not fetch")
        },
        now: () => 3_000,
        readCache: async (key) => cache.get(key),
      },
    )

    expect(offline.cards).toHaveLength(1)
    expect(offline.summary).toContain("cached")
    expect(offline.sources.some((item) => item.source_type === "cache")).toBe(true)
  })

  test("tool_docs uses installed local tool behavior instead of model memory", async () => {
    const result = await KnowledgeBroker.query(
      {
        intent: "tool_docs",
        action: "lookup",
        query: "ffuf",
        mode: "offline",
        limit: 5,
      },
      {
        which: (name) => (name === "ffuf" ? "/usr/bin/ffuf" : null),
        run: async (argv) => ({
          argv,
          stdout: argv.includes("--version") ? "ffuf 2.1.0\n" : "Usage: ffuf [flags]\n-json output json\n",
          stderr: "",
          exitCode: 0,
        }),
      },
    )

    expect(result.cards).toHaveLength(1)
    const card = result.cards[0]
    expect(card?.kind).toBe("research")
    if (card?.kind === "research") {
      expect(card.source_pack).toBe("tool_docs")
      expect(card.claims.some((claim) => claim.claim.includes("ffuf 2.1.0"))).toBe(true)
    }
  })
})
