import { describe, expect, test } from "bun:test"
import { collectNvdRanges, evaluateNvdApplicability, normalizeComponent } from "../../../src/core/knowledge"

const nodes = [
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
]

describe("core/knowledge/nvd-match", () => {
  test("matches observed versions against NVD affected ranges", () => {
    const ranges = collectNvdRanges(nodes)
    const vulnerable = evaluateNvdApplicability({
      component: normalizeComponent("nginx 1.18.0"),
      ranges,
      summary: "nginx resolver one-byte memory overwrite",
    })
    expect(vulnerable.state).toBe("conditional")
    expect(vulnerable.version_match).toBe(true)
    expect(vulnerable.preconditions.some((item) => item.includes("resolver"))).toBe(true)

    const fixed = evaluateNvdApplicability({
      component: normalizeComponent("nginx 1.20.1"),
      ranges,
      summary: "nginx resolver one-byte memory overwrite",
    })
    expect(fixed.state).toBe("not_applicable")
    expect(fixed.version_match).toBe(false)
  })

  test("does not turn incomplete matching product data into not_applicable", () => {
    const incomplete = collectNvdRanges([
      {
        cpeMatch: [
          {
            vulnerable: true,
            criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
          },
        ],
      },
    ])

    const result = evaluateNvdApplicability({
      component: normalizeComponent("nginx 1.18.0"),
      ranges: incomplete,
      summary: "nginx resolver issue",
    })

    expect(result.state).toBe("possible")
    expect(result.version_match).toBe("unknown")
    expect(result.reason).toContain("does not provide an evaluable affected version range")
  })

  test("does not exclude component-mentioned advisories when structured ranges are missing", () => {
    const result = evaluateNvdApplicability({
      component: normalizeComponent("nginx 1.18.0"),
      ranges: [],
      summary: "A vulnerability in nginx HTTP/2 handling may allow denial of service.",
    })

    expect(result.state).toBe("unknown")
    expect(result.version_match).toBe("unknown")
  })

  test("keeps non-matching product data as not_applicable", () => {
    const apacheOnly = collectNvdRanges([
      {
        cpeMatch: [
          {
            vulnerable: true,
            criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            versionEndExcluding: "2.4.50",
          },
        ],
      },
    ])

    const result = evaluateNvdApplicability({
      component: normalizeComponent("nginx 1.18.0"),
      ranges: apacheOnly,
      summary: "Apache HTTP Server path traversal",
    })

    expect(result.state).toBe("not_applicable")
    expect(result.version_match).toBe(false)
  })
})
