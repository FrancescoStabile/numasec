// Rubrics for the three benchmark scenarios. Each rubric takes the raw text
// corpus produced by the numasec session (operation numasec.md + concatenated
// assistant message parts) and returns a 0-100 score plus per-check details.
//
// The scoring is intentionally string-match based: we are evaluating whether
// the agent *observed* a thing, not whether a downstream test framework
// passed. Comparable across runs and across providers.

export type Check = {
  id: string
  label: string
  points: number
  earned: number
  evidence?: string
}

export type Score = {
  scenario: string
  score: number
  max: number
  checks: Check[]
}

function countMatches(corpus: string, re: RegExp): string[] {
  const m = corpus.match(re)
  return m ? Array.from(new Set(m)) : []
}

function awardProRata(found: number, target: number, points: number): number {
  if (target <= 0) return points
  return Math.round((Math.min(found, target) / target) * points)
}

export function scoreWebSurface(corpus: string): Score {
  const endpoints = countMatches(corpus, /\/(rest|api)\/[A-Za-z0-9_\-\/]+/g)
  const forms = countMatches(corpus, /<form[^>]*|type=["']password["']|name=["'](email|password|login|username)["']/gi)
  const secretsShape = /(api[_-]?key|secret|token|jwt|bearer|password)\s*[:=]\s*["'][A-Za-z0-9+/=_.\-]{16,}["']/i.test(
    corpus,
  ) || /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/.test(corpus)

  const checks: Check[] = [
    {
      id: "endpoints",
      label: "≥20 endpoints discovered",
      points: 50,
      earned: awardProRata(endpoints.length, 20, 50),
      evidence: `${endpoints.length} unique`,
    },
    {
      id: "forms",
      label: "≥3 forms / credential fields",
      points: 30,
      earned: awardProRata(forms.length, 3, 30),
      evidence: `${forms.length} hits`,
    },
    {
      id: "secrets_shape",
      label: "≥1 secret-shaped string in a JS chunk",
      points: 20,
      earned: secretsShape ? 20 : 0,
    },
  ]

  return {
    scenario: "web-surface",
    max: 100,
    score: checks.reduce((a, c) => a + c.earned, 0),
    checks,
  }
}

export function scoreAppsecTriage(corpus: string): Score {
  const lc = corpus.toLowerCase()
  const vulns = [
    {
      id: "sqli_search",
      label: "SQL injection in /rest/products/search",
      points: 20,
      hit:
        /\/rest\/products\/search/i.test(corpus) &&
        /(sql\s*injection|sqli|union\s+select|or\s+1\s*=\s*1)/i.test(lc),
    },
    {
      id: "xss_search",
      label: "XSS in search",
      points: 20,
      hit: /\b(xss|cross[-\s]site\s+scripting|<script)/i.test(corpus) && /search/i.test(lc),
    },
    {
      id: "broken_auth_jwt",
      label: "Broken auth / JWT weakness on /rest/user/login",
      points: 20,
      hit:
        /\/rest\/user\/login/i.test(corpus) &&
        /(jwt|broken\s+auth|weak\s+algorithm|alg\s*=\s*none|hs256|rs256)/i.test(lc),
    },
    {
      id: "idor_basket",
      label: "IDOR in basket",
      points: 20,
      hit: /basket/i.test(corpus) && /(idor|insecure\s+direct\s+object|broken\s+object\s+level)/i.test(lc),
    },
    {
      id: "weak_cors",
      label: "Weak CORS policy",
      points: 20,
      hit: /(cors|access-control-allow-origin)/i.test(lc) && /(weak|\*|misconfig|any|permissive)/i.test(lc),
    },
  ]

  const checks: Check[] = vulns.map((v) => ({
    id: v.id,
    label: v.label,
    points: v.points,
    earned: v.hit ? v.points : 0,
  }))

  const flagged = checks.filter((c) => c.earned > 0).length
  const passThreshold = flagged >= 2

  return {
    scenario: "appsec-triage",
    max: 100,
    score: passThreshold ? checks.reduce((a, c) => a + c.earned, 0) : 0,
    checks: [
      ...checks,
      {
        id: "threshold",
        label: "≥2 of 5 known vulns flagged (gate)",
        points: 0,
        earned: 0,
        evidence: passThreshold ? `passed: ${flagged}/5` : `failed: ${flagged}/5`,
      },
    ],
  }
}

export function scorePwn(corpus: string, opContext: { slug?: string; observations: number }): Score {
  const checks: Check[] = [
    {
      id: "operation_created",
      label: "Operation slug created by pwn_bootstrap",
      points: 40,
      earned: opContext.slug ? 40 : 0,
      evidence: opContext.slug ?? "none",
    },
    {
      id: "play_invoked",
      label: "web-surface play trace executed",
      points: 30,
      earned: /(web[-\s]?surface|recon|endpoint|http)/i.test(corpus) ? 30 : 0,
    },
    {
      id: "observations",
      label: "≥1 observation written",
      points: 30,
      earned: opContext.observations >= 1 ? 30 : 0,
      evidence: `${opContext.observations} files`,
    },
  ]

  return {
    scenario: "pwn",
    max: 100,
    score: checks.reduce((a, c) => a + c.earned, 0),
    checks,
  }
}

export function scoreFor(
  scenario: string,
  corpus: string,
  opContext: { slug?: string; observations: number },
): Score {
  if (scenario === "web-surface") return scoreWebSurface(corpus)
  if (scenario === "appsec-triage") return scoreAppsecTriage(corpus)
  if (scenario === "pwn") return scorePwn(corpus, opContext)
  throw new Error(`unknown scenario: ${scenario}`)
}
