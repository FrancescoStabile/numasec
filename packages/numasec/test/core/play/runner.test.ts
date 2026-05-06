import { describe, expect, test } from "bun:test"
import { PlayRegistry, PlayRunner, PlayArgError, PlayNotFoundError } from "../../../src/core/play"
import type { Play, NormalizedToolStep, NormalizedSkillStep, PlayEnvironment } from "../../../src/core/play"

describe("core/play/runner", () => {
  test("registry exposes the 12 GA plays", () => {
    const ids = PlayRegistry.ids().sort()
    expect(ids).toEqual(["api-surface", "appsec-triage", "appsec-web-triage", "auth-surface", "binary-triage", "cloud-posture", "container-surface", "ctf-warmup", "iac-triage", "network-surface", "osint-target", "web-surface"])
    for (const id of ids) {
      const p = PlayRegistry.get(id)!
      expect(p.id).toBe(id)
      expect(p.name.length).toBeGreaterThan(0)
      expect(p.description.length).toBeGreaterThan(0)
      expect(p.steps.length).toBeGreaterThan(0)
    }
  })

  test("runner resolves tool and skill steps in declared order with template substitution", () => {
    const fake: Play = {
      id: "__fake",
      name: "Fake",
      description: "test-only",
      args: [{ name: "target", required: true, type: "string" }],
      steps: [
        { skill: "passive-osint", brief: "sweep {{target}}" },
        { tool: "scanner", args: { target: "{{target}}", profile: "light" } },
        { tool: "bash", args: { command: "echo {{target}} {{missing|fallback}}" } },
      ],
    }
    // inject fake into the registry's internal map via monkey patch for this test only
    const originalGet = PlayRegistry.get
    ;(PlayRegistry as any).get = (id: string) => (id === fake.id ? fake : originalGet(id))
    try {
      const res = PlayRunner.run({ id: "__fake", args: { target: "acme.com" } })
      expect(res.trace.length).toBe(3)
      expect(res.trace[0]).toEqual({ kind: "skill", skill: "passive-osint", brief: "sweep acme.com" })
      expect(res.trace[1]).toEqual({ kind: "tool", tool: "scanner", args: { target: "acme.com", profile: "light" } })
      expect(res.trace[2]).toEqual({ kind: "tool", tool: "bash", args: { command: "echo acme.com fallback" } })
    } finally {
      ;(PlayRegistry as any).get = originalGet
    }
  })

  test("runner rejects missing required args", () => {
    expect(() => PlayRunner.run({ id: "web-surface", args: {} })).toThrow(PlayArgError)
    expect(() => PlayRunner.run({ id: "network-surface", args: {} })).toThrow(PlayArgError)
  })

  test("runner rejects unknown play id", () => {
    expect(() => PlayRunner.run({ id: "does-not-exist" })).toThrow(PlayNotFoundError)
  })

  describe("web-surface play", () => {
    const TARGET = "https://app.example.com"

    test("omitted domain: skips passive-osint so local web mapping starts immediately", () => {
      const res = PlayRunner.run({
        id: "web-surface",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(), runtimes: { browser: true } },
      })
      expect(res.trace[0]).toEqual({
        kind: "tool",
        label: "crawl target",
        tool: "scanner",
        args: {
          mode: "crawl",
          target: TARGET,
          options: { maxUrls: 50, maxDepth: 2, timeout: 10_000 },
        },
      })
      expect(res.skipped.length).toBe(1)
      expect(res.skipped[0].reason).toBe('if "domain" was falsy')
    })

    test("degraded path: resolves passive osint, crawl, js, dir-fuzz and skips browser passive when browser runtime is unavailable", () => {
      const res = PlayRunner.run({
        id: "web-surface",
        args: { target: TARGET, domain: "example.com" },
        environment: { binaries: new Set<string>(), runtimes: { browser: false } },
      })

      expect(res.trace).toEqual([
        {
          kind: "skill",
          skill: "passive-osint",
          brief: "enumerate subdomains of example.com using crt.sh, wayback, theHarvester, holehe — no active probes, passive only",
        },
        {
          kind: "tool",
          label: "crawl target",
          tool: "scanner",
          args: {
            mode: "crawl",
            target: TARGET,
            options: { maxUrls: 50, maxDepth: 2, timeout: 10_000 },
          },
        },
        {
          kind: "tool",
          label: "JavaScript endpoint extraction",
          tool: "scanner",
          args: {
            mode: "js",
            target: TARGET,
            options: { maxFiles: 20, timeout: 10_000 },
          },
        },
        {
          kind: "tool",
          label: "Light web dir-fuzz",
          tool: "scanner",
          args: {
            mode: "dir-fuzz",
            target: TARGET,
            options: {
              concurrency: 10,
              timeout: 10_000,
              wordlist: ["common"],
              extensions: ["php", "txt", "js"],
              filterStatus: [200, 201, 204, 301, 302, 307, 308, 401, 403],
            },
          },
        },
      ])
      expect(res.skipped.length).toBe(1)
      expect(res.skipped[0].reason).toBe("missing optional capability: browser runtime")
    })

    test("ready path: includes browser passive findings when browser runtime is available", () => {
      const res = PlayRunner.run({
        id: "web-surface",
        args: { target: TARGET, domain: "example.com" },
        environment: { binaries: new Set<string>(), runtimes: { browser: true } },
      })

      expect(res.trace).toEqual([
        {
          kind: "skill",
          skill: "passive-osint",
          brief: "enumerate subdomains of example.com using crt.sh, wayback, theHarvester, holehe — no active probes, passive only",
        },
        {
          kind: "tool",
          label: "crawl target",
          tool: "scanner",
          args: {
            mode: "crawl",
            target: TARGET,
            options: { maxUrls: 50, maxDepth: 2, timeout: 10_000 },
          },
        },
        {
          kind: "tool",
          label: "JavaScript endpoint extraction",
          tool: "scanner",
          args: {
            mode: "js",
            target: TARGET,
            options: { maxFiles: 20, timeout: 10_000 },
          },
        },
        {
          kind: "tool",
          label: "Light web dir-fuzz",
          tool: "scanner",
          args: {
            mode: "dir-fuzz",
            target: TARGET,
            options: {
              concurrency: 10,
              timeout: 10_000,
              wordlist: ["common"],
              extensions: ["php", "txt", "js"],
              filterStatus: [200, 201, 204, 301, 302, 307, 308, 401, 403],
            },
          },
        },
        {
          kind: "tool",
          label: "Browser passive findings",
          tool: "browser",
          args: { action: "passive_appsec", url: TARGET },
        },
      ])
      expect(res.skipped.length).toBe(0)
    })
  })

  describe("network-surface play", () => {
    const TARGET = "10.0.0.5"
    const EXPECTED_PORTS = [
      21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
      1433, 1521, 2049, 3000, 3001, 3306, 3389, 4000, 5000, 5173, 5432, 5900,
      6379, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 27017,
    ]

    test("resolves normalized scanner steps without legacy network args", () => {
      const res = PlayRunner.run({
        id: "network-surface",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(), runtimes: {} },
      })

      expect(res.trace).toEqual([
        {
          kind: "tool",
          label: "Scan common TCP ports",
          tool: "scanner",
          args: {
            mode: "ports",
            target: TARGET,
            options: {
              concurrency: 50,
              timeout: 3_000,
            },
          },
        },
        {
          kind: "tool",
          label: "Probe common services on common ports",
          tool: "scanner",
          args: {
            mode: "service",
            target: TARGET,
            options: {
              ports: EXPECTED_PORTS,
              concurrency: 10,
              timeout: 5_000,
            },
          },
        },
        {
          kind: "tool",
          label: "Map to PTES intelligence gathering",
          tool: "methodology",
          args: { framework: "ptes", phase: "Intelligence Gathering" },
        },
      ])
      expect(res.skipped).toEqual([])
    })
  })

  describe("appsec-triage play", () => {
    test("resolves normalized repo-marker and grep steps without bash or unsupported grep metadata", () => {
      const res = PlayRunner.run({
        id: "appsec-triage",
        args: { path: "./fixture-repo" },
        environment: { binaries: new Set<string>(), runtimes: {} },
      })

      expect(res.trace).toEqual([
        {
          kind: "tool",
          label: "Detect Node markers",
          tool: "glob",
          args: { pattern: "package.json", path: "./fixture-repo" },
        },
        {
          kind: "tool",
          label: "Detect Python markers",
          tool: "glob",
          args: { pattern: "{pyproject.toml,requirements.txt}", path: "./fixture-repo" },
        },
        {
          kind: "tool",
          label: "Detect Go markers",
          tool: "glob",
          args: { pattern: "go.mod", path: "./fixture-repo" },
        },
        {
          kind: "tool",
          label: "Detect Rust markers",
          tool: "glob",
          args: { pattern: "Cargo.toml", path: "./fixture-repo" },
        },
        {
          kind: "tool",
          label: "Detect JVM markers",
          tool: "glob",
          args: { pattern: "{pom.xml,build.gradle}", path: "./fixture-repo" },
        },
        {
          kind: "tool",
          label: "Detect PHP markers",
          tool: "glob",
          args: { pattern: "composer.json", path: "./fixture-repo" },
        },
        {
          kind: "tool",
          label: "Find hard-coded secrets",
          tool: "grep",
          args: {
            path: "./fixture-repo",
            pattern:
              "(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]+PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]{10,}|api[_-]?key\\s*[:=]\\s*[\\\"'][^\\\"']{16,}|password\\s*[:=]\\s*[\\\"'][^\\\"']{4,})",
          },
        },
        {
          kind: "tool",
          label: "Find dynamic code execution patterns",
          tool: "grep",
          args: {
            path: "./fixture-repo",
            pattern: "\\beval\\s*\\(|\\bexec\\s*\\(|Function\\s*\\(|new Function\\(",
          },
        },
        {
          kind: "tool",
          label: "Find unsafe deserialization patterns",
          tool: "grep",
          args: {
            path: "./fixture-repo",
            pattern: "pickle\\.loads|yaml\\.load\\b|ObjectInputStream|Marshal\\.load|unserialize\\(",
          },
        },
        {
          kind: "tool",
          label: "Find SQL string concatenation patterns",
          tool: "grep",
          args: {
            path: "./fixture-repo",
            pattern:
              "(SELECT|INSERT|UPDATE|DELETE)\\s+[^;]*['\\\"]\\s*\\+|query\\([^)]*\\$\\{|execute\\([^)]*%s",
          },
        },
        {
          kind: "tool",
          label: "Map to WSTG input validation",
          tool: "methodology",
          args: { framework: "wstg", phase: "WSTG-INPV" },
        },
      ])
      expect(res.skipped).toEqual([])
    })
  })

  describe("appsec-web-triage play", () => {
    test("resolves web DAST steps through semantic probe completion", () => {
      const res = PlayRunner.run({
        id: "appsec-web-triage",
        args: { target: "https://app.example.com" },
        environment: { binaries: new Set<string>(), runtimes: { browser: false } },
      })

      expect(res.trace.map((item) => (item.kind === "tool" ? item.tool : item.skill))).toEqual([
        "doctor",
        "knowledge",
        "scanner",
        "scanner",
        "appsec_probe",
      ])
      expect(res.skipped).toEqual([])
    })
  })

  describe("osint-target play", () => {
    test("writes a real markdown scaffold instead of instruction-shaped write args", () => {
      const res = PlayRunner.run({
        id: "osint-target",
        args: { target: "example.com" },
        environment: { binaries: new Set<string>(), runtimes: {} },
      })

      expect(res.trace).toEqual([
        {
          kind: "skill",
          skill: "passive-osint",
          brief:
            "run the full passive-osint workflow against example.com: crt.sh subdomains, wayback URLs, theHarvester emails/hosts, holehe for account presence",
        },
        {
          kind: "tool",
          tool: "methodology",
          args: { framework: "mitre", phase: "Reconnaissance" },
        },
        {
          kind: "tool",
          tool: "write",
          args: {
            filePath: "./osint-example.com.md",
            content: `# OSINT Target Profile: example.com

## Sources reviewed

- Passive OSINT workflow executed for example.com
- crt.sh results
- Wayback URLs
- theHarvester findings
- holehe account hits

## Summary

Fill in the synthesized profile for example.com here.

## Suggested next moves

- Prioritize the most interesting subdomains
- Highlight notable account hits
- Capture high-value archived endpoints
`,
          },
        },
      ])
      expect(res.skipped).toEqual([])
    })
  })

  test("format renders an ordered, numbered step list", () => {
    const res = PlayRunner.run({ id: "network-surface", args: { target: "10.0.0.5" } })
    const out = PlayRunner.format(res)
    expect(out).toContain("# Play: Network Surface Map")
    expect(out).toMatch(/1\. tool: scanner/)
    expect(out).toMatch(/2\. tool: scanner/)
  })

  test("PlayEnvironment is exported from the barrel", () => {
    // Type-level check: if this compiles, the export exists
    const env: PlayEnvironment = { binaries: new Set<string>(), runtimes: {} }
    expect(env.binaries.size).toBe(0)
  })

  test("findUnmetRequirement prioritizes required over optional when both are unmet", () => {
    const step: NormalizedToolStep = {
      kind: "tool",
      label: "test step",
      tool: "some-tool",
      args: {},
      requires: [
        { kind: "runtime", id: "optional-rt", label: "optional runtime", missingAs: "optional" },
        { kind: "binary", id: "required-bin", label: "required binary", missingAs: "required" },
      ],
    }
    const fakePlay: Play = {
      id: "__prio",
      name: "Prio Fake",
      description: "test-only",
      args: [],
      steps: [step],
    }
    const originalGet = PlayRegistry.get
    ;(PlayRegistry as any).get = (id: string) => (id === fakePlay.id ? fakePlay : originalGet(id))
    try {
      const res = PlayRunner.run({
        id: "__prio",
        args: {},
        environment: { binaries: new Set<string>(), runtimes: {} },
      })
      expect(res.trace.length).toBe(0)
      expect(res.skipped.length).toBe(1)
      expect(res.skipped[0].reason).toBe("missing required capability: required binary")
    } finally {
      ;(PlayRegistry as any).get = originalGet
    }
  })

  test("findUnmetRequirement handles binary requirements", () => {
    const step: NormalizedToolStep = {
      kind: "tool",
      label: "needs nmap",
      tool: "scanner",
      args: {},
      requires: [{ kind: "binary", id: "nmap", label: "nmap binary", missingAs: "required" }],
    }
    const fakePlay: Play = {
      id: "__binary",
      name: "Binary Fake",
      description: "test-only",
      args: [],
      steps: [step],
    }
    const originalGet = PlayRegistry.get
    ;(PlayRegistry as any).get = (id: string) => (id === fakePlay.id ? fakePlay : originalGet(id))
    try {
      const env: PlayEnvironment = { binaries: new Set<string>(), runtimes: {} }
      const res = PlayRunner.run({ id: "__binary", args: {}, environment: env })
      expect(res.skipped.length).toBe(1)
      expect(res.skipped[0].reason).toBe("missing required capability: nmap binary")

      const envWithNmap: PlayEnvironment = { binaries: new Set(["nmap"]), runtimes: {} }
      const res2 = PlayRunner.run({ id: "__binary", args: {}, environment: envWithNmap })
      expect(res2.trace.length).toBe(1)
      expect(res2.skipped.length).toBe(0)
    } finally {
      ;(PlayRegistry as any).get = originalGet
    }
  })

  test("format renders label when present in normalized steps", () => {
    const toolStep: NormalizedToolStep = {
      kind: "tool",
      label: "run the scanner",
      tool: "scanner",
      args: { target: "{{target}}" },
    }
    const skillStep: NormalizedSkillStep = {
      kind: "skill",
      label: "gather intel",
      skill: "passive-osint",
      brief: "sweep {{target}}",
    }
    const fakePlay: Play = {
      id: "__label",
      name: "Label Fake",
      description: "test-only",
      args: [{ name: "target", required: true, type: "string" }],
      steps: [toolStep, skillStep],
    }
    const originalGet = PlayRegistry.get
    ;(PlayRegistry as any).get = (id: string) => (id === fakePlay.id ? fakePlay : originalGet(id))
    try {
      const res = PlayRunner.run({ id: "__label", args: { target: "example.com" } })
      const out = PlayRunner.format(res)
      expect(out).toContain("run the scanner")
      expect(out).toContain("gather intel")
    } finally {
      ;(PlayRegistry as any).get = originalGet
    }
  })

  test("runner skips optional step when browser capability is missing", () => {
    const crawlStep: NormalizedToolStep = {
      kind: "tool",
      label: "crawl target",
      tool: "scanner",
      args: { mode: "crawl", target: "{{target}}" },
    }
    const browserStep: NormalizedToolStep = {
      kind: "tool",
      label: "browser passive appsec",
      tool: "browser",
      args: { action: "passive_appsec", url: "{{target}}" },
      requires: [{ kind: "runtime", id: "browser", label: "browser runtime", missingAs: "optional" }],
    }
    const fakeNormalized: Play = {
      id: "__normalized",
      name: "Normalized Fake",
      description: "test-only",
      args: [{ name: "target", required: true, type: "string" }],
      steps: [crawlStep, browserStep],
    }
    const originalGet = PlayRegistry.get
    ;(PlayRegistry as any).get = (id: string) => (id === fakeNormalized.id ? fakeNormalized : originalGet(id))
    try {
      const res = PlayRunner.run({
        id: "__normalized",
        args: { target: "https://example.com" },
        environment: { binaries: new Set<string>(), runtimes: { browser: false } },
      })
      expect(res.trace.length).toBe(1)
      expect(res.trace[0]).toEqual({
        kind: "tool",
        label: "crawl target",
        tool: "scanner",
        args: { mode: "crawl", target: "https://example.com" },
      })
      expect(res.skipped.length).toBe(1)
      expect(res.skipped[0].reason).toBe("missing optional capability: browser runtime")
    } finally {
      ;(PlayRegistry as any).get = originalGet
    }
  })

  describe("api-surface play", () => {
    const TARGET = "https://api.example.com"

    test("resolves 3 steps and skips browser passive when browser runtime is unavailable", () => {
      const res = PlayRunner.run({
        id: "api-surface",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(), runtimes: { browser: false } },
      })
      expect(res.trace.length).toBe(3)
      expect(res.trace).toEqual([
        {
          kind: "tool",
          label: "crawl target",
          tool: "scanner",
          args: {
            mode: "crawl",
            target: TARGET,
            options: { maxUrls: 50, maxDepth: 2, timeout: 10_000 },
          },
        },
        {
          kind: "tool",
          label: "JavaScript endpoint extraction",
          tool: "scanner",
          args: {
            mode: "js",
            target: TARGET,
            options: { maxFiles: 20, timeout: 10_000 },
          },
        },
        {
          kind: "tool",
          label: "Light API dir-fuzz",
          tool: "scanner",
          args: {
            mode: "dir-fuzz",
            target: TARGET,
            options: {
              concurrency: 10,
              timeout: 10_000,
              wordlist: ["common", "api"],
              extensions: ["json", "txt"],
              filterStatus: [200, 201, 204, 301, 302, 307, 308, 401, 403],
            },
          },
        },
      ])
      expect(res.skipped.length).toBe(1)
      expect(res.skipped[0].reason).toContain("browser runtime")
      expect(res.skipped[0].reason).toContain("optional")
    })

    test("resolves 4 steps including browser passive when browser runtime is available", () => {
      const res = PlayRunner.run({
        id: "api-surface",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(), runtimes: { browser: true } },
      })
      expect(res.trace).toEqual([
        {
          kind: "tool",
          label: "crawl target",
          tool: "scanner",
          args: {
            mode: "crawl",
            target: TARGET,
            options: { maxUrls: 50, maxDepth: 2, timeout: 10_000 },
          },
        },
        {
          kind: "tool",
          label: "JavaScript endpoint extraction",
          tool: "scanner",
          args: {
            mode: "js",
            target: TARGET,
            options: { maxFiles: 20, timeout: 10_000 },
          },
        },
        {
          kind: "tool",
          label: "Light API dir-fuzz",
          tool: "scanner",
          args: {
            mode: "dir-fuzz",
            target: TARGET,
            options: {
              concurrency: 10,
              timeout: 10_000,
              wordlist: ["common", "api"],
              extensions: ["json", "txt"],
              filterStatus: [200, 201, 204, 301, 302, 307, 308, 401, 403],
            },
          },
        },
        {
          kind: "tool",
          label: "Browser passive findings",
          tool: "browser",
          args: {
            action: "passive_appsec",
            url: TARGET,
          },
        },
      ])
      expect(res.skipped.length).toBe(0)
    })

    test("all normalized steps carry labels in declared order", () => {
      const res = PlayRunner.run({
        id: "api-surface",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(), runtimes: { browser: true } },
      })
      expect(res.trace[0].label).toBeTruthy()
      expect(res.trace[1].label).toBeTruthy()
      expect(res.trace[2].label).toBeTruthy()
      expect(res.trace[3].label).toBeTruthy()
    })

    test("target template is substituted in every step", () => {
      const res = PlayRunner.run({
        id: "api-surface",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(), runtimes: { browser: true } },
      })
      const serialized = JSON.stringify(res.trace)
      expect(serialized).toContain(TARGET)
      expect(serialized).not.toContain("{{target}}")
    })

    test("browser passive step is the 4th step and uses browser tool", () => {
      const res = PlayRunner.run({
        id: "api-surface",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(), runtimes: { browser: true } },
      })
      const browserStep = res.trace[3]
      expect(browserStep).toMatchObject({ kind: "tool", tool: "browser" })
    })
  })

  test("runner runs optional step when browser capability is present", () => {
    const crawlStep: NormalizedToolStep = {
      kind: "tool",
      label: "crawl target",
      tool: "scanner",
      args: { mode: "crawl", target: "{{target}}" },
    }
    const browserStep: NormalizedToolStep = {
      kind: "tool",
      label: "browser passive appsec",
      tool: "browser",
      args: { action: "passive_appsec", url: "{{target}}" },
      requires: [{ kind: "runtime", id: "browser", label: "browser runtime", missingAs: "optional" }],
    }
    const fakeNormalized: Play = {
      id: "__normalized2",
      name: "Normalized Fake 2",
      description: "test-only",
      args: [{ name: "target", required: true, type: "string" }],
      steps: [crawlStep, browserStep],
    }
    const originalGet = PlayRegistry.get
    ;(PlayRegistry as any).get = (id: string) => (id === fakeNormalized.id ? fakeNormalized : originalGet(id))
    try {
      const res = PlayRunner.run({
        id: "__normalized2",
        args: { target: "https://example.com" },
        environment: { binaries: new Set<string>(), runtimes: { browser: true } },
      })
      expect(res.trace.length).toBe(2)
      expect(res.skipped.length).toBe(0)
      expect(res.trace[1]).toEqual({
        kind: "tool",
        label: "browser passive appsec",
        tool: "browser",
        args: { action: "passive_appsec", url: "https://example.com" },
      })
    } finally {
      ;(PlayRegistry as any).get = originalGet
    }
  })

  describe("auth-surface play", () => {
    const TARGET = "https://auth.example.com"

    test("degraded path: skips browser step and reports browser runtime in reason when browser unavailable", () => {
      const res = PlayRunner.run({
        id: "auth-surface",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(), runtimes: { browser: false } },
      })
      expect(res.trace).toEqual([
        {
          kind: "tool",
          label: "crawl auth entrypoints",
          tool: "scanner",
          args: { mode: "crawl", target: TARGET, options: { maxUrls: 50, maxDepth: 2, timeout: 10_000 } },
        },
        {
          kind: "tool",
          label: "extract auth hints from javascript",
          tool: "scanner",
          args: { mode: "js", target: TARGET, options: { maxFiles: 20, timeout: 10_000 } },
        },
      ])
      expect(res.skipped.length).toBe(1)
      expect(res.skipped[0].reason).toBe("missing optional capability: browser runtime")
    })

    test("ready path: zero skipped when browser runtime is available", () => {
      const res = PlayRunner.run({
        id: "auth-surface",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(), runtimes: { browser: true } },
      })
      expect(res.trace.length).toBe(3)
      expect(res.skipped.length).toBe(0)
      expect(res.trace).toEqual([
        {
          kind: "tool",
          label: "crawl auth entrypoints",
          tool: "scanner",
          args: { mode: "crawl", target: TARGET, options: { maxUrls: 50, maxDepth: 2, timeout: 10_000 } },
        },
        {
          kind: "tool",
          label: "extract auth hints from javascript",
          tool: "scanner",
          args: { mode: "js", target: TARGET, options: { maxFiles: 20, timeout: 10_000 } },
        },
        {
          kind: "tool",
          label: "browser auth/session passive findings",
          tool: "browser",
          args: { action: "passive_appsec", url: TARGET },
        },
      ])
    })
  })

  describe("ctf-warmup play", () => {
    const TARGET = "./artifact.bin"

    test("degraded path: keeps the forensics skill and methodology but skips local enrichments when binaries are unavailable", () => {
      const res = PlayRunner.run({
        id: "ctf-warmup",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(), runtimes: {} },
      })

      expect(res.trace).toEqual([
        {
          kind: "skill",
          label: "Primary artifact triage with forensics-kit",
          skill: "forensics-kit",
          brief:
            "triage the local challenge artifact at ./artifact.bin; run file, strings (min-len 8), and exiftool where useful; use binwalk/xxd only if the artifact looks binary; summarize type, metadata, interesting strings, entropy clues, and likely next moves",
        },
        {
          kind: "tool",
          label: "Map to MITRE artifact context",
          tool: "methodology",
          args: { framework: "mitre", query: TARGET },
        },
      ])
      expect(res.skipped).toEqual([
        {
          step: {
            kind: "tool",
            label: "Local file and strings enrichment",
            tool: "bash",
            args: {
              command:
                "file {{target}} 2>/dev/null; echo ---; strings -n 8 {{target}} 2>/dev/null | head -n 80",
            },
            requires: [
              { kind: "binary", id: "file", label: "file binary", missingAs: "optional" },
              { kind: "binary", id: "strings", label: "strings binary", missingAs: "optional" },
            ],
          },
          reason: "missing optional capability: file binary",
        },
        {
          step: {
            kind: "tool",
            label: "Exif metadata enrichment",
            tool: "bash",
            args: { command: "exiftool {{target}} 2>/dev/null" },
            requires: [{ kind: "binary", id: "exiftool", label: "exiftool binary", missingAs: "optional" }],
          },
          reason: "missing optional capability: exiftool binary",
        },
      ])
    })

    test("partial binary path: skips file-strings enrichment when strings is missing", () => {
      const res = PlayRunner.run({
        id: "ctf-warmup",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(["file", "exiftool"]), runtimes: {} },
      })

      expect(res.trace).toEqual([
        {
          kind: "skill",
          label: "Primary artifact triage with forensics-kit",
          skill: "forensics-kit",
          brief:
            "triage the local challenge artifact at ./artifact.bin; run file, strings (min-len 8), and exiftool where useful; use binwalk/xxd only if the artifact looks binary; summarize type, metadata, interesting strings, entropy clues, and likely next moves",
        },
        {
          kind: "tool",
          label: "Exif metadata enrichment",
          tool: "bash",
          args: { command: "exiftool ./artifact.bin 2>/dev/null" },
        },
        {
          kind: "tool",
          label: "Map to MITRE artifact context",
          tool: "methodology",
          args: { framework: "mitre", query: TARGET },
        },
      ])
      expect(res.skipped).toEqual([
        {
          step: {
            kind: "tool",
            label: "Local file and strings enrichment",
            tool: "bash",
            args: {
              command:
                "file {{target}} 2>/dev/null; echo ---; strings -n 8 {{target}} 2>/dev/null | head -n 80",
            },
            requires: [
              { kind: "binary", id: "file", label: "file binary", missingAs: "optional" },
              { kind: "binary", id: "strings", label: "strings binary", missingAs: "optional" },
            ],
          },
          reason: "missing optional capability: strings binary",
        },
      ])
    })

    test("ready path: includes local enrichment steps when artifact triage binaries are present", () => {
      const res = PlayRunner.run({
        id: "ctf-warmup",
        args: { target: TARGET },
        environment: { binaries: new Set<string>(["file", "strings", "exiftool"]), runtimes: {} },
      })

      expect(res.trace).toEqual([
        {
          kind: "skill",
          label: "Primary artifact triage with forensics-kit",
          skill: "forensics-kit",
          brief:
            "triage the local challenge artifact at ./artifact.bin; run file, strings (min-len 8), and exiftool where useful; use binwalk/xxd only if the artifact looks binary; summarize type, metadata, interesting strings, entropy clues, and likely next moves",
        },
        {
          kind: "tool",
          label: "Local file and strings enrichment",
          tool: "bash",
          args: {
            command:
              "file ./artifact.bin 2>/dev/null; echo ---; strings -n 8 ./artifact.bin 2>/dev/null | head -n 80",
          },
        },
        {
          kind: "tool",
          label: "Exif metadata enrichment",
          tool: "bash",
          args: { command: "exiftool ./artifact.bin 2>/dev/null" },
        },
        {
          kind: "tool",
          label: "Map to MITRE artifact context",
          tool: "methodology",
          args: { framework: "mitre", query: TARGET },
        },
      ])
      expect(res.skipped).toEqual([])
    })
  })

  describe("cloud-posture play", () => {
    test("required adapter path: skips the primary cloud step when prowler is unavailable", () => {
      const res = PlayRunner.run({
        id: "cloud-posture",
        args: { provider: "aws" },
        environment: { binaries: new Set<string>(), runtimes: {} },
      })

      expect(res.trace).toEqual([])
      expect(res.skipped).toEqual([
        {
          step: {
            kind: "tool",
            label: "Run AWS posture sweep with prowler",
            tool: "cloud_posture",
            args: { provider: "{{provider}}", mode: "quick", profile: "{{profile}}", region: "{{region}}" },
            requires: [{ kind: "binary", id: "prowler", label: "prowler adapter", missingAs: "required" }],
          },
          reason: "missing required capability: prowler adapter",
        },
      ])
    })

    test("ready path: resolves the cloud adapter step when prowler is available", () => {
      const res = PlayRunner.run({
        id: "cloud-posture",
        args: { provider: "aws", profile: "dev", region: "eu-west-1" },
        environment: { binaries: new Set<string>(["prowler"]), runtimes: {} },
      })

      expect(res.trace).toEqual([
        {
          kind: "tool",
          label: "Run AWS posture sweep with prowler",
          tool: "cloud_posture",
          args: {
            provider: "aws",
            mode: "quick",
            profile: "dev",
            region: "eu-west-1",
          },
        },
      ])
      expect(res.skipped).toEqual([])
    })
  })

  describe("container-surface play", () => {
    test("required adapter path: skips the primary image step when trivy is unavailable", () => {
      const res = PlayRunner.run({
        id: "container-surface",
        args: { image: "nginx:latest" },
        environment: { binaries: new Set<string>(), runtimes: {} },
      })

      expect(res.trace).toEqual([])
      expect(res.skipped).toEqual([
        {
          step: {
            kind: "tool",
            label: "Run container image triage with trivy",
            tool: "container_surface",
            args: { image: "{{image}}", mode: "quick" },
            requires: [{ kind: "binary", id: "trivy", label: "trivy adapter", missingAs: "required" }],
          },
          reason: "missing required capability: trivy adapter",
        },
      ])
    })

    test("ready path: resolves the container adapter step when trivy is available", () => {
      const res = PlayRunner.run({
        id: "container-surface",
        args: { image: "nginx:latest" },
        environment: { binaries: new Set<string>(["trivy"]), runtimes: {} },
      })

      expect(res.trace).toEqual([
        {
          kind: "tool",
          label: "Run container image triage with trivy",
          tool: "container_surface",
          args: {
            image: "nginx:latest",
            mode: "quick",
          },
        },
      ])
      expect(res.skipped).toEqual([])
    })
  })

  describe("iac-triage play", () => {
    test("required adapter path: skips the primary IaC step when checkov is unavailable", () => {
      const res = PlayRunner.run({
        id: "iac-triage",
        args: { path: "./iac" },
        environment: { binaries: new Set<string>(), runtimes: {} },
      })

      expect(res.trace).toEqual([])
      expect(res.skipped).toEqual([
        {
          step: {
            kind: "tool",
            label: "Run IaC scan with checkov",
            tool: "iac_triage",
            args: { path: "{{path}}", mode: "quick" },
            requires: [{ kind: "binary", id: "checkov", label: "checkov adapter", missingAs: "required" }],
          },
          reason: "missing required capability: checkov adapter",
        },
      ])
    })

    test("ready path: resolves the IaC adapter step when checkov is available", () => {
      const res = PlayRunner.run({
        id: "iac-triage",
        args: { path: "./iac" },
        environment: { binaries: new Set<string>(["checkov"]), runtimes: {} },
      })

      expect(res.trace).toEqual([
        {
          kind: "tool",
          label: "Run IaC scan with checkov",
          tool: "iac_triage",
          args: {
            path: "./iac",
            mode: "quick",
          },
        },
      ])
      expect(res.skipped).toEqual([])
    })
  })

  describe("binary-triage play", () => {
    test("required adapter path: skips the primary binary step when checksec is unavailable", () => {
      const res = PlayRunner.run({
        id: "binary-triage",
        args: { path: "./chal.bin" },
        environment: { binaries: new Set<string>(), runtimes: {} },
      })

      expect(res.trace).toEqual([])
      expect(res.skipped).toEqual([
        {
          step: {
            kind: "tool",
            label: "Run binary scan with checksec",
            tool: "binary_triage",
            args: { path: "{{path}}" },
            requires: [{ kind: "binary", id: "checksec", label: "checksec adapter", missingAs: "required" }],
          },
          reason: "missing required capability: checksec adapter",
        },
      ])
    })

    test("ready path: resolves the binary adapter step when checksec is available", () => {
      const res = PlayRunner.run({
        id: "binary-triage",
        args: { path: "./chal.bin" },
        environment: { binaries: new Set<string>(["checksec"]), runtimes: {} },
      })

      expect(res.trace).toEqual([
        {
          kind: "tool",
          label: "Run binary scan with checksec",
          tool: "binary_triage",
          args: {
            path: "./chal.bin",
          },
        },
      ])
      expect(res.skipped).toEqual([])
    })
  })
})
