import { afterEach, test, expect } from "bun:test"
import path from "path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Agent } from "../../src/agent/agent"
import { Permission } from "../../src/permission"

// Helper to evaluate permission for a tool with wildcard pattern
function evalPerm(agent: Agent.Info | undefined, permission: string): Permission.Action | undefined {
  if (!agent) return undefined
  return Permission.evaluate(permission, "*", agent.permission).action
}

afterEach(async () => {
  await Instance.disposeAll()
})

test("returns default native agents when no config", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agents = await Agent.list()
      const names = agents.map((a) => a.name)
      expect(names).toContain("pentest")
      expect(names).toContain("recon")
      expect(names).toContain("general")
      expect(names).toContain("explore")
      expect(names).toContain("compaction")
      expect(names).toContain("title")
      expect(names).toContain("summary")
    },
  })
})

test("pentest agent has correct default properties", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const pentest = await Agent.get("pentest")
      expect(pentest).toBeDefined()
      expect(pentest?.mode).toBe("primary")
      expect(pentest?.native).toBe(true)
      expect(evalPerm(pentest, "edit")).toBe("allow")
      expect(evalPerm(pentest, "bash")).toBe("ask")  // pentest restricts bash to ask
    },
  })
})

test("recon agent restricts bash to safe commands only", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const recon = await Agent.get("recon")
      expect(recon).toBeDefined()
      // Wildcard bash is denied
      expect(evalPerm(recon, "bash")).toBe("deny")
      // But specific recon commands are allowed
      expect(Permission.evaluate("bash", "nmap -sV target", recon!.permission).action).toBe("allow")
      expect(Permission.evaluate("bash", "dig example.com", recon!.permission).action).toBe("allow")
    },
  })
})

test("explore agent denies edit and write", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const explore = await Agent.get("explore")
      expect(explore).toBeDefined()
      expect(explore?.mode).toBe("subagent")
      expect(evalPerm(explore, "edit")).toBe("deny")
      expect(evalPerm(explore, "write")).toBe("deny")
      expect(evalPerm(explore, "todowrite")).toBe("deny")
    },
  })
})

test("explore agent asks for external directories and allows Truncate.GLOB", async () => {
  const { Truncate } = await import("../../src/tool/truncate")
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const explore = await Agent.get("explore")
      expect(explore).toBeDefined()
      expect(Permission.evaluate("external_directory", "/some/other/path", explore!.permission).action).toBe("ask")
      expect(Permission.evaluate("external_directory", Truncate.GLOB, explore!.permission).action).toBe("allow")
    },
  })
})

test("general agent denies todo tools", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const general = await Agent.get("general")
      expect(general).toBeDefined()
      expect(general?.mode).toBe("subagent")
      expect(general?.hidden).toBeUndefined()
      expect(evalPerm(general, "todowrite")).toBe("deny")
    },
  })
})

test("compaction agent denies all permissions", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const compaction = await Agent.get("compaction")
      expect(compaction).toBeDefined()
      expect(compaction?.hidden).toBe(true)
      expect(evalPerm(compaction, "bash")).toBe("deny")
      expect(evalPerm(compaction, "edit")).toBe("deny")
      expect(evalPerm(compaction, "read")).toBe("deny")
    },
  })
})

// ── 5-Agent Architecture Tests ──────────────────────────────────────

test("has exactly 5 primary agents", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agents = await Agent.list()
      const primary = agents.filter((a) => a.mode !== "subagent" && !a.hidden)
      expect(primary.length).toBe(5)
      expect(primary.map((a) => a.name).sort()).toEqual(["hunt", "pentest", "recon", "report", "review"])
    },
  })
})

test("all primary agents have dedicated prompts", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agents = await Agent.list()
      const primary = agents.filter((a) => a.mode !== "subagent" && !a.hidden)
      for (const agent of primary) {
        expect(agent.prompt).toBeTruthy()
        expect(agent.prompt!.length).toBeGreaterThan(100)
      }
    },
  })
})

test("all primary agents have colors", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agents = await Agent.list()
      const primary = agents.filter((a) => a.mode !== "subagent" && !a.hidden)
      for (const agent of primary) {
        expect(agent.color).toBeTruthy()
      }
    },
  })
})

test("hunt agent has correct properties and permissions", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const hunt = await Agent.get("hunt")
      expect(hunt).toBeDefined()
      expect(hunt?.mode).toBe("primary")
      expect(hunt?.native).toBe(true)
      expect(hunt?.color).toBe("error")
      // bash is ask by default, specific tools allowed
      expect(evalPerm(hunt, "bash")).toBe("ask")
      expect(Permission.evaluate("bash", "nmap -sV target", hunt!.permission).action).toBe("allow")
      expect(Permission.evaluate("bash", "nuclei -u target", hunt!.permission).action).toBe("allow")
    },
  })
})

test("review agent denies scanner tools and bash", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const review = await Agent.get("review")
      expect(review).toBeDefined()
      expect(review?.mode).toBe("primary")
      expect(review?.native).toBe(true)
      expect(review?.color).toBe("warning")
      // bash denied by default
      expect(evalPerm(review, "bash")).toBe("deny")
      // scanner tools denied
      expect(evalPerm(review, "injection_test")).toBe("deny")
      expect(evalPerm(review, "xss_test")).toBe("deny")
      expect(evalPerm(review, "ssrf_test")).toBe("deny")
      expect(evalPerm(review, "auth_test")).toBe("deny")
      expect(evalPerm(review, "access_control_test")).toBe("deny")
      expect(evalPerm(review, "observe_surface")).toBe("deny")
      expect(evalPerm(review, "plan_next")).toBe("deny")
      expect(evalPerm(review, "upsert_finding")).toBe("deny")
      expect(evalPerm(review, "exec_command")).toBe("deny")
      expect(evalPerm(review, "security_shell")).toBe("deny")
      // read tools allowed
      expect(evalPerm(review, "read")).toBe("allow")
      expect(evalPerm(review, "glob")).toBe("allow")
      expect(evalPerm(review, "grep")).toBe("allow")
    },
  })
})

test("report agent denies bash and scanner tools", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const report = await Agent.get("report")
      expect(report).toBeDefined()
      expect(report?.mode).toBe("primary")
      expect(report?.native).toBe(true)
      expect(report?.color).toBe("success")
      // bash denied
      expect(evalPerm(report, "bash")).toBe("deny")
      // scanner tools denied
      expect(evalPerm(report, "injection_test")).toBe("deny")
      expect(evalPerm(report, "xss_test")).toBe("deny")
      expect(evalPerm(report, "observe_surface")).toBe("deny")
      expect(evalPerm(report, "exec_command")).toBe("deny")
      expect(evalPerm(report, "security_shell")).toBe("deny")
      expect(evalPerm(report, "batch_replay")).toBe("deny")
      expect(evalPerm(report, "upsert_finding")).toBe("deny")
      // read and report tools allowed
      expect(evalPerm(report, "read")).toBe("allow")
      expect(evalPerm(report, "query_graph")).toBe("allow")
      expect(evalPerm(report, "derive_attack_paths")).toBe("allow")
      expect(evalPerm(report, "get_findings")).toBe("allow")
      expect(evalPerm(report, "generate_report")).toBe("allow")
    },
  })
})

test("scanner and analyst subagents have dedicated prompts", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const scanner = await Agent.get("scanner")
      const analyst = await Agent.get("analyst")
      expect(scanner).toBeDefined()
      expect(analyst).toBeDefined()
      expect(scanner?.mode).toBe("subagent")
      expect(analyst?.mode).toBe("subagent")
      expect(scanner?.prompt).toBeTruthy()
      expect(analyst?.prompt).toBeTruthy()
      expect(scanner?.prompt!.length).toBeGreaterThan(100)
      expect(analyst?.prompt!.length).toBeGreaterThan(100)
    },
  })
})

test("custom agent from config creates new agent", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        my_custom_agent: {
          model: "openai/gpt-4",
          description: "My custom agent",
          temperature: 0.5,
          top_p: 0.9,
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const custom = await Agent.get("my_custom_agent")
      expect(custom).toBeDefined()
      expect(String(custom?.model?.providerID)).toBe("openai")
      expect(String(custom?.model?.modelID)).toBe("gpt-4")
      expect(custom?.description).toBe("My custom agent")
      expect(custom?.temperature).toBe(0.5)
      expect(custom?.topP).toBe(0.9)
      expect(custom?.native).toBe(false)
      expect(custom?.mode).toBe("all")
    },
  })
})

test("custom agent config overrides native agent properties", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        pentest: {
          model: "anthropic/claude-3",
          description: "Custom build agent",
          temperature: 0.7,
          color: "#FF0000",
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const pentest = await Agent.get("pentest")
      expect(pentest).toBeDefined()
      expect(String(pentest?.model?.providerID)).toBe("anthropic")
      expect(String(pentest?.model?.modelID)).toBe("claude-3")
      expect(pentest?.description).toBe("Custom build agent")
      expect(pentest?.temperature).toBe(0.7)
      expect(pentest?.color).toBe("#FF0000")
      expect(pentest?.native).toBe(true)
    },
  })
})

test("agent disable removes agent from list", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        explore: { disable: true },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const explore = await Agent.get("explore")
      expect(explore).toBeUndefined()
      const agents = await Agent.list()
      const names = agents.map((a) => a.name)
      expect(names).not.toContain("explore")
    },
  })
})

test("agent permission config merges with defaults", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        build: {
          permission: {
            bash: {
              "rm -rf *": "deny",
            },
          },
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const build = await Agent.get("build")
      expect(build).toBeDefined()
      // Specific pattern is denied
      expect(Permission.evaluate("bash", "rm -rf *", build!.permission).action).toBe("deny")
      // Edit still allowed
      expect(evalPerm(build, "edit")).toBe("allow")
    },
  })
})

test("global permission config applies to all agents", async () => {
  await using tmp = await tmpdir({
    config: {
      permission: {
        bash: "deny",
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const pentest = await Agent.get("pentest")
      expect(pentest).toBeDefined()
      expect(evalPerm(pentest, "bash")).toBe("deny")
    },
  })
})

test("agent steps/maxSteps config sets steps property", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        build: { steps: 50 },
        plan: { maxSteps: 100 },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const build = await Agent.get("build")
      const plan = await Agent.get("plan")
      expect(build?.steps).toBe(50)
      expect(plan?.steps).toBe(100)
    },
  })
})

test("agent mode can be overridden", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        explore: { mode: "primary" },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const explore = await Agent.get("explore")
      expect(explore?.mode).toBe("primary")
    },
  })
})

test("agent name can be overridden", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        build: { name: "Builder" },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const build = await Agent.get("build")
      expect(build?.name).toBe("Builder")
    },
  })
})

test("agent prompt can be set from config", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        build: { prompt: "Custom system prompt" },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const build = await Agent.get("build")
      expect(build?.prompt).toBe("Custom system prompt")
    },
  })
})

test("unknown agent properties are placed into options", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        build: {
          random_property: "hello",
          another_random: 123,
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const build = await Agent.get("build")
      expect(build?.options.random_property).toBe("hello")
      expect(build?.options.another_random).toBe(123)
    },
  })
})

test("agent options merge correctly", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        build: {
          options: {
            custom_option: true,
            another_option: "value",
          },
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const build = await Agent.get("build")
      expect(build?.options.custom_option).toBe(true)
      expect(build?.options.another_option).toBe("value")
    },
  })
})

test("multiple custom agents can be defined", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        agent_a: {
          description: "Agent A",
          mode: "subagent",
        },
        agent_b: {
          description: "Agent B",
          mode: "primary",
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agentA = await Agent.get("agent_a")
      const agentB = await Agent.get("agent_b")
      expect(agentA?.description).toBe("Agent A")
      expect(agentA?.mode).toBe("subagent")
      expect(agentB?.description).toBe("Agent B")
      expect(agentB?.mode).toBe("primary")
    },
  })
})

test("Agent.list keeps the default agent first and sorts the rest by name", async () => {
  await using tmp = await tmpdir({
    config: {
      default_agent: "recon",
      agent: {
        zebra: {
          description: "Zebra",
          mode: "subagent",
        },
        alpha: {
          description: "Alpha",
          mode: "subagent",
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const names = (await Agent.list()).map((a) => a.name)
      expect(names[0]).toBe("recon")
      expect(names.slice(1)).toEqual(names.slice(1).toSorted((a, b) => a.localeCompare(b)))
    },
  })
})

test("Agent.get returns undefined for non-existent agent", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const nonExistent = await Agent.get("does_not_exist")
      expect(nonExistent).toBeUndefined()
    },
  })
})

test("default permission includes doom_loop and external_directory as ask", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const pentest = await Agent.get("pentest")
      expect(evalPerm(pentest, "doom_loop")).toBe("ask")
      expect(evalPerm(pentest, "external_directory")).toBe("ask")
    },
  })
})

test("webfetch is allowed by default", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const pentest = await Agent.get("pentest")
      expect(evalPerm(pentest, "webfetch")).toBe("allow")
    },
  })
})

test("legacy tools config converts to permissions", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        build: {
          tools: {
            bash: false,
            read: false,
          },
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const build = await Agent.get("build")
      expect(evalPerm(build, "bash")).toBe("deny")
      expect(evalPerm(build, "read")).toBe("deny")
    },
  })
})

test("legacy tools config maps write/edit/patch/multiedit to edit permission", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        build: {
          tools: {
            write: false,
          },
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const build = await Agent.get("build")
      expect(evalPerm(build, "edit")).toBe("deny")
    },
  })
})

test("Truncate.GLOB is allowed even when user denies external_directory globally", async () => {
  const { Truncate } = await import("../../src/tool/truncate")
  await using tmp = await tmpdir({
    config: {
      permission: {
        external_directory: "deny",
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const pentest = await Agent.get("pentest")
      expect(Permission.evaluate("external_directory", Truncate.GLOB, pentest!.permission).action).toBe("allow")
      expect(Permission.evaluate("external_directory", Truncate.DIR, pentest!.permission).action).toBe("deny")
      expect(Permission.evaluate("external_directory", "/some/other/path", pentest!.permission).action).toBe("deny")
    },
  })
})

test("Truncate.GLOB is allowed even when user denies external_directory per-agent", async () => {
  const { Truncate } = await import("../../src/tool/truncate")
  await using tmp = await tmpdir({
    config: {
      agent: {
        build: {
          permission: {
            external_directory: "deny",
          },
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const build = await Agent.get("build")
      expect(Permission.evaluate("external_directory", Truncate.GLOB, build!.permission).action).toBe("allow")
      expect(Permission.evaluate("external_directory", Truncate.DIR, build!.permission).action).toBe("deny")
      expect(Permission.evaluate("external_directory", "/some/other/path", build!.permission).action).toBe("deny")
    },
  })
})

test("explicit Truncate.GLOB deny is respected", async () => {
  const { Truncate } = await import("../../src/tool/truncate")
  await using tmp = await tmpdir({
    config: {
      permission: {
        external_directory: {
          "*": "deny",
          [Truncate.GLOB]: "deny",
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const pentest = await Agent.get("pentest")
      expect(Permission.evaluate("external_directory", Truncate.GLOB, pentest!.permission).action).toBe("deny")
      expect(Permission.evaluate("external_directory", Truncate.DIR, pentest!.permission).action).toBe("deny")
    },
  })
})

test("skill directories are allowed for external_directory", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const skillDir = path.join(dir, ".numasec", "skill", "perm-skill")
      await Bun.write(
        path.join(skillDir, "SKILL.md"),
        `---
name: perm-skill
description: Permission skill.
---

# Permission Skill
`,
      )
    },
  })

  const home = process.env.NUMASEC_TEST_HOME
  process.env.NUMASEC_TEST_HOME = tmp.path

  try {
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pentest = await Agent.get("pentest")
        const skillDir = path.join(tmp.path, ".numasec", "skill", "perm-skill")
        const target = path.join(skillDir, "reference", "notes.md")
        expect(Permission.evaluate("external_directory", target, pentest!.permission).action).toBe("allow")
      },
    })
  } finally {
    process.env.NUMASEC_TEST_HOME = home
  }
})

test("defaultAgent returns pentest when no default_agent config", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agent = await Agent.defaultAgent()
      expect(agent).toBe("pentest")
    },
  })
})

test("defaultAgent respects default_agent config set to recon", async () => {
  await using tmp = await tmpdir({
    config: {
      default_agent: "recon",
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agent = await Agent.defaultAgent()
      expect(agent).toBe("recon")
    },
  })
})

test("defaultAgent respects default_agent config set to custom agent with mode all", async () => {
  await using tmp = await tmpdir({
    config: {
      default_agent: "my_custom",
      agent: {
        my_custom: {
          description: "My custom agent",
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agent = await Agent.defaultAgent()
      expect(agent).toBe("my_custom")
    },
  })
})

test("defaultAgent throws when default_agent points to subagent", async () => {
  await using tmp = await tmpdir({
    config: {
      default_agent: "explore",
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      await expect(Agent.defaultAgent()).rejects.toThrow('default agent "explore" is a subagent')
    },
  })
})

test("defaultAgent throws when default_agent points to hidden agent", async () => {
  await using tmp = await tmpdir({
    config: {
      default_agent: "compaction",
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      await expect(Agent.defaultAgent()).rejects.toThrow('default agent "compaction" is hidden')
    },
  })
})

test("defaultAgent throws when default_agent points to non-existent agent", async () => {
  await using tmp = await tmpdir({
    config: {
      default_agent: "does_not_exist",
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      await expect(Agent.defaultAgent()).rejects.toThrow('default agent "does_not_exist" not found')
    },
  })
})

test("defaultAgent returns recon when pentest is disabled and default_agent not set", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        pentest: { disable: true },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agent = await Agent.defaultAgent()
      // pentest is disabled, so it should return recon (next primary agent)
      expect(agent).toBe("recon")
    },
  })
})

test("defaultAgent throws when all primary agents are disabled", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        pentest: { disable: true },
        recon: { disable: true },
        hunt: { disable: true },
        review: { disable: true },
        report: { disable: true },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      // all primary visible agents are disabled
      await expect(Agent.defaultAgent()).rejects.toThrow("no primary visible agent found")
    },
  })
})
