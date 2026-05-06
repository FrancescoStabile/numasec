import { describe, expect, test } from "bun:test"
import { normalizeComponent } from "../../../src/core/knowledge"

describe("core/knowledge/component", () => {
  test("normalizes infrastructure components and versions", () => {
    const nginx = normalizeComponent("nginx 1.18.0")
    expect(nginx?.name).toBe("nginx")
    expect(nginx?.version).toBe("1.18.0")
    expect(nginx?.cpe_candidates.some((item) => item.includes(":nginx:"))).toBe(true)

    const ssh = normalizeComponent("OpenSSH_8.2p1 Ubuntu")
    expect(ssh?.name).toBe("openssh")
    expect(ssh?.version).toBe("8.2p1")

    const apache = normalizeComponent("Apache/2.4.49")
    expect(apache?.name).toBe("apache httpd")
    expect(apache?.version).toBe("2.4.49")
  })
})
