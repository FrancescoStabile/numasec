import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "fs"
import { tmpdir } from "os"
import path from "path"
import { Operation } from "@/core/operation"
import { check, checkUrl, ScopeDeniedError, opsec as readOpsec } from "@/core/boundary/guard"

function mkws() {
  const dir = mkdtempSync(path.join(tmpdir(), "numasec-opsec-"))
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

describe("core/boundary opsec guard", () => {
  test("normal mode: crt.sh allowed when boundary permits", async () => {
    const { dir, cleanup } = mkws()
    try {
      await Operation.create({
        workspace: dir,
        label: "normal op",
        kind: "pentest",
        target: "https://target.test",
      })
      // default scope: only in=target.test, mode=ask — crt.sh not matched → ask
      const d = await checkUrl(dir, "https://crt.sh/?q=target.test")
      expect(d.mode).toBe("ask")
    } finally {
      cleanup()
    }
  })

  test("strict mode: 3rd-party intel hosts are denied", async () => {
    const { dir, cleanup } = mkws()
    try {
      const info = await Operation.create({
        workspace: dir,
        label: "strict op",
        kind: "pentest",
        target: "https://target.test",
        opsec: "strict",
      })
      expect(info.opsec).toBe("strict")
      expect(await readOpsec(dir)).toBe("strict")

      for (const url of [
        "https://crt.sh/?q=target.test",
        "https://api.shodan.io/host/1.2.3.4",
        "https://www.virustotal.com/api/v3/domains/target.test",
        "https://urlscan.io/search/",
        "https://otx.alienvault.com/api/v1/indicators",
        "https://wayback-api.archive.org/web/timemap/link/target.test",
      ]) {
        await expect(checkUrl(dir, url)).rejects.toBeInstanceOf(ScopeDeniedError)
      }
    } finally {
      cleanup()
    }
  })

  test("strict mode: target-scope URLs are allowed", async () => {
    const { dir, cleanup } = mkws()
    try {
      await Operation.create({
        workspace: dir,
        label: "strict op",
        kind: "pentest",
        target: "https://target.test",
        opsec: "strict",
      })
      const d = await checkUrl(dir, "https://target.test/login")
      expect(d.mode).toBe("allow")
    } finally {
      cleanup()
    }
  })

  test("strict mode: unmatched ask-default upgraded to deny (localhost excluded)", async () => {
    const { dir, cleanup } = mkws()
    try {
      await Operation.create({
        workspace: dir,
        label: "strict op",
        kind: "pentest",
        target: "https://target.test",
        opsec: "strict",
      })
      await expect(checkUrl(dir, "https://other.example.com/")).rejects.toBeInstanceOf(
        ScopeDeniedError,
      )
      const d = await checkUrl(dir, "http://localhost:8080/")
      // localhost bypasses the strict-mode ask→deny upgrade; base evaluate still returns ask
      expect(d.mode).toBe("ask")
    } finally {
      cleanup()
    }
  })

  test("setOpsec writes opsec header and read parses it", async () => {
    const { dir, cleanup } = mkws()
    try {
      const info = await Operation.create({
        workspace: dir,
        label: "toggle op",
        kind: "pentest",
        target: "https://target.test",
      })
      expect(info.opsec).toBe("normal")
      await Operation.setOpsec(dir, info.slug, "strict")
      const reread = await Operation.read(dir, info.slug)
      expect(reread?.opsec).toBe("strict")
      await Operation.setOpsec(dir, info.slug, "normal")
      const back = await Operation.read(dir, info.slug)
      expect(back?.opsec).toBe("normal")
    } finally {
      cleanup()
    }
  })

  test("check() supports raw non-URL requests under strict (passes through evaluate)", async () => {
    const { dir, cleanup } = mkws()
    try {
      await Operation.create({
        workspace: dir,
        label: "strict op",
        kind: "pentest",
        target: "https://target.test",
        opsec: "strict",
      })
      // path with no host → strict upgrade would deny because no host check; that's expected
      await expect(
        check(dir, { kind: "path", value: "/etc/passwd" }),
      ).rejects.toBeInstanceOf(ScopeDeniedError)
    } finally {
      cleanup()
    }
  })
})
