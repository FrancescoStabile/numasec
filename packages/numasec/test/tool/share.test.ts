import { describe, expect, test } from "bun:test"
import * as fs from "node:fs/promises"
import path from "node:path"
import { Operation } from "../../src/core/operation"
import { run as share } from "../../src/tool/share"
import { tmpdir } from "../fixture/fixture"

describe("tool/share", () => {
  test("default run emits a redacted, unsigned tarball with manifest inside", async () => {
    await using fixture = await tmpdir()
    const op = await Operation.create({
      workspace: fixture.path,
      label: "Acme Assess",
      kind: "pentest",
      target: "https://acme.example.com",
    })
    const opDir = Operation.opDir(fixture.path, op.slug)

    // Drop fake evidence + a report. Include a JWT so we can verify redaction.
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZyYW5jZXNjbyJ9.abcdefghijklmno"
    await fs.writeFile(
      path.join(opDir, "evidence", "notes.md"),
      `# probe\nfound token: ${jwt}\n`,
    )
    await fs.writeFile(
      path.join(opDir, "report-001.md"),
      `# Report\nleaked: ${jwt}\n`,
    )

    const result = await share({ workspace: fixture.path })

    expect(result.slug).toBe(op.slug)
    expect(result.signed).toBe(false)
    expect(result.redacted).toBe(true)
    expect(result.size).toBeGreaterThan(0)
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/)

    const st = await fs.stat(result.path)
    expect(st.isFile()).toBe(true)
    expect(st.size).toBe(result.size)

    // Inspect the archive: must contain manifest.json and the redacted files.
    const proc = Bun.spawn(["tar", "-tzf", result.path], { stdout: "pipe" })
    const listing = await new Response(proc.stdout).text()
    await proc.exited
    expect(listing).toContain("./manifest.json")
    expect(listing).toContain("./evidence/notes.md")
    expect(listing).toContain("./report-001.md")
    expect(listing).toContain("./numasec.md")

    // Redaction should have stripped the JWT in the staged copies.
    const stagingDir = result.path.replace(/\.tar\.gz$/, "")
    const notes = await fs.readFile(path.join(stagingDir, "evidence", "notes.md"), "utf8")
    const report = await fs.readFile(path.join(stagingDir, "report-001.md"), "utf8")
    expect(notes).not.toContain(jwt)
    expect(notes).toContain("[redacted:jwt]")
    expect(report).not.toContain(jwt)

    // manifest.json should enumerate the staged files with sha256 digests.
    const manifest = JSON.parse(
      await fs.readFile(path.join(stagingDir, "manifest.json"), "utf8"),
    )
    expect(manifest.operation).toBe(op.slug)
    expect(manifest.redacted).toBe(true)
    expect(Array.isArray(manifest.files)).toBe(true)
    expect(manifest.files.length).toBeGreaterThan(0)
    for (const f of manifest.files) {
      expect(f.sha256).toMatch(/^[0-9a-f]{64}$/)
      expect(typeof f.size).toBe("number")
    }
  })

  test("sign:true without a key gracefully degrades (signed=false + warning)", async () => {
    await using fixture = await tmpdir()
    await Operation.create({
      workspace: fixture.path,
      label: "Ghost",
      kind: "pentest",
    })
    // Ensure no signing key env vars leak in from the host runner.
    const saved = {
      mk: process.env.NUMASEC_MINISIGN_KEY,
      mp: process.env.NUMASEC_MINISIGN_PASSWORD,
      ck: process.env.COSIGN_KEY,
    }
    delete process.env.NUMASEC_MINISIGN_KEY
    delete process.env.NUMASEC_MINISIGN_PASSWORD
    delete process.env.COSIGN_KEY

    try {
      const result = await share({ workspace: fixture.path, sign: true })
      expect(result.signed).toBe(false)
      expect(result.warning).toBeDefined()
      expect(result.warning!.toLowerCase()).toContain("signing")
      expect(result.size).toBeGreaterThan(0)
      // no sig side-car should be written when signing fails
      await expect(fs.stat(result.path + ".sig")).rejects.toBeDefined()
    } finally {
      if (saved.mk !== undefined) process.env.NUMASEC_MINISIGN_KEY = saved.mk
      if (saved.mp !== undefined) process.env.NUMASEC_MINISIGN_PASSWORD = saved.mp
      if (saved.ck !== undefined) process.env.COSIGN_KEY = saved.ck
    }
  })

  test("errors when there is no active operation", async () => {
    await using fixture = await tmpdir()
    await expect(share({ workspace: fixture.path })).rejects.toThrow(/no active operation/)
  })
})
