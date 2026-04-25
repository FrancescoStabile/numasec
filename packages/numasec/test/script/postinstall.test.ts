import { expect, test } from "bun:test"
import fs from "fs/promises"
import os from "os"
import path from "path"
import { tmpdir } from "../fixture/fixture"

function packagePlatform() {
  if (os.platform() === "darwin") return "darwin"
  if (os.platform() === "win32") return "windows"
  return os.platform()
}

function packageArch() {
  if (os.arch() === "x64") return "x64"
  if (os.arch() === "arm64") return "arm64"
  if (os.arch() === "arm") return "arm"
  return os.arch()
}

test.skipIf(process.platform === "win32")("postinstall prints a concise success message after linking the platform binary", async () => {
  await using fixture = await tmpdir({
    init: async (dir) => {
      const packageName = `numasec-${packagePlatform()}-${packageArch()}`
      const binaryName = packagePlatform() === "windows" ? "numasec.exe" : "numasec"
      const packageDir = path.join(dir, "node_modules", packageName)
      const binDir = path.join(packageDir, "bin")

      await fs.mkdir(binDir, { recursive: true })
      await fs.mkdir(path.join(dir, "bin"), { recursive: true })
      await Bun.write(path.join(packageDir, "package.json"), JSON.stringify({ name: packageName, version: "0.0.0" }))
      await Bun.write(path.join(binDir, binaryName), "#!/usr/bin/env sh\n")
      await Bun.write(path.join(dir, "postinstall.mjs"), Bun.file("script/postinstall.mjs"))
    },
  })

  const proc = Bun.spawn(["node", "postinstall.mjs"], {
    cwd: fixture.path,
    stdout: "pipe",
    stderr: "pipe",
  })
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ])

  expect(code).toBe(0)
  expect(stderr).toBe("")
  expect(stdout).toContain("numasec installed")
  expect(stdout).toContain("Run `numasec` to start")
  await expect(fs.access(path.join(fixture.path, "bin", ".numasec"))).resolves.toBeNull()
})
