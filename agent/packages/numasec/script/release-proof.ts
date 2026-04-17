#!/usr/bin/env bun

import fs from "fs/promises"
import os from "os"
import path from "path"
import pkg from "../package.json"

const dir = path.resolve(import.meta.dir, "..")
const root = path.resolve(dir, "../../..")
const startup = process.argv.includes("--startup-only")

type Runout = {
  code: number
  out: string
  err: string
}

async function exists(file: string) {
  return fs.access(file).then(
    () => true,
    () => false,
  )
}

async function shell(cmd: string[], cwd: string, env?: Record<string, string>) {
  const proc = Bun.spawn({
    cmd,
    cwd,
    env: {
      ...process.env,
      ...env,
    },
    stdout: "pipe",
    stderr: "pipe",
  })
  const out = await new Response(proc.stdout).text()
  const err = await new Response(proc.stderr).text()
  const code = await proc.exited
  const runout: Runout = { code, out, err }
  if (code === 0) return runout
  const lines = [`Command failed: ${cmd.join(" ")}`]
  if (out.trim()) lines.push(out.trim())
  if (err.trim()) lines.push(err.trim())
  throw new Error(lines.join("\n"))
}

async function avx2() {
  if (process.arch !== "x64") return false
  if (process.platform === "linux") {
    const text = await Bun.file("/proc/cpuinfo")
      .text()
      .catch(() => "")
    return /(^|\s)avx2(\s|$)/i.test(text)
  }
  if (process.platform === "darwin") {
    const runout = await shell(["sysctl", "-n", "hw.optional.avx2_0"], root).catch(() => undefined)
    if (!runout) return false
    return runout.out.trim() === "1"
  }
  return false
}

async function musl() {
  if (process.platform !== "linux") return false
  if (await exists("/etc/alpine-release")) return true
  const runout = await shell(["ldd", "--version"], root).catch(() => undefined)
  if (!runout) return false
  const text = `${runout.out}\n${runout.err}`.toLowerCase()
  return text.includes("musl")
}

async function buildArgs() {
  if (await musl()) return ["--musl-only"]
  const args = ["--single"]
  if (process.arch !== "x64") return args
  if (await avx2()) return args
  args.push("--baseline")
  return args
}

async function names() {
  const osname = process.platform === "win32" ? "windows" : process.platform
  const base = `numasec-${osname}-${process.arch}`
  const basecpu = process.arch === "x64" && !(await avx2())
  if (osname === "linux") {
    if (await musl()) {
      if (process.arch === "x64") {
        if (basecpu) return [`${base}-baseline-musl`, `${base}-musl`, `${base}-baseline`, base]
        return [`${base}-musl`, `${base}-baseline-musl`, base, `${base}-baseline`]
      }
      return [`${base}-musl`, base]
    }
    if (process.arch === "x64") {
      if (basecpu) return [`${base}-baseline`, base, `${base}-baseline-musl`, `${base}-musl`]
      return [base, `${base}-baseline`, `${base}-musl`, `${base}-baseline-musl`]
    }
    return [base, `${base}-musl`]
  }
  if (process.arch === "x64") {
    if (basecpu) return [`${base}-baseline`, base]
    return [base, `${base}-baseline`]
  }
  return [base]
}

function binary(input: string) {
  const name = process.platform === "win32" ? "numasec.exe" : "numasec"
  return path.join(input, "bin", name)
}

async function platformDir() {
  const list = await names()
  for (const name of list) {
    const file = path.join(dir, "dist", name, "package.json")
    if (await exists(file)) return path.join(dir, "dist", name)
  }
  throw new Error(`Missing current platform package in dist/: ${list.join(", ")}`)
}

async function buildReady() {
  const file = path.join(dir, "dist", "numasec", "package.json")
  if (!(await exists(file))) return false
  const meta = await Bun.file(file)
    .json()
    .catch(() => undefined)
  if (!meta) return false
  if (typeof meta.version !== "string") return false
  if (meta.version !== pkg.version) return false
  const found = await platformDir().catch(() => "")
  if (!found) return false
  return exists(binary(found))
}

async function build() {
  if (await buildReady()) return
  const args = await buildArgs()
  console.log(`Building release-proof artifacts: bun run build ${args.join(" ")}`)
  await shell(["bun", "run", "build", ...args], dir, {
    NUMASEC_CHANNEL: "latest",
    NUMASEC_VERSION: pkg.version,
  })
}

async function smoke(file: string) {
  const version = await shell([file, "--version"], root)
  if (!version.out.trim()) throw new Error(`${file} --version returned empty output`)
  const help = await shell([file, "--help"], root)
  const text = `${help.out}\n${help.err}`.trim()
  if (!text) throw new Error(`${file} --help returned empty output`)
}

async function pack(input: string, out: string) {
  const runout = await shell(["npm", "pack", "--pack-destination", out], input)
  const file = runout.out
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .at(-1)
  if (!file) throw new Error(`npm pack did not return a tarball name for ${input}`)
  return path.join(out, file)
}

function shim(input: string) {
  const name = process.platform === "win32" ? "numasec.cmd" : "numasec"
  return path.join(input, "node_modules", ".bin", name)
}

async function npmSmoke(tmp: string) {
  const out = path.join(tmp, "pack")
  const app = path.join(tmp, "app")
  await fs.mkdir(out, { recursive: true })
  await fs.mkdir(app, { recursive: true })
  const main = await pack(path.join(dir, "dist", "numasec"), out)
  const platform = await pack(await platformDir(), out)
  await shell(["npm", "install", "--prefix", app, platform, main], root)
  await smoke(shim(app))
}

async function installSmoke(tmp: string) {
  const bindir = path.join(tmp, "bin")
  await fs.mkdir(bindir, { recursive: true })
  await shell(["bash", path.join(root, "install.sh"), "--install-dir", bindir], root)
  await smoke(path.join(bindir, "numasec"))
}

async function main() {
  if (!startup) await build()
  const file = binary(await platformDir())
  console.log(`Smoking built binary: ${file}`)
  await smoke(file)
  if (startup) return
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "numasec-release-proof-"))
  try {
    console.log("Smoking npm package install")
    await npmSmoke(tmp)
    console.log("Smoking source install script")
    await installSmoke(tmp)
  } finally {
    await fs.rm(tmp, {
      recursive: true,
      force: true,
    })
  }
}

await main().catch((error) => {
  const text = error instanceof Error ? error.message : String(error)
  console.error(text)
  process.exit(1)
})
