import z from "zod"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { copyFile, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises"
import path from "node:path"
import * as Tool from "./tool"
import DESCRIPTION from "./share.txt"
import { Operation } from "@/core/operation"
import { Deliverable } from "@/core/deliverable"
import { redactString } from "@/core/replay/redact"
import { which } from "@/util/which"

const parameters = z.object({
  redact: z.boolean().default(true).describe("apply replay redactor to text files before packing (default true)"),
  sign: z.boolean().default(false).describe("sign the tarball's sha256 with minisign/cosign if a key is configured"),
})

type Params = z.infer<typeof parameters>

type Metadata = {
  slug?: string
  path?: string
  size?: number
  sha256?: string
  signed: boolean
  redacted: boolean
  warning?: string
}

const REDACT_EXTS = new Set([".md", ".txt", ".json", ".log", ".yml", ".yaml", ".csv"])

async function walk(dir: string): Promise<string[]> {
  const out: string[] = []
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => [])
  for (const entry of entries) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...(await walk(full)))
    else if (entry.isFile()) out.push(full)
  }
  return out
}

async function redactFile(p: string): Promise<void> {
  const ext = path.extname(p).toLowerCase()
  if (!REDACT_EXTS.has(ext)) return
  const before = await readFile(p, "utf8").catch(() => null)
  if (before === null) return
  const after = redactString(before, "on")
  if (after !== before) await writeFile(p, after, "utf8")
}

async function copyDir(src: string, dst: string): Promise<void> {
  if (!existsSync(src)) return
  await mkdir(dst, { recursive: true })
  const entries = await readdir(src, { withFileTypes: true })
  for (const entry of entries) {
    const from = path.join(src, entry.name)
    const to = path.join(dst, entry.name)
    if (entry.isDirectory()) await copyDir(from, to)
    else if (entry.isFile()) await copyFile(from, to)
  }
}

async function sha256OfFile(p: string): Promise<string> {
  const buf = await readFile(p)
  return createHash("sha256").update(buf).digest("hex")
}

function trySign(payload: string): { scheme: string; value: string } | { scheme: null; warning: string } {
  const minisignKey = process.env.NUMASEC_MINISIGN_KEY
  const minisignPass = process.env.NUMASEC_MINISIGN_PASSWORD
  if (minisignKey && minisignPass && existsSync(minisignKey) && which("minisign")) {
    const r = spawnSync(
      "minisign",
      ["-S", "-s", minisignKey, "-x", "-", "-m", "-"],
      { input: payload + "\n" + minisignPass + "\n", encoding: "utf-8" },
    )
    if (r.status === 0 && r.stdout) return { scheme: "minisign", value: r.stdout.trim() }
  }
  const cosignKey = process.env.COSIGN_KEY
  if (cosignKey && existsSync(cosignKey) && which("cosign")) {
    const r = spawnSync("cosign", ["sign-blob", "--yes", "--key", cosignKey, "-"], {
      input: payload,
      encoding: "utf-8",
    })
    if (r.status === 0 && r.stdout) return { scheme: "cosign", value: r.stdout.trim() }
  }
  const reasons: string[] = []
  if (!which("minisign") && !which("cosign")) reasons.push("neither minisign nor cosign is on PATH")
  if (!minisignKey && !cosignKey) reasons.push("no signing key configured (set NUMASEC_MINISIGN_KEY or COSIGN_KEY)")
  return {
    scheme: null,
    warning: reasons.length ? reasons.join("; ") : "signing key is present but signing failed",
  }
}

export interface ShareResult {
  path: string
  size: number
  sha256: string
  signed: boolean
  redacted: boolean
  warning?: string
  slug: string
}

export async function run(input: {
  workspace: string
  redact?: boolean
  sign?: boolean
}): Promise<ShareResult> {
  const redact = input.redact ?? true
  const sign = input.sign ?? false
  const workspace = input.workspace

  const slug = await Operation.activeSlug(workspace)
  if (!slug) throw new Error("no active operation — start one with /pwn first")

  const opDir = Operation.opDir(workspace, slug)
  const stamp = new Date().toISOString().replace(/[:.]/g, "-")
  const stagingDir = path.join(opDir, `share-${stamp}`)
  const tarballPath = path.join(opDir, `share-${stamp}.tar.gz`)
  await mkdir(stagingDir, { recursive: true })

  const fascicule = Operation.opFile(workspace, slug)
  if (existsSync(fascicule)) {
    await copyFile(fascicule, path.join(stagingDir, Operation.OP_FILENAME))
  }
  await copyDir(path.join(opDir, "evidence"), path.join(stagingDir, "evidence"))
  const entries = await readdir(opDir, { withFileTypes: true }).catch(() => [])
  for (const entry of entries) {
    if (entry.isFile() && entry.name.startsWith("report-") && entry.name.endsWith(".md")) {
      await copyFile(path.join(opDir, entry.name), path.join(stagingDir, entry.name))
    }
  }

  // Deliverable.build may throw if the operation store schema is drifting —
  // don't let that block the share tarball. Capture manifest if it succeeded.
  let deliverableWarning: string | undefined
  try {
    const built = await Deliverable.build(workspace, slug)
    await copyFile(built.manifestPath, path.join(stagingDir, "deliverable-manifest.json"))
    if (existsSync(built.reportPath)) {
      await copyFile(built.reportPath, path.join(stagingDir, "deliverable-report.md"))
    }
  } catch (e) {
    deliverableWarning = `deliverable.build failed: ${(e as Error).message}`
  }

  if (redact) {
    for (const p of await walk(stagingDir)) await redactFile(p)
  }

  // Per-file manifest of the staged payload, emitted *into* the staging dir
  // so it's part of the tarball and independently hash-verifiable.
  const staged = await walk(stagingDir)
  const manifest = {
    operation: slug,
    generated_at: Date.now(),
    redacted: redact,
    files: await Promise.all(
      staged.map(async (p) => {
        const st = await stat(p)
        return {
          path: path.relative(stagingDir, p),
          size: st.size,
          sha256: await sha256OfFile(p),
        }
      }),
    ),
  }
  await writeFile(path.join(stagingDir, "manifest.json"), JSON.stringify(manifest, null, 2), "utf8")

  const proc = Bun.spawn(["tar", "-czf", tarballPath, "-C", stagingDir, "."], {
    stdout: "pipe",
    stderr: "pipe",
  })
  const exit = await proc.exited
  if (exit !== 0) {
    const stderr = await new Response(proc.stderr).text()
    throw new Error(`tar failed (exit ${exit}): ${stderr}`)
  }

  const size = (await stat(tarballPath)).size
  const tarSha = await sha256OfFile(tarballPath)

  let signed = false
  let warning = deliverableWarning
  if (sign) {
    const attempt = trySign(tarSha)
    if (attempt.scheme !== null) {
      await writeFile(tarballPath + ".sig", attempt.value, "utf8")
      signed = true
    } else {
      warning = [warning, `signing skipped: ${attempt.warning}`].filter(Boolean).join("; ")
    }
  }

  return { path: tarballPath, size, sha256: tarSha, signed, redacted: redact, warning, slug }
}

function formatOutput(r: ShareResult): string {
  const lines = [
    `Archive: ${r.path} (${r.size} bytes)`,
    `sha256:  ${r.sha256}`,
    `signed:  ${r.signed ? "yes" : "no"}`,
    `redacted: ${r.redacted ? "yes" : "no"}`,
  ]
  if (r.warning) lines.push(`warning: ${r.warning}`)
  return lines.join("\n")
}

export const ShareTool = Tool.define<typeof parameters, Metadata, never>(
  "share",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const workspace = process.cwd()
          yield* ctx.ask({
            permission: "share",
            patterns: [workspace],
            always: ["*"],
            metadata: { redact: params.redact, sign: params.sign },
          })
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace))
          if (!slug) {
            return {
              title: "share: no active operation",
              output: "No active operation. Start one with /pwn first.",
              metadata: { signed: false, redacted: params.redact },
            }
          }
          const result = yield* Effect.promise(() =>
            run({ workspace, redact: params.redact, sign: params.sign }),
          )
          return {
            title: `share · ${path.basename(result.path)}`,
            output: formatOutput(result),
            metadata: {
              slug: result.slug,
              path: result.path,
              size: result.size,
              sha256: result.sha256,
              signed: result.signed,
              redacted: result.redacted,
              warning: result.warning,
            },
          }
        }),
    }
  }),
)
