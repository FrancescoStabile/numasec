import { appendFile, mkdir, readFile, writeFile, stat } from "fs/promises"
import { createHash } from "crypto"
import path from "path"
import { z } from "zod"

export const Entry = z.object({
  sha256: z.string(),
  ext: z.string(),
  size: z.number(),
  mime: z.string().optional(),
  label: z.string().optional(),
  source: z.string().optional(),
  at: z.number(),
})
export type Entry = z.infer<typeof Entry>

const MANIFEST = "manifest.jsonl"
const DIR_NAME = "evidence"

function evidenceDir(workspace: string, slug: string): string {
  return path.join(workspace, ".numasec", "operation", slug, DIR_NAME)
}

function sniffExtFromMime(mime?: string): string {
  if (!mime) return "bin"
  const lower = mime.toLowerCase()
  if (lower.startsWith("text/html")) return "html"
  if (lower.startsWith("text/plain")) return "txt"
  if (lower.startsWith("text/markdown")) return "md"
  if (lower.startsWith("application/json")) return "json"
  if (lower.startsWith("image/png")) return "png"
  if (lower.startsWith("image/jpeg")) return "jpg"
  if (lower.startsWith("image/gif")) return "gif"
  if (lower.startsWith("image/webp")) return "webp"
  if (lower.startsWith("application/pdf")) return "pdf"
  if (lower.includes("har")) return "har"
  if (lower.includes("pcap")) return "pcap"
  return "bin"
}

async function readManifest(workspace: string, slug: string): Promise<Entry[]> {
  const p = path.join(evidenceDir(workspace, slug), MANIFEST)
  const raw = await readFile(p, "utf8").catch(() => "")
  if (!raw) return []
  return raw
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => Entry.parse(JSON.parse(l)))
}

export async function list(workspace: string, slug: string): Promise<Entry[]> {
  return readManifest(workspace, slug)
}

export async function get(workspace: string, slug: string, sha256: string): Promise<{ entry: Entry; bytes: Uint8Array } | undefined> {
  const entries = await readManifest(workspace, slug)
  const entry = entries.find((e) => e.sha256 === sha256)
  if (!entry) return undefined
  const p = path.join(evidenceDir(workspace, slug), `${entry.sha256}.${entry.ext}`)
  const bytes = await readFile(p).catch(() => undefined)
  if (!bytes) return undefined
  return { entry, bytes: new Uint8Array(bytes) }
}

export async function put(
  workspace: string,
  slug: string,
  input: Uint8Array | string | { path: string },
  meta: { mime?: string; label?: string; source?: string; ext?: string } = {},
): Promise<Entry> {
  const bytes =
    input instanceof Uint8Array
      ? Buffer.from(input)
      : typeof input === "string"
        ? Buffer.from(input, "utf8")
        : await readFile(input.path)

  const sha256 = createHash("sha256").update(bytes).digest("hex")
  const ext = (meta.ext ?? sniffExtFromMime(meta.mime)).replace(/^\./, "")
  const dir = evidenceDir(workspace, slug)
  await mkdir(dir, { recursive: true })
  const file = path.join(dir, `${sha256}.${ext}`)

  const existing = await stat(file).catch(() => undefined)
  if (!existing) {
    await writeFile(file, bytes)
  }

  const entries = await readManifest(workspace, slug)
  const already = entries.find((e) => e.sha256 === sha256)
  if (already) return already

  const entry: Entry = {
    sha256,
    ext,
    size: bytes.length,
    mime: meta.mime,
    label: meta.label,
    source: meta.source,
    at: Date.now(),
  }
  await appendFile(path.join(dir, MANIFEST), JSON.stringify(entry) + "\n", "utf8")
  return entry
}
