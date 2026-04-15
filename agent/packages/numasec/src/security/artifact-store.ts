import { createHash } from "crypto"
import { mkdir } from "fs/promises"
import path from "path"
import { Global } from "../global"
import type { SessionID } from "../session/schema"
import { canonicalSecuritySessionID } from "./security-session"

export const DEFAULT_INLINE_BYTES = 8 * 1024
export const DEFAULT_PREVIEW_BYTES = 1024

export type ArtifactMode = "auto" | "inline" | "external"

export interface EvidenceArtifact {
  id: string
  sha256: string
  size_bytes: number
  mime_type: string
  path: string
  relative_path: string
  preview: string
  preview_truncated: boolean
  source_tool: string
}

function bytes(value: string): number {
  return new TextEncoder().encode(value).length
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex")
}

function artifactID(value: string): string {
  return `EART-${value.slice(0, 16).toUpperCase()}`
}

function root(sessionID: SessionID): string {
  return path.join(Global.Path.data, "evidence-artifact", canonicalSecuritySessionID(sessionID))
}

export function encodeArtifactPayload(input: unknown): string {
  try {
    const value = JSON.stringify(input)
    if (typeof value === "string") return value
    throw new Error("JSON.stringify returned non-string value")
  } catch (cause) {
    throw new Error(`record_evidence payload is not serializable: ${String(cause)}`)
  }
}

export function shouldPersistArtifact(size: number, mode: ArtifactMode, maxInlineBytes: number): boolean {
  if (mode === "inline") return false
  if (mode === "external") return true
  return size > maxInlineBytes
}

export async function persistEvidenceArtifact(input: {
  sessionID: SessionID
  payload: unknown
  sourceTool?: string
  previewBytes?: number
}): Promise<EvidenceArtifact> {
  const text = encodeArtifactPayload(input.payload)
  const sha256 = hash(text)
  const id = artifactID(sha256)
  const dir = root(input.sessionID)
  await mkdir(dir, { recursive: true })
  const target = path.join(dir, `${id}.json`)
  const file = Bun.file(target)
  if (!(await file.exists())) {
    await Bun.write(file, text)
  }
  const limit = input.previewBytes ?? DEFAULT_PREVIEW_BYTES
  const preview = text.slice(0, limit)
  const relative = path.relative(Global.Path.data, target)
  return {
    id,
    sha256,
    size_bytes: bytes(text),
    mime_type: "application/json",
    path: target,
    relative_path: relative,
    preview,
    preview_truncated: text.length > limit,
    source_tool: input.sourceTool ?? "",
  }
}

export function makeArtifactReference(artifact: EvidenceArtifact): Record<string, unknown> {
  return {
    artifact_id: artifact.id,
    sha256: artifact.sha256,
    size_bytes: artifact.size_bytes,
    mime_type: artifact.mime_type,
    path: artifact.path,
    relative_path: artifact.relative_path,
    preview: artifact.preview,
    preview_truncated: artifact.preview_truncated,
    source_tool: artifact.source_tool,
    storage: "local",
  }
}
