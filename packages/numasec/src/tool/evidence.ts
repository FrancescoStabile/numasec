import { Effect } from "effect"
import z from "zod"
import * as Tool from "./tool"
import { Operation } from "@/core/operation"
import { Evidence } from "@/core/evidence"
import { Cyber } from "@/core/cyber"
import { Instance } from "@/project/instance"

const parameters = z.object({
  action: z.enum(["list", "add_text", "add_file"]).default("list"),
  label: z.string().optional(),
  text: z.string().optional(),
  path: z.string().optional(),
  mime: z.string().optional(),
})

type Params = z.infer<typeof parameters>
type Metadata = Record<string, unknown>

export const EvidenceTool = Tool.define<typeof parameters, Metadata, never>(
  "evidence",
  Effect.gen(function* () {
    return {
      description:
        "Manage evidence for the active operation. List current evidence, add text evidence, or import a local file into the active operation evidence store.",
      parameters,
      execute: (params: Params, _ctx: Tool.Context) =>
        Effect.gen(function* () {
          const workspace = Instance.directory
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          if (!slug) {
            return {
              title: "evidence · no active operation",
              output: "No active operation.",
              metadata: { action: params.action, active: false },
            }
          }

          if (params.action === "list") {
            const entries = yield* Effect.promise(() => Evidence.list(workspace, slug))
            const output =
              entries.length === 0
                ? "No evidence stored."
                : entries
                    .map((entry) => `${entry.sha256} · ${entry.ext} · ${entry.size} bytes${entry.label ? ` · ${entry.label}` : ""}`)
                    .join("\n")
            return {
              title: `evidence · ${entries.length}`,
              output,
              metadata: { action: "list", count: entries.length, slug },
            }
          }

          if (params.action === "add_text") {
            if (!params.text) {
              return {
                title: "evidence add_text",
                output: "Provide text when action = add_text.",
                metadata: { action: "add_text", slug },
              }
            }
            const entry = yield* Effect.promise(() =>
              Evidence.put(workspace, slug, params.text!, {
                mime: params.mime ?? "text/plain",
                label: params.label,
                source: "evidence tool",
              }),
            )
            yield* Cyber.appendLedger({
              kind: "evidence.added",
              source: "evidence",
              evidence_refs: [entry.sha256],
              summary: `added evidence ${entry.sha256}`,
              data: { action: "add_text", label: params.label, mime: params.mime ?? "text/plain", sha256: entry.sha256 },
            }).pipe(Effect.catch(() => Effect.succeed("")))
            return {
              title: `evidence · ${entry.sha256}`,
              output: `Stored text evidence ${entry.sha256}.${entry.ext}`,
              metadata: { action: "add_text", sha256: entry.sha256, slug },
            }
          }

          if (!params.path) {
            return {
              title: "evidence add_file",
              output: "Provide path when action = add_file.",
              metadata: { action: "add_file", slug },
            }
          }
          const entry = yield* Effect.promise(() =>
            Evidence.put(workspace, slug, { path: params.path! }, { mime: params.mime, label: params.label, source: params.path }),
          )
          yield* Cyber.appendLedger({
            kind: "evidence.added",
            source: "evidence",
            evidence_refs: [entry.sha256],
            summary: `imported evidence ${entry.sha256}`,
            data: { action: "add_file", path: params.path, label: params.label, mime: params.mime, sha256: entry.sha256 },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          return {
            title: `evidence · ${entry.sha256}`,
            output: `Stored file evidence ${entry.sha256}.${entry.ext}`,
            metadata: { action: "add_file", sha256: entry.sha256, slug },
          }
        }),
    }
  }),
)
