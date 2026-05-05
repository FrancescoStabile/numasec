import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./analyze.txt"
import { BinaryTriageTool } from "./binary-triage"
import { CloudPostureTool } from "./cloud-posture"
import { ContainerSurfaceTool } from "./container-surface"
import { IacTriageTool } from "./iac-triage"
import { Agent } from "@/agent/agent"
import * as Truncate from "./truncate"

const parameters = z
  .object({
    target: z.enum(["iac", "container", "cloud", "binary"]).describe("artifact slice to inspect"),
    path: z.string().min(1).optional().describe("local IaC directory or binary file path"),
    image: z.string().min(1).optional().describe("container image reference to inspect"),
    provider: z.literal("aws").optional().describe("cloud provider for this slice"),
    mode: z.enum(["quick", "full"]).optional().default("quick").describe("scan depth"),
    profile: z.string().optional().describe("optional AWS profile"),
    region: z.string().optional().describe("optional AWS region"),
  })
  .superRefine((value, issue) => {
    if (value.target === "iac" || value.target === "binary") {
      if (!value.path) {
        issue.addIssue({
          code: "custom",
          path: ["path"],
          message: `path is required when target=${value.target}`,
        })
      }
    }

    if (value.target === "container" && !value.image) {
      issue.addIssue({
        code: "custom",
        path: ["image"],
        message: "image is required when target=container",
      })
    }

    if (value.target === "cloud" && !value.provider) {
      issue.addIssue({
        code: "custom",
        path: ["provider"],
        message: "provider is required when target=cloud",
      })
    }
  })

type Params = z.infer<typeof parameters>
type Metadata = {
  surface: "analyze"
  delegated_to: "iac_triage" | "container_surface" | "cloud_posture" | "binary_triage"
  target: Params["target"]
  available?: boolean
  [key: string]: unknown
}

export const AnalyzeTool = Tool.define<typeof parameters, Metadata, Agent.Service | Truncate.Service>(
  "analyze",
  Effect.gen(function* () {
    const iac = yield* IacTriageTool
    const container = yield* ContainerSurfaceTool
    const cloud = yield* CloudPostureTool
    const binary = yield* BinaryTriageTool

    const iacTool = yield* Tool.init(iac)
    const containerTool = yield* Tool.init(container)
    const cloudTool = yield* Tool.init(cloud)
    const binaryTool = yield* Tool.init(binary)

    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          if (params.target === "iac") {
            const result = yield* iacTool.execute(
              {
                path: params.path,
                mode: params.mode,
              },
              ctx as any,
            )
            return {
              ...result,
              metadata: {
                ...result.metadata,
                surface: "analyze",
                delegated_to: "iac_triage",
                target: "iac",
              } satisfies Metadata,
            }
          }

          if (params.target === "container") {
            const result = yield* containerTool.execute(
              {
                image: params.image,
                mode: params.mode,
              },
              ctx as any,
            )
            return {
              ...result,
              metadata: {
                ...result.metadata,
                surface: "analyze",
                delegated_to: "container_surface",
                target: "container",
              } satisfies Metadata,
            }
          }

          if (params.target === "cloud") {
            const result = yield* cloudTool.execute(
              {
                provider: params.provider,
                mode: params.mode,
                profile: params.profile,
                region: params.region,
              },
              ctx as any,
            )
            return {
              ...result,
              metadata: {
                ...result.metadata,
                surface: "analyze",
                delegated_to: "cloud_posture",
                target: "cloud",
              } satisfies Metadata,
            }
          }

          const result = yield* binaryTool.execute(
            {
              path: params.path,
            },
            ctx as any,
          )
          return {
            ...result,
            metadata: {
              ...result.metadata,
              surface: "analyze",
              delegated_to: "binary_triage",
              target: "binary",
            } satisfies Metadata,
          }
        }),
    }
  }),
)
