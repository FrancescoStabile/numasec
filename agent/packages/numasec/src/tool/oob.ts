import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./oob.txt"

export const OobTool = bridgeTool(
  "oob",
  DESCRIPTION,
  z.object({
    action: z.enum(["setup", "poll"]).describe("OOB action: setup (start listener) or poll (check for callbacks)"),
    server: z.string().optional().describe("OOB server URL"),
    correlation_id: z.string().optional().describe("Correlation ID from setup"),
  }),
)
