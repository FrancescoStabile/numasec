import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./get_findings.txt"

export const GetFindingsTool = bridgeTool(
  "get_findings",
  DESCRIPTION,
  z.object({
    session_id: z.string().describe("Session ID to query"),
    severity_filter: z.string().optional().describe("Filter by severity: critical, high, medium, low, info"),
  }),
)
