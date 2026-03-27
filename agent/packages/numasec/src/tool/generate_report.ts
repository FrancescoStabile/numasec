import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./generate_report.txt"

export const GenerateReportTool = bridgeTool(
  "generate_report",
  DESCRIPTION,
  z.object({
    session_id: z.string().describe("Session ID to generate report for"),
    format: z.enum(["sarif", "markdown", "json"]).optional().default("markdown").describe("Report format"),
  }),
)
