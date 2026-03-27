import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./access_control_test.txt"

export const AccessControlTestTool = bridgeTool(
  "access_control_test",
  DESCRIPTION,
  z.object({
    url: z.string().describe("Target URL to test"),
    checks: z.string().optional().default("idor,csrf,cors").describe("Comma-separated: idor,csrf,cors"),
    headers: z.string().optional().describe("JSON object of additional headers"),
  }),
)
