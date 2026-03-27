import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./xss_test.txt"

export const XssTestTool = bridgeTool(
  "xss_test",
  DESCRIPTION,
  z.object({
    url: z.string().describe("Target URL to test"),
    params: z.string().optional().describe("Comma-separated parameter names to test"),
    method: z.string().optional().default("GET"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    waf_evasion: z.boolean().optional().default(false).describe("Enable WAF evasion techniques"),
  }),
)
