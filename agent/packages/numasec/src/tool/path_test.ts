import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./path_test.txt"

export const PathTestTool = bridgeTool(
  "path_test",
  DESCRIPTION,
  z.object({
    url: z.string().describe("Target URL to test"),
    checks: z.string().optional().default("lfi,xxe,redirect,host_header").describe("Comma-separated: lfi,xxe,redirect,host_header"),
    params: z.string().optional().describe("Comma-separated parameter names to test"),
    method: z.string().optional().default("GET"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    waf_evasion: z.boolean().optional().default(false).describe("Enable WAF evasion techniques"),
  }),
)
