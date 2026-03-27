import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./injection_test.txt"

export const InjectionTestTool = bridgeTool(
  "injection_test",
  DESCRIPTION,
  z.object({
    url: z.string().describe("Target URL to test"),
    types: z.string().optional().default("sql,nosql,ssti,cmdi").describe("Comma-separated: sql,nosql,cmdi,ssti"),
    params: z.string().optional().describe("Comma-separated parameter names to test"),
    method: z.string().optional().default("GET"),
    body: z.string().optional().describe("Request body for POST/PUT"),
    content_type: z.string().optional().default("form").describe("Content type: form, json"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    waf_evasion: z.boolean().optional().default(false).describe("Enable WAF evasion techniques"),
  }),
)
