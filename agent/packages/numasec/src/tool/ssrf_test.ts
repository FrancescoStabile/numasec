import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./ssrf_test.txt"

export const SsrfTestTool = bridgeTool(
  "ssrf_test",
  DESCRIPTION,
  z.object({
    url: z.string().describe("Target URL to test for SSRF"),
    headers: z.string().optional().describe("JSON object of additional headers"),
  }),
)
