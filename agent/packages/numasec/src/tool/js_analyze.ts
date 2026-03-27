import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./js_analyze.txt"

export const JsAnalyzeTool = bridgeTool(
  "js_analyze",
  DESCRIPTION,
  z.object({
    url: z.string().describe("Target URL or JS file URL to analyze"),
    js_files: z.string().optional().describe("Comma-separated JS file URLs to analyze directly"),
    headers: z.string().optional().describe("JSON object of additional headers"),
  }),
)
