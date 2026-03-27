import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./browser_tool.txt"

export const BrowserTool = bridgeTool(
  "browser",
  DESCRIPTION,
  z.object({
    action: z.enum(["navigate", "click", "fill", "screenshot"]).describe("Browser action to perform"),
    url: z.string().optional().describe("URL to navigate to (for navigate action)"),
    selector: z.string().optional().describe("CSS selector for click/fill actions"),
    value: z.string().optional().describe("Value for fill action"),
    wait_for: z.string().optional().default("load").describe("Wait condition: load, networkidle, domcontentloaded"),
    timeout: z.number().optional().default(30).describe("Timeout in seconds"),
  }),
)
