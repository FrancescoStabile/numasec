import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./run_scanner_batch.txt"

export const RunScannerBatchTool = bridgeTool(
  "run_scanner_batch",
  DESCRIPTION,
  z.object({
    session_id: z.string().describe("Session ID"),
    tasks: z.string().describe("JSON array of {tool, params} objects, e.g. [{\"tool\": \"xss_test\", \"params\": {\"url\": \"...\"}}]"),
  }),
)
