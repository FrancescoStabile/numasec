import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./dir_fuzz.txt"

export const DirFuzzTool = bridgeTool(
  "dir_fuzz",
  DESCRIPTION,
  z.object({
    url: z.string().describe("Target base URL (e.g., http://example.com)"),
    wordlist: z.string().optional().describe("Comma-separated custom paths; uses built-in list if omitted"),
    extensions: z.string().optional().describe("Comma-separated file extensions to append (e.g., 'php,bak,old')"),
  }),
)
