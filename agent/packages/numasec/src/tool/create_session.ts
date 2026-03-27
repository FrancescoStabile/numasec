import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./create_session.txt"

export const CreateSessionTool = bridgeTool(
  "create_session",
  DESCRIPTION,
  z.object({
    target_url: z.string().describe("Target URL or hostname being assessed (e.g., https://example.com)"),
  }),
)
