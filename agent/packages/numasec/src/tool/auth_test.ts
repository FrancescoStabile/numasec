import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./auth_test.txt"

export const AuthTestTool = bridgeTool(
  "auth_test",
  DESCRIPTION,
  z.object({
    url: z.string().describe("Target URL or auth endpoint"),
    token: z.string().optional().describe("JWT or auth token to analyze"),
    headers: z.string().optional().describe("JSON object of additional headers"),
    checks: z.string().optional().default("jwt,creds").describe("Comma-separated: jwt,creds"),
  }),
)
