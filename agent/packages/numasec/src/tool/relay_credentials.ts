import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./relay_credentials.txt"

export const RelayCredentialsTool = bridgeTool(
  "relay_credentials",
  DESCRIPTION,
  z.object({
    session_id: z.string().describe("Session ID"),
    credential_type: z.enum(["bearer", "cookie", "api_key", "password"]).optional().default("bearer"),
    value: z.string().optional().describe("Token/cookie value (for bearer, cookie, api_key types)"),
    source: z.string().optional().describe("Tool that discovered the credential"),
    username: z.string().optional().describe("Username (for password type)"),
    password: z.string().optional().describe("Password (for password type)"),
  }),
)
