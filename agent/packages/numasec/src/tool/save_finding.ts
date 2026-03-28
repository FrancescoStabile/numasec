import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./save_finding.txt"

export const SaveFindingTool = bridgeTool(
  "save_finding",
  DESCRIPTION,
  z.object({
    session_id: z.string().optional().describe("Session ID from create_session"),
    title: z.string().describe("Finding title"),
    severity: z.enum(["critical", "high", "medium", "low", "info"]).describe("Severity level"),
    description: z.string().optional().describe("Detailed vulnerability description"),
    url: z.string().optional(),
    parameter: z.string().optional().describe("Vulnerable parameter name"),
    evidence: z.string().optional().describe("Evidence from testing"),
    cwe: z.string().optional().describe("CWE identifier (e.g., CWE-89)"),
    payload: z.string().optional().describe("Payload that triggered the finding"),
    tool_used: z.string().optional().describe("Tool that discovered the finding"),
    related_to: z.string().optional().describe("Comma-separated finding IDs this finding relates to"),
    chain_id: z.string().optional().describe("Attack chain ID to group related findings"),
    confidence: z.number().optional().describe("Confidence score 0.0-1.0"),
  }),
)
