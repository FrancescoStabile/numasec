import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./recon.txt"

export const ReconTool = bridgeTool(
  "recon",
  DESCRIPTION,
  z.object({
    target: z.string().describe("Hostname, IP, or URL to scan"),
    checks: z.string().optional().default("ports,tech").describe("Comma-separated checks: ports,tech,subdomains,dns,services"),
    ports: z.string().optional().default("top-100").describe("Port specification: top-100, top-1000, or specific ports"),
    timeout: z.number().optional().default(2.0).describe("Per-connection timeout in seconds"),
  }),
)
