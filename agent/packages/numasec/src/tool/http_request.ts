import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./http_request.txt"

export const HttpRequestTool = bridgeTool(
  "http_request",
  DESCRIPTION,
  z.object({
    url: z.string().describe("Full URL to send request to"),
    method: z.string().optional().default("GET").describe("HTTP method: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH"),
    headers: z.string().optional().describe("JSON object of request headers"),
    body: z.string().optional().describe("Request body"),
    follow_redirects: z.boolean().optional().default(true),
    timeout: z.number().optional().default(30).describe("Request timeout in seconds"),
  }),
)
