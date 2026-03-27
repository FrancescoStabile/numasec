import z from "zod"
import { bridgeTool } from "../bridge/tool"
import DESCRIPTION from "./crawl.txt"

export const CrawlTool = bridgeTool(
  "crawl",
  DESCRIPTION,
  z.object({
    url: z.string().describe("Starting URL for the crawl"),
    depth: z.number().optional().default(2).describe("Maximum crawl depth"),
    max_pages: z.number().optional().default(50).describe("Maximum pages to crawl"),
    force_browser: z.boolean().optional().default(false).describe("Force browser-based crawling for SPAs"),
    openapi_url: z.string().optional().describe("URL to OpenAPI/Swagger spec (JSON or YAML)"),
  }),
)
