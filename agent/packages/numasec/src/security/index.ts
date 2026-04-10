/**
 * Security module index — exports all security tools for registration.
 *
 * Import this in the tool registry to register all security tools.
 */

// Primitive tools
export { HttpRequestTool } from "./tool/http-request"
export { ShellTool } from "./tool/shell"
export { BrowserTool } from "./tool/browser"

// Composite scanning tools
export { ReconTool } from "./tool/recon"
export { CrawlTool } from "./tool/crawl"
export { DirFuzzTool } from "./tool/dir-fuzz"
export { JsAnalyzeTool } from "./tool/js-analyze"
export { InjectionTestTool } from "./tool/injection-test"
export { XssTestTool } from "./tool/xss-test"
export { AuthTestTool } from "./tool/auth-test"
export { AccessControlTestTool } from "./tool/access-control-test"
export { SsrfTestTool } from "./tool/ssrf-test"
export { UploadTestTool } from "./tool/upload-test"
export { RaceTestTool } from "./tool/race-test"
export { GraphqlTestTool } from "./tool/graphql-test"

// Session & reporting tools
export { SaveFindingTool } from "./tool/save-finding"
export { GetFindingsTool } from "./tool/get-findings"
export { BuildChainsTool } from "./tool/build-chains"
export { GenerateReportTool } from "./tool/generate-report"

// Planner
export { generatePlan, formatPlan, applyReplanSignal } from "./planner/planner"

// Enrichment (for external use)
export { enrichFinding, generateFindingId, normalizeSeverity } from "./enrichment/enrich"
export { getCweInfo } from "./enrichment/cwe-map"
export { calculateBaseScore } from "./enrichment/cvss-calculator"
export { getOwaspCategory } from "./enrichment/owasp-map"

// Knowledge base
export { buildRetriever, KnowledgeRetriever } from "./kb/retriever"

// HTTP client
export { httpRequest } from "./http-client"

// Environment detection
export { detectEnvironment } from "./env/detect"

// All tools as array (for registry)
import { HttpRequestTool } from "./tool/http-request"
import { ShellTool } from "./tool/shell"
import { BrowserTool } from "./tool/browser"
import { ReconTool } from "./tool/recon"
import { CrawlTool } from "./tool/crawl"
import { DirFuzzTool } from "./tool/dir-fuzz"
import { JsAnalyzeTool } from "./tool/js-analyze"
import { InjectionTestTool } from "./tool/injection-test"
import { XssTestTool } from "./tool/xss-test"
import { AuthTestTool } from "./tool/auth-test"
import { AccessControlTestTool } from "./tool/access-control-test"
import { SsrfTestTool } from "./tool/ssrf-test"
import { UploadTestTool } from "./tool/upload-test"
import { RaceTestTool } from "./tool/race-test"
import { GraphqlTestTool } from "./tool/graphql-test"
import { SaveFindingTool } from "./tool/save-finding"
import { GetFindingsTool } from "./tool/get-findings"
import { BuildChainsTool } from "./tool/build-chains"
import { GenerateReportTool } from "./tool/generate-report"

export const SecurityTools = [
  // Primitives
  HttpRequestTool,
  ShellTool,
  BrowserTool,
  // Scanning
  ReconTool,
  CrawlTool,
  DirFuzzTool,
  JsAnalyzeTool,
  InjectionTestTool,
  XssTestTool,
  AuthTestTool,
  AccessControlTestTool,
  SsrfTestTool,
  UploadTestTool,
  RaceTestTool,
  GraphqlTestTool,
  // Session
  SaveFindingTool,
  GetFindingsTool,
  BuildChainsTool,
  GenerateReportTool,
]
