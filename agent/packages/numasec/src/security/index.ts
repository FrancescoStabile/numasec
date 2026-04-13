/**
 * Security module index — exports all security tools for registration.
 *
 * Import this in the tool registry to register all security tools.
 */

// Primitive tools
export { HttpRequestTool } from "./tool/http-request"
export { ShellTool } from "./tool/shell"
export { BrowserTool } from "./tool/browser"
export { ExecCommandTool } from "./tool/exec-command"
export { MutateInputTool } from "./tool/mutate-input"
export { ExtractObservationTool } from "./tool/extract-observation"
export { VerifyAssertionTool } from "./tool/verify-assertion"
export { RecordEvidenceTool } from "./tool/record-evidence"
export { LinkEvidenceTool } from "./tool/link-evidence"
export { QueryGraphTool } from "./tool/query-graph"
export { ObserveSurfaceTool } from "./tool/observe-surface"
export { UpsertHypothesisTool } from "./tool/upsert-hypothesis"
export { UpsertFindingTool } from "./tool/upsert-finding"
export { ConfirmFindingTool } from "./tool/confirm-finding"
export { DeriveAttackPathsTool } from "./tool/derive-attack-paths"
export { PlanNextTool } from "./tool/plan-next"
export { BatchReplayTool } from "./tool/batch-replay"

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

// Intelligence tools
export { KbSearchTool } from "./tool/kb-search"
export { PentestPlanTool } from "./tool/pentest-plan"

// Planner
export { generatePlan, formatPlan, applyReplanSignal } from "./planner/planner"

// Enrichment (for external use)
export { enrichFinding, generateFindingId, normalizeSeverity } from "./enrichment/enrich"
export { getCweInfo } from "./enrichment/cwe-map"
export { calculateBaseScore } from "./enrichment/cvss-calculator"
export { getOwaspCategory } from "./enrichment/owasp-map"
export { getNextActions } from "./enrichment/next-actions"

// Chain builder
export { buildChainGroups } from "./chain-builder"
export type { ChainGroup } from "./chain-builder"

// Knowledge base
export { buildRetriever, KnowledgeRetriever } from "./kb/retriever"

// HTTP client
export { httpRequest } from "./http-client"

// Environment detection
export { detectEnvironment } from "./env/detect"

// Evidence graph store
export { EvidenceGraphStore, EvidenceGraphStoreError, createEvidenceFingerprint } from "./evidence-store"
export {
  DEFAULT_INLINE_BYTES,
  DEFAULT_PREVIEW_BYTES,
  encodeArtifactPayload,
  makeArtifactReference,
  persistEvidenceArtifact,
  shouldPersistArtifact,
} from "./artifact-store"

// All tools as array (for registry)
import { HttpRequestTool } from "./tool/http-request"
import { ShellTool } from "./tool/shell"
import { BrowserTool } from "./tool/browser"
import { ExecCommandTool } from "./tool/exec-command"
import { MutateInputTool } from "./tool/mutate-input"
import { ExtractObservationTool } from "./tool/extract-observation"
import { VerifyAssertionTool } from "./tool/verify-assertion"
import { RecordEvidenceTool } from "./tool/record-evidence"
import { LinkEvidenceTool } from "./tool/link-evidence"
import { QueryGraphTool } from "./tool/query-graph"
import { ObserveSurfaceTool } from "./tool/observe-surface"
import { UpsertHypothesisTool } from "./tool/upsert-hypothesis"
import { UpsertFindingTool } from "./tool/upsert-finding"
import { ConfirmFindingTool } from "./tool/confirm-finding"
import { DeriveAttackPathsTool } from "./tool/derive-attack-paths"
import { PlanNextTool } from "./tool/plan-next"
import { BatchReplayTool } from "./tool/batch-replay"
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
import { KbSearchTool } from "./tool/kb-search"
import { PentestPlanTool } from "./tool/pentest-plan"

export const SecurityTools = [
  // Primitives
  HttpRequestTool,
  ShellTool,
  BrowserTool,
  ExecCommandTool,
  MutateInputTool,
  ExtractObservationTool,
  VerifyAssertionTool,
  RecordEvidenceTool,
  LinkEvidenceTool,
  QueryGraphTool,
  ObserveSurfaceTool,
  UpsertHypothesisTool,
  UpsertFindingTool,
  ConfirmFindingTool,
  DeriveAttackPathsTool,
  PlanNextTool,
  BatchReplayTool,
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
  // Intelligence
  KbSearchTool,
  PentestPlanTool,
]
