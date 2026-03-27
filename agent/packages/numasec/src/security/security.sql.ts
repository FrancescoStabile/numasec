/**
 * Drizzle schema for security findings and target profiles.
 * Mirrors the Python Finding model for TS-native persistence.
 */
import { sqliteTable, text, integer, real, index } from "drizzle-orm/sqlite-core"
import { SessionTable } from "../session/session.sql"
import type { SessionID } from "../session/schema"
import { Timestamps } from "../storage/schema.sql"

// ── Branded IDs ──────────────────────────────────────────────
export type FindingID = string & { __brand: "FindingID" }
export type TargetID = string & { __brand: "TargetID" }

// ── Target ───────────────────────────────────────────────────
export const TargetTable = sqliteTable(
  "target",
  {
    id: text().$type<TargetID>().primaryKey(),
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    url: text().notNull(),
    scope: text({ mode: "json" }).$type<string[]>(), // allowed URL patterns
    technologies: text({ mode: "json" }).$type<string[]>(),
    open_ports: text({ mode: "json" }).$type<number[]>(),
    endpoints: text({ mode: "json" }).$type<string[]>(),
    notes: text(),
    ...Timestamps,
  },
  (table) => [
    index("target_session_idx").on(table.session_id),
  ],
)

// ── Finding ──────────────────────────────────────────────────
export const FindingTable = sqliteTable(
  "finding",
  {
    id: text().$type<FindingID>().primaryKey(),
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    target_id: text().$type<TargetID>(),

    // Core
    title: text().notNull(),
    severity: text().notNull().$type<"critical" | "high" | "medium" | "low" | "info">(),
    description: text().notNull().default(""),
    evidence: text().notNull().default(""),
    confirmed: integer({ mode: "boolean" }).notNull().default(false),
    false_positive: integer({ mode: "boolean" }).notNull().default(false),

    // HTTP context
    url: text().notNull().default(""),
    method: text().notNull().default(""),
    parameter: text().notNull().default(""),
    payload: text().notNull().default(""),
    request_dump: text().notNull().default(""),
    response_status: integer(),

    // Standards mapping
    cwe_id: text().notNull().default(""),
    cvss_score: real(),
    cvss_vector: text().notNull().default(""),
    owasp_category: text().notNull().default(""),
    rule_id: text().notNull().default(""),
    attack_technique: text().notNull().default(""),
    wstg_id: text().notNull().default(""),

    // Remediation
    remediation_summary: text().notNull().default(""),

    // Confidence & chain
    confidence: real().notNull().default(0.5),
    related_finding_ids: text({ mode: "json" }).$type<string[]>(),
    chain_id: text().notNull().default(""),

    // Tool
    tool_used: text().notNull().default(""),

    ...Timestamps,
  },
  (table) => [
    index("finding_session_idx").on(table.session_id),
    index("finding_severity_idx").on(table.severity),
    index("finding_session_severity_idx").on(table.session_id, table.severity),
    index("finding_owasp_idx").on(table.owasp_category),
  ],
)

// ── Credential ───────────────────────────────────────────────
export type CredentialID = string & { __brand: "CredentialID" }

export const CredentialTable = sqliteTable(
  "credential",
  {
    id: text().$type<CredentialID>().primaryKey(),
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    username: text().notNull(),
    password: text().notNull(),
    source: text().notNull().default(""), // where it was found
    url: text().notNull().default(""),
    valid: integer({ mode: "boolean" }).notNull().default(false),
    ...Timestamps,
  },
  (table) => [
    index("credential_session_idx").on(table.session_id),
  ],
)

// ── OWASP Coverage ───────────────────────────────────────────
export const CoverageTable = sqliteTable(
  "coverage",
  {
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    category: text().notNull(), // e.g. "A01:2021"
    tested: integer({ mode: "boolean" }).notNull().default(false),
    finding_count: integer().notNull().default(0),
    ...Timestamps,
  },
  (table) => [
    index("coverage_session_idx").on(table.session_id),
    index("coverage_session_category_idx").on(table.session_id, table.category),
  ],
)
