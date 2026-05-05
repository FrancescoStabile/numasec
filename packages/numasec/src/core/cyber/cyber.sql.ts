import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core"
import { ProjectTable } from "@/project/project.sql"
import { Timestamps } from "@/storage/schema.sql"

export const CyberLedgerTable = sqliteTable(
  "cyber_ledger",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    operation_slug: text().notNull(),
    session_id: text(),
    message_id: text(),
    kind: text().notNull(),
    source: text(),
    status: text(),
    risk: text(),
    summary: text(),
    evidence_refs: text({ mode: "json" }).$type<string[]>(),
    data: text({ mode: "json" }).notNull().$type<Record<string, unknown>>(),
    time_created: integer().notNull().$default(() => Date.now()),
  },
  (table) => [
    index("cyber_ledger_project_op_time_idx").on(table.project_id, table.operation_slug, table.time_created),
    index("cyber_ledger_kind_idx").on(table.kind),
    index("cyber_ledger_session_idx").on(table.session_id),
  ],
)

export const CyberFactTable = sqliteTable(
  "cyber_fact",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    operation_slug: text().notNull(),
    entity_kind: text().notNull(),
    entity_key: text().notNull(),
    fact_name: text().notNull(),
    value_json: text({ mode: "json" }).notNull().$type<unknown>(),
    writer_kind: text().notNull(),
    status: text().notNull(),
    confidence: integer(),
    source_event_id: text(),
    evidence_refs: text({ mode: "json" }).$type<string[]>(),
    expires_at: integer(),
    ...Timestamps,
  },
  (table) => [
    uniqueIndex("cyber_fact_unique_idx").on(
      table.project_id,
      table.operation_slug,
      table.entity_kind,
      table.entity_key,
      table.fact_name,
    ),
    index("cyber_fact_project_op_status_idx").on(table.project_id, table.operation_slug, table.status),
    index("cyber_fact_entity_idx").on(table.entity_kind, table.entity_key),
    index("cyber_fact_source_event_idx").on(table.source_event_id),
  ],
)

export const CyberRelationTable = sqliteTable(
  "cyber_relation",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    operation_slug: text().notNull(),
    src_kind: text().notNull(),
    src_key: text().notNull(),
    relation: text().notNull(),
    dst_kind: text().notNull(),
    dst_key: text().notNull(),
    writer_kind: text().notNull(),
    status: text().notNull(),
    confidence: integer(),
    source_event_id: text(),
    evidence_refs: text({ mode: "json" }).$type<string[]>(),
    ...Timestamps,
  },
  (table) => [
    uniqueIndex("cyber_relation_unique_idx").on(
      table.project_id,
      table.operation_slug,
      table.src_kind,
      table.src_key,
      table.relation,
      table.dst_kind,
      table.dst_key,
    ),
    index("cyber_relation_project_op_status_idx").on(table.project_id, table.operation_slug, table.status),
    index("cyber_relation_src_idx").on(table.src_kind, table.src_key),
    index("cyber_relation_dst_idx").on(table.dst_kind, table.dst_key),
  ],
)
