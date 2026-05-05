CREATE TABLE `cyber_fact` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`operation_slug` text NOT NULL,
	`entity_kind` text NOT NULL,
	`entity_key` text NOT NULL,
	`fact_name` text NOT NULL,
	`value_json` text NOT NULL,
	`writer_kind` text NOT NULL,
	`status` text NOT NULL,
	`confidence` integer,
	`source_event_id` text,
	`evidence_refs` text,
	`expires_at` integer,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_cyber_fact_project_id_project_id_fk` FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `cyber_ledger` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`operation_slug` text NOT NULL,
	`session_id` text,
	`message_id` text,
	`kind` text NOT NULL,
	`source` text,
	`status` text,
	`risk` text,
	`summary` text,
	`evidence_refs` text,
	`data` text NOT NULL,
	`time_created` integer NOT NULL,
	CONSTRAINT `fk_cyber_ledger_project_id_project_id_fk` FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `cyber_relation` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`operation_slug` text NOT NULL,
	`src_kind` text NOT NULL,
	`src_key` text NOT NULL,
	`relation` text NOT NULL,
	`dst_kind` text NOT NULL,
	`dst_key` text NOT NULL,
	`writer_kind` text NOT NULL,
	`status` text NOT NULL,
	`confidence` integer,
	`source_event_id` text,
	`evidence_refs` text,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_cyber_relation_project_id_project_id_fk` FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE UNIQUE INDEX `cyber_fact_unique_idx` ON `cyber_fact` (`project_id`,`operation_slug`,`entity_kind`,`entity_key`,`fact_name`);--> statement-breakpoint
CREATE INDEX `cyber_fact_project_op_status_idx` ON `cyber_fact` (`project_id`,`operation_slug`,`status`);--> statement-breakpoint
CREATE INDEX `cyber_fact_entity_idx` ON `cyber_fact` (`entity_kind`,`entity_key`);--> statement-breakpoint
CREATE INDEX `cyber_fact_source_event_idx` ON `cyber_fact` (`source_event_id`);--> statement-breakpoint
CREATE INDEX `cyber_ledger_project_op_time_idx` ON `cyber_ledger` (`project_id`,`operation_slug`,`time_created`);--> statement-breakpoint
CREATE INDEX `cyber_ledger_kind_idx` ON `cyber_ledger` (`kind`);--> statement-breakpoint
CREATE INDEX `cyber_ledger_session_idx` ON `cyber_ledger` (`session_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `cyber_relation_unique_idx` ON `cyber_relation` (`project_id`,`operation_slug`,`src_kind`,`src_key`,`relation`,`dst_kind`,`dst_key`);--> statement-breakpoint
CREATE INDEX `cyber_relation_project_op_status_idx` ON `cyber_relation` (`project_id`,`operation_slug`,`status`);--> statement-breakpoint
CREATE INDEX `cyber_relation_src_idx` ON `cyber_relation` (`src_kind`,`src_key`);--> statement-breakpoint
CREATE INDEX `cyber_relation_dst_idx` ON `cyber_relation` (`dst_kind`,`dst_key`);
