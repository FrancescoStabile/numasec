CREATE TABLE `target` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`url` text NOT NULL,
	`scope` text,
	`technologies` text,
	`open_ports` text,
	`endpoints` text,
	`notes` text,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_target_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX `target_session_idx` ON `target` (`session_id`);
--> statement-breakpoint
CREATE TABLE `finding` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`target_id` text,
	`title` text NOT NULL,
	`severity` text NOT NULL,
	`description` text NOT NULL DEFAULT '',
	`evidence` text NOT NULL DEFAULT '',
	`confirmed` integer NOT NULL DEFAULT 0,
	`false_positive` integer NOT NULL DEFAULT 0,
	`url` text NOT NULL DEFAULT '',
	`method` text NOT NULL DEFAULT '',
	`parameter` text NOT NULL DEFAULT '',
	`payload` text NOT NULL DEFAULT '',
	`request_dump` text NOT NULL DEFAULT '',
	`response_status` integer,
	`cwe_id` text NOT NULL DEFAULT '',
	`cvss_score` real,
	`cvss_vector` text NOT NULL DEFAULT '',
	`owasp_category` text NOT NULL DEFAULT '',
	`rule_id` text NOT NULL DEFAULT '',
	`attack_technique` text NOT NULL DEFAULT '',
	`wstg_id` text NOT NULL DEFAULT '',
	`remediation_summary` text NOT NULL DEFAULT '',
	`confidence` real NOT NULL DEFAULT 0.5,
	`related_finding_ids` text,
	`chain_id` text NOT NULL DEFAULT '',
	`tool_used` text NOT NULL DEFAULT '',
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_finding_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX `finding_session_idx` ON `finding` (`session_id`);
--> statement-breakpoint
CREATE INDEX `finding_severity_idx` ON `finding` (`severity`);
--> statement-breakpoint
CREATE INDEX `finding_session_severity_idx` ON `finding` (`session_id`, `severity`);
--> statement-breakpoint
CREATE INDEX `finding_owasp_idx` ON `finding` (`owasp_category`);
--> statement-breakpoint
CREATE TABLE `credential` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`username` text NOT NULL,
	`password` text NOT NULL,
	`source` text NOT NULL DEFAULT '',
	`url` text NOT NULL DEFAULT '',
	`valid` integer NOT NULL DEFAULT 0,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_credential_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX `credential_session_idx` ON `credential` (`session_id`);
--> statement-breakpoint
CREATE TABLE `coverage` (
	`session_id` text NOT NULL,
	`category` text NOT NULL,
	`tested` integer NOT NULL DEFAULT 0,
	`finding_count` integer NOT NULL DEFAULT 0,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_coverage_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX `coverage_session_idx` ON `coverage` (`session_id`);
--> statement-breakpoint
CREATE INDEX `coverage_session_category_idx` ON `coverage` (`session_id`, `category`);
