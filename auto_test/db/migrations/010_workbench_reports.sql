-- MySQL 5.6 compatible. Original evidence plus indexed list projections.
CREATE TABLE IF NOT EXISTS agent_test_tasks (
  task_id varchar(64) NOT NULL,
  module varchar(20) NOT NULL,
  name varchar(255) NOT NULL,
  status varchar(32) NOT NULL,
  created_at varchar(50) NOT NULL,
  payload longtext NOT NULL,
  runtime_payload longtext NULL,
  request_payload longtext NULL,
  runtime_summary longtext NULL,
  runtime_deleted tinyint NOT NULL DEFAULT 0,
  PRIMARY KEY (task_id),
  KEY idx_test_tasks_module_status (module, status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS agent_test_reports (
  report_id varchar(64) NOT NULL,
  task_id varchar(64) NOT NULL,
  module varchar(20) NOT NULL,
  report_type varchar(20) NOT NULL,
  source_name varchar(1000) NOT NULL,
  run_id varchar(191) NOT NULL,
  schema_version varchar(128) NOT NULL,
  created_at varchar(50) NOT NULL,
  content_hash char(64) NOT NULL,
  result_count int unsigned NOT NULL,
  finding_count int unsigned NOT NULL,
  summary longtext NOT NULL,
  payload longtext NOT NULL,
  finding_markdown longtext NOT NULL,
  PRIMARY KEY (report_id),
  KEY idx_test_reports_task (task_id, report_type),
  KEY idx_test_reports_module (module, report_type, created_at),
  CONSTRAINT fk_test_reports_task FOREIGN KEY (task_id)
    REFERENCES agent_test_tasks (task_id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS agent_test_results (
  result_id varchar(64) NOT NULL,
  report_id varchar(64) NOT NULL,
  ordinal int unsigned NOT NULL,
  pointer varchar(191) NOT NULL,
  case_id varchar(191) NOT NULL,
  title varchar(255) NOT NULL,
  description text NOT NULL,
  outcome varchar(64) NOT NULL,
  direction varchar(32) NOT NULL,
  review_outcomes text NOT NULL,
  payload longtext NOT NULL,
  PRIMARY KEY (result_id),
  UNIQUE KEY uk_test_result_position (report_id, ordinal),
  KEY idx_test_results_filter (report_id, outcome, direction, ordinal),
  CONSTRAINT fk_test_results_report FOREIGN KEY (report_id)
    REFERENCES agent_test_reports (report_id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS agent_test_report_findings (
  entry_id varchar(64) NOT NULL,
  report_id varchar(64) NOT NULL,
  finding_id varchar(191) NOT NULL,
  title varchar(255) NOT NULL,
  severity varchar(32) NOT NULL,
  status varchar(64) NOT NULL,
  payload longtext NOT NULL,
  PRIMARY KEY (entry_id),
  KEY idx_test_findings_report (report_id, finding_id),
  CONSTRAINT fk_test_findings_report FOREIGN KEY (report_id)
    REFERENCES agent_test_reports (report_id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
