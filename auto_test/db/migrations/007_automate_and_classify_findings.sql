-- Make Finding generation batch-aware, remediation-oriented, and idempotent.
-- MySQL 5.6 compatible; apply once after migration 006.

CREATE TABLE IF NOT EXISTS `agent_security_finding_batches` (
  `batch_id` varchar(64) NOT NULL COMMENT 'Finding分析批次编号',
  `source_run_ids` longtext NOT NULL COMMENT '来源测试Run编号JSON',
  `target_key` varchar(128) NOT NULL COMMENT '被测Target唯一编号',
  `asset_snapshot_id` varchar(128) DEFAULT NULL COMMENT 'Agent资产快照编号',
  `analysis_status` varchar(32) NOT NULL COMMENT 'READY/COMPLETED/PENDING/FAILED/EMPTY',
  `case_count` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '本批Case数',
  `finding_count` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '本批Finding数',
  `model_name` varchar(128) DEFAULT NULL COMMENT '分析模型',
  `classification_version` varchar(64) NOT NULL COMMENT '分类契约版本',
  `report_json_path` varchar(1000) DEFAULT NULL COMMENT '批次JSON报告路径',
  `error_message` text COMMENT '失败原因（已脱敏）',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`batch_id`),
  KEY `idx_agent_security_finding_batches_target` (`target_key`(96),`created_at`),
  KEY `idx_agent_security_finding_batches_status` (`analysis_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Agent安全Finding分析批次';

ALTER TABLE `agent_security_findings`
  ADD COLUMN `target_key` varchar(128) NOT NULL DEFAULT '' COMMENT '被测Target唯一编号' AFTER `agent_code`,
  ADD COLUMN `asset_snapshot_id` varchar(128) DEFAULT NULL COMMENT 'Agent资产快照编号' AFTER `target_key`,
  ADD COLUMN `issue_type` varchar(64) NOT NULL DEFAULT '' COMMENT '安全问题类型' AFTER `title`,
  ADD COLUMN `primary_trigger_type` varchar(64) NOT NULL DEFAULT 'OTHER' COMMENT '主要诱因类型' AFTER `issue_type`,
  ADD COLUMN `trigger_types` text NOT NULL COMMENT '全部诱因类型JSON' AFTER `primary_trigger_type`,
  ADD COLUMN `remediation_type` varchar(64) NOT NULL DEFAULT 'NEEDS_TRIAGE' COMMENT 'Finding修复类型' AFTER `trigger_types`,
  ADD COLUMN `remediation_scope` varchar(32) NOT NULL DEFAULT 'MIXED' COMMENT '修复范围' AFTER `remediation_type`,
  ADD COLUMN `root_cause_family` varchar(64) NOT NULL DEFAULT 'UNKNOWN' COMMENT '稳定根因族' AFTER `remediation_scope`,
  ADD COLUMN `finding_fingerprint` varchar(64) NOT NULL DEFAULT '' COMMENT '跨批次同类Finding归组键' AFTER `root_cause_family`,
  ADD COLUMN `severity` tinyint(3) unsigned NOT NULL DEFAULT '1' COMMENT '严重度：0低1中2高3严重' AFTER `confidence`,
  ADD COLUMN `analysis_status` varchar(32) NOT NULL DEFAULT 'COMPLETED' COMMENT '分析状态' AFTER `severity`,
  ADD COLUMN `source_run_id` varchar(128) DEFAULT NULL COMMENT '最近来源测试Run' AFTER `analysis_status`,
  ADD COLUMN `classification_version` varchar(64) NOT NULL DEFAULT 'finding-taxonomy-v1' COMMENT '分类契约版本' AFTER `source_run_id`,
  ADD COLUMN `first_seen_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Finding首次发现时间' AFTER `classification_version`,
  ADD COLUMN `last_seen_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Finding最近发现时间' AFTER `first_seen_at`,
  ADD KEY `idx_agent_security_findings_target_type` (`target_key`(96),`remediation_type`(48),`status`),
  ADD KEY `idx_agent_security_findings_fingerprint` (`finding_fingerprint`);

CREATE TABLE IF NOT EXISTS `agent_security_finding_cases` (
  `finding_id` varchar(64) NOT NULL COMMENT 'Finding编号',
  `case_id` varchar(64) NOT NULL COMMENT 'Case编号',
  `first_batch_id` varchar(64) NOT NULL COMMENT '首次关联批次',
  `last_batch_id` varchar(64) NOT NULL COMMENT '最近关联批次',
  `linked_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '首次关联时间',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`finding_id`,`case_id`),
  KEY `idx_agent_security_finding_cases_case` (`case_id`),
  KEY `idx_agent_security_finding_cases_batch` (`last_batch_id`),
  CONSTRAINT `fk_agent_security_finding_cases_finding`
    FOREIGN KEY (`finding_id`) REFERENCES `agent_security_findings` (`finding_id`)
    ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT `fk_agent_security_finding_cases_case`
    FOREIGN KEY (`case_id`) REFERENCES `agent_security_cases` (`case_id`)
    ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Finding与Case关联历史';
