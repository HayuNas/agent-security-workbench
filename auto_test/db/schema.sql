-- Current MySQL 5.6-compatible schema for the Agent security test registry.
-- Database: dm_data
-- Table prefix approved by the project owner: agent_security

CREATE TABLE IF NOT EXISTS `agent_security_scenarios` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `scenario_code` varchar(64) NOT NULL COMMENT '场景编号',
  `scenario_name` varchar(128) NOT NULL COMMENT '场景名称',
  `scope_type` tinyint(3) unsigned NOT NULL DEFAULT '0' COMMENT '场景范围',
  `agent_code` varchar(64) DEFAULT NULL COMMENT 'Agent编号',
  `description` text COMMENT '场景说明',
  `enabled` tinyint(3) unsigned NOT NULL DEFAULT '1' COMMENT '是否启用',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_agent_security_scenarios_code` (`scenario_code`),
  KEY `idx_agent_security_scenarios_scope` (`scope_type`,`agent_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Agent安全测试场景';

CREATE TABLE IF NOT EXISTS `agent_security_cases` (
  `case_id` varchar(64) NOT NULL COMMENT 'Case编号',
  `scenario_id` bigint(20) unsigned NOT NULL COMMENT '场景ID',
  `agent_code` varchar(64) NOT NULL COMMENT 'Agent编号',
  `engine` varchar(16) NOT NULL COMMENT '测试引擎',
  `pack_id` varchar(128) NOT NULL COMMENT 'Pack编号',
  `prompt` longtext NOT NULL COMMENT '攻击Prompt',
  `found_at` datetime DEFAULT NULL COMMENT '发现时间',
  `root_cause` text COMMENT '问题归因',
  `advice` text COMMENT '修复建议',
  `status` tinyint(3) unsigned DEFAULT NULL COMMENT '修复状态',
  `finding_id` varchar(64) DEFAULT NULL COMMENT '当前关联Finding编号',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`case_id`),
  KEY `idx_agent_security_cases_scenario` (`scenario_id`),
  KEY `idx_agent_security_cases_agent` (`agent_code`),
  KEY `idx_agent_security_cases_repair` (`status`),
  KEY `idx_agent_security_cases_finding` (`finding_id`),
  CONSTRAINT `fk_agent_security_cases_scenario`
    FOREIGN KEY (`scenario_id`) REFERENCES `agent_security_scenarios` (`id`)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Agent全部安全测试Case';

CREATE TABLE IF NOT EXISTS `agent_security_findings` (
  `finding_id` varchar(64) NOT NULL COMMENT 'Finding编号',
  `batch_id` varchar(64) NOT NULL COMMENT '分析批次编号',
  `scenario_id` bigint(20) unsigned NOT NULL COMMENT '场景ID',
  `agent_code` varchar(64) NOT NULL COMMENT 'Agent编号',
  `target_key` varchar(128) NOT NULL DEFAULT '' COMMENT '被测Target唯一编号',
  `asset_snapshot_id` varchar(128) DEFAULT NULL COMMENT 'Agent资产快照编号',
  `title` varchar(255) NOT NULL COMMENT '缺陷标题',
  `issue_type` varchar(64) NOT NULL DEFAULT '' COMMENT '安全问题类型',
  `primary_trigger_type` varchar(64) NOT NULL DEFAULT 'OTHER' COMMENT '主要诱因类型',
  `trigger_types` text NOT NULL COMMENT '全部诱因类型JSON',
  `remediation_type` varchar(64) NOT NULL DEFAULT 'NEEDS_TRIAGE' COMMENT 'Finding修复类型',
  `remediation_scope` varchar(32) NOT NULL DEFAULT 'MIXED' COMMENT '修复范围',
  `root_cause_family` varchar(64) NOT NULL DEFAULT 'UNKNOWN' COMMENT '稳定根因族',
  `finding_fingerprint` varchar(64) NOT NULL DEFAULT '' COMMENT '跨批次同类Finding归组键',
  `tested_deployment_commit` varchar(64) DEFAULT NULL COMMENT '被测部署Commit',
  `analysis_source_branch` varchar(128) NOT NULL COMMENT '分析源码分支',
  `analysis_source_commit` varchar(64) NOT NULL COMMENT '分析源码Commit',
  `root_cause` longtext NOT NULL COMMENT '根因假设',
  `evidence` longtext NOT NULL COMMENT '失败机制与源码证据JSON',
  `remediation` longtext NOT NULL COMMENT '修复要求JSON',
  `acceptance` longtext NOT NULL COMMENT '验收方案JSON',
  `confidence` tinyint(3) unsigned NOT NULL COMMENT '可信度：0低，1中，2高',
  `severity` tinyint(3) unsigned NOT NULL DEFAULT '1' COMMENT '严重度：0低1中2高3严重',
  `analysis_status` varchar(32) NOT NULL DEFAULT 'COMPLETED' COMMENT '分析状态',
  `source_run_id` varchar(128) DEFAULT NULL COMMENT '最近来源测试Run',
  `classification_version` varchar(64) NOT NULL DEFAULT 'finding-taxonomy-v1' COMMENT '分类契约版本',
  `first_seen_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Finding首次发现时间',
  `last_seen_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Finding最近发现时间',
  `model_name` varchar(128) NOT NULL COMMENT '分析模型',
  `fix_commit` varchar(64) DEFAULT NULL COMMENT '修复Commit',
  `resolution_note` text COMMENT '修复确认说明',
  `status` tinyint(3) unsigned NOT NULL DEFAULT '0' COMMENT '状态：0未修复，1已修复，2修复后仍有问题',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`finding_id`),
  KEY `idx_agent_security_findings_batch` (`batch_id`),
  KEY `idx_agent_security_findings_scenario` (`scenario_id`),
  KEY `idx_agent_security_findings_agent_status` (`agent_code`,`status`),
  KEY `idx_agent_security_findings_target_type` (`target_key`(96),`remediation_type`(48),`status`),
  KEY `idx_agent_security_findings_fingerprint` (`finding_fingerprint`),
  CONSTRAINT `fk_agent_security_findings_scenario`
    FOREIGN KEY (`scenario_id`) REFERENCES `agent_security_scenarios` (`id`)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Agent安全缺陷Finding';

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

ALTER TABLE `agent_security_cases`
  ADD CONSTRAINT `fk_agent_security_cases_finding`
    FOREIGN KEY (`finding_id`) REFERENCES `agent_security_findings` (`finding_id`)
    ON UPDATE CASCADE ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS `agent_security_case_runs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `run_id` varchar(64) NOT NULL COMMENT '运行编号',
  `case_id` varchar(64) NOT NULL COMMENT 'Case编号',
  `tested_at` datetime NOT NULL COMMENT '测试时间',
  `result` tinyint(3) unsigned NOT NULL COMMENT '测试结果',
  `outcome` varchar(64) DEFAULT NULL COMMENT 'Oracle结果',
  `evidence` text COMMENT '判定证据',
  `response` text COMMENT 'Agent回复',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '写入时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_agent_security_case_runs_run_id` (`run_id`),
  KEY `idx_agent_security_case_runs_case_time` (`case_id`,`tested_at`),
  KEY `idx_agent_security_case_runs_result` (`result`),
  CONSTRAINT `fk_agent_security_case_runs_case`
    FOREIGN KEY (`case_id`) REFERENCES `agent_security_cases` (`case_id`)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Agent安全Case每次执行记录';

-- agent_security_case_runs.result:
--   0 = 本次未发现问题
--   1 = 本次攻击成功
--   2 = 本次无法确定
-- agent_security_cases.status:
--   NULL = 目前未发现问题
--   0 = 问题未修复
--   1 = 已修复
--   2 = 修复后仍有问题或问题复发
-- agent_security_findings.confidence:
--   0 = 低；1 = 中；2 = 高
-- agent_security_findings.status:
--   0 = 未修复；1 = 已修复；2 = 修复后仍有问题
