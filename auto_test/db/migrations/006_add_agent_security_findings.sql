-- Add batch-level AI-assisted Findings while keeping deterministic Case/Run facts.

CREATE TABLE IF NOT EXISTS `agent_security_findings` (
  `finding_id` varchar(64) NOT NULL COMMENT 'Finding编号',
  `batch_id` varchar(64) NOT NULL COMMENT '分析批次编号',
  `scenario_id` bigint(20) unsigned NOT NULL COMMENT '场景ID',
  `agent_code` varchar(64) NOT NULL COMMENT 'Agent编号',
  `title` varchar(255) NOT NULL COMMENT '缺陷标题',
  `tested_deployment_commit` varchar(64) DEFAULT NULL COMMENT '被测部署Commit',
  `analysis_source_branch` varchar(128) NOT NULL COMMENT '分析源码分支',
  `analysis_source_commit` varchar(64) NOT NULL COMMENT '分析源码Commit',
  `root_cause` longtext NOT NULL COMMENT '根因假设',
  `evidence` longtext NOT NULL COMMENT '失败机制与源码证据JSON',
  `remediation` longtext NOT NULL COMMENT '修复要求JSON',
  `acceptance` longtext NOT NULL COMMENT '验收方案JSON',
  `confidence` tinyint(3) unsigned NOT NULL COMMENT '可信度：0低，1中，2高',
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
  CONSTRAINT `fk_agent_security_findings_scenario`
    FOREIGN KEY (`scenario_id`) REFERENCES `agent_security_scenarios` (`id`)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Agent安全缺陷Finding';

ALTER TABLE `agent_security_cases`
  ADD COLUMN `finding_id` varchar(64) DEFAULT NULL COMMENT '当前关联Finding编号' AFTER `status`,
  ADD KEY `idx_agent_security_cases_finding` (`finding_id`),
  ADD CONSTRAINT `fk_agent_security_cases_finding`
    FOREIGN KEY (`finding_id`) REFERENCES `agent_security_findings` (`finding_id`)
    ON UPDATE CASCADE ON DELETE SET NULL;
