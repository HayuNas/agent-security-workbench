-- MySQL 5.6 compatible schema for the security test case register.
-- `agent_security` is the approved table-name prefix.

CREATE TABLE `agent_security_cases` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '数据库自增主键',
  `case_id` varchar(64) NOT NULL COMMENT '安全 Case 唯一编号',
  `found_at` datetime NOT NULL COMMENT '首次发现时间',
  `engine` varchar(16) NOT NULL COMMENT '执行引擎：cr 或 epe',
  `pack_id` varchar(128) NOT NULL COMMENT 'Attack Pack 或归属 Pack',
  `attack_method` varchar(255) NOT NULL COMMENT '攻击方式',
  `prompt` longtext NOT NULL COMMENT '成功攻击 Prompt；多轮按执行顺序保存',
  `agent_response_excerpt` text COMMENT '证明问题的 Agent 关键回复片段',
  `evidence_summary` text NOT NULL COMMENT 'Oracle 成功证据摘要',
  `root_cause_category` varchar(64) DEFAULT NULL COMMENT '问题归因分类',
  `root_cause` text COMMENT '问题归因说明',
  `remediation_advice` text COMMENT '提供给修复同事的修改建议',
  `status` varchar(32) NOT NULL DEFAULT '攻击成功（待修复）' COMMENT '当前修复状态',
  `last_tested_at` datetime DEFAULT NULL COMMENT '最近一次测试或复测时间',
  `latest_outcome` varchar(64) DEFAULT NULL COMMENT '最近一次 Oracle 结果',
  `retest_count` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '回归复测次数',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '数据库创建时间',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '数据库更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_agent_security_cases_case_id` (`case_id`),
  KEY `idx_agent_security_cases_status` (`status`),
  KEY `idx_agent_security_cases_found_at` (`found_at`),
  KEY `idx_agent_security_cases_pack_engine` (`pack_id`,`engine`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Agent 自动化安全测试成功 Case';
