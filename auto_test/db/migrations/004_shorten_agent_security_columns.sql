-- MySQL 5.6: shorten long column names without losing data.

ALTER TABLE `agent_security_cases`
  CHANGE COLUMN `first_vulnerable_at` `found_at` datetime DEFAULT NULL
    COMMENT '发现时间',
  CHANGE COLUMN `remediation_advice` `advice` text
    COMMENT '修复建议',
  CHANGE COLUMN `repair_status` `status` tinyint(3) unsigned DEFAULT NULL
    COMMENT '修复状态';

ALTER TABLE `agent_security_case_runs`
  CHANGE COLUMN `attack_result` `result` tinyint(3) unsigned NOT NULL
    COMMENT '测试结果',
  CHANGE COLUMN `oracle_outcome` `outcome` varchar(64) DEFAULT NULL
    COMMENT 'Oracle结果',
  CHANGE COLUMN `evidence_summary` `evidence` text
    COMMENT '判定证据',
  CHANGE COLUMN `agent_response_excerpt` `response` text
    COMMENT 'Agent回复';

ALTER TABLE `agent_security_scenarios`
  MODIFY COLUMN `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  MODIFY COLUMN `scenario_code` varchar(64) NOT NULL COMMENT '场景编号',
  MODIFY COLUMN `scenario_name` varchar(128) NOT NULL COMMENT '场景名称',
  MODIFY COLUMN `scope_type` tinyint(3) unsigned NOT NULL DEFAULT '0' COMMENT '场景范围',
  MODIFY COLUMN `agent_code` varchar(64) DEFAULT NULL COMMENT 'Agent编号',
  MODIFY COLUMN `description` text COMMENT '场景说明',
  MODIFY COLUMN `enabled` tinyint(3) unsigned NOT NULL DEFAULT '1' COMMENT '是否启用',
  MODIFY COLUMN `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  MODIFY COLUMN `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间';

ALTER TABLE `agent_security_cases`
  MODIFY COLUMN `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  MODIFY COLUMN `case_code` varchar(64) NOT NULL COMMENT 'Case编号',
  MODIFY COLUMN `scenario_id` bigint(20) unsigned NOT NULL COMMENT '场景ID',
  MODIFY COLUMN `agent_code` varchar(64) NOT NULL COMMENT 'Agent编号',
  MODIFY COLUMN `engine` varchar(16) NOT NULL COMMENT '测试引擎',
  MODIFY COLUMN `pack_id` varchar(128) NOT NULL COMMENT 'Pack编号',
  MODIFY COLUMN `prompt` longtext NOT NULL COMMENT '攻击Prompt',
  MODIFY COLUMN `root_cause` text COMMENT '问题归因',
  MODIFY COLUMN `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  MODIFY COLUMN `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间';

ALTER TABLE `agent_security_case_runs`
  MODIFY COLUMN `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  MODIFY COLUMN `run_id` varchar(64) NOT NULL COMMENT '运行编号',
  MODIFY COLUMN `case_id` bigint(20) unsigned NOT NULL COMMENT 'Case ID',
  MODIFY COLUMN `tested_at` datetime NOT NULL COMMENT '测试时间',
  MODIFY COLUMN `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '写入时间';
