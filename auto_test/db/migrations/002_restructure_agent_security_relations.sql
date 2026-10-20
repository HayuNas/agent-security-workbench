-- MySQL 5.6 compatible relational security-test registry.
-- Precondition: the legacy agent_security_cases table is empty.

DROP TABLE `agent_security_cases`;

CREATE TABLE `agent_security_scenarios` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '数据库自增主键',
  `scenario_code` varchar(64) NOT NULL COMMENT '场景唯一编号',
  `scenario_name` varchar(128) NOT NULL COMMENT '安全测试场景名称',
  `scope_type` tinyint(3) unsigned NOT NULL DEFAULT '0' COMMENT '0=通用场景，1=Agent专用场景',
  `agent_code` varchar(64) DEFAULT NULL COMMENT '专用Agent编号；通用场景为空',
  `description` text COMMENT '场景说明',
  `enabled` tinyint(3) unsigned NOT NULL DEFAULT '1' COMMENT '0=停用，1=启用',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_agent_security_scenarios_code` (`scenario_code`),
  KEY `idx_agent_security_scenarios_scope` (`scope_type`,`agent_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Agent安全测试场景';

CREATE TABLE `agent_security_cases` (
  `case_id` varchar(64) NOT NULL COMMENT 'Case编号',
  `scenario_id` bigint(20) unsigned NOT NULL COMMENT '所属安全场景ID',
  `agent_code` varchar(64) NOT NULL COMMENT '本Case测试的Agent编号',
  `engine` varchar(16) NOT NULL COMMENT '执行引擎：cr或epe',
  `pack_id` varchar(128) NOT NULL COMMENT '程序实际执行的Pack编号',
  `prompt` longtext NOT NULL COMMENT '测试Prompt；多轮按执行顺序保存',
  `found_at` datetime DEFAULT NULL COMMENT '发现时间',
  `root_cause` text COMMENT '问题归因；攻击成功后填写',
  `advice` text COMMENT '修复建议',
  `status` tinyint(3) unsigned DEFAULT NULL COMMENT '修复状态',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Case创建时间',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Case更新时间',
  PRIMARY KEY (`case_id`),
  KEY `idx_agent_security_cases_scenario` (`scenario_id`),
  KEY `idx_agent_security_cases_agent` (`agent_code`),
  KEY `idx_agent_security_cases_repair` (`status`),
  CONSTRAINT `fk_agent_security_cases_scenario`
    FOREIGN KEY (`scenario_id`) REFERENCES `agent_security_scenarios` (`id`)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Agent全部安全测试Case';

CREATE TABLE `agent_security_case_runs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '数据库自增主键',
  `run_id` varchar(64) NOT NULL COMMENT '单次执行编号',
  `case_id` varchar(64) NOT NULL COMMENT 'Case编号',
  `tested_at` datetime NOT NULL COMMENT '实际测试时间',
  `result` tinyint(3) unsigned NOT NULL COMMENT '测试结果',
  `outcome` varchar(64) DEFAULT NULL COMMENT 'Oracle结果',
  `evidence` text COMMENT '判定证据',
  `response` text COMMENT 'Agent回复',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '日志写入时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_agent_security_case_runs_run_id` (`run_id`),
  KEY `idx_agent_security_case_runs_case_time` (`case_id`,`tested_at`),
  KEY `idx_agent_security_case_runs_result` (`result`),
  CONSTRAINT `fk_agent_security_case_runs_case`
    FOREIGN KEY (`case_id`) REFERENCES `agent_security_cases` (`case_id`)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Agent安全Case每次执行记录';
