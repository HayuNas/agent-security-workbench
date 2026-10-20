ALTER TABLE `agent_security_scenarios`
  MODIFY COLUMN `scenario_code` varchar(64) NOT NULL COMMENT '场景编号';

ALTER TABLE `agent_security_cases`
  MODIFY COLUMN `case_id` varchar(64) NOT NULL COMMENT 'Case编号';
