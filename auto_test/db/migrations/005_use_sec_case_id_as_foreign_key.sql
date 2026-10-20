-- Replace the numeric Case surrogate key with the existing SEC Case ID.

ALTER TABLE `agent_security_case_runs`
  ADD COLUMN `case_ref` varchar(64) DEFAULT NULL COMMENT 'Case编号' AFTER `run_id`;

UPDATE `agent_security_case_runs` r
INNER JOIN `agent_security_cases` c ON c.`id` = r.`case_id`
SET r.`case_ref` = c.`case_code`;

ALTER TABLE `agent_security_case_runs`
  DROP FOREIGN KEY `fk_agent_security_case_runs_case`,
  DROP INDEX `idx_agent_security_case_runs_case_time`,
  DROP COLUMN `case_id`,
  CHANGE COLUMN `case_ref` `case_id` varchar(64) NOT NULL COMMENT 'Case编号';

ALTER TABLE `agent_security_cases`
  DROP INDEX `uk_agent_security_cases_code`,
  DROP PRIMARY KEY,
  DROP COLUMN `id`,
  CHANGE COLUMN `case_code` `case_id` varchar(64) NOT NULL COMMENT 'Case编号',
  ADD PRIMARY KEY (`case_id`);

ALTER TABLE `agent_security_case_runs`
  ADD KEY `idx_agent_security_case_runs_case_time` (`case_id`,`tested_at`),
  ADD CONSTRAINT `fk_agent_security_case_runs_case`
    FOREIGN KEY (`case_id`) REFERENCES `agent_security_cases` (`case_id`)
    ON UPDATE CASCADE ON DELETE RESTRICT;
