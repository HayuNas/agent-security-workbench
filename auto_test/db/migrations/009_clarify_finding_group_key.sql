-- Finding IDs identify one batch occurrence; the fingerprint only groups peers.

ALTER TABLE `agent_security_findings`
  MODIFY COLUMN `finding_fingerprint` varchar(64) NOT NULL DEFAULT ''
  COMMENT '跨批次同类Finding归组键';
