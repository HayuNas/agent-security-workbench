-- Backfill pre-taxonomy Findings without inventing classifications.

UPDATE `agent_security_findings` f
JOIN `agent_security_scenarios` s ON s.id=f.scenario_id
SET
  f.target_key=COALESCE(NULLIF(f.target_key, ''), f.agent_code),
  f.issue_type=COALESCE(NULLIF(f.issue_type, ''), s.scenario_code),
  f.primary_trigger_type='OTHER',
  f.trigger_types='["OTHER"]',
  f.remediation_type='NEEDS_TRIAGE',
  f.remediation_scope='MIXED',
  f.root_cause_family='UNKNOWN',
  f.finding_fingerprint=CASE
    WHEN f.finding_fingerprint='' THEN SHA2(
      CONCAT_WS('|', f.agent_code, s.scenario_code, 'LEGACY', f.finding_id),
      256
    )
    ELSE f.finding_fingerprint
  END,
  f.analysis_status='COMPLETED',
  f.classification_version='legacy-backfill-v1',
  f.first_seen_at=f.created_at,
  f.last_seen_at=f.updated_at;

INSERT INTO `agent_security_finding_batches` (
  batch_id, source_run_ids, target_key, asset_snapshot_id,
  analysis_status, case_count, finding_count, model_name,
  classification_version, report_json_path, error_message,
  created_at, updated_at
)
SELECT
  f.batch_id,
  '[]',
  MIN(COALESCE(NULLIF(f.target_key, ''), f.agent_code)),
  NULL,
  'COMPLETED_LEGACY',
  COUNT(DISTINCT c.case_id),
  COUNT(DISTINCT f.finding_id),
  MAX(f.model_name),
  'legacy-backfill-v1',
  NULL,
  NULL,
  MIN(f.created_at),
  MAX(f.updated_at)
FROM agent_security_findings f
LEFT JOIN agent_security_cases c ON c.finding_id=f.finding_id
GROUP BY f.batch_id
ON DUPLICATE KEY UPDATE
  target_key=VALUES(target_key),
  analysis_status=VALUES(analysis_status),
  case_count=VALUES(case_count),
  finding_count=VALUES(finding_count),
  model_name=VALUES(model_name),
  classification_version=VALUES(classification_version),
  updated_at=VALUES(updated_at);

INSERT INTO `agent_security_finding_cases` (
  finding_id, case_id, first_batch_id, last_batch_id, linked_at
)
SELECT
  c.finding_id,
  c.case_id,
  f.batch_id,
  f.batch_id,
  COALESCE(c.found_at, c.created_at)
FROM agent_security_cases c
JOIN agent_security_findings f ON f.finding_id=c.finding_id
WHERE c.finding_id IS NOT NULL
ON DUPLICATE KEY UPDATE
  last_batch_id=VALUES(last_batch_id),
  updated_at=CURRENT_TIMESTAMP;
