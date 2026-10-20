"""Additive MySQL 5.6 migration; legacy evidence tables are not dropped."""

COLUMNS = {
    "agent_security_scenarios": {
        "test_kind": "varchar(20) NOT NULL DEFAULT 'attack'",
        "sort_order": "int NOT NULL DEFAULT 0",
        "revision": "bigint unsigned NOT NULL DEFAULT 1",
    },
    "agent_security_cases": {
        "test_kind": "varchar(20) NOT NULL DEFAULT 'attack'",
        "target_key": "varchar(191) NOT NULL DEFAULT ''",
        "source_case_id": "varchar(191) NOT NULL DEFAULT ''",
        "title": "varchar(255) NOT NULL DEFAULT ''",
        "library_kind": "varchar(32) NOT NULL DEFAULT ''",
        "regression_payload": "longtext",
    },
    "agent_security_case_runs": {
        "test_kind": "varchar(20) NOT NULL DEFAULT 'attack'",
        "record_kind": "varchar(32) NOT NULL DEFAULT 'legacy_summary'",
        "parent_run_id": "varchar(64) DEFAULT NULL",
        "result_id": "varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL",
        "report_id": "varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL",
        "ordinal": "int unsigned DEFAULT NULL",
        "pointer": "varchar(191) NOT NULL DEFAULT ''",
        "source_case_id": "varchar(191) NOT NULL DEFAULT ''",
        "title": "varchar(255) NOT NULL DEFAULT ''",
        "description": "text",
        "direction": "varchar(32) NOT NULL DEFAULT ''",
        "review_outcomes": "text",
        "payload": "longtext",
    },
    "agent_security_findings": {
        "test_kind": "varchar(20) NOT NULL DEFAULT 'attack'",
        "payload": "longtext",
        "manual_payload": "longtext",
    },
    "agent_manual_reviews": {
        "source_result_id": "varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL",
        "source_run_id": "varchar(64) DEFAULT NULL",
    },
    "agent_test_report_findings": {"ordinal": "int unsigned NOT NULL DEFAULT 0"},
}
INDEXES = {
    "agent_security_case_runs": {
        "uk_case_run_result": "UNIQUE KEY uk_case_run_result (result_id)",
        "idx_case_run_report": "KEY idx_case_run_report (report_id,outcome,direction,ordinal)",
        "idx_case_run_parent": "KEY idx_case_run_parent (parent_run_id)",
    },
    "agent_security_findings": {
        "idx_finding_kind": "KEY idx_finding_kind (test_kind,status)",
    },
    "agent_manual_reviews": {
        "idx_manual_review_result": "KEY idx_manual_review_result (source_result_id)",
    },
}


def initialize(conn):
    with conn.cursor() as cur:
        for table, columns in COLUMNS.items():
            cur.execute(f"SHOW COLUMNS FROM {table}")
            existing = {row[0]: row for row in cur.fetchall()}
            additions = [f"ADD COLUMN {name} {definition}" for name, definition in columns.items() if name not in existing]
            # Guard and positive scenarios must not be mislabeled as attacks.
            if table in {"agent_security_cases", "agent_security_findings"} and existing["scenario_id"][2] == "NO":
                additions.append("MODIFY COLUMN scenario_id bigint unsigned NULL")
            if additions:
                cur.execute(f"ALTER TABLE {table} " + ", ".join(additions))
            binary_columns = {name: definition for name, definition in columns.items() if "COLLATE utf8mb4_bin" in definition}
            if binary_columns:
                cur.execute(f"SHOW FULL COLUMNS FROM {table}")
                collations = {row[0]: row[2] for row in cur.fetchall()}
                changes = [f"MODIFY COLUMN {name} {definition}" for name, definition in binary_columns.items()
                           if collations[name] != "utf8mb4_bin"]
                if changes:
                    cur.execute(f"ALTER TABLE {table} " + ", ".join(changes))
        for table, indexes in INDEXES.items():
            cur.execute(f"SHOW INDEX FROM {table}")
            existing = {row[2] for row in cur.fetchall()}
            additions = [f"ADD {definition}" for name, definition in indexes.items() if name not in existing]
            if additions:
                cur.execute(f"ALTER TABLE {table} " + ", ".join(additions))
    conn.commit()
