"""Extend the existing review and Finding batch tables, without model calls."""
import argparse

from ..records import report_store


def initialize():
    definitions = {
        "agent_manual_reviews": {
            "analysis_scope": "CHAR(64) NULL",
            "analysis_status": "VARCHAR(20) NOT NULL DEFAULT 'not_required'",
            "analysis_batch_id": "VARCHAR(64) NULL",
        },
        "agent_security_finding_batches": {
            "review_task_id": "VARCHAR(64) NULL",
            "review_scope": "CHAR(64) NULL",
            "review_payload": "LONGTEXT NULL",
        },
    }
    with report_store.connection() as conn, conn.cursor() as cur:
        for table, fields in definitions.items():
            cur.execute("SHOW COLUMNS FROM " + table)
            columns = {row[0] for row in cur.fetchall()}
            additions = [f"ADD COLUMN {name} {definition}" for name, definition in fields.items() if name not in columns]
            if additions:
                cur.execute("ALTER TABLE " + table + " " + ", ".join(additions))
        for table, name, columns in (
            ("agent_manual_reviews", "idx_review_analysis", "task_id,analysis_status,analysis_scope"),
            ("agent_security_finding_batches", "idx_review_batch", "review_task_id,analysis_status"),
        ):
            cur.execute("SHOW INDEX FROM " + table)
            if name not in {row[2] for row in cur.fetchall()}:
                cur.execute(f"ALTER TABLE {table} ADD INDEX {name} ({columns})")
        conn.commit()
    # Old RF records remain as audit evidence; no historical model jobs are started.
    from . import review_analysis
    migrated = 0
    while True:
        with report_store.connection() as conn, conn.cursor() as cur:
            cur.execute("""SELECT m.review_id,m.payload,r.payload,x.payload,x.pointer
                FROM agent_manual_reviews m
                JOIN agent_security_case_runs x ON x.result_id=m.source_result_id
                JOIN agent_test_reports r ON r.report_id=x.report_id
                WHERE m.action='include' AND m.analysis_scope IS NULL LIMIT 100""")
            rows = cur.fetchall()
            for key, payload, header, item, pointer in rows:
                receipt = report_store.unpacked(payload)["review"]
                scope = review_analysis.scope_for(receipt, report_store.unpacked(header), report_store.unpacked(item), pointer)
                cur.execute("""UPDATE agent_manual_reviews SET analysis_scope=%s,analysis_status='pending'
                    WHERE review_id=%s AND analysis_scope IS NULL""", (scope, key))
            conn.commit()
        migrated += len(rows)
        if len(rows) < 100:
            break
    return {"migrated_reviews": migrated, "model_calls": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", required=True)
    parser.parse_args()
    print(initialize())
