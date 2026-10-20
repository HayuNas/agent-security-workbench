"""Read-only Case workspace projections; links use identifiers, never scene similarity."""
import json

from . import case_store, report_store
from .findings import SUCCESS_OUTCOMES

def repair_expression(alias):
    return f"""COALESCE({alias}.status,(SELECT CASE
        WHEN SUM(f.status=2)>0 THEN 2 WHEN SUM(f.status=0)>0 THEN 0
        WHEN COUNT(*)>0 THEN 1 ELSE NULL END
        FROM agent_security_finding_cases fc JOIN agent_security_findings f ON f.finding_id=fc.finding_id
        WHERE fc.case_id={alias}.case_id))"""


def _review_links(cur, case_ids):
    links = {key: set() for key in case_ids}
    if not case_ids:
        return links
    cur.execute("""SELECT fc.case_id,f.manual_payload FROM agent_security_finding_cases fc
        JOIN agent_security_findings f ON f.finding_id=fc.finding_id
        WHERE fc.case_id IN (""" + ",".join(["%s"] * len(case_ids)) + ") AND f.manual_payload IS NOT NULL", case_ids)
    for case_id, payload in cur.fetchall():
        registry = report_store.unpacked(payload)
        if case_id in registry.get("case_ids", []):
            links[case_id].update(registry.get("reviews", {}))
    return links


def enrich(cur, rows):
    if not rows:
        return
    ids = [row["id"] for row in rows]
    cur.execute(f"""SELECT c.case_id,{repair_expression('c')},
        (SELECT COUNT(*) FROM agent_security_finding_cases f WHERE f.case_id=c.case_id),
        latest.outcome,latest.tested_at,latest.run_id
        FROM agent_security_cases c
        LEFT JOIN agent_security_case_runs latest ON latest.id=(
            SELECT x.id FROM agent_security_case_runs x
            JOIN agent_security_cases source ON source.case_id=x.case_id
            WHERE (x.case_id=c.case_id OR
                (x.source_case_id=c.case_id AND x.test_kind=c.test_kind AND source.target_key=c.target_key))
            AND (x.result_id IS NOT NULL OR NOT EXISTS (
                SELECT 1 FROM agent_security_case_runs child WHERE child.parent_run_id=x.run_id))
            ORDER BY x.tested_at DESC,x.id DESC LIMIT 1)
        WHERE c.case_id IN ({','.join(['%s'] * len(ids))})""", ids)
    extra = {row[0]: row[1:] for row in cur.fetchall()}
    links = _review_links(cur, ids)
    review_ids = sorted(set().union(*links.values()))
    original = {}
    if review_ids:
        cur.execute("""SELECT m.review_id,x.outcome,x.tested_at,x.run_id,m.action
            FROM agent_manual_reviews m JOIN agent_security_case_runs x ON x.run_id=m.source_run_id
            WHERE m.review_id IN (""" + ",".join(["%s"] * len(review_ids)) + ")", review_ids)
        original = {rid: (outcome, str(tested), run, action) for rid, outcome, tested, run, action in cur.fetchall()}
    for row in rows:
        status, findings, outcome, tested, run = extra.get(row["id"], (None, 0, None, None, None))
        candidates = [original[rid] for rid in links[row["id"]] if rid in original]
        manual_action = None
        if run:
            candidates.append((outcome, str(tested), run, None))
        if candidates:
            outcome, tested, run, manual_action = max(candidates, key=lambda value: (value[1], value[2]))
        row.update(repairStatus=status, findingCount=findings,
                   lastRun={"outcome": outcome, "testedAt": str(tested), "runId": run, "manualAction": manual_action} if run else None)


def _context(kind, case_id):
    value = case_store.detail(kind, case_id)
    if not value:
        raise ValueError("用例不存在")
    target = (value["case"].get("target") or {}).get("target_key") or "ky-agent:ky-sales"
    return value, target


def _run_scope(case_id, target, kind, review_ids=()):
    linked = (" OR x.run_id IN (SELECT source_run_id FROM agent_manual_reviews WHERE review_id IN (" +
              ",".join(["%s"] * len(review_ids)) + "))") if review_ids else ""
    clause = """(x.case_id=%s OR (x.source_case_id=%s AND x.test_kind=%s AND source.target_key=%s)""" + linked + """)
        AND (x.result_id IS NOT NULL OR NOT EXISTS (
          SELECT 1 FROM agent_security_case_runs child WHERE child.parent_run_id=x.run_id))"""
    return clause, (case_id, case_id, case_store.test_kind(kind), target, *review_ids)


def activity(kind, case_id, section, page=1, page_size=20):
    if section not in {"runs", "findings", "reviews"} or page < 1 or not 1 <= page_size <= 100:
        raise ValueError("查询参数无效")
    value, target = _context(kind, case_id)
    with case_store.reader() as conn, conn.cursor() as cur:
        linked_reviews = sorted(_review_links(cur, [case_id])[case_id])
        if section == "runs":
            where, args = _run_scope(case_id, target, kind, linked_reviews)
            base = """FROM agent_security_case_runs x
                JOIN agent_security_cases source ON source.case_id=x.case_id
                LEFT JOIN agent_test_reports rr ON rr.report_id=x.report_id
                LEFT JOIN agent_test_tasks t ON t.task_id=rr.task_id WHERE """ + where
            cur.execute("SELECT COUNT(*) " + base, args)
            total = cur.fetchone()[0]
            cur.execute("""SELECT x.run_id,x.result_id,x.tested_at,x.outcome,x.record_kind,
                rr.schema_version,rr.task_id,t.name """ + base +
                " ORDER BY x.tested_at DESC,x.id DESC LIMIT %s OFFSET %s", (*args, page_size, (page-1)*page_size))
            items = [{"id": run, "resultId": result, "testedAt": str(tested), "outcome": outcome,
                      "recordKind": record_kind, "schema": schema or "", "taskId": task, "taskName": name or "历史执行"}
                     for run, result, tested, outcome, record_kind, schema, task, name in cur.fetchall()]
        elif section == "findings":
            base = """FROM agent_security_finding_cases fc
                JOIN agent_security_findings f ON f.finding_id=fc.finding_id WHERE fc.case_id=%s"""
            cur.execute("SELECT COUNT(*) " + base, (case_id,))
            total = cur.fetchone()[0]
            cur.execute("""SELECT f.finding_id,f.title,f.status,f.severity,f.analysis_status,f.updated_at """ + base +
                        " ORDER BY f.updated_at DESC,f.finding_id LIMIT %s OFFSET %s", (case_id, page_size, (page-1)*page_size))
            items = [{"id": fid, "title": title, "status": status, "severity": severity,
                      "analysisStatus": analysis, "updatedAt": str(updated)}
                     for fid, title, status, severity, analysis, updated in cur.fetchall()]
        else:
            # Manual links already carry review IDs. Read only related registries, never all audit bodies.
            ids = set(linked_reviews)
            direct = (value["case"].get("manual_review") or {}).get("id")
            if direct:
                ids.add(direct)
            # source_run_id also includes explicit negative review decisions for this Case.
            where, args = _run_scope(case_id, target, kind)
            base = """FROM agent_manual_reviews m WHERE
                m.source_run_id IN (SELECT x.run_id FROM agent_security_case_runs x
                JOIN agent_security_cases source ON source.case_id=x.case_id WHERE """ + where + ")"
            params = list(args)
            if ids:
                base += " OR m.review_id IN (" + ",".join(["%s"] * len(ids)) + ")"
                params.extend(sorted(ids))
            cur.execute("SELECT COUNT(*) " + base, params)
            total = cur.fetchone()[0]
            cur.execute("SELECT m.review_id,m.action,m.reviewed_at,m.payload " + base +
                        " ORDER BY m.reviewed_at DESC,m.review_id LIMIT %s OFFSET %s",
                        (*params, page_size, (page-1)*page_size))
            items = []
            for rid, action, reviewed, payload in cur.fetchall():
                review = json.loads(payload).get("review") or {}
                items.append({"id": rid, "action": action, "reviewedAt": reviewed,
                              "reason": review.get("reason") or "", "outcome": review.get("outcome"),
                              "reviewedBy": review.get("reviewedBy") or "历史记录未记载",
                              "taskId": review.get("taskId")})
    return report_store.evidence({"items": items, "total": total, "page": page, "pageSize": page_size})


def _execution(row):
    payload, reason, reply, outcome, run_id, tested, record_kind, schema = row
    data = report_store.unpacked(payload) if payload else {"outcome": outcome, "reason": reason, "reply": reply}
    data.setdefault("outcome", outcome)
    data["recordMetadata"] = {"runId": run_id, "testedAt": str(tested), "recordKind": record_kind,
                              "schema": schema or "", "storage": "payload" if payload else "legacy_excerpt",
                              "possiblyTruncated": not payload and len(reply or "") >= 6000}
    return report_store.evidence(data)


_EXECUTION_COLUMNS = """SELECT x.payload,x.evidence,x.response,x.outcome,x.run_id,x.tested_at,
    x.record_kind,rr.schema_version FROM agent_security_case_runs x
    JOIN agent_security_cases source ON source.case_id=x.case_id
    LEFT JOIN agent_test_reports rr ON rr.report_id=x.report_id WHERE """


def discovery(kind, case_id):
    value, target = _context(kind, case_id)
    case = value["case"]
    snapshot = case.get("failure_evidence") or {}
    if snapshot.get("turns") or snapshot.get("agent_reply") or snapshot.get("reply"):
        record = {**snapshot, "outcome": snapshot.get("outcome") or case.get("first_outcome")}
        record["recordMetadata"] = {"testedAt": case.get("found_at"), "storage": "case_snapshot"}
        return report_store.evidence({"record": record, "source": "case_snapshot"})
    with case_store.reader() as conn, conn.cursor() as cur:
        review_ids = sorted(_review_links(cur, [case_id])[case_id])
        where, args = _run_scope(case_id, target, kind, review_ids)
        outcomes = sorted(SUCCESS_OUTCOMES | {"FAIL", "SCRIPT_DRIFT"})
        # Only explicit Case/run/review links count; never infer discovery from the current input.
        cur.execute(_EXECUTION_COLUMNS + where + " AND (x.outcome IN (" +
                    ",".join(["%s"] * len(outcomes)) + ") OR EXISTS ("
                    "SELECT 1 FROM agent_manual_reviews m WHERE m.source_run_id=x.run_id AND m.action='include'))"
                    " ORDER BY x.tested_at ASC,x.id ASC LIMIT 1", (*args, *outcomes))
        row = cur.fetchone()
    if row and row[0]:
        return {"record": _execution(row), "source": "first_issue_run"}
    if case.get("successful_outputs"):
        return report_store.evidence({"record": {"evidenceReplies": case["successful_outputs"],
            "outcome": case.get("first_outcome"),
            "recordMetadata": {"testedAt": case.get("found_at"), "storage": "reply_snapshot"}},
            "source": "case_snapshot"})
    return {"record": _execution(row) if row else None, "source": "first_issue_run"}


def run_detail(kind, case_id, run_id):
    _, target = _context(kind, case_id)
    with case_store.reader() as conn, conn.cursor() as cur:
        where, args = _run_scope(case_id, target, kind, sorted(_review_links(cur, [case_id])[case_id]))
        cur.execute(_EXECUTION_COLUMNS + where +
            " AND x.run_id=%s", (*args, run_id))
        row = cur.fetchone()
    if not row:
        raise ValueError("该执行记录不属于当前用例")
    return _execution(row)
