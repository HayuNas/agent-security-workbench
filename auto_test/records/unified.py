"""Canonical cases, executions, Findings and reviews reuse the original tables."""
from __future__ import annotations

import hashlib
import json
import os

from . import report_store as reports
from .mysql import _mysql_datetime, _run_code
from .findings import is_success_outcome


def enabled():
    value = os.getenv("WORKBENCH_RECORDS_BACKEND", "mysql").strip().lower()
    if value not in {"mysql", "legacy"}:
        raise ValueError("WORKBENCH_RECORDS_BACKEND must be mysql or legacy")
    return value == "mysql" and reports.enabled()


def target_key(report):
    target = report.get("target") or {}
    if isinstance(target, dict) and target.get("target_key"):
        return str(target["target_key"])
    return "guard" if reports.report_module(report) == "guard" else "ky-agent:ky-sales"


def legacy_run(report, item):
    schema = report["schema_version"]
    key = (item.get("iteration_id") if schema.endswith("security-attack-pack-report") else
           item.get("query_id") if schema.endswith("epe-report") else
           item.get("case_id") if schema.endswith("security-regression-report") else None)
    if key is None:
        return None
    return _run_code(str(report.get("experiment_id") or report.get("run_id") or "security-run"), str(key or ""))


def case_key(kind, target, source_id, item, *, origin=""):
    value = source_id or item.get("prompt") or item.get("input") or item.get("initial_message") or item.get("turns") or item
    if kind == "attack":
        messages = [str(turn.get("message") or turn.get("customer_message") or "").strip()
                    for turn in item.get("turns") or [] if isinstance(turn, dict)]
        messages = [message for message in messages if message]
        messages = messages or item.get("customer_messages") or item.get("messages") or [
            item.get("initial_message") or item.get("prompt") or item.get("input") or ""]
        value = {"pack": item.get("_pack_id") or item.get("pack_id") or "",
                 "messages": messages} if any(messages) else {"source": source_id, "origin": origin}
    prefix = {"attack": "SEC", "positive": "BIZ", "guard": "GUARD"}[kind]
    return prefix + "-" + reports.identity(kind, target, value)[:40].upper()


def result_code(kind, outcome):
    if kind == "attack":
        return 1 if is_success_outcome(outcome) else 0 if outcome == "RESISTED" else 2
    return 1 if outcome == "FAIL" else 0 if outcome == "PASS" else 2


def write_results(cur, report_id, report, rows):
    entries = list(reports.result_entries(report))
    kind, target = reports.report_module(report), target_key(report)
    old_ids = sorted({key for _, item, _ in entries if (key := legacy_run(report, item))})
    old = {}
    if old_ids:
        cur.execute("SELECT run_id,case_id FROM agent_security_case_runs WHERE run_id IN (" +
                    ",".join(["%s"] * len(old_ids)) + ")", old_ids)
        old = dict(cur.fetchall())
    cur.execute("SELECT scenario_code,id FROM agent_security_scenarios")
    scenarios = dict(cur.fetchall())
    cases, runs = {}, []
    for row, (_, item, pack) in zip(rows, entries):
        rid, _, ordinal, pointer, source, title, description, outcome, direction, allowed, payload = row
        parent = legacy_run(report, item)
        case_id = old.get(parent) or case_key(kind, target, source,
            {**item, "_pack_id": pack.get("pack_id") or report.get("query_pack") or ""}, origin=report_id)
        # A source case can be tested in both directions without becoming two Cases.
        if kind == "guard":
            case_target = "guard:" + str(item.get("agent_id") or "default")
            source = str(item.get("source_case_id") or source)
            case_id = case_key(kind, case_target, source, item)
        else:
            case_target = target
        scenario_code = str(pack.get("pack_id") or item.get("pack_id") or "").upper()
        cases[case_id] = (case_id, scenarios.get(scenario_code), case_target[-64:], "guard" if kind == "guard" else "epe" if schema_is_epe(report) else str(report.get("engine") or "cr")[:16],
                          scenario_code[:128], description, kind, case_target[:191], source[:191], title)
        runs.append(("EXEC-" + rid[:56], case_id, _mysql_datetime(report.get("created_at")),
                     result_code(kind, outcome), outcome, "", "", kind,
                     "attempt" if schema_is_epe(report) else "execution",
                     parent if parent in old else None, rid, report_id, ordinal, pointer,
                     row[4], title, description, direction, allowed, payload))
    if cases:
        # Existing case identity, repair status and attribution are authoritative.
        cur.executemany("""INSERT INTO agent_security_cases
            (case_id,scenario_id,agent_code,engine,pack_id,prompt,test_kind,target_key,source_case_id,title)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE case_id=VALUES(case_id)""", list(cases.values()))
    if runs:
        cur.executemany("""INSERT INTO agent_security_case_runs
            (run_id,case_id,tested_at,result,outcome,evidence,response,test_kind,record_kind,parent_run_id,
             result_id,report_id,ordinal,pointer,source_case_id,title,description,direction,review_outcomes,payload)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE run_id=VALUES(run_id)""", runs)


def schema_is_epe(report):
    return str(report.get("schema_version") or "").endswith("epe-report")


def _severity(value):
    if isinstance(value, int):
        return max(0, min(3, value))
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(str(value).upper(), 1)


def write_finding(cur, finding, *, kind, batch_id, target="", manual=False):
    fid = str(finding.get("finding_id") or "")
    if not fid or len(fid) > 64:
        raise ValueError("Finding ID missing or too long")
    source = finding.get("source_context") or {}
    if not isinstance(source, dict):
        source = {}
    target = str(finding.get("target_key") or target)
    payload = reports.packed(reports.encoded(reports.evidence(finding)))
    cur.execute("""INSERT INTO agent_security_findings
        (finding_id,batch_id,scenario_id,agent_code,target_key,title,trigger_types,
         analysis_source_branch,analysis_source_commit,root_cause,evidence,remediation,acceptance,
         confidence,severity,model_name,status,test_kind,payload,manual_payload)
        VALUES (%s,%s,NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE payload=COALESCE(payload,VALUES(payload))""",
        (fid, batch_id[:64], target[-64:], target[:128], str(finding.get("title") or fid)[:255], "[]",
         str(source.get("branch") or "")[:128], str(source.get("commit") or "")[:64],
         reports.encoded(finding.get("root_cause") or finding.get("root_cause_hypothesis") or ""),
         reports.encoded(finding.get("evidence") or {}),
         reports.encoded(finding.get("remediation") or finding.get("remediation_requirements") or {}),
         reports.encoded(finding.get("acceptance") or finding.get("acceptance_criteria") or {}),
         1, _severity(finding.get("severity")), str(finding.get("model_name") or "")[:128],
         0, kind, payload, payload if manual else None))
    if manual:
        cur.execute("UPDATE agent_security_findings SET manual_payload=%s WHERE finding_id=%s", (payload, fid))


def write_findings(cur, report_id, report):
    kind, target = reports.report_module(report), target_key(report)
    batch_id = str(report.get("batch_id") or report_id)
    for finding in report.get("findings") or []:
        write_finding(cur, finding, kind=kind, batch_id=batch_id, target=target)
        wanted = set(finding.get("case_ids") or []) | set(finding.get("guard_case_ids") or [])
        if wanted:
            # Only evidence from the explicitly named source run can establish new links.
            cur.execute("""SELECT DISTINCT x.case_id,x.source_case_id
                FROM agent_security_case_runs x JOIN agent_test_reports r ON r.report_id=x.report_id
                WHERE r.task_id=(SELECT task_id FROM agent_test_reports WHERE report_id=%s)
                AND r.run_id=%s""", (report_id, str(report.get("source_run_id") or "")))
            linked = {case_id for case_id, source_id in cur.fetchall() if case_id in wanted or source_id in wanted}
            for case_id in linked:
                cur.execute("""INSERT INTO agent_security_finding_cases
                    (finding_id,case_id,first_batch_id,last_batch_id) VALUES (%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE last_batch_id=VALUES(last_batch_id)""",
                    (finding["finding_id"], case_id, batch_id[:64], batch_id[:64]))


def finding_detail(cur, fid):
    cur.execute("""SELECT payload,title,status,fix_commit,resolution_note,test_kind,
                   root_cause,evidence,remediation,acceptance
                   FROM agent_security_findings WHERE finding_id=%s""", (fid,))
    row = cur.fetchone()
    if not row:
        return None
    data = reports.unpacked(row[0]) if row[0] else {
        "finding_id": fid, "root_cause": row[6], "evidence": row[7],
        "remediation": row[8], "acceptance": row[9]}
    return {**data, "title": row[1], "repair_status": row[2], "fix_commit": row[3],
            "resolution_note": row[4], "test_kind": row[5]}


def finding_by_id(fid):
    with reports.connection() as conn:
        with conn.cursor() as cur:
            return finding_detail(cur, fid)


def review_reference(result_id):
    with reports.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT r.task_id,r.source_name,x.pointer FROM agent_security_case_runs x
                JOIN agent_test_reports r ON r.report_id=x.report_id
                WHERE x.result_id=%s AND x.outcome='REVIEW' AND x.test_kind IN ('attack','positive')""", (result_id,))
            row = cur.fetchone()
            return hashlib.sha256(f"{row[0]}/{row[1]}/{row[2]}".encode()).hexdigest()[:32] if row else None


def receipts():
    with reports.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT review_id,payload FROM agent_manual_reviews")
            return {key: json.loads(payload)["review"] for key, payload in cur.fetchall()}


def save_receipt(receipt, *, cur=None):
    if cur is None:
        with reports.connection() as conn:
            with conn.cursor() as cursor:
                save_receipt(receipt, cur=cursor)
            conn.commit()
        return
    rid = reports.identity(reports.identity(receipt["taskId"], receipt["sourceReport"]), receipt["sourcePointer"])
    cur.execute("SELECT run_id FROM agent_security_case_runs WHERE result_id=%s", (rid,))
    row = cur.fetchone()
    cur.execute("SELECT payload FROM agent_manual_reviews WHERE review_id=%s FOR UPDATE", (receipt["id"],))
    old = cur.fetchone()
    payload = json.loads(old[0]) if old else {}
    previous = payload.get("review") or {}
    if previous and any(previous.get(k) != receipt.get(k) for k in ("action", "reason", "outcome", "taskId", "sourcePointer")):
        raise ValueError("Conflicting review decision; original retained")
    # Existing audit snapshots are retained, but new decisions reference execution evidence.
    payload["review"] = receipt
    cur.execute("""INSERT INTO agent_manual_reviews
        (review_id,task_id,test_kind,action,reviewed_at,payload,source_result_id,source_run_id)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE
        payload=VALUES(payload),source_result_id=VALUES(source_result_id),source_run_id=VALUES(source_run_id)""",
        (receipt["id"], receipt["taskId"], receipt["kind"], receipt["action"], receipt["reviewedAt"],
         reports.encoded(payload), rid if row else None, row[0] if row else None))


def manual_registry(cur=None):
    if cur is None:
        with reports.connection() as conn:
            with conn.cursor() as cursor:
                return manual_registry(cursor)
    registry = {"findings": {}, "case_links": {}}
    cur.execute("SELECT finding_id,manual_payload FROM agent_security_findings WHERE manual_payload IS NOT NULL")
    for fid, payload in cur.fetchall():
        finding = reports.unpacked(payload)
        registry["findings"][fid] = finding
        for case_id in finding.get("case_ids") or []:
            identity = f'{finding["kind"]}|{finding["target_key"]}|{case_id}'
            registry["case_links"][hashlib.sha256(identity.encode()).hexdigest()[:20].upper()] = fid
    return registry


def save_manual_registry(registry, *, cur=None):
    if cur is None:
        with reports.connection() as conn:
            with conn.cursor() as cursor:
                save_manual_registry(registry, cur=cursor)
            conn.commit()
        return
    for finding in registry["findings"].values():
        write_finding(cur, finding, kind=finding["kind"], batch_id="MANUAL", manual=True)
        for case_id in finding.get("case_ids") or []:
            cur.execute("SELECT case_id FROM agent_security_cases WHERE case_id=%s", (case_id,))
            if cur.fetchone():
                cur.execute("""INSERT INTO agent_security_finding_cases
                    (finding_id,case_id,first_batch_id,last_batch_id) VALUES (%s,%s,'MANUAL','MANUAL')
                    ON DUPLICATE KEY UPDATE last_batch_id=VALUES(last_batch_id)""",
                    (finding["finding_id"], case_id))


def register_library_cases(cases, kind, *, cur=None, replace=False):
    if cur is None:
        with reports.connection() as conn:
            with conn.cursor() as cursor:
                register_library_cases(cases, kind, cur=cursor, replace=replace)
            conn.commit()
        return
    test_kind = "attack" if kind == "security" else "positive"
    for case in cases:
        case_id = str(case["case_id"])
        if len(case_id) > 64:
            raise ValueError("Case ID exceeds canonical key width")
        cur.execute("SELECT regression_payload FROM agent_security_cases WHERE case_id=%s FOR UPDATE", (case_id,))
        old = cur.fetchone()
        payload = reports.packed(reports.encoded(reports.evidence(case)))
        if old and old[0] and reports.unpacked(old[0]) != reports.unpacked(payload) and not replace:
            raise ValueError(f"Regression Case already differs: {case_id}")
        target = str((case.get("target") or {}).get("target_key") or "ky-agent:ky-sales")
        cur.execute("""INSERT INTO agent_security_cases
            (case_id,scenario_id,agent_code,engine,pack_id,prompt,test_kind,target_key,
             source_case_id,title,library_kind,regression_payload)
            VALUES (%s,NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE library_kind=VALUES(library_kind),regression_payload=VALUES(regression_payload)""",
            (case_id, target[-64:], str(case.get("engine") or "cr")[:16], str(case.get("pack_id") or "")[:128],
             "", test_kind, target[:191], case_id, str(case.get("scenario_name") or case_id)[:255], kind, payload))
