"""Persistent Finding links for confirmed reviews; exact cases, never scene-only grouping."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .model_config import _root
from ..core.redaction import redact_value
from ..records.library_lock import atomic_library_write, serialized_library_write


def _path():
    return _root() / "review-findings.json"


def _load():
    from ..records import unified
    from ..records import case_store
    if case_store.enabled():
        with case_store.reader() as conn, conn.cursor() as cur:
            return unified.manual_registry(cur)
    if unified.enabled():
        return unified.manual_registry()
    if os.getenv("WORKBENCH_CONFIG_BACKEND", "mysql").strip().lower() == "mysql":
        from risk_guard.config_storage import MySQLStore
        conn = MySQLStore("review_links")
        try:
            row = conn.execute("SELECT payload FROM registry WHERE id=1").fetchone()
            return json.loads(row[0]) if row else {"findings": {}}
        finally:
            conn.close()
    return json.loads(_path().read_text(encoding="utf-8")) if _path().exists() else {"findings": {}}


def _save(registry):
    from ..records import unified
    from ..records import case_store
    if case_store.enabled():
        with case_store.transaction() as conn, conn.cursor() as cur:
            return unified.save_manual_registry(registry, cur=cur)
    if unified.enabled():
        return unified.save_manual_registry(registry)
    content = json.dumps(redact_value(registry), ensure_ascii=False, indent=2)
    if os.getenv("WORKBENCH_CONFIG_BACKEND", "mysql").strip().lower() == "mysql":
        from risk_guard.config_storage import MySQLStore
        conn = MySQLStore("review_links")
        try:
            conn.execute("INSERT OR REPLACE INTO registry VALUES (1,?)", (content,))
            conn.commit()
        finally:
            conn.close()
    else:
        atomic_library_write(_path(), content)


def _time(value):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _automatic_links(root, receipt, case_id):
    """Only related analysis from the originating task and report."""
    directory = (Path(root) / receipt["taskId"]).resolve()
    source = (directory / receipt["sourceReport"]).resolve()
    if not source.is_relative_to(directory):
        raise ValueError("复核来源路径越界")
    if not source.exists():
        return []
    report = json.loads(source.read_text(encoding="utf-8"))
    parts = receipt["sourcePointer"].split("/")
    item = report
    for part in parts:
        item = item[int(part)] if isinstance(item, list) else item[part]
    source_id = item.get("source_id") or item.get("case_id")
    links = []
    for p in (directory / "findings").glob("*.json"):
        if not p.resolve().is_relative_to(directory) or p.stat().st_size > 20_000_000:
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for finding in data.get("findings", []):
            by_case = case_id in finding.get("case_ids", [])
            by_source = (receipt["kind"] == "positive" and source_id
                         and source_id in finding.get("source_ids", [])
                         and Path(data.get("source_report") or "").parent == source.parent)
            if (by_case or by_source) and finding.get("finding_id"):
                links.append({"finding_id": finding["finding_id"], "title": finding.get("title", ""),
                              "artifact": p.relative_to(directory).as_posix(), "task_id": receipt["taskId"],
                              "exact_case": finding.get("case_ids") == [case_id]})
    return links


@serialized_library_write
def ensure(root, receipt, library_path):
    if receipt["action"] != "include":
        return []
    library_path = Path(library_path)
    library = json.loads(library_path.read_text(encoding="utf-8"))
    cases = {c["case_id"]: c for c in library["cases"]}
    registry = _load()
    ids = []
    report_path = Path(receipt["reviewReport"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    for case_id in receipt["libraryCaseIds"]:
        case = cases.get(case_id)
        if case is None:
            raise ValueError("关联回归用例不存在，未生成空 Finding")
        target = (case.get("target") or report.get("target") or {}).get("target_key") or "ky-agent:ky-sales"
        identity = f'{receipt["kind"]}|{target}|{case_id}'
        identity = hashlib.sha256(identity.encode()).hexdigest()[:20].upper()
        links = _automatic_links(root, receipt, case_id)
        exact = {x["finding_id"] for x in links if x["exact_case"]}
        default_id = "RF-" + identity
        fid = registry.setdefault("case_links", {}).get(identity)
        if not fid:
            # Reuse an unambiguous one-case automatic issue. Grouped analysis
            # is linked as context, not merged with an independently found bug.
            fid = next(iter(exact)) if len(exact) == 1 and default_id not in registry["findings"] else default_id
            if fid in registry["findings"] and registry["findings"][fid]["target_key"] != target:
                fid = default_id
            registry["case_links"][identity] = fid
        finding = registry["findings"].setdefault(fid, {
            "finding_id": fid, "kind": receipt["kind"], "target_key": target,
            "title": "人工确认的" + ("攻击问题" if receipt["kind"] == "attack" else "业务问题"),
            "status": "confirmed", "case_ids": [case_id], "reviews": {},
            "automatic_findings": [], "created_at": receipt["reviewedAt"],
            "reproduction": "在复测页选择对应回归库并按关联用例编号执行；不要重放失败回复作为参考答案。",
            "acceptance_criteria": "关联用例完成有效复测且问题不再出现；异常、未执行或证据不足不算修复。",
        })
        finding["reviews"][receipt["id"]] = {
            "review_id": receipt["id"], "reason": receipt["reason"],
            "outcome": receipt["outcome"], "reviewed_at": receipt["reviewedAt"],
            "task_id": receipt["taskId"], "source_report": receipt["sourceReport"],
            "source_pointer": receipt["sourcePointer"],
        }
        if _time((finding.get("latest_retest") or {}).get("tested_at")) < _time(receipt["reviewedAt"]):
            finding.pop("latest_retest", None)
        existing = {(x["task_id"], x["artifact"], x["finding_id"]) for x in finding["automatic_findings"]}
        for link in links:
            key = (link["task_id"], link["artifact"], link["finding_id"])
            if key not in existing:
                finding["automatic_findings"].append(link)
                existing.add(key)
        case["finding_ids"] = sorted(set(case.get("finding_ids", [])) | {fid})
        ids.append(fid)
    # Both writes are repeatable: a crash after the first is repaired on retry.
    from ..records import unified
    if unified.enabled():
        unified.register_library_cases([cases[key] for key in receipt["libraryCaseIds"]],
            "security" if receipt["kind"] == "attack" else "business_bad", replace=True)
    _save(registry)
    atomic_library_write(library_path, json.dumps(library, ensure_ascii=False, indent=2))
    return ids


def details(receipt, library_path):
    registry = _load()
    from ..records import case_store
    kind = case_store.kind_for(library_path)
    library = case_store.load(kind, receipt.get("libraryCaseIds", [])) if kind else (
        json.loads(Path(library_path).read_text(encoding="utf-8")) if Path(library_path).exists() else {"cases": []})
    cases = {c["case_id"]: c for c in library["cases"]}
    results = []
    for fid in receipt.get("findingIds", []):
        if fid not in registry["findings"]:
            continue
        finding = dict(registry["findings"][fid])
        finding["regression_cases"] = [
            {"case_id": key, "result": cases.get(key, {}).get("result"),
             "latest_outcome": cases.get(key, {}).get("latest_outcome"),
             "last_tested_at": cases.get(key, {}).get("last_tested_at"),
             "available": key in cases} for key in finding["case_ids"]
        ]
        # Existing attack retests maintain these fields. Missing positive retest
        # evidence must never be interpreted as fixed.
        if finding["kind"] == "attack" and all(
                c["available"] and c["result"] == "已修复" and c["latest_outcome"] == "RESISTED"
                for c in finding["regression_cases"]):
            finding["status"] = "regression_passed"
        if finding["kind"] == "positive" and finding.get("latest_retest"):
            retest = finding["latest_retest"]
            finding["status"] = retest["status"]
            for row in finding["regression_cases"]:
                if row["case_id"] == retest["case_id"]:
                    row.update(latest_outcome=retest["outcome"], last_tested_at=retest["tested_at"],
                               result={"regression_passed": "复测通过", "confirmed": "仍有业务失败",
                                       "retest_inconclusive": "复测待确认"}[retest["status"]])
        results.append(finding)
    return redact_value(results)


@serialized_library_write
def record_positive_retest(report, path):
    """Update only exact case + target matches; unrelated runs never close issues."""
    from ..records import case_store
    accepted = set()
    if case_store.enabled():
        with case_store.transaction() as conn, conn.cursor() as cur:
            for item in report.get("results") or []:
                if item.get("case_revision") is None:
                    continue
                original = case_store.detail("business_bad", item["case_id"])
                if not original or original["revision"] != item["case_revision"]:
                    continue
                case = original["case"]
                if ((case.get("target") or {}).get("target_key") or "ky-agent:ky-sales") != (
                        (report.get("target") or {}).get("target_key") or "ky-agent:ky-sales"):
                    continue
                case.update(latest_outcome=item.get("outcome"), last_tested_at=report.get("created_at"),
                            latest_retest_run=report.get("run_id"))
                case_store.put(cur, "business_bad", case, expected=original["revision"], allow_create=False)
                accepted.add(item["case_id"])
    registry = _load()
    if not registry["findings"]:
        return
    target = (report.get("target") or {}).get("target_key") or "ky-agent:ky-sales"
    for item in report.get("results", []):
        if case_store.enabled() and item.get("case_id") not in accepted:
            continue
        for finding in registry["findings"].values():
            if (finding["kind"] != "positive" or finding["target_key"] != target
                    or item.get("case_id") not in finding["case_ids"]):
                continue
            outcome = item.get("outcome")
            partial = ((item.get("judge") or {}).get("completion_gate") or {}).get("coverage_status") == "partial"
            has_evidence = any(t.get("agent_reply") or t.get("reply") or (t.get("trace") or {}).get("reply")
                               for t in item.get("turns", []) if isinstance(t, dict))
            state = "regression_passed" if outcome == "PASS" and not partial and has_evidence and not item.get("error") else (
                "confirmed" if outcome == "FAIL" else "retest_inconclusive")
            tested_at = report.get("created_at") or ""
            latest_review = max((_time(v["reviewed_at"]) for v in finding["reviews"].values()),
                                default=_time(None))
            if _time(tested_at) < max(_time((finding.get("latest_retest") or {}).get("tested_at")), latest_review):
                continue
            finding["latest_retest"] = {"case_id": item["case_id"], "run_id": report.get("run_id"),
                "outcome": outcome, "tested_at": tested_at, "status": state, "report": str(path)}
    _save(registry)
