"""Canonical regression libraries. Files are explicit execution snapshots only."""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from . import report_store
from ..core.paths import SECURITY_CASES_PATH, BUSINESS_BAD_CASES_PATH, BUSINESS_CASES_PATH, INTERNAL_POSITIVE_PATHS

PATHS = {"security": SECURITY_CASES_PATH, "business_bad": BUSINESS_BAD_CASES_PATH,
         "business": BUSINESS_CASES_PATH, "guard_internal": INTERNAL_POSITIVE_PATHS[0]}
INTERNAL_GROUPS = {path.stem: path for path in INTERNAL_POSITIVE_PATHS}
KINDS = {*PATHS, "attack_fixed"}
_connection = ContextVar("case_library_transaction", default=None)


class Conflict(ValueError):
    pass


def enabled():
    value = os.getenv("WORKBENCH_CASE_BACKEND", "mysql").strip().lower()
    if value not in {"mysql", "legacy"}:
        raise ValueError("WORKBENCH_CASE_BACKEND must be mysql or legacy")
    return value == "mysql"


def kind_for(path):
    if not enabled():
        return None
    resolved = Path(path).resolve()
    if resolved in {value.resolve() for value in INTERNAL_POSITIVE_PATHS}:
        return "guard_internal"
    return next((kind for kind, value in PATHS.items() if resolved == value.resolve()), None)


def group_for(path):
    resolved = Path(path).resolve()
    return next((group for group, value in INTERNAL_GROUPS.items() if resolved == value.resolve()), "")


def test_kind(kind):
    return "attack" if kind in {"security", "attack_fixed"} else "guard" if kind == "guard_internal" else "positive"


@contextmanager
def transaction():
    current = _connection.get()
    if current is not None:
        yield current
        return
    with report_store.connection() as conn:
        locked = False
        token = None
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT GET_LOCK(%s,60)", ("ky_workbench_library_write",))
                if cur.fetchone()[0] != 1:
                    raise TimeoutError("回归库正在更新，请重试")
                locked = True
            conn.begin()
            token = _connection.set(conn)
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if token is not None:
                _connection.reset(token)
            if locked:
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT RELEASE_LOCK(%s)", ("ky_workbench_library_write",))
                except Exception:
                    pass


@contextmanager
def reader():
    if _connection.get() is not None:
        yield _connection.get()
    else:
        with report_store.connection() as conn:
            yield conn


def metadata(cur, kind):
    if kind not in KINDS:
        raise ValueError("未知回归库")
    cur.execute("SELECT revision,metadata FROM agent_case_libraries WHERE kind=%s", (kind,))
    row = cur.fetchone()
    if not row:
        raise RuntimeError("回归库尚未迁移，拒绝回退本地文件")
    return int(row[0]), json.loads(row[1])


def presentation(case):
    scenario = case.get("scenario") or {}
    scenario = scenario if isinstance(scenario, dict) else {}
    messages = case.get("messages") or [t.get("customer_message", "") for t in case.get("reference_turns") or []]
    title = str(case.get("title") or case.get("scenario_name") or scenario.get("name")
                or scenario.get("summary") or scenario.get("type") or str(case.get("content") or "")[:80]
                or case["case_id"])[:255]
    description = str(case.get("description") or case.get("content") or (messages[0] if messages else ""))[:2000]
    target = str((case.get("target") or {}).get("target_key") or
                 (f"guard:{case['agent_id']}" if case.get("agent_id") else "ky-agent:ky-sales"))
    engine = str(case.get("engine") or ("guard" if case.get("content") is not None else
                 "business" if case.get("case_type") == "positive_business" else
                 "epe" if str(case.get("attack_method", "")).upper().startswith("EPE") else "cr"))
    return title, description, target, engine


def load(kind, ids=None, *, group=""):
    with reader() as conn, conn.cursor() as cur:
        revision, meta = metadata(cur, kind)
        where, args = "library_kind=%s AND case_deleted=0", [kind]
        if group:
            where += " AND dataset_group=%s"
            args.append(group)
        if ids is not None:
            if not ids:
                return {**meta, "cases": [], "_libraryVersion": str(revision), "_caseRevisions": {}, "_libraryKind": kind}
            where += " AND case_id IN (" + ",".join(["%s"] * len(ids)) + ")"
            args.extend(ids)
        cur.execute("SELECT case_id,regression_payload,case_revision FROM agent_security_cases WHERE " +
                    where + " ORDER BY case_id", args)
        rows = cur.fetchall()
        return {**meta, "cases": [report_store.unpacked(row[1]) for row in rows],
                "_libraryVersion": str(revision), "_caseRevisions": {row[0]: row[2] for row in rows}, "_libraryKind": kind}


def put(cur, kind, case, *, expected=None, allow_create=True, refresh_projection=False, group=None):
    case_id = str(case["case_id"])
    if not case_id or len(case_id) > 64:
        raise ValueError("用例编号无效")
    metadata(cur, kind)
    cur.execute("""SELECT library_kind,case_revision,regression_payload,case_deleted
        FROM agent_security_cases WHERE case_id=%s FOR UPDATE""", (case_id,))
    old = cur.fetchone()
    if old and old[0] not in {"", kind}:
        raise Conflict("该编号已经属于其他用例库")
    if old and old[3]:
        raise Conflict("用例已删除，不能由旧执行结果自动恢复")
    if not allow_create and (not old or old[0] != kind):
        raise Conflict("用例不存在，请刷新")
    current_revision = int(old[1]) if old and old[0] == kind else 0
    if expected is not None and current_revision != expected:
        raise Conflict("用例版本已更新，请刷新后再操作")
    # Runnable input remains exact. Public API responses are separately redacted.
    text = report_store.packed(report_store.encoded(case))
    title, description, target, engine = presentation(case)
    active = case.get("status", "active") == "active"
    if group is not None and (kind != "guard_internal" or group not in INTERNAL_GROUPS and group != ""):
        raise ValueError("未知固定数据集分组")
    if old and old[2] and report_store.unpacked(old[2]) == case and old[0] == kind and group is None:
        if refresh_projection:
            cur.execute("""UPDATE agent_security_cases SET title=%s,case_description=%s,
                target_key=%s,case_enabled=%s WHERE case_id=%s""", (title, description, target, active, case_id))
        return current_revision
    revision = current_revision + 1
    cur.execute("""INSERT INTO agent_security_cases
        (case_id,scenario_id,agent_code,engine,pack_id,prompt,test_kind,target_key,source_case_id,title,
         library_kind,regression_payload,case_revision,case_enabled,case_deleted,case_description)
        VALUES (%s,NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,%s)
        ON DUPLICATE KEY UPDATE engine=VALUES(engine),target_key=VALUES(target_key),title=VALUES(title),
        library_kind=VALUES(library_kind),regression_payload=VALUES(regression_payload),
        case_revision=VALUES(case_revision),case_enabled=VALUES(case_enabled),case_description=VALUES(case_description)""",
        (case_id, target[-64:], engine, str(case.get("pack_id") or "")[:128], "\n\n".join(case.get("messages") or []),
         test_kind(kind), target[:191], str(case.get("source_case_id") or case_id)[:191], title, kind,
         text, revision, active, description))
    if group is not None:
        cur.execute("UPDATE agent_security_cases SET dataset_group=%s WHERE case_id=%s", (group, case_id))
    cur.execute("UPDATE agent_case_libraries SET revision=revision+1 WHERE kind=%s", (kind,))
    return revision


def save(kind, library):
    """Compatibility boundary for existing runners, using row revisions instead of whole-file overwrite."""
    revisions = library.get("_caseRevisions") or {}
    with transaction() as conn, conn.cursor() as cur:
        metadata(cur, kind)
        for case in library["cases"]:
            put(cur, kind, case, expected=revisions.get(case["case_id"], 0))


def import_library(kind, library):
    """Append new source records without overwriting edited or deleted Cases."""
    with transaction() as conn, conn.cursor() as cur:
        metadata(cur, kind)
        inserted = 0
        for case in library["cases"]:
            cur.execute("SELECT library_kind FROM agent_security_cases WHERE case_id=%s FOR UPDATE", (case["case_id"],))
            old = cur.fetchone()
            if old and old[0] == kind:
                continue
            put(cur, kind, case, expected=0)
            inserted += 1
        meta = {key: value for key, value in library.items() if key != "cases" and not key.startswith("_")}
        cur.execute("UPDATE agent_case_libraries SET metadata=%s,revision=revision+1 WHERE kind=%s",
                    (report_store.encoded(meta), kind))
        return inserted


def detail(kind, case_id):
    with reader() as conn, conn.cursor() as cur:
        metadata(cur, kind)
        cur.execute("""SELECT regression_payload,case_revision,case_enabled,dataset_group FROM agent_security_cases
            WHERE library_kind=%s AND case_id=%s AND case_deleted=0""", (kind, case_id))
        row = cur.fetchone()
        if not row:
            return None
        return {"case": report_store.unpacked(row[0]), "revision": row[1], "enabled": bool(row[2]), "datasetGroup": row[3]}


def _dialogue_excerpt(label, role, value):
    text = str(value or "").strip()
    return {"label": label, "role": role, "text": text[:240], "truncated": len(text) > 240} if text else None


def _display_title(kind, case):
    if case.get("title"):
        return str(case["title"])[:255]
    scenario = case.get("scenario")
    scenario = scenario if isinstance(scenario, dict) else {}
    if kind == "guard_internal":
        labels = case.get("labels") or {}
        return str(labels.get("scenario_name") or
                   ("输出检测样本" if case.get("direction") == "output" else "输入检测样本"))[:255]
    name = str(case.get("scenario_name") or scenario.get("name") or scenario.get("scenario_name")
               or scenario.get("interaction_type") or
               ("正向问题用例" if kind == "business_bad" else "正常业务用例"))
    product = str(scenario.get("product_name") or "").strip()
    return (f"{product} · {name}" if product and product not in name else name)[:255]


def listing(kind, *, page=1, page_size=30, search="", target="", engine="", state="", repair="", group="", include_activity=False, ids=None):
    if not 1 <= page_size <= 100 or page < 1:
        raise ValueError("分页参数无效")
    with reader() as conn, conn.cursor() as cur:
        version, _ = metadata(cur, kind)
        where, args = "library_kind=%s AND case_deleted=0", [kind]
        if ids is not None:
            if len(ids) > 5000 or len(ids) != len(set(ids)):
                raise ValueError("选择的用例编号无效")
            if ids:
                where += " AND case_id IN (" + ",".join(["%s"] * len(ids)) + ")"
                args.extend(ids)
            else:
                where += " AND 1=0"
        if group:
            if kind != "guard_internal" or group not in INTERNAL_GROUPS:
                raise ValueError("未知固定数据集分组")
            where += " AND dataset_group=%s"
            args.append(group)
        for key, value in (("target_key", target), ("engine", engine)):
            if value and value != "all":
                where += f" AND {key}=%s"
                args.append(value)
        if state in {"enabled", "disabled"}:
            where += " AND case_enabled=%s"
            args.append(state == "enabled")
        if repair == "unknown":
            from .case_view import repair_expression
            where += " AND " + repair_expression("agent_security_cases") + " IS NULL"
        elif repair in {"0", "1", "2"}:
            from .case_view import repair_expression
            where += " AND " + repair_expression("agent_security_cases") + "=%s"
            args.append(int(repair))
        if search:
            query = "%" + search.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
            where += " AND (title LIKE %s ESCAPE '!' OR case_description LIKE %s ESCAPE '!' OR case_id LIKE %s ESCAPE '!')"
            args.extend([query]*3)
        cur.execute("SELECT COUNT(*) FROM agent_security_cases WHERE " + where, args)
        total = cur.fetchone()[0]
        structured = kind in {"business", "business_bad", "guard_internal"}
        columns = "case_id,title,case_description,target_key,engine,case_enabled,case_revision,dataset_group"
        columns += ",regression_payload" if structured else ",LEFT(prompt,241)"
        cur.execute("SELECT " + columns + " FROM agent_security_cases WHERE " + where + " ORDER BY case_id LIMIT %s OFFSET %s",
            (*args, page_size, (page-1)*page_size))
        records = cur.fetchall()
        rows = [{"id": cid, "title": title, "description": description, "target": agent, "engine": engine,
                 "selectable": bool(active), "status": "启用" if active else "停用", "revision": rev, "datasetGroup": dataset_group}
                for cid, title, description, agent, engine, active, rev, dataset_group in
                (record[:8] for record in records)]
        # Only the requested page gets bounded excerpts; full dialogues stay in the detail API.
        for row, record in zip(rows, records):
            if structured:
                case = report_store.unpacked(record[8])
                row["displayTitle"] = _display_title(kind, case)
                row.update(direction=case.get("direction", "all"),
                           expectedDecision=case.get("expected_decision", "ALLOW"), stage=case.get("stage", "full"))
                if kind in {"business", "business_bad"}:
                    turn = next((t for t in case.get("reference_turns") or [] if isinstance(t, dict)), {})
                    excerpts = [_dialogue_excerpt("客户输入", "input", turn.get("customer_message"))]
                    if kind == "business_bad":
                        # Never pair a historical reply with an edited replay input.
                        evidence = case.get("failure_evidence") or {}
                        original = next((t for t in evidence.get("turns") or [] if isinstance(t, dict)
                                         and turn.get("customer_message")
                                         and t.get("customer_message") == turn["customer_message"]), {})
                        excerpts.append(_dialogue_excerpt("发现时回复", "output", original.get("agent_reply")))
                    else:
                        excerpts.append(_dialogue_excerpt("参考回复", "output", turn.get("reference_reply")))
                else:
                    output = case.get("direction") == "output"
                    excerpts = [_dialogue_excerpt("输出样本" if output else "输入样本",
                                                  "output" if output else "input", case.get("content"))]
            else:
                excerpts = [_dialogue_excerpt("测试输入", "input", record[8])]
            row["dialoguePreview"] = [item for item in excerpts if item]
        cur.execute("""SELECT DISTINCT target_key FROM agent_security_cases
            WHERE library_kind=%s AND case_deleted=0 ORDER BY target_key""", (kind,))
        targets = [r[0] for r in cur.fetchall()]
        if include_activity:
            from .case_view import enrich
            enrich(cur, rows)
    return report_store.evidence({"rows": rows, "total": total, "page": page, "pageSize": page_size,
                                 "version": str(version), "targets": targets, "kind": kind,
                                 "groups": list(INTERNAL_GROUPS) if kind == "guard_internal" else []})


def selected(kind, ids, version):
    with transaction():
        payload = load(kind, ids)
        if payload["_libraryVersion"] != version:
            raise Conflict("用例库已更新，请刷新列表")
        if len(ids) != len(set(ids)) or len(payload["cases"]) != len(ids):
            raise ValueError("用例重复或已不存在")
        if any(case.get("status", "active") != "active" for case in payload["cases"]):
            raise ValueError("已停用用例不可执行")
        return payload


def merge_snapshot(kind, snapshot):
    with transaction() as conn, conn.cursor() as cur:
        conflicts, saved = [], []
        for case in snapshot["cases"]:
            expected = (snapshot.get("_caseRevisions") or {}).get(case["case_id"])
            if expected is None:
                conflicts.append(case["case_id"])
                continue
            try:
                put(cur, kind, case, expected=expected, allow_create=False)
                saved.append(case["case_id"])
            except Conflict:
                conflicts.append(case["case_id"])
        return {"status": "PENDING_MERGE" if conflicts else "SYNCED", "case_count": len(saved), "conflicts": conflicts}
