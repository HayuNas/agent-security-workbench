"""MySQL task and schedule state; execution files are not a fallback store."""
import json
import os
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

import pymysql

from ..records import report_store


class StorageUnavailable(RuntimeError):
    pass


class StorageConflict(ValueError):
    pass


def enabled():
    backend = os.getenv("WORKBENCH_RUNTIME_BACKEND", "mysql").strip().lower()
    if backend not in {"mysql", "legacy"}:
        raise ValueError("WORKBENCH_RUNTIME_BACKEND must be mysql or legacy")
    return backend == "mysql"


@contextmanager
def connection():
    try:
        with report_store.connection() as conn:
            yield conn
    except pymysql.MySQLError as exc:
        raise StorageUnavailable("任务数据库暂不可用；首次升级请先执行任务数据迁移") from exc


def locate(path):
    from . import api
    path = Path(path).resolve()
    if path.name not in {"task.json", "request.json"}:
        return None
    for scope, root in (("guard", api.GUARD_ROOT), ("agent", api.ROOT)):
        if path.parent.parent == root.resolve():
            try:
                return scope, str(UUID(path.parent.name)), path.name
            except ValueError:
                return None
    return None


def scope_filter(scope):
    return "module='guard'" if scope == "guard" else "module IN ('attack','positive','skill')"


def module_for(scope, value):
    return "guard" if scope == "guard" else str(value.get("kind") or (value.get("config") or {}).get("kind") or "attack")


def projection(value):
    keys = ("id", "name", "autoNamed", "storageSource", "status", "createdAt", "startedAt", "finishedAt", "error", "reportStorage")
    result = {key: value[key] for key in keys if key in value}
    result["kind"] = value.get("kind") or (value.get("config") or {}).get("kind", "attack")
    config = value.get("config") or {}
    if result["kind"] == "attack" and config.get("source") == "generate" and not config.get("library"):
        result["plannedCount"] = int(config.get("count") or 0) * len(config.get("scenes") or []) * len(config.get("tactics") or [])
    if result["kind"] == "guard":
        result["progress"] = value.get("progress") or {}
        result["config"] = {key: item for key, item in (value.get("config") or {}).items()
            if key in {"dataset", "agentId", "useSampleAgent", "direction", "workers", "outputMode",
                       "streamChunkSize", "streamWindowSize", "limit", "positiveLimit", "guardMode"}}
    return result


def read(path):
    location = locate(path)
    if not location:
        raise ValueError("任务存储路径无效")
    scope, task_id, name = location
    column = "runtime_payload" if name == "task.json" else "request_payload"
    with connection() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT {column} FROM agent_test_tasks WHERE task_id=%s AND runtime_deleted=0 AND " + scope_filter(scope), (task_id,))
        row = cur.fetchone()
        return report_store.unpacked(row[0]) if row and row[0] else None


def write(path, value):
    location = locate(path)
    if not location:
        raise ValueError("任务存储路径无效")
    scope, task_id, name = location
    if str(value.get("id")) != task_id:
        raise ValueError("任务编号与存储位置不一致")
    module = module_for(scope, value)
    text = report_store.packed(report_store.encoded(value))
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT module,runtime_deleted FROM agent_test_tasks WHERE task_id=%s FOR UPDATE", (task_id,))
        old = cur.fetchone()
        if old and (old[0] == "guard") != (scope == "guard"):
            raise StorageConflict("任务编号已经属于其他模块，请新建任务")
        if name == "request.json" and old and not value.get("kind") and not (value.get("config") or {}).get("kind"):
            module = old[0]
        if old and (old[0] != module or old[1]):
            raise StorageConflict("任务编号已经使用，请新建任务")
        cur.execute("""INSERT INTO agent_test_tasks (task_id,module,name,status,created_at,payload)
            VALUES (%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE task_id=VALUES(task_id)""",
            (task_id, module, value.get("name", ""), value.get("status", "preparing"), value.get("createdAt", ""),
             report_store.encoded(report_store.evidence(value))))
        if name == "request.json":
            cur.execute("UPDATE agent_test_tasks SET request_payload=%s WHERE task_id=%s", (text, task_id))
        else:
            cur.execute("""UPDATE agent_test_tasks SET name=%s,status=%s,created_at=%s,
                runtime_payload=%s,runtime_summary=%s WHERE task_id=%s""",
                (value.get("name", ""), value.get("status", ""), value.get("createdAt", ""),
                 text, report_store.encoded(projection(value)), task_id))
        conn.commit()


def paths(scope):
    from . import api
    root = api.GUARD_ROOT if scope == "guard" else api.ROOT
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT task_id FROM agent_test_tasks WHERE runtime_deleted=0 AND runtime_payload IS NOT NULL AND runtime_summary IS NOT NULL AND " + scope_filter(scope))
        return [root / row[0] / "task.json" for row in cur.fetchall()]


def history(scope, page, page_size, search, offset=None):
    start = (page-1)*page_size if offset is None else offset
    where = "runtime_deleted=0 AND runtime_payload IS NOT NULL AND runtime_summary IS NOT NULL AND " + scope_filter(scope)
    if scope == "agent":
        where += " AND module<>'skill'"
    args = []
    if search:
        where += " AND LOCATE(LOWER(%s),LOWER(name))>0"
        args.append(search)
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM agent_test_tasks WHERE " + where, args)
        total = cur.fetchone()[0]
        cur.execute("SELECT runtime_summary FROM agent_test_tasks WHERE " + where +
                    " ORDER BY created_at DESC,task_id DESC LIMIT %s OFFSET %s", [*args, page_size, start])
        items = [json.loads(row[0]) for row in cur.fetchall()]
        if scope == "agent":
            from .review_queries import pending_counts
            counts = pending_counts(cur, [item["id"] for item in items])
            for item in items:
                item["pendingReviewCount"] = counts.get(item["id"], 0)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


def review_counts(task_ids):
    from .review_queries import pending_counts
    with connection() as conn, conn.cursor() as cur:
        return pending_counts(cur, task_ids)


def delete_task(path):
    scope, task_id, _ = locate(path)
    with connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE agent_test_tasks SET runtime_deleted=1 WHERE task_id=%s AND " + scope_filter(scope), (task_id,))
        conn.commit()


def read_many(scope, task_ids):
    if not task_ids:
        return {}
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT task_id,runtime_summary FROM agent_test_tasks WHERE runtime_deleted=0 AND " +
                    scope_filter(scope) + " AND task_id IN (" + ",".join(["%s"] * len(task_ids)) + ")", task_ids)
        return {row[0]: json.loads(row[1]) for row in cur.fetchall() if row[1]}


def overview_records():
    from . import api
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT task_id,module,runtime_summary FROM agent_test_tasks WHERE runtime_deleted=0 AND runtime_payload IS NOT NULL AND runtime_summary IS NOT NULL")
        return [((api.GUARD_ROOT if module == "guard" else api.ROOT) / task_id, json.loads(summary))
                for task_id, module, summary in cur.fetchall()]


def schedule_paths(root):
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT schedule_id FROM agent_test_schedules WHERE deleted=0 ORDER BY created_at DESC,schedule_id DESC")
        return [root / (row[0] + ".json") for row in cur.fetchall()]


def read_schedule(schedule_id):
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT payload,revision FROM agent_test_schedules WHERE schedule_id=%s AND deleted=0", (schedule_id,))
        row = cur.fetchone()
        if not row:
            return None
        record = report_store.unpacked(row[0])
        cur.execute("SELECT COUNT(*) FROM agent_test_schedule_runs WHERE schedule_id=%s", (schedule_id,))
        record.update(runCount=cur.fetchone()[0], _storageRevision=row[1])
        return record


def due_schedule_paths(root, current):
    with connection() as conn, conn.cursor() as cur:
        cur.execute("""SELECT s.schedule_id FROM agent_test_schedules s WHERE s.deleted=0 AND
            ((s.enabled=1 AND s.next_run_at<=%s) OR EXISTS (SELECT 1 FROM agent_test_schedule_runs r
             WHERE r.schedule_id=s.schedule_id AND r.status IN ('queued','running','retry','retrying','waiting_retry')))""", (current,))
        return [root / (row[0] + ".json") for row in cur.fetchall()]


def write_schedule(value):
    schedule_id = str(UUID(value["id"]))
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT revision,deleted FROM agent_test_schedules WHERE schedule_id=%s FOR UPDATE", (schedule_id,))
        old = cur.fetchone()
        expected = value.get("_storageRevision", 0)
        if old and (old[1] or old[0] != expected):
            raise StorageConflict("定时计划已被修改，请刷新")
        if not old and expected:
            raise StorageConflict("定时计划已不存在")
        if not old:
            cur.execute("""INSERT INTO agent_test_schedules
                (schedule_id,name,module,enabled,next_run_at,created_at,revision,payload)
                VALUES (%s,%s,%s,%s,%s,%s,0,'{}')""",
                (schedule_id, value["name"], value["module"], bool(value.get("enabled")),
                 value.get("nextRunAt", ""), value.get("createdAt", "")))
        for run in value.get("runs") or []:
            cur.execute("""INSERT INTO agent_test_schedule_runs (schedule_id,run_id,task_id,status,payload)
                VALUES (%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE
                task_id=VALUES(task_id),status=VALUES(status),payload=VALUES(payload)""",
                (schedule_id, run["id"], run.get("taskId", ""), run.get("status", ""),
                 report_store.packed(report_store.encoded(run))))
        cur.execute("SELECT COUNT(*) FROM agent_test_schedule_runs WHERE schedule_id=%s", (schedule_id,))
        value["runCount"] = cur.fetchone()[0]
        revision = expected + 1
        stored = {key: item for key, item in value.items() if key != "_storageRevision"}
        cur.execute("""INSERT INTO agent_test_schedules
            (schedule_id,name,module,enabled,next_run_at,created_at,revision,payload)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE name=VALUES(name),module=VALUES(module),
            enabled=VALUES(enabled),next_run_at=VALUES(next_run_at),revision=VALUES(revision),payload=VALUES(payload)""",
            (schedule_id, value["name"], value["module"], bool(value.get("enabled")), value.get("nextRunAt", ""),
             value.get("createdAt", ""), revision, report_store.packed(report_store.encoded(stored))))
        conn.commit()
        value["_storageRevision"] = revision


def delete_schedule(schedule_id):
    with connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE agent_test_schedules SET deleted=1,enabled=0 WHERE schedule_id=%s", (schedule_id,))
        conn.commit()
