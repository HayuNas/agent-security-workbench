"""Migrate task requests, runtime state, schedules and schedule history to MySQL."""
import argparse
import json
import shutil
from datetime import datetime

from ..records import report_store
from . import api, task_store
from .model_config import _root


def initialize():
    with task_store.connection() as conn, conn.cursor() as cur:
        cur.execute("SHOW COLUMNS FROM agent_test_tasks")
        existing = {row[0] for row in cur.fetchall()}
        columns = {"runtime_payload": "LONGTEXT NULL", "request_payload": "LONGTEXT NULL",
                   "runtime_summary": "LONGTEXT NULL", "runtime_deleted": "TINYINT NOT NULL DEFAULT 0"}
        missing = [f"ADD COLUMN {name} {definition}" for name, definition in columns.items() if name not in existing]
        if missing:
            cur.execute("ALTER TABLE agent_test_tasks " + ", ".join(missing))
        cur.execute("SHOW INDEX FROM agent_test_tasks")
        if "idx_runtime_history" not in {row[2] for row in cur.fetchall()}:
            cur.execute("ALTER TABLE agent_test_tasks ADD INDEX idx_runtime_history (module,runtime_deleted,created_at,task_id)")
        cur.execute("""CREATE TABLE IF NOT EXISTS agent_test_schedules (
            schedule_id VARCHAR(64) PRIMARY KEY,name VARCHAR(255) NOT NULL,module VARCHAR(20) NOT NULL,
            enabled TINYINT NOT NULL,next_run_at VARCHAR(50) NOT NULL,created_at VARCHAR(50) NOT NULL,
            revision BIGINT NOT NULL,payload LONGTEXT NOT NULL,deleted TINYINT NOT NULL DEFAULT 0,
            KEY idx_schedule_due (deleted,enabled,next_run_at))
            ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin""")
        cur.execute("""CREATE TABLE IF NOT EXISTS agent_test_schedule_runs (
            schedule_id VARCHAR(64) NOT NULL,run_id VARCHAR(64) NOT NULL,task_id VARCHAR(64) NOT NULL,
            status VARCHAR(32) NOT NULL,payload LONGTEXT NOT NULL,PRIMARY KEY (schedule_id,run_id),
            KEY idx_schedule_run_task (task_id),KEY idx_schedule_run_active (schedule_id,status),CONSTRAINT fk_schedule_run_schedule
            FOREIGN KEY (schedule_id) REFERENCES agent_test_schedules (schedule_id) ON DELETE RESTRICT)
            ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin""")
        conn.commit()


def migrate(apply=False):
    tasks = [path for root in (api.ROOT, api.GUARD_ROOT) for path in root.glob("*/task.json")]
    schedules = list((api.ROOT / "schedules").glob("*.json"))
    sources = {path: json.loads(path.read_text(encoding="utf-8")) for path in [*tasks, *schedules]}
    requests = {path: json.loads(path.read_text(encoding="utf-8")) for task in tasks
                if (path := task.with_name("request.json")).is_file()}
    summary = {"tasks": len(tasks), "schedules": len(schedules),
               "schedule_runs": sum(len(sources[path].get("runs") or []) for path in schedules)}
    if not apply:
        return {"mode": "preview", **summary}
    if any(sources[path].get("status") in {"running", "queued"} for path in tasks):
        raise ValueError("任务仍在执行，请等待结束后迁移")
    backup = _root() / "migration-backups" / ("runtime-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    backup.mkdir(parents=True)
    for path in [*sources, *requests]:
        destination = backup / path.relative_to(api.ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    initialize()
    skipped = 0
    for path in tasks:
        if task_store.read(path) is not None:
            skipped += 1
        else:
            task_store.write(path, sources[path])
            if task_store.read(path) != sources[path]:
                raise ValueError("任务迁移校验失败")
        request = requests.get(path.with_name("request.json"))
        if request and task_store.read(path.with_name("request.json")) is None:
            task_store.write(path.with_name("request.json"), request)
            if task_store.read(path.with_name("request.json")) != request:
                raise ValueError("任务提交配置迁移校验失败")
    for path in schedules:
        if task_store.read_schedule(path.stem) is not None:
            skipped += 1
            continue
        task_store.write_schedule(sources[path])
    return {"mode": "migrated", **summary, "skipped": skipped, "backup": str(backup)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    print(json.dumps(migrate(parser.parse_args().apply), ensure_ascii=False, indent=2))
