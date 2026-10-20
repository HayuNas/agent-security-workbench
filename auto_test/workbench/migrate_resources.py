"""Import remaining runtime files without replacing existing database objects."""
import argparse
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from ..assets import store as asset_store
from ..core.paths import (AI_WEB_PRIVATE_ASSET_ROOT, BUSINESS_SCENARIO_SOURCES_PATH,
                          AI_WEB_CONTRACTS_PATH, RESULTS_ROOT, AUTO_TEST_ROOT)
from ..oracles.protected_assets import DEFAULT_ASSET_PATH
from ..records import resources, report_store
from ..core.redaction import redact_value


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def same(a, b):
    return report_store.encoded(a) == report_store.encoded(b)


def import_object(category, key, value, *, metadata=None, owner_id=""):
    digest = hashlib.sha256(report_store.encoded(value).encode()).hexdigest()
    receipt_key = category + "/" + key
    receipt = resources.get("migration_source", receipt_key)
    old = resources.get(category, key)
    if old:
        if not same(old["value"], value):
            if receipt and receipt["value"].get("sha256") == digest:
                return False
            raise resources.Conflict(f"目标已有不同内容，未覆盖：{category}/{key}")
    elif receipt:
        return False
    else:
        resources.put(category, key, value, metadata=metadata, owner_id=owner_id, only_if_missing=True)
        if not same(resources.get(category, key)["value"], value):
            raise ValueError("运行资料迁移内容校验失败")
    resources.put("migration_source", receipt_key, {"sha256": digest}, only_if_missing=True)
    return not bool(old)


def standalone_files(root):
    for folder in ("security", "paper", "business", "guard", "integration", "material-audit"):
        for path in sorted((root / folder).rglob("*")):
            if path.is_file() and path.suffix in {".json", ".md", ".log"}:
                if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                    raise ValueError("历史结果目录包含越界文件")
                yield path


def import_standalone(root, *, apply=False):
    root = Path(root)
    paths = list(standalone_files(root))
    summary = {"files": len(paths), "inserted_reports": 0, "reused_reports": 0}
    if not apply:
        return summary
    from . import api, artifacts
    for path in paths:
        if path.stat().st_size > 48 * 1024 * 1024:
            raise ValueError("历史结果超过单对象迁移限制：" + str(path))
        text = path.read_text(encoding="utf-8-sig")
        value = json.loads(text) if path.suffix == ".json" else None
        report = value if isinstance(value, dict) and report_store.supported(value) else None
        group = path.parent.relative_to(root).as_posix()
        task_id = str(uuid5(NAMESPACE_URL, "ky-workbench-legacy-results/" + group))
        kind = ("guard" if "guard" in Path(group).parts else
                "positive" if "business" in Path(group).parts else "attack")
        directory = (api.GUARD_ROOT if kind == "guard" else api.ROOT) / task_id
        oid = artifacts.owner(directory)
        key = oid + "/" + path.name
        digest = hashlib.sha256(text.encode()).hexdigest()
        with resources.transaction() as cur:
            resources._lock(cur, "task_artifact", key, oid)
            previous = resources.get("task_artifact", key, cur=cur)
            if previous:
                if previous["metadata"].get("source_sha256") != digest:
                    raise resources.Conflict("已迁移的历史文件发生变化，未覆盖：" + str(path))
                continue
            metadata = {"name": path.name, "bytes": len(text.encode()), "source_sha256": digest,
                        "legacy_source": path.relative_to(root).as_posix(),
                        "private": path.name in artifacts.PRIVATE}
            record = {"id": task_id, "name": "CLI 历史 " + group, "kind": kind, "status": "completed",
                      "createdAt": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
                      "config": {"kind": kind, "source": "legacy_cli_import"}}
            report_store.write_cli_task(cur, record, kind)
            stored = text
            if report:
                content_hash = hashlib.sha256(
                    report_store.encoded(report_store.evidence(report)).encode()).hexdigest()
                cur.execute("""SELECT report_id FROM agent_test_reports WHERE schema_version=%s
                    AND content_hash=%s ORDER BY report_id LIMIT 1""", (report["schema_version"], content_hash))
                existing = cur.fetchone()
                if existing:
                    report_id = existing[0]
                    summary["reused_reports"] += 1
                else:
                    markdown = path.with_suffix(".md")
                    report_store.write_report(cur, task_id, path.name, report,
                        markdown.read_text(encoding="utf-8-sig") if markdown.is_file() else "")
                    report_id = report_store.identity(task_id, path.name)
                    summary["inserted_reports"] += 1
                stored = None
                metadata["report_id"] = report_id
            resources.put("task_artifact", key, stored, owner_id=oid, metadata=metadata,
                          cur=cur, only_if_missing=True)
        saved = artifacts.get(directory, path.name)
        if report:
            if not same(json.loads(saved), report_store.evidence(report)):
                raise ValueError("历史报告入库后内容校验失败")
        elif saved != text:
            raise ValueError("历史文件入库后内容校验失败")
    contracts = resources.get("contract_registry", "ai-web")
    if contracts:
        registry = contracts["value"]
        changed = False
        for target in registry.get("targets", {}).values():
            original = str(target.get("report") or "")
            if not original or original.startswith("mysql:"):
                continue
            path = Path(original).resolve()
            if not path.is_relative_to(root.resolve()):
                continue
            group = path.parent.relative_to(root.resolve()).as_posix()
            task_id = str(uuid5(NAMESPACE_URL, "ky-workbench-legacy-results/" + group))
            directory = api.ROOT / task_id
            if resources.get("task_artifact", artifacts.owner(directory) + "/" + path.name):
                target.update(report=artifacts.reference(directory / path.name), legacy_report=original)
                changed = True
        if changed:
            resources.put("contract_registry", "ai-web", registry, expected=contracts["revision"])
    return summary


def migrate(*, apply=False, assets_root=AI_WEB_PRIVATE_ASSET_ROOT,
            task_root=RESULTS_ROOT / "workbench", include_tasks=False,
            results_root=RESULTS_ROOT, include_standalone=False):
    assets_root, task_root = Path(assets_root), Path(task_root)
    snapshots = sorted(assets_root.glob("*/*.json"))
    index_path = assets_root / "index.json"
    index = read_json(index_path) if index_path.is_file() else {"targets": {}}
    source_paths = [
        ("business_sources", "default", BUSINESS_SCENARIO_SOURCES_PATH),
        ("contract_registry", "ai-web", AI_WEB_CONTRACTS_PATH),
        ("protected_asset", "ky-agent/default", DEFAULT_ASSET_PATH),
    ]
    existing = [(category, key, path) for category, key, path in source_paths if path.is_file()]
    review_policies = sorted((AUTO_TEST_ROOT / "data" / "review_targets").glob("*/*.json"))
    task_dirs = []
    if include_tasks and task_root.is_dir():
        from uuid import UUID
        for root in (task_root, task_root / "guard"):
            if root.is_dir():
                for directory in root.iterdir():
                    if directory.is_dir():
                        try:
                            UUID(directory.name)
                            task_dirs.append(directory)
                        except ValueError:
                            pass
    summary = {"mode": "apply" if apply else "preview", "asset_snapshots": len(snapshots),
               "asset_targets": len(index.get("targets", {})), "runtime_sources": len(existing),
               "task_directories": len(task_dirs), "model_calls": 0}
    summary["target_review_policies"] = len(review_policies)
    if include_standalone:
        summary["standalone"] = import_standalone(results_root)
    if not apply:
        return summary
    resources.initialize()
    for path in snapshots:
        registry = read_json(path)
        asset_store.write(registry, make_current=False, only_if_missing=True)
        saved = asset_store.read(asset_store.target_id(registry), registry["snapshot_id"])
        for field in ("assets", "marker_groups", "source_snapshot_sha256"):
            if not same(saved.get(field), registry.get(field)):
                raise ValueError("资产快照迁移校验失败")
    for record in index.get("targets", {}).values():
        registry = read_json(assets_root / record["app_id"] / record["registry_file"])
        asset_store.write(registry, only_if_missing=True)
    for category, key, path in existing:
        import_object(category, key, read_json(path))
    for path in review_policies:
        value = read_json(path)
        if value.get("target_key") != f"{path.parent.name}:{path.stem}":
            raise ValueError("辅助审查配置文件与目标编号不一致")
        import_object("target_review_policy", value["target_key"], value)
    from risk_guard.settings import DEFAULT_POLICIES_PATH
    if DEFAULT_POLICIES_PATH.is_file():
        from risk_guard.policy_admin import save_base_policy
        save_base_policy(read_json(DEFAULT_POLICIES_PATH), only_if_missing=True)
    usage_path = BUSINESS_SCENARIO_SOURCES_PATH.parent / ".material_usage.sqlite3"
    if usage_path.is_file():
        from risk_guard.config_storage import connect
        source = sqlite3.connect(f"{usage_path.resolve().as_uri()}?mode=ro", uri=True)
        target = connect(usage_path, "material_usage", backend="mysql")
        try:
            tables = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            with target:
                target.execute("BEGIN IMMEDIATE")
                for table in ("material_usage", "source_usage"):
                    if table not in tables:
                        continue
                    for key, sequence in source.execute(f"SELECT id,sequence FROM {table}"):
                        old = target.execute(f"SELECT sequence FROM {table} WHERE id=?", (key,)).fetchone()
                        if old and old[0] != sequence:
                            raise resources.Conflict("已有较新抽样记录，未覆盖")
                        target.execute(f"INSERT OR IGNORE INTO {table} VALUES (?,?)", (key, sequence))
        finally:
            source.close()
            target.close()
    backups = sorted(BUSINESS_SCENARIO_SOURCES_PATH.parent.glob("*.before-materials.json"))
    backups += sorted((BUSINESS_SCENARIO_SOURCES_PATH.parent / ".backups").glob("*.json"))
    for path in backups:
        value = read_json(path)
        digest = hashlib.sha256(report_store.encoded(value).encode()).hexdigest()
        import_object("business_sources_history", digest, value, metadata={"source_name": path.name})
    if task_dirs:
        from . import api, artifacts, task_store
        previous = api.ROOT, api.GUARD_ROOT
        api.ROOT, api.GUARD_ROOT = task_root.resolve(), (task_root / "guard").resolve()
        try:
            for directory in task_dirs:
                task = task_store.read(directory / "task.json")
                if not task:
                    continue
                if task.get("status") in {"queued", "running"}:
                    raise ValueError("存在运行任务，请空闲时迁移")
                artifacts.capture(directory)
                log = directory / "output.log"
                offset = 0
                if log.is_file():
                    with log.open("r", encoding="utf-8", errors="replace") as handle:
                        while True:
                            text = handle.read(60000)
                            if not text:
                                break
                            raw = str(redact_value(text)).encode()
                            offset = artifacts.append_log(directory, offset, raw)
                report_store.import_task(directory, task=task)
                artifacts.link_reports(directory)
                if task.get("kind") == "skill":
                    from . import live_jobs
                    if not resources.get("live_record", task["id"]):
                        payload = artifacts.json_value(directory, "result.json")
                        record = {**task, "rows": [], "storageSource": "live-record",
                                  "config": {"source": "url", **task.get("config", {})}}
                        if payload:
                            record["reply"] = {"data": payload, "httpStatus": 200, "elapsedMs": 0}
                        if record["status"] == "stopped":
                            record["status"] = "interrupted"
                        live_jobs.save(record, allow_legacy=True)
        finally:
            api.ROOT, api.GUARD_ROOT = previous
    if include_standalone:
        summary["standalone"] = import_standalone(results_root, apply=True)
    summary["verified"] = True
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--include-tasks", action="store_true")
    parser.add_argument("--include-standalone", action="store_true")
    parser.add_argument("--task-root", type=Path, default=RESULTS_ROOT / "workbench")
    args = parser.parse_args()
    print(json.dumps(migrate(apply=args.apply, include_tasks=args.include_tasks,
                             task_root=args.task_root, include_standalone=args.include_standalone), ensure_ascii=False))
