"""Migrate managed Case libraries; executable Packs and Skills stay in code."""
import argparse
import json
import shutil
from datetime import datetime
from pathlib import Path

from ..records import case_store as store, report_store
from .model_config import _root


def initialize(conn):
    with conn.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS agent_case_libraries
            (kind VARCHAR(32) PRIMARY KEY, revision BIGINT NOT NULL, metadata LONGTEXT NOT NULL)
            ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin""")
        cur.execute("SHOW COLUMNS FROM agent_security_cases")
        columns = {row[0] for row in cur.fetchall()}
        definitions = {"case_revision": "BIGINT NOT NULL DEFAULT 1",
                       "case_enabled": "TINYINT NOT NULL DEFAULT 1", "case_deleted": "TINYINT NOT NULL DEFAULT 0",
                       "case_description": "TEXT", "dataset_group": "VARCHAR(64) NOT NULL DEFAULT ''"}
        additions = [f"ADD COLUMN {name} {definition}" for name, definition in definitions.items() if name not in columns]
        if additions:
            cur.execute("ALTER TABLE agent_security_cases " + ", ".join(additions))
        cur.execute("SHOW INDEX FROM agent_security_cases")
        if "idx_case_library" not in {row[2] for row in cur.fetchall()}:
            cur.execute("ALTER TABLE agent_security_cases ADD INDEX idx_case_library (library_kind,case_deleted,case_enabled)")
        cur.execute("SHOW INDEX FROM agent_security_cases")
        if "idx_case_dataset_group" not in {row[2] for row in cur.fetchall()}:
            cur.execute("ALTER TABLE agent_security_cases ADD INDEX idx_case_dataset_group (library_kind,dataset_group,case_deleted)")
        cur.execute("SHOW INDEX FROM agent_security_case_runs")
        if "idx_case_run_source" not in {row[2] for row in cur.fetchall()}:
            cur.execute("ALTER TABLE agent_security_case_runs ADD INDEX idx_case_run_source (source_case_id(96),test_kind)")
    conn.commit()


def source_libraries(fixed_only=False):
    kinds = {"business", "guard_internal"} if fixed_only else set(store.PATHS)
    paths = {kind: [path] if kind != "guard_internal" else list(store.INTERNAL_GROUPS.values())
             for kind, path in store.PATHS.items() if kind in kinds}
    data, groups = {}, {}
    for kind, files in paths.items():
        sources = {path.stem: json.loads(path.read_text(encoding="utf-8")) for path in files}
        if kind == "guard_internal":
            data[kind] = {"schema_version": "1.0-internal-guard-library",
                          "datasets": {group: {k: v for k, v in source.items() if k != "cases"}
                                       for group, source in sources.items()},
                          "cases": [case for source in sources.values() for case in source["cases"]]}
            groups = {case["case_id"]: group for group, source in sources.items() for case in source["cases"]}
        else:
            data[kind] = next(iter(sources.values()))
        ids = [case["case_id"] for case in data[kind]["cases"]]
        if not all(ids) or len(set(ids)) != len(ids):
            raise ValueError(f"迁移用例编号为空或重复：{kind}")
    return data, paths, groups


def migrate(apply=False, *, fixed_only=False):
    data, paths, groups = source_libraries(fixed_only)
    summary = {kind: len(value["cases"]) for kind, value in data.items()}
    if not apply:
        return {"mode": "preview", "cases": summary}
    backup = _root() / "migration-backups" / ("case-libraries-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    backup.mkdir(parents=True)
    for files in paths.values():
        for path in files:
            shutil.copy2(path, backup / path.name)
    with report_store.connection() as conn:
        initialize(conn)
    with store.transaction() as conn, conn.cursor() as cur:
        cur.execute("SELECT case_id,library_kind,regression_payload FROM agent_security_cases WHERE library_kind IN (" +
                    ",".join(["%s"] * len(data)) + ")", tuple(data))
        original = cur.fetchall()
        (backup / "database-before.json").write_text(json.dumps(original, ensure_ascii=False), encoding="utf-8")
        for kind, library in data.items():
            cur.execute("SELECT revision FROM agent_case_libraries WHERE kind=%s", (kind,))
            if cur.fetchone():
                # A completed library is authoritative; never overwrite it with a stale JSON file.
                continue
            cur.execute("INSERT INTO agent_case_libraries VALUES (%s,1,%s)",
                        (kind, report_store.encoded({k: v for k, v in library.items() if k != "cases"})))
            for case in library["cases"]:
                cur.execute("SELECT case_revision,regression_payload,library_kind FROM agent_security_cases WHERE case_id=%s", (case["case_id"],))
                old = cur.fetchone()
                # Earlier migration redacted payloads; accept only an exact or redaction-equivalent source.
                if old and old[1]:
                    remote = report_store.unpacked(old[1])
                    if remote != case and remote != report_store.evidence(case):
                        raise store.Conflict(f"迁移内容冲突，未覆盖：{case['case_id']}")
                store.put(cur, kind, case, expected=old[0] if old and old[2] == kind else 0,
                          refresh_projection=True, group=groups.get(case["case_id"]) if kind == "guard_internal" else None)
            loaded = store.load(kind)
            if {c["case_id"]: c for c in loaded["cases"]} != {c["case_id"]: c for c in library["cases"]}:
                raise ValueError("迁移校验失败")
    return {"mode": "migrated", "cases": summary, "backup": str(backup)}


def migrate_legacy_outputs(archive, apply=False, case_ids=None):
    """Recover missing replies once; normal execution never reads this archive."""
    from ..records.cases import _successful_session_outputs, _successful_session_turns, security_case_target_key
    from ..guard.cases import _SUCCESS_OUTCOMES, _resolve_successful_outputs
    archive = Path(archive).resolve(strict=True)
    if not archive.is_dir():
        raise ValueError("历史档案须为目录")
    library = store.load("security")
    selected = set(case_ids) if case_ids is not None else None
    missing = {case["case_id"]: case for case in library["cases"] if not case.get("successful_outputs")
               and (selected is None or case["case_id"] in selected)}
    recovered = {}
    for path in sorted(archive.rglob("SR-*.json")):
        if not path.resolve().is_relative_to(archive):
            continue
        report = json.loads(path.read_text(encoding="utf-8"))
        target = (report.get("target") or {}).get("target_key") or "ky-agent:ky-sales"
        for item in report.get("results") or []:
            case = missing.get(item.get("case_id"))
            if not case or item.get("outcome") not in _SUCCESS_OUTCOMES or security_case_target_key(case) != target:
                continue
            # IDs alone cannot prove that an edited Case still uses the same input.
            turns = _successful_session_turns(item)
            messages = [str(turn.get("message") or "").strip() for turn in turns]
            if messages != [str(message).strip() for message in case.get("messages") or []]:
                continue
            outputs = _successful_session_outputs(item)
            if outputs:
                recovered[case["case_id"]] = {**case, "successful_outputs": outputs,
                    "successful_output_source": {"type": "legacy_archive", "report": path.name,
                                                 "run_id": report.get("run_id")}}
    for case_id, case in missing.items():
        if case_id in recovered or case.get("first_outcome") not in _SUCCESS_OUTCOMES:
            continue
        name = Path(case.get("source_json") or "").name
        for path in archive.rglob(name) if name else []:
            if not path.is_file() or not path.resolve().is_relative_to(archive):
                continue
            outputs, _ = _resolve_successful_outputs({**case, "source_json": str(path),
                "source_reports": [], "latest_retest_json": ""}, {})
            if outputs:
                recovered[case_id] = {**case, "successful_outputs": [text for _, text in outputs],
                    "successful_output_source": {"type": "legacy_archive", "report": path.name}}
                break
    if apply and recovered:
        with store.transaction() as conn, conn.cursor() as cur:
            for case_id, case in recovered.items():
                store.put(cur, "security", case, expected=library["_caseRevisions"][case_id], allow_create=False)
    return {"mode": "migrated" if apply else "preview", "recovered": len(recovered),
            "remaining": len(missing) - len(recovered)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--fixed", action="store_true", help="只迁移固定正常业务库和内部护栏正常样本")
    parser.add_argument("--legacy-outputs", type=Path, help="一次性补迁历史成功回复，不恢复本地日志功能")
    parser.add_argument("--case", action="append", help="补迁回复时只处理指定 Case，可重复")
    args = parser.parse_args()
    result = migrate_legacy_outputs(args.legacy_outputs, args.apply, args.case) if args.legacy_outputs else migrate(args.apply, fixed_only=args.fixed)
    print(json.dumps(result, ensure_ascii=False, indent=2))
