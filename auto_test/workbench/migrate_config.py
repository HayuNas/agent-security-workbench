"""Run with services stopped: python -m auto_test.workbench.migrate_config --apply."""
import argparse
import json
import os
import sqlite3
from contextlib import ExitStack, closing
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet
from risk_guard.config_storage import MySQLStore, SCHEMAS


def _sources(config_dir, guard_db, stores=None):
    sources = {"models": config_dir / "models.sqlite3", "agents": config_dir / "agents.sqlite3"}
    if guard_db is not None:
        sources["guard"] = guard_db
    for namespace, name in (("reviews", "reviews.sqlite3"), ("asset_sync", "asset-sync.sqlite3")):
        if (config_dir / name).is_file():
            sources[namespace] = config_dir / name
    return {key: value for key, value in sources.items() if stores is None or key in stores}


def migrate(config_dir, guard_db, apply=False, stores=None):
    if stores is not None and (not stores or set(stores) - set(SCHEMAS)):
        raise ValueError("Unknown or empty store selection")
    # Hold reservations on every source until MySQL commits, so background
    # configuration writers cannot race the copied snapshot.
    with ExitStack() as stack:
        if apply:
            for path in _sources(config_dir, guard_db, stores).values():
                if not path.is_file():
                    raise ValueError(f"源文件不存在，未执行迁移：{path}")
                conn = stack.enter_context(closing(sqlite3.connect(str(path), timeout=15)))
                conn.execute("BEGIN IMMEDIATE")
        return _migrate(config_dir, guard_db, apply, stores)


def _migrate(config_dir, guard_db, apply=False, stores=None):
    sources = _sources(config_dir, guard_db, stores)
    data = {}
    cipher = None
    for namespace, path in sources.items():
        if not path.is_file():
            raise ValueError(f"源文件不存在，未执行迁移：{path}")
        source = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            present = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            data[namespace] = {table: source.execute(f"SELECT * FROM {table}").fetchall()
                               for table in SCHEMAS[namespace]
                               if table in present or (namespace, table) != ("guard", "base")}
        finally:
            source.close()
    links = config_dir / "review-findings.json"
    if links.is_file() and (stores is None or "review_links" in stores):
        registry = json.loads(links.read_text(encoding="utf-8"))
        if not isinstance(registry, dict) or not isinstance(registry.get("findings"), dict):
            raise ValueError("Invalid review Finding registry")
        data["review_links"] = {"registry": [(1, json.dumps(registry, ensure_ascii=False, indent=2))]}
    if stores is not None and set(stores) - set(data):
        raise ValueError("Selected store has no migration source")
    if data.get("models", {}).get("settings") or data.get("models", {}).get("snapshots"):
        key = os.getenv("WORKBENCH_CONFIG_KEY")
        cipher = Fernet(key.encode() if key else (config_dir / "encryption.key").read_bytes())
        for rows in data["models"].values():
            for row in rows:
                json.loads(cipher.decrypt(row[-1]))
    summary = {ns: {t: len(rows) for t, rows in tables.items()} for ns, tables in data.items()}
    if not apply:
        return {"mode": "preview", "source_rows": summary}
    backup = config_dir / "migration-backups" / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup.mkdir(parents=True)
    for ns, path in sources.items():
        source = sqlite3.connect(str(path))
        dest = sqlite3.connect(str(backup / f"{ns}.sqlite3"))
        try: source.backup(dest)
        finally:
            dest.close()
            source.close()
    if (config_dir / "encryption.key").exists():
        (backup / "encryption.key").write_bytes((config_dir / "encryption.key").read_bytes())
    if "review_links" in data:
        (backup / links.name).write_bytes(links.read_bytes())
    # One MySQL connection/transaction covers all three stores, all conflicts
    # are checked before commit. A retry only accepts byte-identical rows.
    stores = {}
    try:
        for ns in data:
            stores[ns] = MySQLStore(ns)
    except Exception:
        for store in stores.values(): store.close()
        raise
    connection = next(iter(stores.values())).conn
    try:
        connection.begin()
        with connection.cursor() as cur:
            for ns in sorted(data):
                cur.execute("SELECT name FROM ky_config_mutex WHERE name=%s FOR UPDATE", (ns,))
            for ns, tables in data.items():
                for table, rows in tables.items():
                    full = f"ky_config_{ns}_{table}"
                    cur.execute(f"SELECT * FROM {full}")
                    existing = {row[0]: row for row in cur.fetchall()}
                    # An existing remote store must match the source exactly.
                    # Never merge an old local copy into an active server store.
                    if existing and existing != {row[0]: row for row in rows}:
                        raise ValueError(f"MySQL {full} 与本地不同，已回滚；禁止覆盖已有配置")
                    if not existing:
                        for row in rows:
                            cur.execute(f"INSERT INTO {full} VALUES ({','.join(['%s'] * len(row))})", row)
                    cur.execute(f"SELECT * FROM {full}")
                    if {row[0]: row for row in cur.fetchall()} != {row[0]: row for row in rows}:
                        raise ValueError(f"MySQL {full} 校验失败，已回滚")
            # Verify the encryption key against the actual target ciphertext.
            if cipher:
                cur.execute("SELECT payload FROM ky_config_models_settings")
                for row in cur.fetchall(): json.loads(cipher.decrypt(row[0]))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        for store in stores.values(): store.close()
    return {"mode": "migrated", "source_rows": summary, "backup": str(backup),
            "activation": "Set WORKBENCH_CONFIG_BACKEND=mysql and RISK_GUARD_CONFIG_BACKEND=mysql, then restart services"}


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="备份并迁移配置、人工复核和资产同步记录；服务应先停止")
    parser.add_argument("--config-dir", type=Path, default=Path(os.getenv("WORKBENCH_CONFIG_DIR", root / ".private/workbench")))
    parser.add_argument("--guard-db", type=Path, default=Path(os.getenv("RISK_GUARD_POLICY_STORE", root.parent / "risk_guard/.runtime/managed-policies.sqlite3")))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--skip-guard", action="store_true", help="护栏部署在另一台机器时，不迁移本机护栏配置")
    parser.add_argument("--stores", nargs="+", choices=tuple(SCHEMAS), help="仅补迁指定存储，已迁移的远端配置保持不动")
    args = parser.parse_args()
    print(json.dumps(migrate(args.config_dir, None if args.skip_guard else args.guard_db, args.apply, args.stores), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
