"""Small SQL adapter for existing configuration stores; MySQL never falls back silently."""
import os
import re
import sqlite3
from pathlib import Path

SCHEMAS = {
    "models": {
        "settings": "id INTEGER PRIMARY KEY, revision BIGINT NOT NULL, payload LONGBLOB NOT NULL",
        "snapshots": "task_id VARCHAR(191) PRIMARY KEY, payload LONGBLOB NOT NULL",
    },
    "agents": {"directory": "id INTEGER PRIMARY KEY, revision BIGINT NOT NULL, payload LONGTEXT NOT NULL"},
    "task_names": {
        "counters": "module VARCHAR(32) PRIMARY KEY, last_number BIGINT NOT NULL",
        "assignments": "task_id VARCHAR(64) PRIMARY KEY, module VARCHAR(32) NOT NULL, name VARCHAR(100) NOT NULL",
    },
    "material_usage": {
        "material_usage": "id VARCHAR(191) PRIMARY KEY, sequence BIGINT NOT NULL",
        "source_usage": "id VARCHAR(191) PRIMARY KEY, sequence BIGINT NOT NULL",
    },
    "reviews": {"reviews": "id VARCHAR(64) PRIMARY KEY, payload LONGTEXT NOT NULL"},
    "asset_sync": {"jobs": "id VARCHAR(191) PRIMARY KEY, payload LONGTEXT NOT NULL"},
    "review_links": {
        "registry": "id INTEGER PRIMARY KEY, payload LONGTEXT NOT NULL",
    },
    "guard": {
        "assets": "agent_id VARCHAR(191) PRIMARY KEY, revision BIGINT NOT NULL, snapshot VARCHAR(191), digest VARCHAR(64), payload LONGTEXT NOT NULL",
        "meta": "id INTEGER PRIMARY KEY, revision BIGINT NOT NULL",
        "base": "id INTEGER PRIMARY KEY, payload LONGTEXT NOT NULL, digest VARCHAR(64) NOT NULL",
    },
}


def mysql_connection():
    import pymysql
    # Same company database configuration as the existing report writer.
    values = {}
    local = Path(__file__).resolve().parents[1] / ".env_develop"
    if local.is_file():
        for line in local.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.lstrip().startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("\"'")
    def value(key, default=""):
        return os.getenv(key, values.get(key, default))
    keys = ("HOST", "USER", "PASSWORD", "DB")
    missing = [f"DM_DATA_MYSQL_{key}" for key in keys if not value(f"DM_DATA_MYSQL_{key}")]
    if missing:
        raise RuntimeError("缺少 MySQL 配置：" + ", ".join(missing))
    if value("DM_DATA_MYSQL_DB") != "dm_data":
        raise RuntimeError("配置存储仅允许使用 dm_data")
    return pymysql.connect(host=value("DM_DATA_MYSQL_HOST"),
        port=int(value("DM_DATA_MYSQL_PORT", "3306")), user=value("DM_DATA_MYSQL_USER"),
        password=value("DM_DATA_MYSQL_PASSWORD"), database="dm_data", charset="utf8mb4",
        connect_timeout=8, read_timeout=30, write_timeout=30, autocommit=False)


class MySQLStore:
    def __init__(self, namespace):
        self.namespace = namespace
        self.conn = mysql_connection()
        try:
            with self.conn.cursor() as c:
                c.execute("CREATE TABLE IF NOT EXISTS ky_config_mutex (name VARCHAR(32) PRIMARY KEY) ENGINE=InnoDB")
                c.execute("INSERT IGNORE INTO ky_config_mutex VALUES (%s)", (namespace,))
                for table, schema in SCHEMAS[namespace].items():
                    c.execute(f"CREATE TABLE IF NOT EXISTS ky_config_{namespace}_{table} ({schema}) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin")
            self.conn.commit()
        except Exception:
            self.conn.close()
            raise

    def execute(self, sql, args=()):
        if sql.startswith("CREATE TABLE"):
            return self  # Schema is provisioned above, outside data transactions.
        if sql in {"BEGIN", "BEGIN IMMEDIATE"}:
            self.conn.begin()
            c = self.conn.cursor()
            if sql == "BEGIN IMMEDIATE":
                c.execute("SELECT name FROM ky_config_mutex WHERE name=%s FOR UPDATE", (self.namespace,))
            return c
        for table in SCHEMAS[self.namespace]:
            sql = re.sub(r"\b" + table + r"\b", f"ky_config_{self.namespace}_{table}", sql)
        sql = sql.replace("?", "%s").replace("INSERT OR IGNORE", "INSERT IGNORE")
        sql = sql.replace("INSERT OR REPLACE", "REPLACE")
        c = self.conn.cursor()
        c.execute(sql, args)
        return c

    def commit(self): self.conn.commit()
    def close(self): self.conn.close()
    def __enter__(self): return self
    def __exit__(self, kind, value, tb):
        if kind is None: self.conn.commit()
        else: self.conn.rollback()


def connect(path, namespace, backend=None):
    env = "RISK_GUARD_CONFIG_BACKEND" if namespace == "guard" else "WORKBENCH_CONFIG_BACKEND"
    backend = (backend or os.getenv(env, "mysql")).strip().lower()
    if backend == "mysql":
        return MySQLStore(namespace)
    if backend != "sqlite":
        raise ValueError(f"{env} 仅支持 mysql 或 sqlite")
    return sqlite3.connect(path, timeout=15)
