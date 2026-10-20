"""Durable runtime objects; large payloads use bounded, transactional chunks."""
from __future__ import annotations

import hashlib
import json
import re
import zlib
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone

from . import report_store

CHUNK_SIZE = 256 * 1024
MAX_BYTES = 64 * 1024 * 1024


class Unavailable(RuntimeError):
    pass


class Conflict(ValueError):
    pass


def enabled():
    return report_store.enabled()


def identity(category, key):
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", category):
        raise ValueError("Invalid runtime object category")
    if not isinstance(key, str) or not key or len(key) > 512 or "\0" in key:
        raise ValueError("Invalid runtime object key")
    return hashlib.sha256((category + "\0" + key).encode()).hexdigest()


@contextmanager
def transaction():
    try:
        with report_store.connection() as conn, conn.cursor() as cur:
            yield cur
            conn.commit()
    except (Conflict, ValueError):
        raise
    except Exception as exc:
        raise Unavailable("运行资料数据库不可用，请确认迁移完成及数据库连接") from exc


def initialize():
    with transaction() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS agent_runtime_objects (
            object_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
            category VARCHAR(40) NOT NULL,object_key VARCHAR(512) NOT NULL,
            owner_id VARCHAR(100) NOT NULL DEFAULT '',revision BIGINT NOT NULL,
            content_hash CHAR(64) NOT NULL,metadata TEXT NOT NULL,updated_at VARCHAR(50) NOT NULL,
            deleted TINYINT NOT NULL DEFAULT 0,
            KEY idx_runtime_object_owner (category,owner_id,deleted))
            ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
        cur.execute("""CREATE TABLE IF NOT EXISTS agent_runtime_object_chunks (
            object_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
            ordinal INT NOT NULL,payload MEDIUMBLOB NOT NULL,
            PRIMARY KEY (object_id,ordinal),
            CONSTRAINT fk_runtime_chunk_object FOREIGN KEY (object_id)
            REFERENCES agent_runtime_objects (object_id) ON DELETE CASCADE)
            ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
        cur.execute("""CREATE TABLE IF NOT EXISTS agent_runtime_log_chunks (
            owner_id VARCHAR(100) NOT NULL,start_offset BIGINT NOT NULL,
            byte_count INT NOT NULL,payload MEDIUMBLOB NOT NULL,
            PRIMARY KEY (owner_id,start_offset))
            ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")


def _lock(cur, category, key, owner_id=""):
    oid = identity(category, key)
    cur.execute("""INSERT IGNORE INTO agent_runtime_objects
        (object_id,category,object_key,owner_id,revision,content_hash,metadata,updated_at)
        VALUES (%s,%s,%s,%s,0,'','{}','')""", (oid, category, key, owner_id))
    cur.execute("""SELECT revision,content_hash,metadata,deleted FROM agent_runtime_objects
        WHERE object_id=%s FOR UPDATE""", (oid,))
    return oid, cur.fetchone()


def _read(cur, category, key):
    oid = identity(category, key)
    cur.execute("""SELECT revision,content_hash,metadata,deleted FROM agent_runtime_objects
        WHERE object_id=%s""", (oid,))
    row = cur.fetchone()
    if not row or not row[0] or row[3]:
        return None
    cur.execute("""SELECT payload FROM agent_runtime_object_chunks
        WHERE object_id=%s ORDER BY ordinal""", (oid,))
    packed = b"".join(bytes(item[0]) for item in cur.fetchall())
    decoder = zlib.decompressobj()
    raw = decoder.decompress(packed, MAX_BYTES + 1)
    if len(raw) > MAX_BYTES or not decoder.eof:
        raise ValueError("Runtime object is too large or incomplete")
    if hashlib.sha256(raw).hexdigest() != row[1]:
        raise ValueError("Runtime object checksum mismatch")
    return {"value": json.loads(raw), "revision": row[0], "metadata": json.loads(row[2]),
            "content_hash": row[1]}


def get(category, key, *, cur=None):
    if cur is not None:
        return _read(cur, category, key)
    with transaction() as reader:
        return _read(reader, category, key)


def _put(cur, category, key, value, *, owner_id="", metadata=None, expected=None,
         only_if_missing=False):
    oid, previous = _lock(cur, category, key, owner_id)
    revision, digest, _, deleted = previous
    if only_if_missing and revision:
        return {"revision": revision, "inserted": False}
    if expected is not None and revision != expected:
        raise Conflict("运行资料已被修改，请刷新后重试")
    raw = report_store.encoded(value).encode("utf-8")
    if len(raw) > MAX_BYTES:
        raise ValueError("Runtime object exceeds 64 MiB")
    content_hash = hashlib.sha256(raw).hexdigest()
    encoded_metadata = report_store.encoded(metadata or {})
    if len(encoded_metadata.encode("utf-8")) > 32000:
        raise ValueError("Runtime object metadata is too large")
    if not deleted and digest == content_hash and previous[2] == encoded_metadata:
        return {"revision": revision, "inserted": False}
    packed = zlib.compress(raw)
    cur.execute("DELETE FROM agent_runtime_object_chunks WHERE object_id=%s", (oid,))
    cur.executemany("""INSERT INTO agent_runtime_object_chunks (object_id,ordinal,payload)
        VALUES (%s,%s,%s)""", [(oid, index // CHUNK_SIZE, packed[index:index + CHUNK_SIZE])
                              for index in range(0, len(packed), CHUNK_SIZE)])
    cur.execute("""UPDATE agent_runtime_objects SET owner_id=%s,revision=%s,content_hash=%s,
        metadata=%s,updated_at=%s,deleted=0 WHERE object_id=%s""",
        (owner_id, revision + 1, content_hash, encoded_metadata,
         datetime.now(timezone.utc).isoformat(), oid))
    return {"revision": revision + 1, "inserted": not bool(revision)}


def put(category, key, value, *, cur=None, **options):
    if cur is not None:
        return _put(cur, category, key, value, **options)
    with transaction() as writer:
        return _put(writer, category, key, value, **options)


def update(category, key, action, *, owner_id=""):
    with transaction() as cur:
        _lock(cur, category, key, owner_id)
        previous = _read(cur, category, key)
        value = action(previous["value"] if previous else None)
        put(category, key, value, owner_id=owner_id, cur=cur)
        return value


def listing(category, *, owner_id=None, page=1, page_size=100):
    if not 1 <= page_size <= 500 or not 1 <= page <= 1000000:
        raise ValueError("Invalid runtime object pagination")
    where, args = "category=%s AND deleted=0 AND revision>0", [category]
    if owner_id is not None:
        where += " AND owner_id=%s"
        args.append(owner_id)
    with transaction() as cur:
        cur.execute("SELECT COUNT(*) FROM agent_runtime_objects WHERE " + where, args)
        total = cur.fetchone()[0]
        cur.execute("""SELECT object_key,revision,metadata,updated_at FROM agent_runtime_objects
            WHERE """ + where + " ORDER BY object_key LIMIT %s OFFSET %s",
            [*args, page_size, (page - 1) * page_size])
        items = [{"key": row[0], "revision": row[1], "metadata": json.loads(row[2]),
                  "updated_at": row[3]} for row in cur.fetchall()]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


def all_metadata(category, *, owner_id=None):
    page = 1
    while True:
        result = listing(category, owner_id=owner_id, page=page, page_size=500)
        yield from result["items"]
        if page * 500 >= result["total"]:
            break
        page += 1


def delete(category, key, *, expected=None, cur=None):
    with transaction() if cur is None else nullcontext(cur) as cur:
        oid, row = _lock(cur, category, key)
        if expected is not None and row[0] != expected:
            raise Conflict("运行资料已被修改，请刷新后重试")
        cur.execute("UPDATE agent_runtime_objects SET deleted=1,revision=revision+1 WHERE object_id=%s", (oid,))
