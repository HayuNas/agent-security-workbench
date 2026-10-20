"""Database execution artifacts; local directories are disposable worker scratch."""
import codecs
import hashlib
import json
import re
import zlib
from pathlib import Path, PurePosixPath

from ..core.redaction import redact_value
from ..records import resources

PRIVATE = {"task.json", "request.json", "library.json", "guard-cases.json",
           "business-cases.json", "judge-policy.json"}
INPUTS = {"library.json", "guard-cases.json", "business-cases.json"}


def enabled():
    from . import task_store
    return task_store.enabled() and resources.enabled()


def owner(directory):
    from . import task_store
    location = task_store.locate(Path(directory) / "task.json")
    if not location:
        raise ValueError("执行资料不属于工作台任务目录")
    scope, task_id, _ = location
    return scope + ":" + task_id


def name(value):
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or ":" in value or not path.parts:
        raise ValueError("执行资料路径无效")
    return str(path)


def reference(path):
    from . import api
    path = Path(path).resolve()
    for root in (api.GUARD_ROOT, api.ROOT):
        if path.is_relative_to(root.resolve()):
            parts = path.relative_to(root).parts
            if len(parts) >= 2:
                owner(root / parts[0])
                return "mysql:artifact:" + parts[0] + "/" + "/".join(parts[1:])
    return str(path)


def put(directory, relative, value):
    relative = name(relative)
    oid = owner(directory)
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    resources.put("task_artifact", oid + "/" + relative, text, owner_id=oid,
        metadata={"name": relative, "bytes": len(text.encode("utf-8")),
                  "private": PurePosixPath(relative).name in PRIVATE})


def get(directory, relative):
    row = resources.get("task_artifact", owner(directory) + "/" + name(relative))
    if not row:
        return None
    value = row["value"]
    if row["metadata"].get("report_id"):
        from ..records import report_store
        report = report_store.detail("report", row["metadata"]["report_id"])
        if report is None:
            raise ValueError("关联报告不存在")
        return json.dumps(report, ensure_ascii=False, indent=2)
    return value


def json_value(directory, relative, default=None):
    if resources.enabled():
        text = get(directory, relative)
        return json.loads(text) if text is not None else default
    path = Path(directory) / name(relative)
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def listing(directory, *, include_private=False):
    return [row["metadata"]["name"] for row in resources.all_metadata("task_artifact", owner_id=owner(directory))
            if include_private or not row["metadata"].get("private")]


def capture(directory):
    directory = Path(directory).resolve()
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.suffix not in {".json", ".md"}:
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(directory):
            raise ValueError("执行目录包含越界文件")
        relative = path.relative_to(directory).as_posix()
        if relative in {"task.json", "request.json"}:
            continue
        if path.stat().st_size > 48 * 1024 * 1024:
            raise ValueError("执行资料超过数据库对象大小限制")
        put(directory, relative, path.read_text(encoding="utf-8"))


def link_reports(directory):
    from ..records import report_store
    oid = owner(directory)
    for row in resources.all_metadata("task_artifact", owner_id=oid):
        relative = row["metadata"]["name"]
        if not relative.endswith(".json") or row["metadata"].get("report_id"):
            continue
        report_id = report_store.identity(Path(directory).name, relative)
        with report_store.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT report_id FROM agent_test_reports WHERE report_id=%s", (report_id,))
            exists = cur.fetchone()
        if exists:
            resources.put("task_artifact", oid + "/" + relative, None, owner_id=oid,
                          metadata={**row["metadata"], "report_id": report_id}, expected=row["revision"])


def cleanup(directory):
    if not enabled():
        return
    import shutil
    owner(directory)
    directory = Path(directory)
    if not directory.is_dir():
        return
    for path in [directory, *directory.rglob("*")]:
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ValueError("临时执行目录包含目录链接，拒绝清理")
    shutil.rmtree(directory)


def restore_inputs(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for relative in INPUTS:
        text = get(directory, relative)
        if text is not None:
            (directory / relative).write_text(text, encoding="utf-8")


def append_log(directory, offset, raw):
    if len(raw) > resources.CHUNK_SIZE:
        raise ValueError("日志块过大")
    oid = owner(directory)
    with resources.transaction() as cur:
        resources._lock(cur, "task_log", oid, oid)
        current = resources.get("task_log", oid, cur=cur)
        state = current["value"] if current else {"size": 0, "events": [], "latest": "", "partial": ""}
        if offset < state["size"]:
            cur.execute("""SELECT payload,byte_count FROM agent_runtime_log_chunks
                WHERE owner_id=%s AND start_offset=%s""", (oid, offset))
            row = cur.fetchone()
            if not row or zlib.decompress(bytes(row[0])) != raw:
                raise resources.Conflict("同一任务日志偏移存在不同内容")
            return offset + len(raw)
        if offset != state["size"]:
            raise resources.Conflict("任务日志偏移不连续")
        cur.execute("""INSERT INTO agent_runtime_log_chunks (owner_id,start_offset,byte_count,payload)
            VALUES (%s,%s,%s,%s)""", (oid, offset, len(raw), zlib.compress(raw)))
        lines = (state.get("partial", "") + raw.decode("utf-8")).split("\n")
        state["partial"] = lines.pop()[-65536:]
        for text in lines:
            if not text.strip():
                continue
            state["latest"] = text[-2000:]
            if ("开始" in text and any(key in text for key in ("Queries=", "Seeds=", "Cases="))) or (
                    "完成" in text and re.search(r"\b(?:Query|Seed|Case)\s+\d+/\d+", text)):
                state["events"].append(text[-2000:])
        state["size"] = offset + len(raw)
        resources.put("task_log", oid, state, cur=cur, owner_id=oid)
        return state["size"]


def log_status(directory):
    record = resources.get("task_log", owner(directory))
    return record["value"] if record else {"size": 0, "events": [], "latest": "", "partial": ""}


def read_log(directory, offset=None, generation="", maximum=32000):
    oid = owner(directory)
    state = log_status(directory)
    size = state["size"]
    current = hashlib.sha256(oid.encode()).hexdigest()
    reset = offset is None or generation != current or offset > size
    start = max(0, size - maximum) if reset else offset
    with resources.transaction() as cur:
        cur.execute("""SELECT start_offset,payload FROM agent_runtime_log_chunks
            WHERE owner_id=%s AND start_offset+byte_count>%s AND start_offset<%s
            ORDER BY start_offset""", (oid, start, start + maximum))
        rows = cur.fetchall()
    raw = b"".join(zlib.decompress(bytes(payload))[max(0, start-pos):max(0, start-pos)+maximum]
                   for pos, payload in rows)[:maximum]
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    text = decoder.decode(raw, final=start+len(raw) >= size)
    next_offset = start + len(raw) - len(decoder.getstate()[0])
    return {"text": redact_value(text), "offset": next_offset, "generation": current,
            "reset": reset, "has_more": next_offset < size}
