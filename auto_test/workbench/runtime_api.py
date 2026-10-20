"""Bounded polling projections. No report payloads or model calls."""
import codecs
import hashlib
import json
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from ..core.redaction import redact_value
from . import task_store

router = APIRouter(prefix="/api/agent/runtime", tags=["任务状态"])
_records = OrderedDict()
_log_events = OrderedDict()
_lock = threading.RLock()


def read_record(path):
    if task_store.enabled():
        return task_store.read(path)
    try:
        stat = path.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
        key = str(path)
        with _lock:
            cached = _records.get(key)
            if cached and cached[0] == stamp:
                return dict(cached[1])
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not data.get("id"):
            return None
        with _lock:
            _records[key] = (stamp, data)
            _records.move_to_end(key)
            while len(_records) > 2000:
                _records.popitem(last=False)
        return dict(data)
    except (OSError, ValueError):
        return None


def progress_lines(path):
    """Resume at a byte cursor; retain only progress events, never full logs."""
    from . import artifacts
    if artifacts.enabled():
        value = artifacts.log_status(path.parent)
        partial = value.get("partial", "").strip()
        return value.get("events", []), partial[-2000:] or value.get("latest", "")
    key = str(path)
    try:
        stat = path.stat()
        identity = (stat.st_dev, stat.st_ino, getattr(stat, "st_birthtime_ns", 0))
        with _lock:
            cached = _log_events.get(key)
            if not cached or cached["identity"] != identity or stat.st_size < cached["offset"] or (
                    stat.st_size == cached["offset"] and stat.st_mtime_ns != cached["mtime"]):
                cached = {"identity": identity, "offset": 0, "mtime": 0, "events": [], "latest": "", "partial": b""}
            import re
            def event(text):
                return ("开始" in text and any(k in text for k in ("Queries=", "Seeds=", "Cases="))) or (
                    "完成" in text and re.search(r"\b(?:Query|Seed|Case)\s+\d+/\d+", text))
            with path.open("rb") as source:
                source.seek(cached["offset"])
                while True:
                    block = source.read(65536)
                    if not block:
                        break
                    lines = (cached["partial"] + block).split(b"\n")
                    cached["partial"] = lines.pop()[-65536:]
                    for raw in lines:
                        text = raw.decode("utf-8", errors="replace").strip()
                        if text:
                            cached["latest"] = text[-2000:]
                            if event(text):
                                cached["events"].append(text)
                    cached["offset"] += len(block)
                cached["mtime"] = stat.st_mtime_ns
            _log_events[key] = cached
            _log_events.move_to_end(key)
            while len(_log_events) > 128:
                _log_events.popitem(last=False)
            partial = cached["partial"].decode("utf-8", errors="replace").strip()
            return cached["events"] + ([partial] if partial and event(partial) else []), partial[-2000:] or cached["latest"]
    except OSError:
        return [], ""


def root(module):
    from . import api
    return api.GUARD_ROOT if module == "guard" else api.ROOT


def location(module, task_id):
    try:
        return root(module) / str(UUID(task_id))
    except ValueError:
        raise HTTPException(404, "任务不存在") from None


def brief(record):
    keys = ("id", "name", "status", "createdAt", "startedAt", "finishedAt", "error", "reportStorage")
    result = {key: record[key] for key in keys if key in record}
    config = record.get("config") or {}
    result["kind"] = record.get("kind") or config.get("kind", "attack")
    return result


@router.get("/history")
def history(module: Literal["agent", "guard"] = "agent",
            page: int = Query(1, ge=1, le=1000000), page_size: int = Query(10, ge=1, le=100),
            search: str = Query("", max_length=200), offset: int | None = Query(None, ge=0, le=100000000)):
    if task_store.enabled():
        return task_store.history(module, page, page_size, search, offset=offset)
    items = []
    for path in root(module).glob("*/task.json"):
        record = read_record(path)
        if not record or record.get("kind") == "skill":
            continue
        if search.casefold() not in str(record.get("name", "")).casefold():
            continue
        item = brief(record)
        if module == "guard":
            # Dataset settings are small and needed for replay, unlike reports/snapshots.
            item["config"] = {key: value for key, value in (record.get("config") or {}).items()
                              if key in {"dataset", "agentId", "useSampleAgent", "direction", "workers",
                                         "outputMode", "streamChunkSize", "streamWindowSize", "limit", "positiveLimit", "guardMode"}}
        items.append(item)
    items.sort(key=lambda row: (row.get("createdAt", ""), row["id"]), reverse=True)
    start = (page-1)*page_size if offset is None else offset
    return {"items": items[start:start+page_size], "total": len(items),
            "page": page, "page_size": page_size}


@router.get("/states")
def states(module: Literal["agent", "guard"] = "agent", ids: str = Query("", max_length=4000)):
    from . import api
    wanted = list(dict.fromkeys(ids.split(","))) if ids else []
    if len(wanted) > 100:
        raise HTTPException(422, "一次最多查询 100 个任务")
    if task_store.enabled():
        for task_id in wanted:
            location(module, task_id)
        stored = task_store.read_many(module, wanted)
        counts = task_store.review_counts(list(stored)) if module == "agent" else {}
    items, missing = [], []
    for task_id in wanted:
        directory = location(module, task_id)
        record = stored.get(task_id) if task_store.enabled() else read_record(directory / "task.json")
        if not record:
            missing.append(task_id)
            continue
        value = brief(record)
        if module == "agent":
            value["progress"] = api._agent_progress(directory, record)
            if task_store.enabled():
                value["pendingReviewCount"] = counts.get(task_id, 0)
        else:
            value["progress"] = record.get("progress") or {}
            value["resultSource"] = "mysql"
        value["revision"] = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
        items.append(value)
    return {"items": items, "missing": missing}


@router.get("/tasks/{task_id}")
def task_detail(task_id: str, module: Literal["agent", "guard"] = "agent"):
    from . import api
    directory = location(module, task_id)
    record = read_record(directory / "task.json")
    if not record:
        raise HTTPException(404, "任务不存在")
    if module == "agent":
        if task_store.enabled():
            record["pendingReviewCount"] = task_store.review_counts([task_id]).get(task_id, 0)
        record["progress"] = api._agent_progress(directory, record)
        from . import artifacts
        if artifacts.enabled():
            record["artifacts"] = artifacts.listing(directory)
        else:
            record["artifacts"] = [p.relative_to(directory).as_posix() for p in directory.rglob("*")
                if p.is_file() and p.suffix in {".json", ".md"}
                and p.name not in {"task.json", "request.json", "library.json", "judge-policy.json"}]
    else:
        record["resultSource"] = "mysql"
    return record


@router.get("/tasks/{task_id}/logs")
def logs(task_id: str, offset: int | None = Query(None, ge=0), generation: str = Query("", max_length=100)):
    path = location("agent", task_id) / "output.log"
    if not read_record(path.parent / "task.json"):
        raise HTTPException(404, "任务不存在")
    from . import artifacts
    if artifacts.enabled():
        return artifacts.read_log(path.parent, offset, generation)
    try:
        with path.open("rb") as source:
            import os
            stat = os.fstat(source.fileno())
            current = f"{stat.st_dev}:{stat.st_ino}:{getattr(stat, 'st_birthtime_ns', 0)}"
            reset = offset is None or generation != current or offset > stat.st_size
            start = max(0, stat.st_size - 32000) if reset else offset
            source.seek(start)
            raw = source.read(32000)
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            record = read_record(path.parent / "task.json") or {}
            finished = record.get("status") not in {"running", "queued"}
            text = decoder.decode(raw, final=finished and start + len(raw) >= stat.st_size)
            remaining = len(decoder.getstate()[0])
            next_offset = start + len(raw) - remaining
            return {"text": redact_value(text), "offset": next_offset, "generation": current,
                    "reset": reset, "has_more": next_offset < stat.st_size}
    except FileNotFoundError:
        return {"text": "", "offset": 0, "generation": "", "reset": True, "has_more": False}
