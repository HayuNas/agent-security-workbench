"""Server-owned Skill and manual guard jobs, with durable request/result state."""
import base64
import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Literal
from contextlib import nullcontext
from uuid import UUID
from urllib.request import Request, urlopen

from fastapi import APIRouter, HTTPException, Query, Request as WebRequest
from pydantic import BaseModel, ConfigDict, Field

from ..core.redaction import redact_value
from ..records import resources
from . import task_naming

router = APIRouter(prefix="/api/agent/live-records", tags=["持久化扫描与护栏"])
pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="live-jobs")
cancel = {}
lock = threading.RLock()
TERMINAL = {"completed", "failed", "interrupted"}


def now():
    return datetime.now(timezone.utc).isoformat()


def metadata(record):
    return {key: record[key] for key in
            ("id", "kind", "name", "status", "createdAt", "autoNamed", "startedAt", "finishedAt", "progress", "error")
            if key in record} | {"storageSource": "live-record"}


def save(record, *, allow_legacy=False, cur=None):
    projection = {**metadata(record), "createdAt": record["createdAt"],
                  "config": {"guardMode": "single"} if record["kind"] == "guard" else {}}
    from ..records import report_store
    with resources.transaction() if cur is None else nullcontext(cur) as cur:
        cur.execute("SELECT module,runtime_deleted,runtime_summary FROM agent_test_tasks WHERE task_id=%s FOR UPDATE", (record["id"],))
        old = cur.fetchone()
        if old and (old[0] != record["kind"] or old[1] or
                    (not allow_legacy and json.loads(old[2] or "{}").get("storageSource") != "live-record")):
            raise resources.Conflict("任务编号已属于其他记录，请新建任务")
        resources.put("live_record", record["id"], record, owner_id=record["kind"],
                      metadata=metadata(record), cur=cur)
        cur.execute("""INSERT INTO agent_test_tasks
            (task_id,module,name,status,created_at,payload,runtime_payload,runtime_summary)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE name=VALUES(name),
            status=VALUES(status),runtime_payload=VALUES(runtime_payload),runtime_summary=VALUES(runtime_summary)""",
            (record["id"], record["kind"], record["name"], record["status"], record["createdAt"],
             "{}", report_store.packed(report_store.encoded(projection)), report_store.encoded(projection)))


def read(task_id):
    key = str(UUID(task_id))
    row = resources.get("live_record", key)
    if not row:
        raise HTTPException(404, "扫描或手工护栏任务不存在")
    return row["value"]


@router.get("")
def history(kind: Literal["skill", "guard"], page: int = Query(1, ge=1, le=1000000),
            page_size: int = Query(10, ge=1, le=100), offset: int | None = Query(None, ge=0, le=100000000),
            search: str = Query("", max_length=200)):
    where = "module=%s AND runtime_deleted=0 AND LOCATE(%s,runtime_summary)>0"
    args = [kind, '"storageSource":"live-record"']
    if search:
        where += " AND LOCATE(LOWER(%s),LOWER(name))>0"
        args.append(search)
    with resources.transaction() as cur:
        cur.execute("SELECT COUNT(*) FROM agent_test_tasks WHERE " + where, args)
        total = cur.fetchone()[0]
        cur.execute("SELECT runtime_summary FROM agent_test_tasks WHERE " + where +
                    " ORDER BY created_at DESC,task_id DESC LIMIT %s OFFSET %s",
                    [*args, page_size, (page-1)*page_size if offset is None else offset])
        rows = [json.loads(row[0]) for row in cur.fetchall()]
    return {"items": rows, "total": total, "page": page, "page_size": page_size}


@router.get("/{task_id}/state")
def state(task_id: UUID):
    row = resources.get("live_record", str(task_id))
    if not row:
        raise HTTPException(404, "任务不存在")
    return row["metadata"]


@router.get("/{task_id}")
def detail(task_id: UUID):
    record = read(str(task_id))
    for row in record.get("rows", []):
        if row.get("responseRef"):
            if not row["responseRef"].startswith(str(task_id) + "/"):
                raise HTTPException(409, "护栏响应引用不属于当前任务")
            response = resources.get("guard_response", row["responseRef"])
            if not response:
                raise resources.Unavailable("护栏响应资料缺失")
            row["response"] = response["value"]
    return record


class LegacyRecord(BaseModel):
    kind: Literal["skill", "guard"]
    record: dict


@router.put("/{task_id}/import")
def import_legacy(task_id: UUID, body: LegacyRecord):
    value = dict(body.record)
    if value.get("id") != str(task_id) or value.get("kind") != body.kind:
        raise HTTPException(422, "历史记录编号不匹配")
    if value.get("status") not in TERMINAL or not isinstance(value.get("config"), dict):
        raise HTTPException(422, "只迁移已结束的浏览器历史")
    if body.kind == "guard" and value["config"].get("guardMode") == "dataset":
        raise HTTPException(422, "固定护栏任务已由工作台保存")
    if len(json.dumps(value).encode()) > 20_000_000:
        raise HTTPException(413, "历史记录过大")
    if resources.get("live_record", str(task_id)):
        return metadata(read(str(task_id)))
    value.update(createdAt=value.get("startedAt") or value.get("finishedAt") or now(),
                 name=str(value.get("name") or "历史扫描记录")[:100], storageSource="live-record",
                 source="legacy_browser_import")
    save(value)
    return metadata(value)


@router.post("/{task_id}/stop")
def stop(task_id: UUID):
    key = str(task_id)
    with lock:
        value = read(key)
        if value["status"] not in TERMINAL:
            cancel.setdefault(key, threading.Event()).set()
            value.update(status="interrupted", finishedAt=now(),
                         error="已停止后续调度；已发送到远端的请求可能仍在执行。")
            save(value)
    return metadata(value)


@router.delete("/{task_id}")
def remove(task_id: UUID):
    with lock:
        record = read(str(task_id))
        if record["status"] not in TERMINAL:
            raise HTTPException(409, "请先停止任务")
        with resources.transaction() as cur:
            cur.execute("UPDATE agent_test_tasks SET runtime_deleted=1 WHERE task_id=%s AND module=%s",
                        (str(task_id), record["kind"]))
            resources.delete("live_record", str(task_id), cur=cur)
    return {"status": "deleted"}


def create(task_id, kind, config, rows=None, archive=None, name="", schedule_id=None):
    task_id = str(UUID(str(task_id)))
    config_hash = hashlib.sha256(json.dumps(
        {"kind": kind, "config": config, "rows": rows, "archive": hashlib.sha256(archive).hexdigest() if archive else ""},
        sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    with lock:
        old = resources.get("live_record", task_id)
        if old:
            if old["value"].get("requestHash") != config_hash:
                raise HTTPException(409, "同一任务编号已用于其他请求")
            return metadata(old["value"])
        named = task_naming.resolve(kind, task_id, name)
        record = {"id": task_id, "kind": kind, **named, "createdAt": now(),
                  "status": "queued", "config": config, "rows": rows or [],
                  "requestHash": config_hash, "storageSource": "live-record"}
        record["snapshot"] = (
            {key: config.get(key) for key in
             ("source", "fileName", "url", "mode", "report", "language", "prompt")} |
            {"request_id": task_id} if kind == "skill" else
            {"agent_id": config.get("agentId"), "direction": config.get("direction"),
             "stage": "full", "request_id": task_id, "samples": len(rows or [])})
        if schedule_id:
            record["scheduleId"] = schedule_id
        with resources.transaction() as cur:
            save(record, cur=cur)
            if archive:
                resources.put("scan_archive", task_id, base64.b64encode(archive).decode(),
                              owner_id=task_id, cur=cur)
        event = cancel.setdefault(task_id, threading.Event())
        try:
            pool.submit(execute, task_id, event)
        except Exception:
            record.update(status="failed", finishedAt=now(), error="无法启动任务")
            save(record)
            raise
    return metadata(record)


@router.post("/skill", status_code=202)
async def create_skill(request: WebRequest):
    limit = 11 * 1024 * 1024
    declared = request.headers.get("content-length")
    if declared and (not declared.isdigit() or int(declared) > limit):
        raise HTTPException(413, "上传内容超过限制")
    # Bound the body before Starlette can spool uploaded data onto disk.
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise HTTPException(413, "上传内容超过限制")
    from python_multipart import MultipartParser
    from python_multipart.multipart import parse_options_header
    content_type, options = parse_options_header(request.headers.get("content-type", ""))
    if content_type != b"multipart/form-data" or not options.get(b"boundary"):
        raise HTTPException(415, "请使用 multipart/form-data")
    parts, current = {}, {}
    ended = []
    headers = {}
    field = bytearray()
    value = bytearray()
    def begin():
        current.clear(); headers.clear()
    def header_field(data, start, end):
        field.extend(data[start:end])
    def header_value(data, start, end):
        value.extend(data[start:end])
    def header_end():
        headers[bytes(field).lower()] = bytes(value)
        field.clear(); value.clear()
    def headers_done():
        _, disposition = parse_options_header(headers.get(b"content-disposition", b""))
        current["name"] = disposition.get(b"name", b"").decode("utf-8")
        current["data"] = bytearray()
    def data(data, start, end):
        current["data"].extend(data[start:end])
    def end():
        key = current.get("name")
        if not key or key in parts or key not in {"id", "name", "config", "archive"}:
            raise HTTPException(422, "表单字段为空或重复")
        parts[key] = bytes(current["data"])
    parser = MultipartParser(options[b"boundary"], {"on_part_begin": begin, "on_header_field": header_field,
        "on_header_value": header_value, "on_header_end": header_end, "on_headers_finished": headers_done,
        "on_part_data": data, "on_part_end": end, "on_end": lambda: ended.append(True)})
    try:
        parser.write(bytes(body)); parser.finalize()
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(422, "上传表单格式无效") from exc
    if not ended:
        raise HTTPException(422, "上传表单不完整")
    try:
        config = json.loads(parts.get("config", b"{}"))
        if not isinstance(config, dict):
            raise ValueError("扫描配置无效")
        task_id = UUID(parts.get("id", b"").decode())
        name = parts.get("name", b"").decode()
        archive = parts.get("archive")
        source = config.get("source")
        url = config.get("url") if source == "url" else ""
        if source not in {"zip", "url"} or bool(archive) == bool(url):
            raise ValueError("archive/url 二选一")
        if source == "zip" and (not archive or len(archive) > 10 * 1024 * 1024):
            raise ValueError("ZIP 无效或超过 10 MiB")
        if config.get("mode") not in {"single", "full"} or config.get("report") not in {"compact", "full"}:
            raise ValueError("扫描模式无效")
        if config.get("language") not in {"zh", "en"} or not isinstance(config.get("prompt", ""), str) or len(config.get("prompt", "")) > 8000:
            raise ValueError("扫描参数无效")
        if len(name) > 100:
            raise ValueError("名称过长")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise HTTPException(422, "扫描提交参数无效") from exc
    return create(task_id, "skill", config, archive=archive, name=name)


class ManualSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    name: str = Field(default="", max_length=100)
    config: dict
    rows: list[dict] = Field(min_length=1, max_length=1000)


@router.post("/guard", status_code=202)
def create_guard(body: ManualSubmission):
    if len(json.dumps(body.model_dump(mode="json"), ensure_ascii=False).encode()) > 10 * 1024 * 1024:
        raise HTTPException(413, "手工护栏批次超过 10 MiB")
    if body.config.get("direction") not in {"input", "output"}:
        raise HTTPException(422, "检测方向无效")
    agent_id = body.config.get("agentId")
    if not isinstance(agent_id, str) or not 1 <= len(agent_id) <= 128:
        raise HTTPException(422, "Agent 标识无效")
    for row in body.rows:
        if not isinstance(row.get("content"), str) or not 1 <= len(row["content"]) <= 100000:
            raise HTTPException(422, "检测文本无效")
        if row.get("expected", "") not in {"", "ALLOW", "BLOCK"}:
            raise HTTPException(422, "预期决定无效")
    rows = [{"content": row["content"], "expected": row.get("expected", ""),
             "requestId": f"{body.id}-{index+1}"} for index, row in enumerate(body.rows)]
    return create(body.id, "guard", body.config, rows=rows, name=body.name)


def execute(task_id, event):
    with lock:
        try:
            record = read(task_id)
            if record["status"] in TERMINAL:
                cancel.pop(task_id, None)
                return
            record.update(status="running", startedAt=now())
            save(record)
        except BaseException:
            cancel.pop(task_id, None)
            raise
    try:
        config = record["config"]
        if record["kind"] == "skill":
            from . import api
            payload = resources.get("scan_archive", task_id)
            archive = base64.b64decode(payload["value"]) if payload else None
            started = time.monotonic()
            result = api._skill_schedule_request(config, task_id, archive=archive)
            if config.get("report") == "compact":
                if not isinstance(result.get("IsSafe"), bool) or not isinstance(result.get("SafetyDetails"), list):
                    raise ValueError("扫描精简返回结构无效")
            elif not isinstance(result.get("stage_reports"), dict) or result.get("status") not in {"completed", "review_required"}:
                raise ValueError("扫描完整返回结构无效")
            record["reply"] = {"data": redact_value(result), "httpStatus": 200,
                               "elapsedMs": round((time.monotonic()-started)*1000)}
        else:
            from .service_config import guard_base_url, guard_token
            for index, row in enumerate(record["rows"]):
                if event.is_set():
                    break
                payload = {"content": row["content"], "direction": config["direction"],
                           "stage": "full", "agent_id": config["agentId"],
                           "request_id": row.get("requestId") or f"{task_id}-{index+1}"}
                token = guard_token(guard_base_url())
                headers = {"Content-Type": "application/json"}
                if token:
                    headers["X-Risk-Guard-Token"] = token
                request = Request(guard_base_url()+"/v1/check?compact=false&include_trace=true",
                    data=json.dumps(payload).encode(), headers=headers, method="POST")
                started = time.monotonic()
                with urlopen(request, timeout=180) as response:
                    from .api import _read_http_body_limited
                    result = json.loads(_read_http_body_limited(response, 20_000_000))
                if not isinstance(result, dict) or result.get("action") not in {"ALLOW", "BLOCK", "REVIEW"} or not isinstance(result.get("degraded"), bool):
                    raise ValueError("护栏响应格式无效")
                response_key = task_id + "/" + str(index)
                response = {"data": redact_value(result), "httpStatus": 200,
                            "elapsedMs": round((time.monotonic()-started)*1000)}
                record["progress"] = {"phase": "running", "completed": index+1,
                    "total": len(record["rows"]), "percent": (index+1)*100/len(record["rows"]),
                    "indeterminate": False, "message": "已保存护栏响应"}
                with lock:
                    if event.is_set():
                        stopped = read(task_id)
                        record.update(status="interrupted", finishedAt=stopped.get("finishedAt", now()))
                    with resources.transaction() as cur:
                        resources.put("guard_response", response_key, response, owner_id=task_id, cur=cur)
                        row["responseRef"] = response_key
                        save(record, cur=cur)
        with lock:
            record.update(status="interrupted" if event.is_set() else "completed", finishedAt=now())
            total = len(record["rows"]) if record["kind"] == "guard" else 1
            record["progress"] = {"phase": record["status"], "completed": total if not event.is_set() else
                                  sum(bool(row.get("response") or row.get("responseRef")) for row in record["rows"]),
                                  "total": total, "percent": 100 if not event.is_set() else None,
                                  "indeterminate": False, "message": "结果已保存到数据库"}
            save(record)
    except Exception as exc:
        with lock:
            try:
                record = read(task_id)
            except HTTPException as missing:
                if missing.status_code == 404:
                    return
                raise
            record.update(status="interrupted" if event.is_set() else "failed",
                          finishedAt=now(), error=str(redact_value("检测或扫描失败：" + type(exc).__name__ + ": " + str(exc)))[:2000])
            save(record)
    finally:
        with lock:
            cancel.pop(task_id, None)


def recover():
    global pool
    if getattr(pool, "_shutdown", False):
        pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="live-jobs")
    for item in resources.all_metadata("live_record"):
        if item["metadata"].get("status") not in TERMINAL:
            value = read(item["key"])
            value.update(status="interrupted", finishedAt=now(),
                         error="工作台已重启，远端结果可能未知；未自动重复执行。")
            save(value)


def shutdown():
    with lock:
        for event in cancel.values():
            event.set()
        pool.shutdown(wait=False, cancel_futures=True)
