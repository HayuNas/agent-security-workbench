"""本地任务 API。启动：python -m uvicorn auto_test.workbench.api:app --port 8092。"""
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import UUID
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler

from .api_docs import SERVICE_DESCRIPTION, TAGS, endpoint_docs
from .contracts import Submission, commands
from .guard_api import (
    GuardTaskSubmission,
    dataset_catalog,
    prepare_dataset,
    runner_args,
)
from .scheduling import ScheduleService, ScheduleValidationError
from . import model_config, agent_config, reviews, task_store, artifacts
from .report_api import router as report_router
from .runtime_api import router as runtime_router
from .review_queries import router as review_query_router
from .case_api import router as case_router
from .scenario_catalog import router as scenario_router, catalog as scenario_catalog
from .review_analysis_api import router as review_analysis_router
from .task_naming import router as task_name_router, resolve as resolve_task_name
from .live_jobs import router as live_router
from .client_state import router as client_state_router
from ..core.paths import (
    BUSINESS_BAD_CASES_PATH,
    REPOSITORY_ROOT,
    RESULTS_ROOT,
    SECURITY_CASES_PATH,
)
from ..core.redaction import redact_value

ROOT = Path(os.getenv('WORKBENCH_RESULTS_DIR',
    str(Path(tempfile.gettempdir()) / 'ky-workbench-scratch')
    if os.getenv('WORKBENCH_RUNTIME_BACKEND', 'mysql') == 'mysql'
    else str(RESULTS_ROOT / 'workbench'))).resolve()
app = FastAPI(
    title='测试平台工作台接口', version='1.0',
    description=SERVICE_DESCRIPTION, openapi_tags=TAGS,
    swagger_ui_parameters={'docExpansion': 'none', 'defaultModelsExpandDepth': -1},
)
app.include_router(report_router)
app.include_router(runtime_router)
app.include_router(review_query_router)
app.include_router(case_router)
app.include_router(scenario_router)
app.include_router(review_analysis_router)
app.include_router(task_name_router)
app.include_router(live_router)
app.include_router(client_state_router)


@app.exception_handler(artifacts.resources.Unavailable)
async def resource_storage_error(request, exc):
    return JSONResponse(status_code=503, content={'detail': '运行资料数据库不可用，请检查连接和迁移状态'})


@app.exception_handler(artifacts.resources.Conflict)
async def resource_storage_conflict(request, exc):
    return JSONResponse(status_code=409, content={'detail': str(exc)})


@app.exception_handler(task_store.StorageUnavailable)
async def runtime_storage_error(request, exc):
    return JSONResponse(status_code=503, content={'detail': str(exc)})


@app.exception_handler(task_store.StorageConflict)
async def runtime_storage_conflict(request, exc):
    return JSONResponse(status_code=409, content={'detail': str(exc)})

# 每个任务独立子进程；共享回归库的读改写由跨进程锁保护。
def _agent_task_workers() -> int:
    try:
        return max(1, min(16, int(os.getenv('WORKBENCH_AGENT_TASK_WORKERS', '4'))))
    except ValueError:
        return 4


pool = ThreadPoolExecutor(max_workers=_agent_task_workers(), thread_name_prefix='agent-jobs')
# 每个护栏任务的快照、取消事件和报告均独立；允许多批回归同时执行。
# 任务并发与单任务 workers 是两层上限，避免无限创建线程压满护栏服务。
def _guard_task_workers() -> int:
    try:
        return max(1, min(32, int(os.getenv('WORKBENCH_GUARD_TASK_WORKERS', '4'))))
    except ValueError:
        return 4


guard_pool = ThreadPoolExecutor(max_workers=_guard_task_workers(), thread_name_prefix='guard-jobs')
# Skill URL 定时扫描使用独立线程，避免远程扫描等待时阻塞调度器轮询。
skill_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='skill-schedule-jobs')
lock = threading.RLock()
processes: dict[str, subprocess.Popen] = {}
agent_futures: dict[str, Any] = {}
guard_futures = {}
guard_cancel_events: dict[str, threading.Event] = {}
closing = threading.Event()

GUARD_ROOT = (ROOT / 'guard').resolve()


def _workbench_root() -> Path:
    """返回当前工作台结果根目录；测试和环境变量覆盖可以即时生效。"""
    return ROOT


def _scheduled_submit(schedule: dict[str, Any]) -> dict[str, Any]:
    """把定时配置转换为已有的 Agent/护栏任务提交。

    每次触发都生成新的任务 UUID，因而每次运行都有独立报告；定时任务
    自身只保存配置快照，不复用上一次的任务目录。
    """
    # 任务目录 ID 不能使用定时任务 ID，否则第二次运行会被幂等校验拦住。
    from uuid import uuid4
    run_task_id = uuid4()
    name = f"{schedule['name']} · 定时执行"
    module = schedule.get('module')
    if module == 'agent':
        submission = Submission(
            id=run_task_id,
            name=name,
            config=schedule['config'],
            agent=schedule.get('agent') or {},
        )
        return create(submission)
    if module == 'guard':
        submission = GuardTaskSubmission(
            id=run_task_id,
            name=name,
            config=schedule['config'],
        )
        return create_guard_task(submission)
    if module == 'skill':
        return _create_scheduled_skill_task(schedule, run_task_id)
    raise RuntimeError(f'不支持的定时任务模块：{module}')


def _multipart_field(boundary: str, name: str, value: str) -> bytes:
    """构造 Skill 扫描接口需要的文本 multipart 字段。"""
    return (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
        f'{value}\r\n'
    ).encode('utf-8')


def _skill_schedule_endpoint() -> tuple[str, str]:
    """读取 Skill 扫描服务地址和令牌；令牌只留在进程内存中。"""
    from .service_config import guard_base_url
    base = (
        os.getenv('SKILL_SCAN_BASE_URL')
        or os.getenv('GUARD_API_URL')
        or guard_base_url()
    )
    if not base or not base.strip():
        # Skill 定时任务由后台执行，不能在用户没有明确配置时悄悄把
        # 请求发到本机 8091；那通常是护栏调试服务，不能代表公司扫描服务。
        raise RuntimeError(
            'Skill 扫描服务地址未配置，请设置 SKILL_SCAN_BASE_URL（或 GUARD_API_URL）；'
            '本地调试时请显式配置 http://127.0.0.1:8091'
        )
    base = base.strip().rstrip('/')
    try:
        parsed = urlsplit(base)
        hostname = (parsed.hostname or '').lower()
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError('Skill 扫描服务地址不是有效的 HTTP/HTTPS 地址') from exc
    loopback = hostname in {'127.0.0.1', 'localhost', '::1'}
    if (
        parsed.scheme not in {'http', 'https'}
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (parsed.scheme == 'https' and port not in {None, 443})
        # 远程扫描服务必须使用 HTTPS；本地调试服务允许显式使用任意
        # loopback 端口（例如 8091），但不会再作为缺省地址被自动采用。
        or (parsed.scheme == 'http' and not loopback)
    ):
        raise RuntimeError('Skill 扫描服务地址未配置或不是有效的 HTTP/HTTPS 地址')
    endpoint = base + '/v1/skill-scan?compact=false'
    from .service_config import guard_token
    token = os.getenv('SKILL_SCAN_TOKEN') or guard_token(base)
    return endpoint, token


def _skill_schedule_read_limit() -> int:
    """限制远程返回体大小，避免异常服务一次性占满 8092 内存。"""
    try:
        value = int(os.getenv('SKILL_SCHEDULE_MAX_RESPONSE_BYTES', '20000000'))
    except ValueError:
        value = 20_000_000
    return max(1_048_576, min(value, 20_000_000))


def _read_http_body_limited(response, maximum: int) -> bytes:
    """分块读取 HTTP 响应，超过上限时立即失败。"""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(65_536, maximum - total + 1))
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode('utf-8', errors='replace')
        total += len(chunk)
        if total > maximum:
            raise RuntimeError('Skill 扫描服务返回体超过大小限制')
        chunks.append(bytes(chunk))
    return b''.join(chunks)


def _skill_schedule_request(config: dict[str, Any], request_id: str, archive: bytes | None = None) -> dict[str, Any]:
    """通过已有的 Skill 扫描 HTTP 接口执行一次 URL 扫描。"""
    endpoint, token = _skill_schedule_endpoint()
    report = str(config.get('report') or 'full')
    if report == 'compact':
        endpoint = endpoint.replace('compact=false', 'compact=true', 1)
    elif config.get('includeSummary'):
        endpoint += '&include_summary=true'
    boundary = '----ky-workbench-' + UUID(request_id).hex
    fields = {
        'url': str(config.get('url') or '').strip(),
        'mode': str(config.get('mode') or 'single'),
        'language': str(config.get('language') or 'zh'),
        'prompt': str(config.get('prompt') or ''),
        'request_id': request_id,
    }
    if archive is not None:
        fields.pop('url', None)
    body = b''.join(_multipart_field(boundary, name, value) for name, value in fields.items())
    if archive is not None:
        filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', str(config.get('fileName') or 'skill.zip'))[:120]
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="archive"; '
                 f'filename="{filename}"\r\nContent-Type: application/zip\r\n\r\n').encode()
        body += archive + b'\r\n'
    body += f'--{boundary}--\r\n'.encode('ascii')
    headers = {
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'Content-Length': str(len(body)),
    }
    if token:
        headers['X-Risk-Guard-Token'] = token
    try:
        timeout = float(os.getenv('SKILL_SCHEDULE_TIMEOUT_SECONDS', '1200'))
    except ValueError:
        timeout = 1200.0
    timeout = max(1.0, min(timeout, 1800.0))
    request = urllib.request.Request(endpoint, data=body, headers=headers, method='POST')
    maximum = _skill_schedule_read_limit()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = _read_http_body_limited(response, maximum).decode('utf-8', errors='replace')
            status = response.status
    except urllib.error.HTTPError as exc:
        detail = _read_http_body_limited(exc, maximum).decode('utf-8', errors='replace')[:1000]
        raise RuntimeError(f'Skill 扫描服务返回 HTTP {exc.code}：{redact_value(detail)}') from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f'Skill 扫描服务不可用：{redact_value(str(exc))}') from exc
    if not 200 <= status < 300:
        raise RuntimeError(f'Skill 扫描服务返回 HTTP {status}：{redact_value(raw[:1000])}')
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError('Skill 扫描服务返回的不是有效 JSON') from exc
    if not isinstance(parsed, dict):
        raise RuntimeError('Skill 扫描服务返回格式不是对象')
    return parsed


def _skill_schedule_markdown(payload: dict[str, Any]) -> str:
    """把远程返回体整理成可直接打开的 Markdown 报告。"""
    lines = ['# Skill 扫描报告', '']
    for key, label in (
        ('request_id', '请求编号'), ('status', '状态'), ('IsSafe', '是否安全'),
        ('Score', '评分'), ('scanner_version', '扫描器版本'),
    ):
        if key in payload:
            lines.append(f'- {label}：{payload[key]}')
    stages = payload.get('stage_reports')
    entries: list[tuple[str, Any]] = []
    if isinstance(stages, dict):
        entries = [(str(name), content) for name, content in stages.items()]
    elif isinstance(stages, list):
        for index, stage in enumerate(stages, 1):
            if isinstance(stage, dict):
                title = str(stage.get('stage') or stage.get('name') or f'阶段 {index}')
                content = stage.get('report') or stage.get('content') or stage
            else:
                title, content = f'阶段 {index}', stage
            entries.append((title, content))
    if entries:
        lines.extend(['', '## 分阶段报告', ''])
        for title, content in entries:
            lines.extend([f'### {title}', ''])
            if isinstance(content, str):
                fence = 'markdown' if content.lstrip().startswith('#') else 'text'
                lines.extend([content] if fence == 'markdown' else [f'```{fence}', content, '```'])
                lines.append('')
            else:
                lines.extend(['```json', json.dumps(content, ensure_ascii=False, indent=2), '```', ''])
    result = payload.get('result')
    if isinstance(result, dict):
        lines.extend(['', '## 扫描结果', '', '```json', json.dumps(result, ensure_ascii=False, indent=2), '```', ''])
    if not entries and not isinstance(result, dict):
        lines.extend(['', '## 返回体', '', '```json', json.dumps(payload, ensure_ascii=False, indent=2), '```', ''])
    return '\n'.join(lines)


def _skill_schedule_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """从两种服务返回格式提取可读摘要；不完整结果不擅自判定安全。"""
    result = payload.get('result') if isinstance(payload.get('result'), dict) else {}
    score = payload.get('Score')
    if score is None:
        score = result.get('score')
    is_safe = payload.get('IsSafe')
    if is_safe is None and type(score) is int and payload.get('status') == 'completed' and not payload.get('warnings'):
        is_safe = score >= 70
    return {
        'isSafe': is_safe,
        'score': score,
        'status': payload.get('status'),
        'warnings': payload.get('warnings') or [],
    }


def _execute_scheduled_skill_task(directory: Path) -> None:
    """后台执行 Skill URL 扫描并保存 JSON/Markdown 报告。"""
    with lock:
        record = _read_json(directory / 'task.json', {})
        if closing.is_set() or record.get('status') != 'queued':
            return
        record.update(
            status='running', startedAt=now(),
            progress={
                'phase': 'scanning',
                'message': '正在调用 Skill 扫描服务，等待报告返回。',
                'completed': 0, 'total': 1, 'percent': None,
                'indeterminate': True, 'updatedAt': now(),
            },
        )
        save(directory / 'task.json', record)
    try:
        request = _read_json(directory / 'request.json', {})
        config = request.get('config') if isinstance(request.get('config'), dict) else {}
        payload = _skill_schedule_request(config, str(record['id']))
        safe_payload = redact_value(payload)
        save(directory / 'result.json', safe_payload)
        (directory / 'report.md').write_text(_skill_schedule_markdown(safe_payload), encoding='utf-8')
        with lock:
            current = _read_json(directory / 'task.json', record)
            if current.get('status') != 'stopped':
                current.update(
                    status='completed', finishedAt=now(),
                    summary=_skill_schedule_summary(payload),
                    progress={
                        'phase': 'completed', 'message': 'Skill 扫描和报告整理已完成。',
                        'completed': 1, 'total': 1, 'percent': 100,
                        'indeterminate': False, 'updatedAt': now(),
                    },
                )
                save(directory / 'task.json', current)
    except Exception as exc:
        with lock:
            current = _read_json(directory / 'task.json', record)
            if current.get('status') != 'stopped':
                current.update(
                    status='failed', finishedAt=now(),
                    error=redact_value(f'{type(exc).__name__}: {exc}'),
                    progress={
                        **(current.get('progress') or {}),
                        'phase': 'failed', 'message': 'Skill 扫描失败，请查看运行历史中的错误。',
                        'indeterminate': False, 'updatedAt': now(),
                    },
                )
                save(directory / 'task.json', current)


def _create_scheduled_skill_task(schedule: dict[str, Any], task_id) -> dict[str, Any]:
    """创建一次 Skill 定时运行记录，并交给独立线程执行。"""
    if closing.is_set():
        raise RuntimeError('任务服务正在关闭，请稍后重试')
    if artifacts.enabled():
        from . import live_jobs
        return live_jobs.create(task_id, 'skill', {'source':'url', **(schedule.get('config') or {})},
                                name=f"{schedule['name']} · 定时执行", schedule_id=schedule.get('id'))
    directory = ROOT / str(task_id)
    record = {
        'id': str(task_id), 'name': f"{schedule['name']} · 定时执行", 'kind': 'skill',
        'createdAt': now(), 'status': 'queued', 'config': schedule.get('config') or {},
        'scheduleId': schedule.get('id'),
    }
    directory.mkdir(parents=True, exist_ok=False)
    save(directory / 'request.json', {'id': str(task_id), 'name': record['name'], 'kind': 'skill', 'config': record['config']})
    save(directory / 'task.json', record)
    try:
        skill_pool.submit(_execute_scheduled_skill_task, directory)
    except Exception as exc:
        record.update(status='failed', finishedAt=now(),
                      error=redact_value(f'{type(exc).__name__}: {exc}'))
        save(directory / 'task.json', record)
        raise
    return record


def _scheduled_task_status(module: str, task_id: str) -> str | None:
    """读取实际子任务的状态，供调度器更新运行历史。"""
    try:
        canonical = str(UUID(task_id))
    except (ValueError, TypeError):
        return None
    task_root = GUARD_ROOT if module == 'guard' else ROOT
    record = _read_json(task_root / canonical / 'task.json', None)
    return str(record.get('status')) if isinstance(record, dict) and record.get('status') else None


# 调度配置与历史持久化到 MySQL，执行线程仍由工作台进程管理。
schedule_service = ScheduleService(
    _workbench_root,
    lock,
    submit_run=_scheduled_submit,
    task_status=_scheduled_task_status,
    interval=5.0 if task_store.enabled() else 0.5,
)


def now():
    return datetime.now(timezone.utc).isoformat()


# 概览展示的是项目所在地区的自然日，避免 UTC 与页面上的北京时间错一天。
try:
    LOCAL_ZONE = ZoneInfo('Asia/Shanghai')
except Exception:  # pragma: no cover - 极少数精简 Python 环境没有时区数据库
    LOCAL_ZONE = timezone(timedelta(hours=8))


def _read_json(path: Path, default):
    """只读加载概览需要的 JSON；单个损坏文件不应阻塞首页。"""
    if task_store.enabled() and task_store.locate(path):
        value = task_store.read(path)
        return value if value is not None else default
    if artifacts.enabled():
        try:
            artifacts.owner(path.parent)
        except ValueError:
            pass
        else:
            return artifacts.json_value(path.parent, path.name, default)
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return default


def _task_paths(module):
    if task_store.enabled():
        return task_store.paths(module)
    root = GUARD_ROOT if module == 'guard' else ROOT
    return list(root.glob('*/task.json'))


def _parse_datetime(value):
    """把常见 ISO 时间转换为本地时区；无效值返回 None。"""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=LOCAL_ZONE)
    return parsed.astimezone(LOCAL_ZONE)


def _local_date(value):
    parsed = _parse_datetime(value)
    return parsed.date() if parsed else None


def _cases_from(path: Path):
    """Read the authoritative library; other paths are frozen datasets."""
    from ..records import case_store
    kind = case_store.kind_for(path)
    if kind:
        return case_store.load(kind)['cases']
    payload = _read_json(path, {})
    if isinstance(payload, dict) and isinstance(payload.get('cases'), list):
        return payload['cases']
    if isinstance(payload, list):
        return payload
    return []


def _finding_count(directory: Path):
    """从任务结果中提取问题数，用于最近任务摘要。"""
    from ..records import report_store
    if report_store.enabled():
        with report_store.connection() as conn, conn.cursor() as cur:
            cur.execute("""SELECT COUNT(DISTINCT f.finding_id) FROM agent_test_report_findings f
                JOIN agent_test_reports r ON r.report_id=f.report_id WHERE r.task_id=%s""", (directory.name,))
            return cur.fetchone()[0]
    result = _read_json(directory / 'result.json', {})
    if not isinstance(result, dict):
        return 0
    total = 0
    batches = result.get('batches')
    if not isinstance(batches, list):
        batches = [result]
    for batch in batches:
        if not isinstance(batch, dict):
            continue
        report = batch.get('finding_report') or batch.get('findingReport')
        if isinstance(report, dict):
            value = report.get('finding_count', report.get('findingCount'))
            if isinstance(value, (int, float)):
                total += int(value)
                continue
            findings = report.get('findings')
            if isinstance(findings, list):
                total += len(findings)
                continue
        # 没有生成 Finding 报告时，安全执行结果仍可能登记了成功 Case。
        case_ids = batch.get('recorded_case_ids')
        if isinstance(case_ids, list):
            total += len(case_ids)
        registration = batch.get('bad_case_registration')
        if isinstance(registration, dict):
            value = registration.get('candidate_count')
            if isinstance(value, (int, float)):
                total += int(value)
    return total


def _task_records():
    """读取工作台任务，忽略正在写入或已经损坏的单个记录。"""
    if task_store.enabled():
        return task_store.overview_records()
    records = []
    task_files = _task_paths('agent')
    # 护栏固定数据集任务保存在同一工作台根目录下的 guard 子目录。
    task_files.extend(_task_paths('guard'))
    for task_file in task_files:
        record = _read_json(task_file, None)
        if isinstance(record, dict) and record.get('id'):
            records.append((task_file.parent, record))
    return records


@app.get('/api/agent/overview', **endpoint_docs('overview'))
def overview():
    """返回工作台首页需要的只读统计，不触发测试、数据库同步或文件写入。"""
    today = datetime.now(LOCAL_ZONE).date()
    days = [today - timedelta(days=offset) for offset in range(6, -1, -1)]
    task_records = _task_records()
    task_dates = {
        id(record): _local_date(record.get('createdAt'))
        for _, record in task_records
    }
    today_tasks = [record for _, record in task_records if task_dates[id(record)] == today]
    completed_today = [record for record in today_tasks if record.get('status') == 'completed']
    finished_today = [record for record in today_tasks
                      if record.get('status') in {'completed', 'failed', 'stopped', 'interrupted'}]
    active_count = sum(record.get('status') in {'queued', 'running'} for _, record in task_records)

    security_cases = _cases_from(SECURITY_CASES_PATH)
    business_bad_cases = _cases_from(BUSINESS_BAD_CASES_PATH)
    security_dates = [_local_date(case.get('found_at')) for case in security_cases if isinstance(case, dict)]
    business_dates = [
        _local_date((case.get('source') or {}).get('registered_at'))
        for case in business_bad_cases
        if isinstance(case, dict) and isinstance(case.get('source'), dict)
    ]
    attack_findings = sum(value == today for value in security_dates)
    positive_failures = sum(value == today for value in business_dates)

    trend = []
    for day in days:
        tests = sum(task_dates[id(record)] == day for _, record in task_records)
        findings = sum(value == day for value in security_dates) + sum(value == day for value in business_dates)
        trend.append({'date': day.isoformat(), 'label': day.strftime('%m/%d'),
                      'tests': tests, 'findings': findings})

    recent_tasks = []
    for directory, record in sorted(task_records,
                                    key=lambda item: item[1].get('createdAt', ''), reverse=True)[:8]:
        config = record.get('config') if isinstance(record.get('config'), dict) else {}
        recent_tasks.append({
            'id': record.get('id'),
            'name': record.get('name') or '未命名测试',
            'status': record.get('status', 'unknown'),
            'kind': record.get('kind') or config.get('kind', 'unknown'),
            'createdAt': record.get('createdAt'),
            'findings': _finding_count(directory),
        })

    success_rate = round(len(completed_today) / len(finished_today) * 100, 1) if finished_today else 0
    return {
        'generatedAt': datetime.now(LOCAL_ZONE).isoformat(),
        'timezone': 'Asia/Shanghai',
        'today': {
            'testCount': len(today_tasks),
            'attackFindings': attack_findings,
            'positiveFailures': positive_failures,
            'findingCount': attack_findings + positive_failures,
            'completedCount': len(completed_today),
            'activeCount': active_count,
            'successRate': success_rate,
        },
        'trend': trend,
        'recentTasks': recent_tasks,
    }


def folder(task_id: str):
    try:
        canonical = str(UUID(task_id))
    except ValueError:
        raise HTTPException(404, '任务不存在')
    return ROOT / canonical


def save(path: Path, value):
    if task_store.enabled() and task_store.locate(path):
        task_store.write(path, value)
        return
    if artifacts.enabled():
        try:
            artifacts.owner(path.parent)
        except ValueError:
            pass
        else:
            artifacts.put(path.parent, path.name, value)
            return
    # 独立临时文件避免不同进程抢写同一个 task.tmp，产生交错或残尾。
    from ..records.library_lock import atomic_library_write
    atomic_library_write(path, json.dumps(value, ensure_ascii=False, indent=2))


def persist_reports(directory: Path):
    """Store completed evidence separately from the Agent execution outcome."""
    from ..records import report_store
    if not report_store.enabled():
        return
    try:
        if artifacts.enabled():
            artifacts.capture(directory)
        summary = report_store.import_task(directory)
        if artifacts.enabled():
            artifacts.link_reports(directory)
        storage = {'status': 'synced', **summary}
    except Exception:
        # Preserve the spool for explicit retry; never rerun Agent calls.
        storage = {'status': 'error', 'message': '报告数据库写入失败，执行结果保留在任务快照，可重试入库。'}
    with lock:
        record = _read_json(directory / 'task.json', None)
        if not isinstance(record, dict):
            return storage
        record['reportStorage'] = storage
        save(directory / 'task.json', record)
    return storage


def _terminate_process_tree(process: subprocess.Popen | None) -> bool:
    """尽力终止任务子进程，并等待它真正退出。

    仅把 task.json 标为 stopped/interrupted 不会释放 Agent 串行队列：外层
    线程仍可能卡在 ``process.wait()``。停止、重启恢复和执行器轮询都复用
    这个函数，确保后续任务不会在旧进程仍存活时偷偷并发执行。
    """
    if process is None:
        return True
    try:
        if process.poll() is not None:
            return True
    except (OSError, AttributeError):
        return False

    try:
        if os.name == 'nt':
            stopped = subprocess.run(
                ['taskkill', '/PID', str(process.pid), '/T', '/F'],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=5,
            )
            if stopped.returncode and process.poll() is None:
                process.kill()
        else:
            import signal
            os.killpg(process.pid, signal.SIGTERM)
    except (OSError, subprocess.TimeoutExpired, AttributeError, TypeError):
        try:
            process.kill()
        except (OSError, AttributeError):
            pass

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except (OSError, AttributeError):
            pass
        try:
            process.wait(timeout=2)
        except (subprocess.TimeoutExpired, OSError, AttributeError, TypeError):
            pass
    except (OSError, AttributeError, TypeError):
        # 极简测试替身或已经被外部回收的进程可能不接受 timeout；poll
        # 仍然是最后的可验证状态。
        pass
    try:
        return process.poll() is not None
    except (OSError, AttributeError):
        return False


def _process_exists(pid: int) -> bool:
    """尽量判断 PID 是否仍存在；仅用于回收已核验的工作进程。"""
    if pid <= 0:
        return False
    if os.name == 'nt':
        # Windows 的 os.kill(pid, 0) 在不同版本上对“进程不存在”和
        # “当前用户无权限”返回值不一致；用查询句柄读取退出码更可靠。
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
            if not handle:
                return False
            exit_code = ctypes.c_ulong()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            kernel32.CloseHandle(handle)
            return bool(ok and exit_code.value == 259)  # STILL_ACTIVE
        except (AttributeError, OSError, TypeError):
            # 精简运行环境没有 ctypes Windows API 时再退回通用实现。
            pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _process_command_line(pid: int) -> str:
    """读取指定 PID 的命令行，用于避免误杀 PID 重用后的其他程序。"""
    if os.name != 'nt':
        try:
            return Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\x00', b' ').decode(
                'utf-8', errors='replace'
            )
        except (FileNotFoundError, OSError, UnicodeError):
            return ''
    powershell = shutil.which('powershell.exe') or shutil.which('powershell')
    if not powershell:
        return ''
    query = (
        f"(Get-CimInstance Win32_Process -Filter \"ProcessId = {int(pid)}\").CommandLine"
    )
    try:
        result = subprocess.run(
            [powershell, '-NoProfile', '-NonInteractive', '-Command', query],
            capture_output=True,
            text=True,
            timeout=3,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError, TypeError):
        return ''
    return result.stdout.strip() if result.returncode == 0 else ''


def _process_identity(pid: int) -> dict[str, Any] | None:
    """读取 PID 的可核验身份，作为 WMI 不可用时的回收兜底。

    Windows 上的 ``Get-CimInstance Win32_Process`` 在部分公司电脑会因为
    权限策略返回“拒绝访问”，导致服务重启后无法读取命令行，也就不敢
    回收旧 worker。这里改用进程查询句柄读取可执行文件和创建时间：两者
    一起可以识别 PID 是否已经被别的 Python 进程复用，不依赖 WMI。
    """
    if pid <= 0:
        return None
    if os.name == 'nt':
        try:
            import ctypes

            class _FileTime(ctypes.Structure):
                _fields_ = [
                    ('dwLowDateTime', ctypes.c_uint32),
                    ('dwHighDateTime', ctypes.c_uint32),
                ]

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, int(pid))
            if not handle:
                return None
            try:
                result: dict[str, Any] = {}
                path = ctypes.create_unicode_buffer(32768)
                length = ctypes.c_uint32(len(path))
                if kernel32.QueryFullProcessImageNameW(
                    handle, 0, path, ctypes.byref(length)
                ):
                    result['executable'] = path.value[:length.value]
                created = _FileTime()
                exited = _FileTime()
                kernel = _FileTime()
                user = _FileTime()
                if kernel32.GetProcessTimes(
                    handle,
                    ctypes.byref(created),
                    ctypes.byref(exited),
                    ctypes.byref(kernel),
                    ctypes.byref(user),
                ):
                    result['creationTime'] = (
                        (int(created.dwHighDateTime) << 32)
                        | int(created.dwLowDateTime)
                    )
                return result or None
            finally:
                kernel32.CloseHandle(handle)
        except (AttributeError, OSError, TypeError, ValueError):
            return None
    # Linux/macOS 的 /proc 路径和 stat 令牌用于同样的 PID 复用判断；
    # 没有这些接口时返回 None，让调用方保持保守策略。
    try:
        executable = os.readlink(f'/proc/{int(pid)}/exe')
        stat = os.stat(f'/proc/{int(pid)}')
    except (FileNotFoundError, OSError, ValueError):
        return None
    return {'executable': executable, 'creationTime': int(stat.st_ctime_ns)}


def _normalized_executable(value: Any) -> str:
    """统一比较 Windows 路径大小写和分隔符。"""
    return str(value or '').replace('\\', '/').strip().lower()


def _filetime_seconds(value: Any) -> float | None:
    """把 Windows FILETIME 转成 Unix 秒；非法值不参与身份判断。"""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    # FILETIME 以 100 纳秒为单位，起点是 1601-01-01 UTC。
    seconds = number / 10_000_000 - 11_644_473_600
    return seconds if seconds > 0 else None


def _worker_identity_matches(record: Mapping[str, Any], pid: int) -> bool:
    """确认 PID 仍是 task.json 记录的 worker，避免误杀 PID 重用进程。"""
    actual = _process_identity(pid)
    if not actual:
        return False
    expected = record.get('workerIdentity')
    if isinstance(expected, Mapping):
        expected_executable = _normalized_executable(expected.get('executable'))
        actual_executable = _normalized_executable(actual.get('executable'))
        if not expected_executable or actual_executable != expected_executable:
            return False
        expected_creation = expected.get('creationTime')
        actual_creation = actual.get('creationTime')
        if expected_creation is None or actual_creation is None:
            return False
        try:
            return int(expected_creation) == int(actual_creation)
        except (TypeError, ValueError):
            return False

    # 旧版本只保存了 workerPid。startedAt 是在 Popen 前写入的，
    # 因而仍能用“同一个 Python 可执行文件 + 创建时间很接近”降低 PID
    # 复用误杀风险；无法取得这两个证据时返回 False，交给人工检查。
    actual_executable = _normalized_executable(actual.get('executable'))
    expected_executable = _normalized_executable(sys.executable)
    if expected_executable and actual_executable != expected_executable:
        return False
    started = record.get('startedAt')
    try:
        started_at = datetime.fromisoformat(str(started).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError, OverflowError):
        return False
    created_at = _filetime_seconds(actual.get('creationTime'))
    if created_at is None:
        # POSIX 的 st_ctime_ns 不是进程创建时间；只有 Windows FILETIME
        # 才能用于这个旧记录兜底。
        return False
    return started_at - 5 <= created_at <= started_at + 120


def _worker_pids_for_directory(directory: Path) -> list[int] | None:
    """查找仍在运行且命令行指向本任务目录的旧 worker。

    旧版本没有把 worker PID 写入 task.json。服务被强制关闭后，下一次
    启动仍需要尽量清理这类遗留进程；无法读取系统进程列表时返回 None，
    由调用方把“未能确认”明确记录下来，而不是假装已经清理。
    """
    normalized_directory = str(directory.resolve()).replace('\\', '/').lower()
    if os.name == 'nt':
        powershell = shutil.which('powershell.exe') or shutil.which('powershell')
        if not powershell:
            return None
        query = (
            "Get-CimInstance Win32_Process | "
            "Where-Object { $_.CommandLine -and "
            "$_.CommandLine -like '*auto_test.workbench.worker*' } | "
            "Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"
        )
        try:
            result = subprocess.run(
                [powershell, '-NoProfile', '-NonInteractive', '-Command', query],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError, TypeError):
            return None
        if result.returncode != 0:
            return None
        try:
            raw = json.loads(result.stdout or 'null')
        except json.JSONDecodeError:
            return None
        rows = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
        matches: list[int] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            command = str(row.get('CommandLine') or '').replace('\\', '/').lower()
            if normalized_directory not in command:
                continue
            try:
                pid = int(row.get('ProcessId') or 0)
            except (TypeError, ValueError):
                continue
            if pid > 0 and pid != os.getpid():
                matches.append(pid)
        return matches
    proc_root = Path('/proc')
    if not proc_root.is_dir():
        return None
    matches = []
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            command = entry.joinpath('cmdline').read_bytes().replace(b'\x00', b' ').decode(
                'utf-8', errors='replace'
            ).replace('\\', '/').lower()
        except (OSError, UnicodeError):
            continue
        if 'auto_test.workbench.worker' not in command or normalized_directory not in command:
            continue
        pid = int(entry.name)
        if pid != os.getpid():
            matches.append(pid)
    return matches


def _terminate_windows_pid(pid: int) -> bool:
    """用 Win32 句柄终止单个 PID，作为 taskkill 受限时的兜底。"""
    if os.name != 'nt' or pid <= 0:
        return False
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
        handle = kernel32.OpenProcess(0x0001 | 0x1000, False, int(pid))
        if not handle:
            return False
        try:
            return bool(kernel32.TerminateProcess(handle, 1))
        finally:
            kernel32.CloseHandle(handle)
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _terminate_pid_tree(pid: int) -> bool:
    """终止一个已经通过命令行核验的 worker PID。"""
    if not _process_exists(pid):
        return True
    if os.name == 'nt':
        try:
            result = subprocess.run(
                ['taskkill', '/PID', str(pid), '/T', '/F'],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired, TypeError):
            # taskkill 在受限环境中可能超时或不可用；这个 PID 已经经过
            # 身份校验，再用 Win32 终止句柄兜底，确保不会继续占队列。
            if not _terminate_windows_pid(pid):
                return False
        else:
            if result.returncode and _process_exists(pid):
                # 某些环境禁止 taskkill 查询进程树，但允许对自己启动
                # 的 worker 取得终止句柄；worker 本身不会再创建测试子进程，
                # 因此单进程兜底足以释放 Agent 串行队列。
                if not _terminate_windows_pid(pid):
                    return False
    else:
        try:
            import signal
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            # 进程可能刚好在 _process_exists() 和 killpg() 之间自然退出，
            # 这已经达到回收目的，不应把它误报成清理失败。
            return True
        except (OSError, TypeError):
            return False
    deadline = time.monotonic() + 5
    while _process_exists(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not _process_exists(pid)


def _terminate_persisted_worker(record: Mapping[str, Any], directory: Path) -> bool:
    """只回收命令行确实属于本任务的遗留 worker。"""
    try:
        pid = int(record.get('workerPid') or 0)
    except (TypeError, ValueError):
        pid = 0
    candidates: list[int] | None
    if pid > 0 and pid != os.getpid():
        candidates = [pid]
    else:
        candidates = _worker_pids_for_directory(directory)
    if candidates is None:
        return False
    marker = str(record.get('workerMarker') or '').strip().lower()
    cleaned = True
    for candidate in candidates:
        if not _process_exists(candidate):
            continue
        command_line = _process_command_line(candidate)
        if not command_line:
            # WMI 在受限账户下可能无法读取命令行；用启动时保存的
            # 可执行文件和创建时间完成同等的 PID 身份校验。
            if not _worker_identity_matches(record, candidate):
                cleaned = False
                continue
            cleaned = _terminate_pid_tree(candidate) and cleaned
            continue
        normalized_command = command_line.replace('\\', '/').lower()
        normalized_directory = str(directory.resolve()).replace('\\', '/').lower()
        if 'auto_test.workbench.worker' not in normalized_command:
            continue
        if normalized_directory not in normalized_command:
            continue
        if marker and marker not in normalized_command:
            continue
        cleaned = _terminate_pid_tree(candidate) and cleaned
    return cleaned


def _wait_for_agent_process(directory: Path, process: subprocess.Popen) -> int:
    """等待 Agent 子进程，同时响应 stopped/interrupted 状态。

    旧实现无条件 ``wait()``。如果停止或服务恢复把记录改成终态但子进程
    没有被成功杀掉，唯一的 Agent worker 就会永久占住，后续任务只能显示
    queued。这里定期观察状态并在需要时终止旧进程。
    """
    while True:
        try:
            return int(process.wait(timeout=0.5))
        except subprocess.TimeoutExpired:
            with lock:
                try:
                    current = state(directory)
                    should_stop = current.get('status') in {'stopped', 'interrupted'}
                except HTTPException:
                    should_stop = True
                should_stop = should_stop or closing.is_set()
            if should_stop:
                if not _terminate_process_tree(process):
                    raise RuntimeError('无法终止已中断的 Agent 测试进程；后续任务保持排队以避免并发执行')
                try:
                    return int(process.wait(timeout=2))
                except subprocess.TimeoutExpired as exc:
                    raise RuntimeError('已停止等待，但 Agent 测试进程仍未退出') from exc
        except (OSError, TypeError):
            # 仅供旧版测试替身兼容；真实 Popen 支持带 timeout 的 wait。
            return int(process.wait())


def _agent_future_done(task_id: str, future: Any) -> None:
    """清理 Agent 队列中的 Future 引用，避免重试后留下幽灵任务。"""
    with lock:
        if agent_futures.get(task_id) is future:
            agent_futures.pop(task_id, None)


def _submit_agent(directory: Path) -> Any:
    """提交 Agent 任务并保留 Future，便于停止排队任务和恢复服务。"""
    task_id = directory.name
    try:
        future = pool.submit(execute, directory)
    except Exception as exc:
        record = _read_json(directory / 'task.json', {})
        if isinstance(record, dict) and record.get('status') == 'queued':
            record.update(
                status='failed',
                finishedAt=now(),
                error=redact_value(f'无法加入本地执行队列：{type(exc).__name__}: {exc}'),
            )
            save(directory / 'task.json', record)
        raise
    agent_futures[task_id] = future
    add_done_callback = getattr(future, 'add_done_callback', None)
    if callable(add_done_callback):
        add_done_callback(lambda done, key=task_id: _agent_future_done(key, done))
    return future


def state(directory: Path):
    record = _read_json(directory / 'task.json', None)
    if record is None:
        raise HTTPException(404, '任务不存在')
    return record


def _delete_task_directory(directory: Path, *, root: Path, missing_message: str,
                           task_id: str):
    """删除工作台任务目录，并确保路径仍位于对应的结果根目录内。

    任务目录只由 UUID 拼接得到，但这里仍再次校验解析后的路径，避免
    意外的软链接或配置错误把删除范围带到工作台目录之外。
    """
    root = root.resolve()
    candidate = directory.resolve(strict=False)
    if candidate == root or not candidate.is_relative_to(root):
        raise HTTPException(404, missing_message)
    if directory.is_symlink():
        raise HTTPException(404, missing_message)
    stored = task_store.enabled() and _read_json(directory / 'task.json', None) is not None
    if not directory.is_dir() and not stored:
        raise HTTPException(404, missing_message)
    try:
        if directory.is_dir():
            shutil.rmtree(directory)
    except FileNotFoundError:
        raise HTTPException(404, missing_message)
    except OSError as exc:
        raise HTTPException(500, f'任务目录删除失败：{exc}')
    if stored:
        task_store.delete_task(directory / 'task.json')
    return {'id': task_id, 'status': 'deleted'}


_progress_cache = {}


def _agent_progress(directory: Path, record: dict | None = None) -> dict:
    record = record or {}
    path = directory / 'output.log'
    if artifacts.enabled():
        log_state = artifacts.log_status(directory)
        stamp = log_state.get('size', 0)
    else:
        stamp = None
    try:
        if stamp is not None:
            raise OSError()
        stat = path.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        stamp = stamp if stamp is not None else (0, 0)
    config = record.get('config') or {}
    key = (str(directory), stamp, record.get('status'),
           record.get('plannedCount'),
           json.dumps({k: config.get(k) for k in ('kind', 'source', 'library', 'count', 'scenes', 'tactics')}, sort_keys=True))
    with lock:
        cached = _progress_cache.get(str(directory))
        if cached and cached[0] == key:
            return dict(cached[1])
        value = _scan_agent_progress(directory, record)
        if len(_progress_cache) >= 1000:
            _progress_cache.pop(next(iter(_progress_cache)))
        _progress_cache[str(directory)] = (key, value)
        return dict(value)


def _scan_agent_progress(directory: Path, record: dict | None = None) -> dict:
    """从执行器已经写出的日志中提取可验证的任务进度。

    执行器的日志是 Agent 测试唯一的实时事实来源。这里不猜测模型内部
    进度，只识别日志中明确出现的 Query、Seed、Case 完成数量；识别不到
    总数时返回不确定进度，页面仍可展示最近一行输出和已耗时状态。
    """
    record = record or {}
    log_path = directory / 'output.log'
    from .runtime_api import progress_lines
    lines, latest = progress_lines(log_path)
    total = 0
    for line in lines:
        # 每个子批次的开始行带有明确的 Queries / Seeds / Cases 总数。
        if ('开始' in line
                and ('Queries=' in line or 'Seeds=' in line or 'Cases=' in line)):
            match = re.search(r'\b(?:Queries|Seeds|Cases)=(\d+)', line)
            if match:
                total += int(match.group(1))
    completed = sum(
        bool(
            re.search(
                r'\b(?:Query|Seed|Case)\s+\d+/\d+.*\|\s*(?:执行\s+\d+\s+\|\s+)?完成(?:\s*\||$)',
                line,
            )
        )
        for line in lines
    )
    status = str(record.get('status') or 'unknown')
    config = record.get('config') or {}
    if record.get('plannedCount') is not None:
        total = max(total, int(record['plannedCount']))
    elif config.get('kind') == 'attack' and config.get('source') == 'generate' and not config.get('library'):
        planned = int(config.get('count') or 0) * len(config.get('scenes') or []) * len(config.get('tactics') or [])
        total = max(total, planned)
    if status == 'completed':
        completed = max(completed, total)
    if total:
        completed = min(completed, total)
    current = str(redact_value(latest))
    if status == 'queued':
        phase = 'queued'
        message = '任务已排队，等待本地执行器启动。'
    elif status in {'completed', 'failed', 'stopped', 'interrupted'}:
        phase = status
        message = current or ('任务' + status)
    elif '报告已保存' in current or 'MySQL 同步' in current:
        phase = 'finalizing'
        message = current
    elif '健康检查' in current:
        phase = 'health_check'
        message = current
    elif 'BIZ' in current or 'Case ' in current:
        phase = 'business_case'
        message = current
    elif 'EPE' in current or 'Query ' in current:
        phase = 'epe_query'
        message = current
    elif 'CR' in current or 'Seed ' in current:
        phase = 'crescendo_seed'
        message = current
    elif current:
        phase = 'running'
        message = current
    else:
        phase = 'starting'
        message = '执行器正在启动，等待第一条进度输出。'
    percent = round(completed / total * 100, 1) if total else None
    return {
        'phase': phase,
        'message': message,
        'completed': completed,
        'total': total,
        'percent': percent,
        'indeterminate': not bool(total) and status in {'queued', 'running'},
        'updatedAt': now(),
    }


def _with_agent_progress(directory: Path, record: dict) -> dict:
    """给任务状态附加动态进度，不把进度重复写入 task.json。"""
    result = dict(record)
    result['progress'] = _agent_progress(directory, result)
    return result


@app.middleware('http')
async def same_origin(request: Request, call_next):
    # 不开放跨域写操作，内网页面经同源代理访问，避免其他站点代发测试任务。
    origin = request.headers.get('origin')
    if origin and urlsplit(origin).netloc != request.headers.get('host'):
        return JSONResponse({'detail': '请通过工作台同源页面访问'}, status_code=403)
    return await call_next(request)


@app.on_event('startup')
def recover():
    global guard_pool, pool, skill_pool
    closing.clear()
    # 目前正常 shutdown 不关闭 Agent 池，但测试或外部生命周期管理器
    # 可能已经关闭它；恢复时统一保证三个队列都可提交新任务。
    if getattr(pool, '_shutdown', False):
        pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='agent-jobs')
    # TestClient 或开发服务器重启后允许重新使用 Skill 定时线程池。
    if getattr(skill_pool, '_shutdown', False):
        skill_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='skill-schedule-jobs')
    # 护栏线程池在 shutdown 时也会被关闭；同一 Python 进程重新进入
    # lifespan（例如 TestClient 或某些热重载模式）时必须重新创建。
    if getattr(guard_pool, '_shutdown', False):
        guard_pool = ThreadPoolExecutor(max_workers=_guard_task_workers(), thread_name_prefix='guard-jobs')
    ROOT.mkdir(parents=True, exist_ok=True)
    if artifacts.enabled():
        from . import live_jobs
        live_jobs.recover()
    for file in _task_paths('agent'):
        # 单个损坏的历史记录不能阻止 8092 启动；后续列表接口会忽略它。
        record = _read_json(file, {})
        if not isinstance(record, dict):
            continue
        status = record.get('status')
        if status in {'running', 'queued'}:
            # 同一进程内重新加载时，先终止仍被 processes 持有的子进程；
            # 进程重启后则用 task.json 中的 PID + 命令行校验回收遗留 worker。
            process = processes.get(file.parent.name)
            cleanup_ok = True
            if process is not None:
                cleanup_ok = _terminate_process_tree(process)
            elif record.get('status') == 'running':
                cleanup_ok = _terminate_persisted_worker(record, file.parent)
            if record.get('status') == 'queued':
                future = agent_futures.get(file.parent.name)
                if future is not None and future.cancel():
                    agent_futures.pop(file.parent.name, None)
            error = '任务服务已重启；未自动重跑，请核对已有报告后再创建任务'
            if record.get('status') == 'running' and not cleanup_ok:
                error += '；未能确认或清理遗留 worker，请检查该任务目录后再重试'
            record.update(status='interrupted', finishedAt=now(), error=error)
            if cleanup_ok:
                record.pop('workerPid', None)
                record.pop('workerMarker', None)
                record.pop('workerIdentity', None)
            save(file, record)
        elif record.get('workerPid'):
            # 上一次重启如果暂时没有权限回收 worker，会把 PID 留在
            # interrupted 记录中；下一次启动继续尝试，避免一次失败让
            # 旧进程永久脱离清理流程。
            if _terminate_persisted_worker(record, file.parent):
                record.pop('workerPid', None)
                record.pop('workerMarker', None)
                record.pop('workerIdentity', None)
                save(file, record)
    GUARD_ROOT.mkdir(parents=True, exist_ok=True)
    for file in _task_paths('guard'):
        record = _read_json(file, {})
        if record.get('status') in {'running', 'queued'}:
            event = guard_cancel_events.get(file.parent.name)
            if event is not None:
                event.set()
            future = guard_futures.get(file.parent.name)
            if record.get('status') == 'queued' and future is not None and future.cancel():
                guard_futures.pop(file.parent.name, None)
            record.update(
                status='interrupted',
                finishedAt=now(),
                error='任务服务已重启；未自动重跑，请核对已有报告后再创建任务',
            )
            save(file, record)
    # 恢复 schedules/*.json 后由独立线程按 nextRunAt 继续调度。已有实际
    # 任务不会在服务重启时偷偷重跑，调度历史会把它们标记为 interrupted。
    schedule_service.start()
    from . import review_analysis
    review_analysis.start()


@app.on_event('shutdown')
def shutdown():
    # 正常关闭服务时终止本服务拥有的子进程，避免后台测试继续消耗请求。
    closing.set()
    if artifacts.enabled():
        from . import live_jobs
        live_jobs.shutdown()
    from . import review_analysis
    review_analysis.stop()
    for task_id in list(processes):
        try:
            stop(task_id)
        except Exception as exc:
            # 关闭流程不能因为单个进程已经失联而提前退出；否则线程池中的
            # 排队任务和调度线程不会被取消，下一次启动仍可能看到“卡住”。
            process = processes.get(task_id)
            cleanup_ok = True
            if process is not None:
                cleanup_ok = _terminate_process_tree(process)
            processes.pop(task_id, None)
            with lock:
                directory = ROOT / task_id
                record = _read_json(directory / 'task.json', {})
                if isinstance(record, dict) and record.get('status') in {'queued', 'running'}:
                    record.update(
                        status='interrupted',
                        finishedAt=now(),
                        error=redact_value(f'任务服务关闭，未能正常停止执行进程：{type(exc).__name__}'),
                    )
                    if cleanup_ok:
                        record.pop('workerPid', None)
                        record.pop('workerMarker', None)
                        record.pop('workerIdentity', None)
                    save(directory / 'task.json', record)
    with lock:
        for future in list(agent_futures.values()):
            cancel = getattr(future, 'cancel', None)
            if callable(cancel):
                cancel()
        agent_futures.clear()
        for event in guard_cancel_events.values():
            event.set()
    schedule_service.stop()
    skill_pool.shutdown(wait=False, cancel_futures=True)
    guard_pool.shutdown(wait=False, cancel_futures=True)


def _schedule_error(exc: Exception) -> HTTPException:
    """把定时配置错误转换成页面易读的 422 响应。"""
    return HTTPException(422, str(exc))


@app.post('/api/agent/schedules', status_code=201, **endpoint_docs('create_schedule'))
def create_schedule(body: dict[str, Any]):
    """创建 Agent、护栏固定库或 Skill URL 定时任务。"""
    if closing.is_set():
        raise HTTPException(503, '任务服务正在关闭，请稍后重试')
    try:
        return schedule_service.create(body)
    except ScheduleValidationError as exc:
        raise _schedule_error(exc) from exc


@app.get('/api/agent/schedules', **endpoint_docs('list_schedules'))
def list_schedules():
    """列出已保存的定时任务。"""
    return schedule_service.list()


@app.get('/api/agent/schedules/{schedule_id}', **endpoint_docs('get_schedule'))
def get_schedule(schedule_id: str):
    try:
        return schedule_service.get(schedule_id)
    except (KeyError, ScheduleValidationError) as exc:
        raise HTTPException(404, '定时任务不存在') from exc


@app.patch('/api/agent/schedules/{schedule_id}', **endpoint_docs('update_schedule'))
@app.put('/api/agent/schedules/{schedule_id}', **endpoint_docs('update_schedule'))
def update_schedule(schedule_id: str, body: dict[str, Any]):
    try:
        return schedule_service.update(schedule_id, body)
    except KeyError as exc:
        raise HTTPException(404, '定时任务不存在') from exc
    except ScheduleValidationError as exc:
        raise _schedule_error(exc) from exc


@app.post('/api/agent/schedules/{schedule_id}/toggle', **endpoint_docs('toggle_schedule'))
def toggle_schedule(schedule_id: str, body: dict[str, Any] | None = None):
    enabled = None
    if isinstance(body, dict) and 'enabled' in body:
        enabled = body['enabled']
        if not isinstance(enabled, bool):
            raise HTTPException(422, 'enabled 必须是布尔值')
    try:
        return schedule_service.toggle(schedule_id, enabled)
    except KeyError as exc:
        raise HTTPException(404, '定时任务不存在') from exc
    except ScheduleValidationError as exc:
        raise _schedule_error(exc) from exc


@app.post('/api/agent/schedules/{schedule_id}/run-now', **endpoint_docs('run_schedule_now'))
def run_schedule_now(schedule_id: str):
    """立即执行一次；不改变原有周期的 nextRunAt。"""
    try:
        return schedule_service.run_now(schedule_id)
    except KeyError as exc:
        raise HTTPException(404, '定时任务不存在') from exc
    except ScheduleValidationError as exc:
        raise _schedule_error(exc) from exc


@app.get('/api/agent/schedules/{schedule_id}/runs', **endpoint_docs('schedule_runs'))
def schedule_runs(schedule_id: str):
    try:
        record = schedule_service.get(schedule_id)
    except (KeyError, ScheduleValidationError) as exc:
        raise HTTPException(404, '定时任务不存在') from exc
    return {'scheduleId': record['id'], 'runs': record.get('runs') or []}


@app.delete('/api/agent/schedules/{schedule_id}', **endpoint_docs('delete_schedule'))
def delete_schedule(schedule_id: str):
    try:
        return schedule_service.delete(schedule_id)
    except KeyError as exc:
        raise HTTPException(404, '定时任务不存在') from exc
    except ScheduleValidationError as exc:
        raise _schedule_error(exc) from exc


def guard_folder(task_id: str):
    """护栏任务只允许通过 UUID 定位到工作台自己的任务目录。"""
    try:
        canonical = str(UUID(task_id))
    except ValueError:
        raise HTTPException(404, '护栏任务不存在')
    return GUARD_ROOT / canonical


def _guard_state(directory: Path):
    record = _read_json(directory / 'task.json', None)
    if record is None:
        raise HTTPException(404, '护栏任务不存在')
    return record


def _guard_worker_state(task_id: str) -> tuple[bool, str]:
    """返回护栏任务后台线程的真实状态。

    task.json 里的 ``stopped`` 只表示页面已请求取消。一次护栏 HTTP
    请求已经发出时，线程必须等本次请求自然返回才能退出；在这段收尾时间
    它仍会占用一个护栏执行槽。这个动态状态不写入 task.json，避免服务
    重启后留下错误的“仍在运行”标记。
    """
    future = guard_futures.get(task_id)
    if future is None:
        return False, 'idle'
    running = getattr(future, 'running', None)
    if callable(running) and running():
        return True, 'running'
    done = getattr(future, 'done', None)
    if callable(done) and done():
        return False, 'finished'
    # Future 已提交但尚未被worker 取走，属于队列等待而非后台执行中。
    return False, 'queued'


def _with_guard_worker_state(record: dict) -> dict:
    """为接口响应补充瞬时 worker 状态，供前端判断是否仍在收尾。"""
    result = dict(record)
    active, worker_state = _guard_worker_state(str(result.get('id') or ''))
    result['workerActive'] = active
    result['workerState'] = worker_state
    return result


def _guard_future_done(task_id: str, future: Any) -> None:
    """清理已完成或已取消的 Future，避免停止排队任务留下幽灵引用。"""
    with lock:
        if guard_futures.get(task_id) is future:
            guard_futures.pop(task_id, None)
            guard_cancel_events.pop(task_id, None)


def _guard_artifacts(directory: Path):
    if artifacts.enabled():
        return artifacts.listing(directory)
    return [
        p.relative_to(directory).as_posix()
        for p in directory.rglob('*')
        if p.is_file() and p.suffix in {'.json', '.md'}
        and p.name not in {'task.json', 'request.json'}
    ]


def _guard_report(directory: Path):
    """读取任务目录内由 run_guard_regression 生成的报告。"""
    reports = sorted((directory / 'reports').glob('*.json')) if (directory / 'reports').exists() else []
    return _read_json(reports[-1], {}) if reports else {}


def execute_guard(directory: Path):
    """在后台执行固定数据集回归，并把报告摘要写回任务记录。"""
    key = directory.name
    with lock:
        record = _guard_state(directory)
        if closing.is_set() or record.get('status') != 'queued':
            return
        record.update(
            status='running',
            startedAt=now(),
            progress={
                'phase': 'preparing',
                'message': '正在加载固定数据集。',
                'completed': 0,
                'total': 0,
                'percent': 0,
                'indeterminate': True,
                'updatedAt': now(),
            },
        )
        save(directory / 'task.json', record)
    try:
        from ..guard.runner import GuardRegressionCancelled, run_guard_regression

        request = _read_json(directory / 'request.json', {})
        config = GuardTaskSubmission.model_validate(request).config
        # 创建任务时已经生成过快照；执行阶段只读取快照，避免排队期间源库变化影响本次回归。
        if artifacts.enabled():
            artifacts.restore_inputs(directory)
        snapshot = {
            'guard_cases': directory / 'guard-cases.json',
            'positive_cases': (
                directory / 'business-cases.json'
                if (directory / 'business-cases.json').is_file() else None
            ),
            'include_positive': (
                config.guardMode == 'dataset'
                and config.dataset in {'combined', 'positive'}
                and (directory / 'business-cases.json').is_file()
            ),
        }
        if not snapshot['guard_cases'].is_file():
            snapshot = prepare_dataset(config, directory)
        output_dir = directory / 'reports'
        args = runner_args(config, snapshot, f"WEB-GUARD-{key}", output_dir)
        last_progress_write = 0.0

        def update_progress(event):
            """把 runner 的逐条完成事件写入任务状态，供前端轮询。"""
            nonlocal last_progress_write
            phase = str(event.get('phase') or 'running')
            # 大型固定库可能每秒完成很多条；页面每 1.2 秒轮询一次，
            # 这里限频写盘，避免进度记录反过来拖慢护栏请求。
            current_time = time.monotonic()
            if phase == 'running' and current_time - last_progress_write < 0.35:
                return
            with lock:
                current = _guard_state(directory)
                if current.get('status') in {'stopped', 'interrupted'}:
                    return
                current['progress'] = {
                    'phase': str(event.get('phase') or 'running'),
                    'message': str(event.get('message') or '护栏任务处理中。'),
                    'completed': int(event.get('completed') or 0),
                    'total': int(event.get('total') or 0),
                    'percent': event.get('percent'),
                    'indeterminate': bool(event.get('indeterminate', False)),
                    'currentCase': event.get('current_case'),
                    'currentOutcome': event.get('current_outcome'),
                    'updatedAt': event.get('updated_at') or now(),
                }
                save(directory / 'task.json', current)
                last_progress_write = current_time

        cancel_event = guard_cancel_events.setdefault(key, threading.Event())
        result = run_guard_regression(
            args,
            progress_callback=update_progress,
            cancel_callback=lambda: closing.is_set() or cancel_event.is_set(),
        )
        report = _guard_report(directory)
        save(directory / 'result.json', {
            'status': result.get('status', 'COMPLETED'),
            'run_id': result.get('run_id'),
            'summary': result.get('summary') or report.get('summary', {}),
            'results': report.get('results', []),
            'finding_report': result.get('finding_report'),
            'json': result.get('json'),
            'markdown': result.get('markdown'),
        })
        with lock:
            record = _guard_state(directory)
            if record.get('status') not in {'stopped', 'interrupted'}:
                record.update(status='completed', finishedAt=now(),
                              summary=result.get('summary') or report.get('summary', {}),
                              runId=result.get('run_id'),
                              progress={
                                  'phase': 'completed',
                                  'message': '护栏固定数据集回归和报告整理已完成。',
                                  'completed': int((result.get('summary') or {}).get('total') or 0),
                                  'total': int((result.get('summary') or {}).get('total') or 0),
                                  'percent': 100,
                                  'indeterminate': False,
                                  'updatedAt': now(),
                              })
                save(directory / 'task.json', record)
    except GuardRegressionCancelled as exc:
        with lock:
            record = _guard_state(directory)
            if record.get('status') not in {'stopped', 'interrupted'}:
                record.update(
                    status='interrupted', finishedAt=now(),
                    error=redact_value(f'任务已中断：{exc}'),
                    progress={
                        **(record.get('progress') or {}),
                        'phase': 'interrupted',
                        'message': '任务已中断，未完成样本不会继续提交。',
                        'indeterminate': False,
                        'updatedAt': now(),
                    },
                )
                save(directory / 'task.json', record)
    except Exception as exc:
        with lock:
            record = _guard_state(directory)
            if record.get('status') not in {'stopped', 'interrupted'}:
                record.update(status='failed', finishedAt=now(),
                              error=redact_value(f'{type(exc).__name__}: {exc}'),
                              progress={
                                  **(record.get('progress') or {}),
                                  'phase': 'failed',
                                  'message': redact_value(f'任务失败：{type(exc).__name__}: {exc}'),
                                  'indeterminate': False,
                                  'updatedAt': now(),
                              })
                save(directory / 'task.json', record)
    finally:
        stored = persist_reports(directory)
        if stored and stored.get('status') == 'synced':
            artifacts.cleanup(directory)


@app.post('/api/agent/guard/tasks/{task_id}/report-sync', tags=['数据库报告'])
def retry_guard_report_sync(task_id: str):
    directory = guard_folder(task_id)
    record = _guard_state(directory)
    active, worker_state = _guard_worker_state(task_id)
    if record.get('status') in {'running', 'queued'} or active or worker_state == 'queued':
        raise HTTPException(409, '任务执行中，请结束后重试入库')
    return persist_reports(directory)


@app.get('/api/agent/guard/libraries', **endpoint_docs('guard_libraries'))
def guard_libraries():
    """列出护栏固定数据集；combined 是前端默认的攻击+正向模式。"""
    return {'default': 'combined', 'datasets': dataset_catalog()}


@app.get('/api/agent/guard/libraries/{dataset_id}', **endpoint_docs('guard_library'))
def guard_library(dataset_id: str):
    for item in dataset_catalog():
        if item['id'] == dataset_id:
            return item
    raise HTTPException(404, '护栏数据集不存在')


@app.post('/api/agent/guard/tasks', status_code=201, **endpoint_docs('create_guard_task'))
def create_guard_task(body: GuardTaskSubmission):
    """创建固定数据集护栏回归；服务地址和令牌只从环境变量读取。"""
    if closing.is_set():
        raise HTTPException(503, '任务服务正在关闭，请稍后重试')
    directory = guard_folder(str(body.id))
    with lock:
        if _read_json(directory / 'task.json', None) is not None:
            previous = _read_json(directory / 'request.json', {})
            if previous != body.model_dump(mode='json'):
                raise HTTPException(409, '相同任务 ID 已提交不同配置，请新建任务')
            return _guard_state(directory)
    try:
        # 提交前生成快照，确保库为空或损坏时不会创建无法执行的任务。
        directory.mkdir(parents=True, exist_ok=True)
        prepare_dataset(body.config, directory)
        if artifacts.enabled():
            artifacts.capture(directory)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(422, f'护栏固定数据集不可用：{exc}')
    record = {
        'id': str(body.id), **resolve_task_name('guard', body.id, body.name), 'kind': 'guard',
        'createdAt': now(), 'status': 'queued', 'config': body.config.model_dump(),
        'progress': {
            'phase': 'queued', 'message': '任务已排队，等待本地护栏工作台启动。',
            'completed': 0, 'total': 0, 'percent': 0,
            'indeterminate': True, 'updatedAt': now(),
        },
        'settingsSnapshot': {
            # 保存实际采用的固定库参数；这里不包含护栏地址和令牌，只用于前端回显与审计。
            **body.config.model_dump(),
            'baseUrlConfigured': bool(os.getenv('RISK_GUARD_BASE_URL')),
        },
    }
    with lock:
        directory.mkdir(parents=True, exist_ok=True)
        save(directory / 'request.json', body.model_dump(mode='json'))
        save(directory / 'task.json', record)
        guard_cancel_events[directory.name] = threading.Event()
        try:
            future = guard_pool.submit(execute_guard, directory)
            guard_futures[directory.name] = future
            add_done_callback = getattr(future, 'add_done_callback', None)
            if callable(add_done_callback):
                add_done_callback(
                    lambda done, key=directory.name: _guard_future_done(key, done)
                )
        except Exception as exc:
            guard_cancel_events.pop(directory.name, None)
            record.update(
                status='failed', finishedAt=now(),
                error=redact_value(f'无法加入护栏任务队列：{type(exc).__name__}: {exc}'),
            )
            save(directory / 'task.json', record)
            raise HTTPException(503, '本地护栏任务队列不可用，请稍后重试') from exc
    return _with_guard_worker_state(record)


@app.get('/api/agent/guard/tasks', **endpoint_docs('list_guard_tasks'))
def list_guard_tasks():
    with lock:
        records = [_guard_state(p.parent) for p in _task_paths('guard')]
        records = [_with_guard_worker_state(record) for record in records]
    return sorted(records, key=lambda item: item.get('createdAt', ''), reverse=True)


@app.get('/api/agent/guard/tasks/{task_id}', **endpoint_docs('get_guard_task'))
def get_guard_task(task_id: str):
    directory = guard_folder(task_id)
    with lock:
        record = _guard_state(directory)
    from ..records import unified
    if unified.enabled():
        record['resultSource'] = 'mysql'
        # Polling progress must never reread multi-megabyte evidence files.
        with lock:
            return _with_guard_worker_state(record)
    report = _guard_report(directory)
    result = _read_json(directory / 'result.json', {})
    record['summary'] = record.get('summary') or result.get('summary') or report.get('summary', {})
    record['results'] = result.get('results') or report.get('results', [])
    record['findingReport'] = result.get('finding_report')
    record['artifacts'] = _guard_artifacts(directory)
    with lock:
        return _with_guard_worker_state(record)


@app.get('/api/agent/guard/tasks/{task_id}/artifact', **endpoint_docs('guard_artifact'))
def guard_artifact(task_id: str, name: str):
    directory = guard_folder(task_id)
    _guard_state(directory)
    if artifacts.enabled():
        if name not in artifacts.listing(directory):
            raise HTTPException(404, '护栏报告不存在')
        content = artifacts.get(directory, name)
        if content is None or len(content.encode('utf-8')) > 20_000_000:
            raise HTTPException(413, '护栏报告超过预览限制')
        return {'name': name, 'content': redact_value(content)}
    path = (directory / name).resolve()
    if (not path.is_relative_to(directory) or path.name in {'task.json', 'request.json'}
            or path.suffix not in {'.json', '.md'} or not path.is_file()):
        raise HTTPException(404, '护栏报告不存在')
    if path.stat().st_size > 20_000_000:
        raise HTTPException(413, '报告超过在线预览限制，请在本机结果目录查看')
    return {'name': name, 'content': redact_value(path.read_text(encoding='utf-8'))}


@app.post('/api/agent/guard/tasks/{task_id}/stop', **endpoint_docs('stop_guard_task'))
def stop_guard_task(task_id: str):
    """停止排队中的护栏任务；正在请求中的单次网络调用会自然结束。"""
    directory = guard_folder(task_id)
    with lock:
        record = _guard_state(directory)
        if record.get('status') not in {'queued', 'running'}:
            return record
        future = guard_futures.get(directory.name)
        cancel_event = guard_cancel_events.get(directory.name)
        if cancel_event is not None:
            cancel_event.set()
        if future is not None:
            future.cancel()
        record.update(
            status='stopped',
            finishedAt=now(),
            progress={
                **(record.get('progress') or {}),
                'phase': 'stopped',
                'message': '已请求停止；正在处理的护栏请求结束后会释放执行槽。',
                'indeterminate': False,
                'updatedAt': now(),
            },
        )
        save(directory / 'task.json', record)
        return _with_guard_worker_state(record)


@app.delete('/api/agent/guard/tasks/{task_id}', **endpoint_docs('delete_guard_task'))
def delete_guard_task(task_id: str):
    """删除已结束的护栏任务；排队或运行中的任务必须先停止。"""
    directory = guard_folder(task_id)
    with lock:
        record = _guard_state(directory)
        if record.get('status') in {'queued', 'running'}:
            raise HTTPException(409, '任务正在运行，请先停止任务后再删除')
        future = guard_futures.get(directory.name)
        if future is not None and not future.done():
            raise HTTPException(409, '任务正在停止，请稍后再删除')
        result = _delete_task_directory(
            directory,
            root=GUARD_ROOT,
            missing_message='护栏任务不存在',
            task_id=task_id,
        )
        guard_futures.pop(directory.name, None)
        guard_cancel_events.pop(directory.name, None)
        return result


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # FastAPI 默认校验错误包含原始 input；配置表单的 API Key 不得被回显。
    if request.url.path == '/api/agent/settings/models':
        return JSONResponse(status_code=422, content={'detail': '模型配置格式不正确，请检查地址、名称和绑定；密钥不会回显'})
    return await request_validation_exception_handler(request, exc)


@app.get('/api/agent/reviews', tags=['人工复核'], summary='列出 Agent 待复核用例', description='仅提取已结束 Agent 报告中 outcome=REVIEW 的用例，按具体结果去重。')
def review_list():
    return reviews.list_reviews(ROOT)


@app.get('/api/agent/reviews/{review_id}', tags=['人工复核'], summary='查看用例对话与原报告')
def review_detail(review_id: str, include_report: bool = True):
    try:
        return reviews.detail(ROOT, review_id, include_report=include_report)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None


@app.post('/api/agent/reviews/{review_id}/decision', tags=['人工复核'], summary='保存人工结论并按选择加入回归库')
def review_decision(review_id: str, body: reviews.Decision):
    try:
        from ..records.report_store import evidence
        return evidence(reviews.decide(ROOT, review_id, body))
    except (ValueError, OSError) as exc:
        raise HTTPException(422, redact_value(str(exc))) from None


@app.post('/api/agent/reviews/{review_id}/sync', tags=['人工复核'], summary='同步或重试同步人工复核到 MySQL', description='不重新登记回归库，不调用模型；未启用数据库或同步失败时保留本地复核结果。')
def review_sync(review_id: str):
    try:
        return reviews.sync_database(review_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@app.get('/api/agent/settings/agents', tags=['Agent 接入配置'], summary='读取共享 Agent 目录', description='所有连接当前工作台的浏览器读取同一目录；不包含认证密钥。')
def get_agent_directory():
    return agent_config.read_directory()


@app.put('/api/agent/settings/agents', tags=['Agent 接入配置'], summary='保存共享 Agent 目录', description='提交完整目录与 revision。版本冲突返回 409；保存后用于后续选择，不修改已有任务快照。')
def put_agent_directory(body: agent_config.AgentDirectory):
    try:
        from . import asset_sync
        previous = {a['id']: a for a in agent_config.read_directory()['agents']}
        result = agent_config.save_directory(body)
        for agent in result['agents']:
            old = previous.get(agent['id'])
            if agent['adapter'] == 'ai-web' and (old is None or asset_sync.fingerprint(old) != asset_sync.fingerprint(agent)):
                try:
                    asset_sync.start(agent['id'])
                except ValueError:
                    # 目录已保存；同步失败由状态接口展示，不能伪报保存失败。
                    asset_sync.write(agent['id'], {'status': 'failed', 'stage': 'pending',
                        'fingerprint': asset_sync.fingerprint(agent), 'updatedAt': asset_sync.now(),
                        'message': '请将护栏标识设为与内部 appId 一致，再同步资产'})
        return result
    except model_config.RevisionConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@app.get('/api/agent/settings/agent-assets', tags=['Agent 接入配置'], summary='查看共享 Agent 的资产同步进度')
def get_agent_asset_status():
    from . import asset_sync
    return {a['id']: asset_sync.status(a) for a in agent_config.read_directory()['agents'] if a['adapter'] == 'ai-web'}


@app.post('/api/agent/settings/agent-assets/{agent_id}/sync', tags=['Agent 接入配置'], summary='下载资产并同步内部 Agent 护栏策略', status_code=202)
def sync_agent_assets(agent_id: str):
    from . import asset_sync
    try:
        return asset_sync.start(agent_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@app.get('/api/agent/settings/models', **endpoint_docs('get_model_config'))
def get_model_config():
    return model_config.read_config()


@app.put('/api/agent/settings/models', **endpoint_docs('put_model_config'))
def put_model_config(body: model_config.ModelConfig):
    try:
        return model_config.save_config(body)
    except model_config.RevisionConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@app.get('/api/agent/health', **endpoint_docs('health'))
def health():
    from ..clients.model import load_model_settings
    models = {}
    for role in ('attack', 'judge', 'finding'):
        try:
            models[role] = load_model_settings(role=role).safe_dict()
        except Exception as exc:
            models[role] = {'error': redact_value(str(exc))}
    environment_models = dict(models)
    configured = model_config.read_config()
    profiles = {p['id']: p for p in configured['profiles']}
    for role in ('generic', 'attack', 'judge', 'finding'):
        selected = configured['bindings'].get(role) or configured['commonModel']
        if selected:
            profile = profiles[selected]
            models[role] = {'provider': 'openai-compatible', 'model': profile['model'],
                            'source': f"workbench-config:{configured['revision']}:{selected}",
                            'api_key_present': profile['keyConfigured']}
    from ..business.scenario_cards import SCENARIO_CARDS, MAIN_SCENE_CANDIDATES
    from ..tactics import load_tactic_catalog
    tactic_catalog = load_tactic_catalog()
    from ..business.strategies import CONVERSATION_STRATEGIES, EXPRESSION_STYLES
    return {'status': 'ok', 'environmentModels': environment_models, 'models': models, 'execution': '本地脚本', 'sharedHistory': True,
            'conversationOptions': [],
            'expressionOptions': [{'id': t['id'], 'name': t['name'], 'description': t['instruction']} for t in EXPRESSION_STYLES.values()],
            'attackTactics': [{'id': t['tactic_id'], 'name': t['name_cn'], 'description': t['guidance']} for t in tactic_catalog['tactics']],
            'attackScenes': [scene for scene in scenario_catalog() if scene.get('supported', True)],
            'positiveScenes':[{'id':s['id'],'name':s['name'],
                               'description':('主线场景 · ' if s['id'] in MAIN_SCENE_CANDIDATES else '补充场景 · ')+s['objective']} for s in SCENARIO_CARDS.values()]}


@app.get('/api/agent/libraries/{kind}', **endpoint_docs('library'))
def library(kind: str):
    try:
        from .libraries import catalog
        return catalog(kind)
    except ImportError:
        raise HTTPException(503, '用例库执行模块加载失败。若刚更新了后端代码，请重启 8092 工作台服务后刷新用例库。') from None
    except (ValueError, OSError) as exc:
        raise HTTPException(422, str(exc))


def execute(directory: Path):
    key = directory.name
    with lock:
        record = state(directory)
        if closing.is_set() or record['status'] != 'queued':
            return
        marker = secrets.token_hex(16)
        record.update(status='running', startedAt=now(), workerMarker=marker)
        record.pop('workerIdentity', None)
        save(directory / 'task.json', record)
        # 日志文件创建也属于启动阶段；权限或磁盘错误不能把任务
        # 永久留在 running，同时还要让串行队列继续向后执行。
        log = None
        process = None
        startup_stage = '创建执行日志'
        try:
            if artifacts.enabled():
                artifacts.restore_inputs(directory)
                log = None
            else:
                log = (directory / 'output.log').open('wb')
            startup_stage = '读取本次模型配置'
            worker_env = {**os.environ, **model_config.task_environment(key), 'PYTHONIOENCODING': 'utf-8'}
            startup_stage = '启动 Python 执行进程'
            process = subprocess.Popen([
                sys.executable, '-u', '-m', 'auto_test.workbench.worker',
                str(directory), marker, str(os.getpid()),
            ],
                cwd=REPOSITORY_ROOT, stdout=subprocess.PIPE if artifacts.enabled() else log,
                stderr=subprocess.STDOUT,
                env=worker_env,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                start_new_session=os.name != 'nt')
            processes[key] = process
            startup_stage = '保存执行进程状态'
            # PID 与 marker 一起写入磁盘，8092 异常退出后下一次启动才有
            # 机会识别并清理这个任务自己的遗留 worker。
            record['workerPid'] = process.pid
            identity = _process_identity(process.pid)
            if identity:
                record['workerIdentity'] = identity
            save(directory / 'task.json', record)
        except Exception as exc:
            detail = redact_value(f'启动失败（{startup_stage}）：{type(exc).__name__}: {exc}')
            if process is not None:
                _terminate_process_tree(process)
            if log is not None:
                log.write((detail + '\n').encode('utf-8'))
                log.close()
            processes.pop(key, None)
            record.update(status='failed', finishedAt=now(), error=detail)
            record.pop('workerPid', None)
            record.pop('workerMarker', None)
            record.pop('workerIdentity', None)
            save(directory / 'task.json', record)
            return
    try:
        log_errors = []
        reader = None
        if artifacts.enabled():
            def collect():
                offset = artifacts.log_status(directory)["size"]
                try:
                    import codecs
                    decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
                    while True:
                        raw = process.stdout.readline(65536)
                        if not raw:
                            tail = decoder.decode(b'', final=True)
                            if tail:
                                artifacts.append_log(directory, offset, redact_value(tail).encode())
                            break
                        text = decoder.decode(raw)
                        if text:
                            offset = artifacts.append_log(directory, offset, str(redact_value(text)).encode('utf-8'))
                except Exception as exc:
                    log_errors.append(type(exc).__name__)
                    _terminate_process_tree(process)
                finally:
                    process.stdout.close()
            reader = threading.Thread(target=collect, name='task-database-log', daemon=True)
            reader.start()
        code = _wait_for_agent_process(directory, process)
        if reader is not None:
            reader.join(timeout=30)
            if reader.is_alive() or log_errors:
                code = code or 1
        with lock:
            record = state(directory)
            if record['status'] not in {'stopped', 'interrupted'}:
                if log_errors or (reader is not None and reader.is_alive()):
                    record['error'] = '执行日志未完整写入数据库；任务已停止，请检查数据库后处理。'
                record.update(status='completed' if code == 0 else 'failed', exitCode=code, finishedAt=now())
            record.pop('workerPid', None)
            record.pop('workerMarker', None)
            record.pop('workerIdentity', None)
            save(directory / 'task.json', record)
    finally:
        if log is not None:
            log.close()
        with lock:
            processes.pop(key, None)
            agent_futures.pop(key, None)
        stored = persist_reports(directory)
        if stored and stored.get('status') == 'synced':
            artifacts.cleanup(directory)


@app.post('/api/agent/tasks/{task_id}/report-sync', tags=['数据库报告'])
def retry_report_sync(task_id: str):
    directory = folder(task_id)
    record = state(directory)
    if record.get('status') in {'running', 'queued'} or task_id in processes:
        raise HTTPException(409, '任务执行中，请结束后重试入库')
    return persist_reports(directory)


@app.post('/api/agent/tasks', status_code=201, **endpoint_docs('create'))
def create(body: Submission):
    if closing.is_set():
        raise HTTPException(503, '任务服务正在关闭，请稍后重试')
    directory = folder(str(body.id))
    with lock:
        if _read_json(directory / 'task.json', None) is not None:
            previous = _read_json(directory / 'request.json', {})
            if previous != body.model_dump(mode='json'):
                raise HTTPException(409, '相同任务 ID 已提交不同配置，请新建任务')
            return state(directory)
    # 提交前验证全部 CLI 参数，避免创建一个明知无法运行的任务。
    scene_names = []
    if body.config.kind == 'attack' and not body.config.library:
        try:
            enabled_scenes = {scene['id']: scene['name'] for scene in scenario_catalog()}
        except Exception:
            raise HTTPException(503, '场景数据库暂不可用') from None
        if set(body.config.scenes) - enabled_scenes.keys():
            raise HTTPException(422, '场景已停用或不存在，请刷新场景目录')
        scene_names = [enabled_scenes[scene] for scene in body.config.scenes]
    elif body.config.kind == 'positive' and body.config.source == 'generate':
        from ..business.scenario_cards import SCENARIO_CARDS
        scene_names = ['内部业务请求' if scene == 'internal_workflow' else SCENARIO_CARDS[scene]['name']
                       for scene in body.config.scenes]
    from ..cli.main import _parse_args
    try:
        for argv in commands(body, directory):
            _parse_args(argv)
        from .libraries import selected_payload
        snapshot = selected_payload(body.config) if body.config.library else None
    except (SystemExit, ValueError):
        raise HTTPException(422, '用例库已变化、选项无效或用例已停用，请刷新列表重新选择')
    with lock:
        if _read_json(directory / 'task.json', None) is not None:
            previous = _read_json(directory / 'request.json', {})
            if previous != body.model_dump(mode='json'):
                raise HTTPException(409, '相同任务 ID 已提交不同配置，请新建任务')
            return state(directory)
        directory.mkdir(parents=True, exist_ok=True)
        save(directory / 'request.json', body.model_dump(mode='json'))
        if snapshot is not None:
            save(directory / 'library.json', snapshot)
        record = {'id': str(body.id), **resolve_task_name(body.config.kind, body.id, body.name,
                  source=body.config.source, scene_names=scene_names), 'createdAt': now(), 'status': 'queued',
                  'config': body.config.model_dump(), 'agent': body.agent.model_dump(),
                  'settingsSnapshot': {'agent': body.agent.model_dump(), 'models': health()['models'],
                                       'commands': commands(body, directory)}}
        frozen_models = model_config.freeze_task(directory.name)
        if frozen_models:
            record['settingsSnapshot']['modelConfig'] = frozen_models
            record['settingsSnapshot']['models'] = frozen_models['roles']
        save(directory / 'task.json', record)
        try:
            _submit_agent(directory)
        except Exception as exc:
            raise HTTPException(503, f'本地任务队列不可用，请稍后重试：{type(exc).__name__}') from exc
        return record


@app.get('/api/agent/tasks', **endpoint_docs('list_tasks'))
def list_tasks():
    with lock:
        records = []
        for task_file in _task_paths('agent'):
            record = _read_json(task_file, None)
            if not isinstance(record, dict) or not record.get('id') or not record.get('createdAt'):
                continue
            # Skill 定时任务也使用通用任务目录以便查看报告，但不能混进
            # Agent 测试侧栏，否则会被误当成 attack/positive 任务渲染。
            if record.get('kind') == 'skill':
                continue
            records.append(_with_agent_progress(task_file.parent, record))
    return sorted(records, key=lambda t: t['createdAt'], reverse=True)


@app.get('/api/agent/tasks/{task_id}', **endpoint_docs('get_task'))
def get_task(task_id: str):
    directory = folder(task_id)
    with lock:
        record = state(directory)
    record = _with_agent_progress(directory, record)
    if artifacts.enabled():
        record['logs'] = artifacts.read_log(directory, maximum=100000)['text']
        record['artifacts'] = artifacts.listing(directory)
        return record
    log_path = directory / 'output.log'
    if log_path.exists():
        with log_path.open('rb') as handle:
            handle.seek(max(0, log_path.stat().st_size - 100_000))
            record['logs'] = redact_value(handle.read().decode('utf-8', errors='replace'))
    # 只暴露该任务的报告，不允许浏览器自由读取本机路径。
    record['artifacts'] = [p.relative_to(directory).as_posix() for p in directory.rglob('*')
        if p.is_file() and p.suffix in {'.json', '.md'} and p.name not in {'task.json', 'request.json', 'library.json', 'judge-policy.json'}]
    return record


@app.get('/api/agent/tasks/{task_id}/artifact', **endpoint_docs('artifact'))
def artifact(task_id: str, name: str):
    directory = folder(task_id)
    state(directory)
    if name == 'task-summary.md':
        from .task_summary import task_summary
        record = state(directory)
        return {'name': name, 'content': task_summary(directory, positive=(record.get('config') or {}).get('kind') == 'positive')}
    if artifacts.enabled():
        if name not in artifacts.listing(directory) or Path(name).suffix not in {'.json', '.md'}:
            raise HTTPException(404, '报告不存在')
        content = artifacts.get(directory, name)
        if content is None:
            raise HTTPException(404, '报告不存在')
        if len(content.encode('utf-8')) > 20_000_000:
            raise HTTPException(413, '报告超过在线预览限制')
        return {'name': name, 'content': redact_value(content)}
    path = (directory / name).resolve()
    if not path.is_relative_to(directory) or path.name in {'task.json', 'request.json', 'library.json', 'judge-policy.json'} or path.suffix not in {'.json', '.md'} or not path.is_file():
        raise HTTPException(404, '报告不存在')
    if path.stat().st_size > 20_000_000:
        raise HTTPException(413, '报告超过在线预览限制，请在本机结果目录查看')
    content = path.read_text(encoding='utf-8')
    if path.suffix == '.md':
        from ..report_digest import concise_report
        companion = path.with_suffix('.json').resolve()
        if companion.is_relative_to(directory) and companion.is_file() and companion.stat().st_size <= 20_000_000:
            try:
                data = json.loads(companion.read_text(encoding='utf-8'))
                if isinstance(data, dict):
                    content = concise_report(data, content)
            except (ValueError, OSError):
                pass  # Legacy Markdown remains readable when its JSON is unavailable.
    return {'name': name, 'content': content if path.name in {'reasoning-findings.json', 'reasoning-findings.md'} else redact_value(content)}


@app.post('/api/agent/tasks/{task_id}/stop', **endpoint_docs('stop'))
def stop(task_id: str):
    directory = folder(task_id)
    with lock:
        record = state(directory)
        process = processes.get(directory.name)
        if record['status'] not in {'queued', 'running'}:
            return record
        if record['status'] == 'queued' and process is None:
            future = agent_futures.get(directory.name)
            cancel = getattr(future, 'cancel', None)
            if callable(cancel) and cancel():
                agent_futures.pop(directory.name, None)
        elif process and process.poll() is None:
            if not _terminate_process_tree(process):
                raise HTTPException(500, '停止子进程失败，请重试')
        elif process is None and record.get('workerPid'):
            if not _terminate_persisted_worker(record, directory):
                raise HTTPException(500, '无法确认或停止任务子进程，请重启工作台后重试')
        record.update(status='stopped', finishedAt=now())
        record.pop('workerPid', None)
        record.pop('workerMarker', None)
        record.pop('workerIdentity', None)
        save(directory / 'task.json', record)
        return record


@app.delete('/api/agent/tasks/{task_id}', **endpoint_docs('delete_task'))
def delete_task(task_id: str):
    """删除已结束的 Agent 任务；排队或运行中的任务必须先停止。"""
    directory = folder(task_id)
    with lock:
        record = state(directory)
        if record.get('status') in {'queued', 'running'}:
            raise HTTPException(409, '任务正在运行，请先停止任务后再删除')
        process = processes.get(directory.name)
        if process is not None and process.poll() is None:
            raise HTTPException(409, '任务正在停止，请稍后再删除')
        result = _delete_task_directory(
            directory,
            root=ROOT,
            missing_message='任务不存在',
            task_id=task_id,
        )
        processes.pop(directory.name, None)
        return result
