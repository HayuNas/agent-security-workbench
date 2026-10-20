"""工作台定时任务的持久化与调度。

定时任务是“测试任务配置 + 执行周期”的保存记录。调度器运行在 8092
进程内，不依赖浏览器页面；真正的 Agent/护栏执行仍交给工作台已有的
队列。这里不保存认证令牌，也不接受命令或本地文件路径。
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import UUID, uuid4
from . import task_store


TERMINAL_STATUSES = {"completed", "failed", "stopped", "interrupted", "skipped"}
# retry/retrying 表示执行器仍在处理当前任务，不能让下一周期重复提交。
ACTIVE_STATUSES = {"queued", "running", "retry", "retrying", "waiting_retry"}
MAX_RUN_HISTORY = 100


class ScheduleValidationError(ValueError):
    """页面传入的定时任务配置不符合工作台契约。"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_time(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ScheduleValidationError(f"{field} 不能为空")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScheduleValidationError(f"{field} 不是有效的 ISO 时间") from exc
    if parsed.tzinfo is None:
        # 页面通常传带时区的时间；没有时区时按本机服务的 UTC 约定解释，
        # 防止服务器换时区后同一个任务发生漂移。
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _positive_int(value: Any, *, field: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise ScheduleValidationError(f"{field} 必须是正整数")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ScheduleValidationError(f"{field} 必须是正整数") from exc
    if number < 1 or number > maximum:
        raise ScheduleValidationError(f"{field} 须为 1～{maximum}")
    return number


def _module(value: Any) -> str:
    name = str(value or "").strip().lower().replace("-", "_")
    aliases = {
        "agent": "agent",
        "agent_test": "agent",
        "attack": "agent",
        "positive": "agent",
        "guard": "guard",
        "guardrail": "guard",
        "guard_test": "guard",
        "guard_dataset": "guard",
        "skill": "skill",
        "skill_scan": "skill",
        "skill_url": "skill",
        "scan": "skill",
    }
    if name not in aliases:
        raise ScheduleValidationError("module 只支持 agent、guard 或 skill")
    return aliases[name]


def _nested_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """兼容页面把任务配置包在 task/submission 中的写法。"""
    nested = payload.get("submission") or payload.get("task")
    if isinstance(nested, Mapping):
        merged = dict(payload)
        for key in ("module", "kind", "type", "agent", "config"):
            if key not in merged and key in nested:
                merged[key] = nested[key]
        return merged
    return dict(payload)


def _interval_seconds(payload: Mapping[str, Any]) -> int:
    """读取几种直观的周期写法，并统一保存为秒。"""
    if payload.get("intervalSeconds") is not None or payload.get("interval_seconds") is not None:
        return _positive_int(
            payload.get("intervalSeconds", payload.get("interval_seconds")),
            field="intervalSeconds",
            maximum=366 * 24 * 60 * 60,
        )
    repeat = payload.get("repeatEvery", payload.get("repeat_every"))
    if isinstance(repeat, Mapping):
        value = _positive_int(repeat.get("value"), field="repeatEvery.value", maximum=366 * 24 * 60)
        unit = str(repeat.get("unit") or "minutes").lower()
    elif repeat is not None:
        value = _positive_int(repeat, field="repeatEvery", maximum=366 * 24 * 60)
        unit = str(payload.get("repeatUnit", payload.get("repeat_unit", "minutes"))).lower()
    else:
        for key, unit_name in (
            ("intervalMinutes", "minutes"),
            ("intervalHours", "hours"),
            ("intervalDays", "days"),
        ):
            if payload.get(key) is not None:
                value = _positive_int(payload[key], field=key, maximum=366 * 24 * 60)
                unit = unit_name
                break
        else:
            # 没填写周期时默认每小时执行一次，便于首页快速创建任务。
            return 3600
    multipliers = {
        "second": 1,
        "seconds": 1,
        "秒": 1,
        "minute": 60,
        "minutes": 60,
        "分钟": 60,
        "hour": 3600,
        "hours": 3600,
        "小时": 3600,
        "day": 86400,
        "days": 86400,
        "天": 86400,
    }
    if unit not in multipliers:
        raise ScheduleValidationError("repeatUnit 只支持 seconds、minutes、hours 或 days")
    seconds = value * multipliers[unit]
    if seconds > 366 * 24 * 60 * 60:
        raise ScheduleValidationError("重复周期不能超过 366 天")
    return seconds


def _skill_config(config: Mapping[str, Any]) -> dict[str, Any]:
    source = str(config.get("source") or "url").lower()
    if source != "url":
        raise ScheduleValidationError("Skill 定时任务当前只支持 URL；ZIP 请先在页面手动扫描")
    url = str(config.get("url") or "").strip()
    from urllib.parse import urlsplit

    # 与真正的 Skill 下载器共用同一套 URL 边界，避免任务能保存但到期后
    # 才因为端口、片段或控制字符失败。这里只校验语法，下载时仍由公司
    # 扫描服务再次校验公网地址、重定向和 ZIP 内容。
    try:
        from risk_guard.skill_download import DownloadFailure, validate_url

        validate_url(url)
    except (DownloadFailure, ValueError, UnicodeError) as exc:
        raise ScheduleValidationError(
            "Skill URL 必须是不带认证信息或片段的 HTTPS ZIP 地址（端口 443）"
        ) from exc
    if len(url) > 8192:
        raise ScheduleValidationError("Skill URL 最多 8192 个字符")
    prompt = str(config.get("prompt") or "")
    if len(prompt) > 8000:
        raise ScheduleValidationError("Skill 提示词最多 8000 个字符")
    mode = str(config.get("mode") or "single")
    report = str(config.get("report") or "full")
    language = str(config.get("language") or "zh")
    if mode not in {"single", "full"}:
        raise ScheduleValidationError("Skill 扫描模式只支持 single 或 full")
    if report not in {"full", "compact"}:
        raise ScheduleValidationError("Skill 报告模式只支持 full 或 compact")
    if language not in {"zh", "en"}:
        raise ScheduleValidationError("Skill 报告语言只支持 zh 或 en")
    return {
        "source": "url", "url": url, "prompt": prompt,
        "mode": mode, "report": report, "language": language,
    }


class ScheduleService:
    """独立的定时任务服务，便于 API 与单元测试共用。"""

    def __init__(
        self,
        root_provider: Callable[[], Path],
        lock: threading.RLock,
        *,
        submit_run: Callable[[dict[str, Any]], Mapping[str, Any]],
        task_status: Callable[[str, str], str | None],
        interval: float = 0.5,
    ) -> None:
        self._root_provider = root_provider
        self._lock = lock
        self._submit_run = submit_run
        self._task_status = task_status
        self._interval = max(0.1, float(interval))
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def root(self) -> Path:
        return self._root_provider().resolve() / "schedules"

    def _path(self, schedule_id: str) -> Path:
        try:
            canonical = str(UUID(str(schedule_id)))
        except (ValueError, AttributeError):
            raise ScheduleValidationError("定时任务 ID 无效")
        root = self.root.resolve()
        path = (root / f"{canonical}.json").resolve()
        if not path.is_relative_to(root):
            raise ScheduleValidationError("定时任务路径无效")
        return path

    @staticmethod
    def _read(path: Path) -> dict[str, Any] | None:
        if task_store.enabled():
            return task_store.read_schedule(path.stem)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _save(path: Path, value: Mapping[str, Any]) -> None:
        if task_store.enabled():
            task_store.write_schedule(value)
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(path)

    @staticmethod
    def _trim_runs(record: dict[str, Any]) -> None:
        runs = record.get("runs")
        if isinstance(runs, list) and len(runs) > MAX_RUN_HISTORY:
            pending = [run for run in runs[:-MAX_RUN_HISTORY] if run.get("status") in ACTIVE_STATUSES]
            record["runs"] = pending + runs[-MAX_RUN_HISTORY:]

    def _record(self, payload: Mapping[str, Any], *, existing: Mapping[str, Any] | None = None) -> dict[str, Any]:
        payload = _nested_payload(payload)
        old = dict(existing or {})
        module_value = payload.get("module") or payload.get("kind") or payload.get("type")
        if not module_value and old.get("module"):
            module_value = old["module"]
        module = _module(module_value)
        name = str(payload.get("name") or old.get("name") or "").strip()
        if not name or len(name) > 100:
            raise ScheduleValidationError("定时任务名称须为 1～100 个字符")
        config_raw = payload.get("config")
        if config_raw is None:
            config_raw = old.get("config") or {}
        if not isinstance(config_raw, Mapping):
            raise ScheduleValidationError("config 必须是对象")
        agent_raw = payload.get("agent")
        if agent_raw is None:
            agent_raw = old.get("agent") or {}
        if not isinstance(agent_raw, Mapping):
            raise ScheduleValidationError("agent 必须是对象")

        if module == "agent":
            # 用现有 Submission 契约校验 Agent 测试；每次触发时再换新的任务 ID。
            from .contracts import Agent, Config, Submission
            from pydantic import ValidationError

            # 首页表单为了易读使用 testKind/scene/tactic 单值字段；这里
            # 转成现有 CLI 契约的 kind/scenes/tactics 数组后再校验。
            agent_config = dict(config_raw)
            if "testKind" in agent_config and "kind" not in agent_config:
                agent_config["kind"] = agent_config["testKind"]
            if "scene" in agent_config and "scenes" not in agent_config:
                agent_config["scenes"] = [agent_config["scene"]]
            if "tactic" in agent_config and "tactics" not in agent_config:
                agent_config["tactics"] = [agent_config["tactic"]]
            for alias in ("testKind", "scene", "tactic"):
                agent_config.pop(alias, None)
            try:
                config = Config.model_validate(agent_config)
                clean_agent_raw = dict(agent_raw)
                # 首页选择器已经把 Agent 编码在 target 中时，不要求用户再
                # 重复填写 adapter/appId；仍支持显式 agent 覆盖。
                if not clean_agent_raw:
                    target = str(agent_config.get("target") or "")
                    if target.startswith("ai-web:"):
                        clean_agent_raw = {
                            "adapter": "ai-web", "agentId": target.split(":", 1)[1],
                        }
                    elif target == "ky-app:sales-agent":
                        clean_agent_raw = {"adapter": "ky-app", "agentId": "sales-agent"}
                agent = Agent.model_validate(clean_agent_raw)
                Submission(id=uuid4(), name=name, config=config, agent=agent)
            except ValidationError as exc:
                raise ScheduleValidationError(f"Agent 测试配置无效：{exc.errors()[0].get('msg', '请检查配置')}") from exc
            clean_config = config.model_dump(mode="json")
            clean_agent = agent.model_dump(mode="json")
            kind = config.kind
        elif module == "guard":
            from .guard_api import GuardTaskConfig, GuardTaskSubmission
            from pydantic import ValidationError

            aliases = {
                "guardDataset": "dataset", "guardMode": "guardMode", "guardDirection": "direction",
                "guardWorkers": "workers", "guardOutputMode": "outputMode",
                "guardStreamChunkSize": "streamChunkSize", "guardStreamWindowSize": "streamWindowSize",
                "guardLimit": "limit", "guardPositiveLimit": "positiveLimit",
            }
            canonical_config = dict(config_raw)
            for source, target in aliases.items():
                # guardMode 本身就是后端的 canonical 字段；页面也可能
                # 直接提交这个名字，不能复制后又把它 pop 掉。
                if source == target:
                    continue
                if source in canonical_config and target not in canonical_config:
                    canonical_config[target] = canonical_config[source]
                # GuardTaskConfig 使用后端字段名，别把页面展示用的别名
                # 留给 extra=forbid 的 Pydantic 模型。
                canonical_config.pop(source, None)
            if not str(canonical_config.get("agentId") or "").strip():
                # 首页留空表示沿用固定库默认 Agent。
                canonical_config.pop("agentId", None)
            try:
                guard_config = GuardTaskConfig.model_validate(canonical_config)
                GuardTaskSubmission(id=uuid4(), name=name, config=guard_config)
            except ValidationError as exc:
                raise ScheduleValidationError(f"护栏测试配置无效：{exc.errors()[0].get('msg', '请检查配置')}") from exc
            clean_config = guard_config.model_dump(mode="json")
            clean_agent = {}
            kind = "guard"
        else:
            clean_config = _skill_config(config_raw)
            clean_agent = {}
            kind = "skill"

        start_value = payload.get("startAt", payload.get("start_at"))
        if start_value is None:
            start_value = old.get("startAt")
        start = _parse_time(start_value, field="startAt") if start_value is not None else _now()
        interval = _interval_seconds(payload if any(
            key in payload for key in (
                "intervalSeconds", "interval_seconds", "repeatEvery", "repeat_every",
                "intervalMinutes", "intervalHours", "intervalDays",
            )
        ) else old)
        enabled_value = payload.get("enabled", old.get("enabled", True))
        if not isinstance(enabled_value, bool):
            raise ScheduleValidationError("enabled 必须是布尔值")
        max_runs = payload.get("maxRuns", payload.get("max_runs", old.get("maxRuns")))
        if max_runs is not None:
            max_runs = _positive_int(max_runs, field="maxRuns", maximum=100000)
        schedule_id = str(payload.get("id") or old.get("id") or uuid4())
        try:
            schedule_id = str(UUID(schedule_id))
        except ValueError as exc:
            raise ScheduleValidationError("定时任务 ID 必须是 UUID") from exc
        created = old.get("createdAt") or _iso(_now())
        next_raw = payload.get("nextRunAt", payload.get("next_run_at", old.get("nextRunAt")))
        if next_raw is None:
            next_run = _iso(start)
        else:
            try:
                next_run = _iso(_parse_time(next_raw, field="nextRunAt"))
            except ScheduleValidationError:
                raise ScheduleValidationError("nextRunAt 不是有效的 ISO 时间")
        result = {
            "id": schedule_id,
            "name": name,
            "module": module,
            "kind": kind,
            "enabled": enabled_value,
            "createdAt": created,
            "updatedAt": _iso(_now()),
            "startAt": _iso(start),
            "nextRunAt": next_run,
            "intervalSeconds": interval,
            "repeatEvery": {"value": interval, "unit": "seconds"},
            "maxRuns": max_runs,
            "agent": clean_agent,
            "config": clean_config,
            "runs": list(old.get("runs") or []),
            "lastRun": old.get("lastRun"),
        }
        self._sync_summary(result)
        return result

    def create(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            record = self._record(payload)
            path = self._path(record["id"])
            if self._read(path) is not None:
                raise ScheduleValidationError("相同定时任务 ID 已存在，请新建任务")
            self._save(path, record)
            self._wake.set()
            return record

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            root = self.root
            if not task_store.enabled() and not root.exists():
                return []
            records = []
            for path in task_store.schedule_paths(root) if task_store.enabled() else root.glob("*.json"):
                item = self._read(path)
                if not item:
                    continue
                if self._refresh(item):
                    self._save(path, item)
                records.append(item)
            return sorted(records, key=lambda item: str(item.get("createdAt") or ""), reverse=True)

    def get(self, schedule_id: str) -> dict[str, Any]:
        with self._lock:
            record = self._read(self._path(schedule_id))
            if record is None:
                raise KeyError(schedule_id)
            if self._refresh(record):
                self._save(self._path(schedule_id), record)
            return record

    def update(self, schedule_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            path = self._path(schedule_id)
            old = self._read(path)
            if old is None:
                raise KeyError(schedule_id)
            merged = dict(old)
            start_changed = "startAt" in payload or "start_at" in payload
            interval_changed = any(
                key in payload
                for key in (
                    "intervalSeconds", "interval_seconds", "repeatEvery", "repeat_every",
                    "intervalMinutes", "intervalHours", "intervalDays",
                )
            )
            if interval_changed:
                # 让新的直观周期字段覆盖旧的 canonical intervalSeconds，
                # 而不是被旧值优先解析。
                merged.pop("intervalSeconds", None)
                merged.pop("repeatEvery", None)
            merged.update(dict(payload))
            merged["id"] = old["id"]
            # 修改周期时沿用原来的下一次执行时间；明确修改首次执行时间
            # 时才把 nextRunAt 一起移动，避免普通编辑导致任务提前执行。
            if start_changed:
                merged["nextRunAt"] = payload.get("startAt", payload.get("start_at"))
            else:
                merged["nextRunAt"] = old.get("nextRunAt")
            record = self._record(merged, existing=old)
            # 普通修改保留已有执行历史；如果只修改周期，不重置首次执行时间。
            record["runs"] = list(old.get("runs") or [])
            record["lastRun"] = old.get("lastRun")
            # enabled 是一个明确的人工操作。把原因保存下来，既避免日后
            # 把“手动停用”和调度器因上限自动暂停混为一谈，也能审计某个
            # 周期任务为什么不再提交下一轮。
            if "enabled" in payload:
                if record["enabled"]:
                    record.pop("disabledReason", None)
                else:
                    record["disabledReason"] = "manual"
            elif not record["enabled"] and old.get("disabledReason"):
                record["disabledReason"] = old["disabledReason"]
            self._save(path, record)
            self._wake.set()
            return record

    def delete(self, schedule_id: str) -> dict[str, str]:
        with self._lock:
            path = self._path(schedule_id)
            record = self._read(path)
            if record is None:
                raise KeyError(schedule_id)
            # 删除配置不会自动取消已经提交给执行器的实际测试。运行中直接
            # 删除会让任务继续消耗接口，却失去调度历史，因此保守地拒绝，
            # 等本轮进入终态后再删除。
            refreshed = self._refresh(record)
            if refreshed and self._active_run(record) is not None:
                self._save(path, record)
            if self._active_run(record) is not None:
                raise ScheduleValidationError("定时任务正在运行，不能删除；请等待本轮完成后再删除")
            if task_store.enabled():
                task_store.delete_schedule(path.stem)
            else:
                path.unlink()
            return {"id": str(UUID(schedule_id)), "status": "deleted"}

    def toggle(self, schedule_id: str, enabled: bool | None = None) -> dict[str, Any]:
        record = self.get(schedule_id)
        value = not bool(record.get("enabled")) if enabled is None else enabled
        return self.update(schedule_id, {"enabled": value})

    def _active_run(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        for run in reversed(record.get("runs") or []):
            if isinstance(run, Mapping) and run.get("status") in ACTIVE_STATUSES:
                return dict(run)
        return None

    def _refresh(self, record: dict[str, Any]) -> bool:
        changed = False
        runs = record.get("runs")
        if not isinstance(runs, list):
            return False
        for run in runs:
            if not isinstance(run, dict) or run.get("status") not in ACTIVE_STATUSES:
                continue
            task_id = str(run.get("taskId") or "")
            if not task_id:
                continue
            status = str(
                self._task_status(str(record.get("module") or ""), task_id) or ""
            ).strip().lower()
            if status in ACTIVE_STATUSES:
                # 任务从排队进入实际执行后，同步更新历史状态；此前这里只同步终态，
                # 会让页面长时间显示“排队中”，看起来像队列卡住。
                if run.get("status") != status:
                    run["status"] = status
                    changed = True
                continue
            if status in TERMINAL_STATUSES:
                run["status"] = status
                run["finishedAt"] = run.get("finishedAt") or _iso(_now())
                changed = True
        if changed:
            active = self._active_run(record)
            record["lastRun"] = next((dict(run) for run in reversed(runs) if isinstance(run, dict)), None)
            self._sync_summary(record)
            if active is None:
                record["updatedAt"] = _iso(_now())
        return changed

    def _append_run(self, record: dict[str, Any], run: dict[str, Any]) -> None:
        run.setdefault("scheduleId", record.get("id"))
        runs = record.setdefault("runs", [])
        if not isinstance(runs, list):
            record["runs"] = runs = []
        previous_count = int(record.get("runCount", len(runs)))
        runs.append(run)
        self._trim_runs(record)
        record["lastRun"] = dict(run)
        self._sync_summary(record)
        if task_store.enabled():
            record["runCount"] = previous_count + 1
        record["updatedAt"] = _iso(_now())

    @staticmethod
    def _sync_summary(record: dict[str, Any]) -> None:
        """补充首页列表常用摘要字段，同时保留完整 runs 历史。"""
        runs = record.get("runs") or []
        last = next((item for item in reversed(runs) if isinstance(item, Mapping)), None)
        record["runCount"] = max(int(record.get("runCount", 0)), len(runs)) if task_store.enabled() else len(runs)
        record["lastRunAt"] = (
            (last.get("finishedAt") or last.get("startedAt") or last.get("createdAt"))
            if last else None
        )
        record["lastStatus"] = last.get("status") if last else None
        record["lastError"] = last.get("error") if last else None

    def _trigger_locked(self, record: dict[str, Any], *, scheduled_at: datetime, manual: bool = False) -> dict[str, Any]:
        active = self._active_run(record)
        run = {
            "id": str(uuid4()),
            "scheduledAt": _iso(scheduled_at),
            "createdAt": _iso(_now()),
            "status": "queued",
            "manual": manual,
        }
        if active is not None:
            run.update(status="skipped", finishedAt=_iso(_now()),
                       skipReason="上一轮定时任务仍在运行，本次执行已跳过")
            self._append_run(record, run)
            return run
        self._append_run(record, run)
        path = self._path(record["id"])
        self._save(path, record)
        try:
            result = dict(self._submit_run(record))
            task_id = str(result.get("id") or "")
            if not task_id:
                raise RuntimeError("执行器没有返回任务 ID")
            run["taskId"] = task_id
            # 执行器可能返回大写或带空格的状态，统一后再交给页面和下一轮调度。
            run["status"] = str(result.get("status") or "queued").strip().lower()
            if run["status"] not in ACTIVE_STATUSES | TERMINAL_STATUSES:
                run["status"] = "queued"
            if run["status"] in TERMINAL_STATUSES:
                run["finishedAt"] = run.get("finishedAt") or _iso(_now())
        except Exception as exc:
            run["status"] = "failed"
            detail = getattr(exc, "detail", None) or str(exc)
            run["error"] = f"{type(exc).__name__}: {detail}"
            run["finishedAt"] = _iso(_now())
        record["lastRun"] = dict(run)
        self._sync_summary(record)
        record["updatedAt"] = _iso(_now())
        self._save(path, record)
        return run

    def run_now(self, schedule_id: str) -> dict[str, Any]:
        with self._lock:
            record = self._read(self._path(schedule_id))
            if record is None:
                raise KeyError(schedule_id)
            self._refresh(record)
            run = self._trigger_locked(record, scheduled_at=_now(), manual=True)
            self._save(self._path(schedule_id), record)
            self._wake.set()
            return record

    def tick(self, *, current: datetime | None = None) -> None:
        moment = (current or _now()).astimezone(timezone.utc)
        with self._lock:
            root = self.root
            if not task_store.enabled() and not root.exists():
                return
            paths = task_store.due_schedule_paths(root, _iso(moment)) if task_store.enabled() else root.glob("*.json")
            for path in paths:
                record = self._read(path)
                if not record or not record.get("id"):
                    continue
                changed = self._refresh(record)
                if not record.get("enabled"):
                    if changed:
                        self._save(path, record)
                    continue
                runs = record.get("runs") or []
                if record.get("maxRuns") and int(record.get("runCount", len(runs))) >= int(record["maxRuns"]):
                    record["enabled"] = False
                    record["disabledReason"] = "max_runs"
                    changed = True
                    if changed:
                        self._save(path, record)
                    continue
                try:
                    due = _parse_time(record.get("nextRunAt"), field="nextRunAt") <= moment
                except ScheduleValidationError:
                    record["enabled"] = False
                    record["disabledReason"] = "invalid_next_run"
                    record["error"] = "nextRunAt 无效，已暂停定时任务"
                    self._save(path, record)
                    continue
                if not due:
                    if changed:
                        self._save(path, record)
                    continue
                scheduled_at = _parse_time(record["nextRunAt"], field="nextRunAt")
                interval = int(record.get("intervalSeconds") or 3600)
                # 错过多个周期时只补一次，避免服务重启后瞬间提交大量测试。
                next_run = scheduled_at + timedelta(seconds=interval)
                while next_run <= moment:
                    next_run += timedelta(seconds=interval)
                record["nextRunAt"] = _iso(next_run)
                self._trigger_locked(record, scheduled_at=scheduled_at)
                self._save(path, record)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                # 单个损坏配置不能杀掉定时器；详细错误会写入对应任务记录。
                pass
            self._wake.wait(self._interval)
            self._wake.clear()

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            if not task_store.enabled():
                self.root.mkdir(parents=True, exist_ok=True)
            self._stop.clear()
            self._wake.clear()
            self._thread = threading.Thread(target=self._loop, name="workbench-scheduler", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2)
        self._thread = None


__all__ = ["ScheduleService", "ScheduleValidationError"]
