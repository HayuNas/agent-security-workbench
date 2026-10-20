"""Run a frozen input/output dataset directly against the Risk Guard API."""

from __future__ import annotations

import http.client
import json
import math
import threading
import uuid
from collections import Counter
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from ..core.paths import (
    BUSINESS_CASES_PATH,
    GUARD_CASES_PATH,
    GUARD_REGRESSION_RESULTS_DIR,
)
from .cases import build_positive_guard_cases, load_guard_cases


class GuardRegressionCancelled(RuntimeError):
    """工作台停止固定库回归时使用的内部取消信号。"""


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _percentile(values: list[float], ratio: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * ratio) - 1)
    return round(ordered[index], 2)


def _format_rate(value: Any) -> str:
    return "N/A" if value is None else f"{float(value):.2%}"


# 报告面向测试人员阅读；接口内部仍保留英文枚举，写入 Markdown 时统一翻译。
# 未知值使用“其他模块”，避免把实现名直接堆到用户报告里。
_MODULE_LABELS = {
    "aliyun_guardrail": "阿里云护栏",
    "prompt_fingerprint": "提示词指纹",
    "protected_assets": "保护资产",
    "protected_asset_winnowing": "保护资产（精确匹配）",
    "protected_asset_fuzzy": "保护资产（模糊匹配）",
    "qwen_guard": "千问护栏",
    "regex": "正则规则",
    "regex_advisory": "正则规则（提示）",
    "none": "未拦截",
    "unknown": "未知模块",
}


def _module_label(value: Any) -> str:
    key = str(value or "unknown").strip().lower()
    return _MODULE_LABELS.get(key, "其他检测模块")


def _direction_label(value: Any) -> str:
    return {"input": "输入", "output": "输出"}.get(str(value or ""), "—")


def _stage_label(value: Any) -> str:
    return {
        "full": "全文检查",
        "stream": "流式检查",
        "audit": "最终审计",
    }.get(str(value or ""), "—")


def _decision_label(value: Any) -> str:
    return {
        "ALLOW": "放行",
        "BLOCK": "拦截",
        "REVIEW": "待复核",
        "ERROR": "错误",
    }.get(str(value or "").upper(), "—")


def _outcome_label(value: Any) -> str:
    return {
        "PASS": "通过",
        "FAIL": "失败",
        "ERROR": "错误",
        "OBSERVED": "已观察",
    }.get(str(value or "").upper(), "—")


def _stream_chunks(text: str, chunk_size: int) -> list[str]:
    if chunk_size < 1:
        raise ValueError("--stream-chunk-size must be greater than 0")
    return [text[index : index + chunk_size] for index in range(0, len(text), chunk_size)]


def _response_summary(response: Mapping[str, Any]) -> dict[str, Any]:
    summary = {
        "decision": str(response.get("decision") or "").upper(),
        "detector": response.get("detector"),
        "rule_id": response.get("rule_id"),
        "reason": response.get("reason"),
        "checked_by": list(response.get("checked_by") or []),
        "degraded": bool(response.get("degraded")),
        "latency_ms": float(response.get("latency_ms") or 0),
        "engine_version": response.get("engine_version"),
        "policy_version": response.get("policy_version"),
    }
    trace = response.get("trace")
    if isinstance(trace, list):
        # 只保留服务端定义的脱敏模块字段；不会把检测原文带进回归报告。
        summary["trace"] = [
            dict(item)
            for item in trace
            if isinstance(item, Mapping)
        ]
    return summary


def _trace_entries(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """提取一次 Case 实际发出的所有护栏响应 trace。"""
    return [entry for _, entry in _scoped_trace_entries(result)]


def _scoped_trace_entries(
    result: Mapping[str, Any],
) -> list[tuple[str, Mapping[str, Any]]]:
    """提取 trace，并标明它来自输入、输出流式或输出最终审计。

    流式输出会按分块重复请求护栏。这里刻意不把多个分块合并：调用数和
    延迟仍需要反映真实负载；样本级去重则在汇总函数中按 case_id 处理。
    """
    entries: list[tuple[str, Mapping[str, Any]]] = []
    direction = str(result.get("direction") or "")
    stage = str(result.get("stage") or "")
    if str(result.get("stage") or "") == "stream":
        stream = result.get("stream")
        checks = stream.get("checks") if isinstance(stream, Mapping) else None
        if isinstance(checks, list):
            for check in checks:
                if isinstance(check, Mapping) and isinstance(check.get("trace"), list):
                    entries.extend(
                        ("output_stream", item)
                        for item in check["trace"]
                        if isinstance(item, Mapping)
                    )
        full_audit = result.get("full_audit")
        if isinstance(full_audit, Mapping) and isinstance(full_audit.get("trace"), list):
            entries.extend(
                ("output_full_audit", item)
                for item in full_audit["trace"]
                if isinstance(item, Mapping)
            )
    elif isinstance(result.get("trace"), list):
        scope = "input" if direction == "input" else "output_full_audit"
        # output_mode=full 会直接执行全文输出检查，也归入 output_full_audit。
        if not direction and stage == "stream":
            scope = "output_stream"
        entries.extend(
            (scope, item) for item in result["trace"] if isinstance(item, Mapping)
        )
    return entries


def _case_module_trace_by_scope(results):
    from .case_metrics import case_key, case_populations
    labels = {key: {"attack": "BLOCK", "positive": "ALLOW", "observation": "OBSERVE"}[value]
              for key, value in case_populations(results).items()}
    entries = {"input": [], "output_stream": [], "output_full_audit": []}
    for i, row in enumerate(results):
        for scope, entry in _scoped_trace_entries(row):
            entries.setdefault(scope, []).append((scope, case_key(row, i), entry))
    summaries = {}
    for scope, items in entries.items():
        invalid = {(key, str(entry.get("module") or "unknown")) for _, key, entry in items
                   if entry.get("status") == "error" or entry.get("degraded")}
        summaries[scope] = _module_trace_summary_from_entries(items, labels, invalid)
    return summaries


def _sample_key(result: Mapping[str, Any], index: int) -> str:
    """返回稳定的样本键；正常报告使用 guard case_id。"""
    case_id = str(result.get("case_id") or result.get("source_case_id") or "").strip()
    return case_id or f"report-row-{index}"


def _module_trace_summary_from_entries(
    entries: list[tuple[str, str, Mapping[str, Any]]],
    expectations: Mapping[str, str] | None = None,
    invalid_samples: set[tuple[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """汇总一个 scope 内的模块负载和去重后的样本命中数。"""
    buckets: dict[str, dict[str, Any]] = {}
    for _, sample_id, entry in entries:
        module = str(entry.get("module") or "unknown")
        bucket = buckets.setdefault(
            module,
            {
                "module": module,
                "enabled": False,
                "calls": 0,
                "blocked": 0,
                "skipped": 0,
                "errors": 0,
                "degraded": 0,
                "durations": [],
                "statuses": Counter(),
                "executed_sample_ids": set(),
                "blocked_sample_ids": set(),
            },
        )
        calls = max(0, int(entry.get("calls") or 0))
        status = str(entry.get("status") or "error")
        duration = float(entry.get("duration_ms") or 0)
        bucket["enabled"] = bool(bucket["enabled"] or entry.get("enabled"))
        bucket["calls"] += calls
        bucket["blocked"] += calls if bool(entry.get("blocked")) else 0
        bucket["skipped"] += 1 if status == "skipped" else 0
        bucket["errors"] += 1 if status == "error" else 0
        bucket["degraded"] += 1 if bool(entry.get("degraded")) else 0
        valid = (sample_id, module) not in (invalid_samples or set())
        if calls and valid:
            bucket["executed_sample_ids"].add(sample_id)
        if bool(entry.get("blocked")) and valid:
            bucket["blocked_sample_ids"].add(sample_id)
        if status != "skipped":
            bucket["durations"].append(duration)
        bucket["statuses"][status] += 1

    summary: list[dict[str, Any]] = []
    for bucket in buckets.values():
        durations = [float(value) for value in bucket.pop("durations")]
        executed_sample_ids = bucket.pop("executed_sample_ids")
        blocked_sample_ids = bucket.pop("blocked_sample_ids")
        # 按预期标签拆分；观察/未标注样本不参与攻击拦截率或正向误拦率。
        populations = {}
        for label, name in (("BLOCK", "attack"), ("ALLOW", "positive"), ("OBSERVE", "observation")):
            ids = {key for key in executed_sample_ids if (expectations or {}).get(key) == label}
            blocked = len(ids & blocked_sample_ids)
            populations[name] = {
                "executed_samples": len(ids),
                "blocked_samples": blocked,
                "block_rate": blocked / len(ids) if ids else None,
            }
        calls = int(bucket["calls"])
        executed_samples = len(executed_sample_ids)
        summary.append(
            {
                **bucket,
                "populations": populations,
                "block_rate": bucket["blocked"] / calls if calls else None,
                # block_rate 保持旧字段语义：模块调用层的命中密度。流式模式下
                # 它不能用来评价一条样本的拦截效果，应使用 sample_block_rate。
                "executed_samples": executed_samples,
                "blocked_samples": len(blocked_sample_ids),
                "sample_block_rate": (
                    len(blocked_sample_ids) / executed_samples
                    if executed_samples
                    else None
                ),
                "avg_duration_ms": round(sum(durations) / len(durations), 2)
                if durations
                else 0.0,
                "p95_duration_ms": _percentile(durations, 0.95),
                "statuses": dict(bucket["statuses"]),
            }
        )
        summary[-1].pop("statuses", None)
        summary[-1]["status_counts"] = dict(bucket["statuses"])
    return sorted(summary, key=lambda item: str(item["module"]))


def _module_trace_summary(results: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """兼容旧模块总表；调用数仍合并所有阶段，新增样本级去重字段。"""
    entries = [
        (scope, _sample_key(result, index), entry)
        for index, result in enumerate(results)
        for scope, entry in _scoped_trace_entries(result)
    ]
    expectations = {_sample_key(row, i): str(row.get("expected_decision") or "").upper()
                    for i, row in enumerate(results)}
    return _module_trace_summary_from_entries(entries, expectations)


def _module_trace_by_scope(
    results: list[Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """按请求语义拆开模块统计，避免把流式分块和最终审计混为一谈。"""
    scoped_entries: dict[str, list[tuple[str, str, Mapping[str, Any]]]] = {
        "input": [],
        "output_stream": [],
        "output_full_audit": [],
    }
    for index, result in enumerate(results):
        sample_id = _sample_key(result, index)
        for scope, entry in _scoped_trace_entries(result):
            scoped_entries.setdefault(scope, []).append((scope, sample_id, entry))
    expectations = {_sample_key(row, i): str(row.get("expected_decision") or "").upper()
                    for i, row in enumerate(results)}
    return {
        scope: _module_trace_summary_from_entries(entries, expectations)
        for scope, entries in scoped_entries.items()
    }


def _terminal_module(result: Mapping[str, Any]) -> str:
    """从产生最终 BLOCK 的 trace 中找模块名，兼容旧服务没有 trace 的情况。"""
    for _, entry in _scoped_trace_entries(result):
        if bool(entry.get("blocked")):
            return str(entry.get("module") or "unknown")
    detector = str(result.get("detector") or "").strip()
    return detector or "unknown"


def _terminal_detector_contribution(
    results: list[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """统计预期攻击样本最终被哪个模块/检测器实时拦截。

    输出流式样本的 full_audit 是事后检查：它不会改变 actual_decision，因而
    不归入这里的“最终拦截”贡献，避免把事后发现误说成在线阻断。
    """
    buckets: dict[str, dict[str, Any]] = {
        scope: {
            "attack_sample_ids": set(),
            "blocked_sample_ids": set(),
            "items": {},
        }
        for scope in ("input", "output", "all")
    }
    # “全部实时”按唯一 source_case_id 归属一个最终拦截模块，避免同一攻击
    # 同时在输入和输出命中时被两个模块各算一次、导致贡献率合计超过 100%。
    # 输入是实际链路中先发生的检查，因此同一 Case 同时命中时优先归入输入。
    all_attribution: dict[str, tuple[int, str, str]] = {}
    for index, result in enumerate(results):
        if str(result.get("expected_decision") or "").upper() != "BLOCK":
            continue
        direction = str(result.get("direction") or "")
        scope = "input" if direction == "input" else "output"
        # 输入和输出通常各有一条 Guard Case，但它们可能属于同一个原始攻击
        # Case。贡献统计按 source_case_id 去重，避免“输入拦一次、输出再拦一次”
        # 被误算成两个攻击 Case；没有来源 ID 的测试数据仍退回 Guard Case ID。
        sample_id = str(result.get("source_case_id") or "").strip() or _sample_key(result, index)
        for target_scope in (scope, "all"):
            buckets[target_scope]["attack_sample_ids"].add(sample_id)
        if str(result.get("actual_decision") or "").upper() != "BLOCK":
            continue
        module = _terminal_module(result)
        detector = str(result.get("detector") or module or "unknown")
        # 输入/输出分组保留各自的 Case 统计；同一源 Case 在两个阶段都命中时，
        # “全部实时”只保留一个归属。
        bucket = buckets[scope]
        bucket["blocked_sample_ids"].add(sample_id)
        item = bucket["items"].setdefault(
            (module, detector),
            {"module": module, "detector": detector, "sample_ids": set()},
        )
        item["sample_ids"].add(sample_id)
        buckets["all"]["blocked_sample_ids"].add(sample_id)
        priority = 0 if scope == "input" else 1
        existing = all_attribution.get(sample_id)
        if existing is None or priority < existing[0]:
            all_attribution[sample_id] = (priority, module, detector)

    for sample_id, (_, module, detector) in all_attribution.items():
        item = buckets["all"]["items"].setdefault(
            (module, detector),
            {"module": module, "detector": detector, "sample_ids": set()},
        )
        item["sample_ids"].add(sample_id)

    contribution: dict[str, dict[str, Any]] = {}
    for scope, bucket in buckets.items():
        attack_samples = len(bucket["attack_sample_ids"])
        blocked_samples = len(bucket["blocked_sample_ids"])
        items = [
            {
                "module": item["module"],
                "detector": item["detector"],
                "attack_samples": len(item["sample_ids"]),
                "share_of_blocked_samples": (
                    len(item["sample_ids"]) / blocked_samples
                    if blocked_samples
                    else None
                ),
            }
            for item in bucket["items"].values()
        ]
        contribution[scope] = {
            "attack_cases": attack_samples,
            "blocked_cases": blocked_samples,
            "blocked_case_rate": (
                blocked_samples / attack_samples if attack_samples else None
            ),
            "attack_samples": attack_samples,
            "blocked_samples": blocked_samples,
            "unblocked_samples": attack_samples - blocked_samples,
            "items": sorted(
                items,
                key=lambda item: (-int(item["attack_samples"]), str(item["module"])),
            ),
        }
    return contribution


def _without_trace(value: Any) -> Any:
    """报告保留批次级 module_trace，避免把每个流式分块 trace 膨胀进浏览器。"""
    if isinstance(value, Mapping):
        return {
            key: _without_trace(item)
            for key, item in value.items()
            if key != "trace"
        }
    if isinstance(value, list):
        return [_without_trace(item) for item in value]
    return value


class GuardApiClient:
    def __init__(
        self,
        base_url: str,
        *,
        token: str = "",
        timeout: float = 30.0,
        include_trace: bool = False,
    ) -> None:
        parts = urlsplit(base_url.rstrip("/"))
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("Guard API base URL must be a valid HTTP(S) URL")
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port
        self.path = parts.path.rstrip("/") + "/v1/check?compact=false"
        if include_trace:
            self.path += "&include_trace=true"
        self.token = token
        self.timeout = timeout
        self._connections: dict[int, http.client.HTTPConnection] = {}
        self._lock = threading.Lock()

    def _connection(self) -> http.client.HTTPConnection:
        thread_id = threading.get_ident()
        with self._lock:
            connection = self._connections.get(thread_id)
            if connection is None:
                connection_type = (
                    http.client.HTTPSConnection
                    if self.scheme == "https"
                    else http.client.HTTPConnection
                )
                connection = connection_type(
                    self.host,
                    self.port,
                    timeout=self.timeout,
                )
                self._connections[thread_id] = connection
            return connection

    def _discard_current_connection(self) -> None:
        thread_id = threading.get_ident()
        with self._lock:
            connection = self._connections.pop(thread_id, None)
        if connection is not None:
            connection.close()

    def close(self) -> None:
        with self._lock:
            connections = list(self._connections.values())
            self._connections.clear()
        for connection in connections:
            connection.close()

    def check(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Risk-Guard-Token"] = self.token
        try:
            connection = self._connection()
            connection.request(
                "POST",
                self.path,
                body=json.dumps(dict(payload), ensure_ascii=False).encode("utf-8"),
                headers=headers,
            )
            response = connection.getresponse()
            body = response.read().decode("utf-8", errors="replace")
            if response.will_close:
                self._discard_current_connection()
        except (OSError, http.client.HTTPException) as exc:
            self._discard_current_connection()
            raise RuntimeError(f"Guard API unavailable: {exc}") from exc
        if not 200 <= response.status < 300:
            raise RuntimeError(f"Guard API HTTP {response.status}: {body[:500]}")
        parsed = json.loads(body)
        if not isinstance(parsed, dict):
            raise ValueError("Guard API response must be a JSON object")
        return parsed


def _markdown(report: Mapping[str, Any]) -> str:
    summary = report.get("summary") or {}
    lines = [
        "# 护栏固定数据集回归报告",
        "",
        f"- 运行编号：`{report.get('run_id')}`",
        f"- 样本总数：{summary.get('total', 0)}",
        f"- 通过：{summary.get('PASS', 0)}",
        f"- 失败：{summary.get('FAIL', 0)}",
        f"- 请求错误：{summary.get('ERROR', 0)}",
        f"- 仅观察：{summary.get('OBSERVED', 0)}",
        f"- 攻击样本总召回率（输入或输出实时拦截）：{_format_rate(summary.get('attack_recall'))}",
        f"- 输入召回率：{_format_rate(summary.get('input_recall'))}",
        f"- 输出流式实时召回率：{_format_rate(summary.get('output_realtime_recall'))}",
        f"- 输出实时或最终审计检出率：{_format_rate(summary.get('output_post_audit_detection_recall'))}",
        f"- 样本级召回率：{_format_rate(summary.get('attack_sample_recall'))}",
        f"- 正向样本实时通过率：{_format_rate(summary.get('positive_realtime_pass_rate'))}",
        f"- 正向样本含最终审计通过率：{_format_rate(summary.get('positive_post_audit_pass_rate'))}",
        f"- 正常内容实时误拦率：{_format_rate(summary.get('normal_false_positive_rate'))}",
        f"- 正常内容含最终审计误告警率：{_format_rate(summary.get('normal_post_audit_false_positive_rate'))}",
        f"- 正向输入误报率：{_format_rate(summary.get('input_false_positive_rate'))}",
        f"- 正向输出实时误报率：{_format_rate(summary.get('output_realtime_false_positive_rate'))}",
        f"- 正向输出实时或最终审计误告警率：{_format_rate(summary.get('output_post_audit_false_positive_rate'))}",
        f"- 正向输出仅最终审计告警率：{_format_rate(summary.get('output_full_audit_alert_rate'))}",
        f"- 非阻断审计告警：{summary.get('advisory_count', 0)} 条",
        f"- 非阻断告警规则数：{len(summary.get('advisory_rule_counts') or {})}",
        f"- P95 平均耗时：{summary.get('p95_latency_ms', 0)} ms",
        f"- 降级判定：{summary.get('degraded', 0)}",
        f"- 流式输出样本：{summary.get('stream_output_cases', 0)}",
        f"- 仅最终审计命中：{summary.get('audit_only_blocks', 0)}",
        "",
        "",
    ]
    metrics = summary.get("case_metrics")
    if metrics:
        lines = [line for line in lines if not any(word in line for word in ("召回率", "检出率", "通过率", "误拦率", "误告警率", "误报率", "仅最终审计告警率"))]
        lines.extend(["", "## Case 统计", "", "按原始 Case 去重；输出包含最终全文审计，异常和降级不计入有效分母。", ""])
        for scope, title in (("all", "综合"), ("input", "输入"), ("output", "输出")):
            for population, label in (("attack", "攻击拦截"), ("positive", "正向误拦")):
                value = metrics[scope][population]
                lines.append(f"- {title}{label}：{value['blocked']} / {value['valid']} Case（{_format_rate(value['rate'])}）；未完成或异常 {value['unknown']} Case；仅最终审计命中 {value['audit_only']} Case")
        lines.append(f"- 本次未提供输出的攻击 Case：{metrics['attack_without_output']}")

    lines.extend(["", "## 分模块统计", ""])
    module_trace = summary.get("module_trace") or []
    if module_trace:
        lines.extend(
            [
                "此表按实际模块调用事件统计；同一 Case 的输出流式检查可能产生多次调用。Case 级拦截效果请看下方分阶段统计。",
                "",
            ]
        )
        lines.extend(
            [
                "| 模块 | 调用数 | 拦截数 | 调用事件拦截占比 | 平均耗时 | P95 耗时 | 异常 | 降级 | 跳过 |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for item in module_trace:
            lines.append(
                "| {module} | {calls} | {blocked} | {rate} | {avg} ms | {p95} ms | {errors} | {degraded} | {skipped} |".format(
                    module=_module_label(item.get("module")),
                    calls=item.get("calls", 0),
                    blocked=item.get("blocked", 0),
                    rate=_format_rate(item.get("block_rate")),
                    avg=item.get("avg_duration_ms", 0),
                    p95=item.get("p95_duration_ms", 0),
                    errors=item.get("errors", 0),
                    degraded=item.get("degraded", 0),
                    skipped=item.get("skipped", 0),
                )
            )
    else:
        lines.append("本次接口未返回逐模块 trace；请确认服务支持 include_trace=true。")
    lines.extend(["", "## 分阶段模块统计（样本级）", ""])
    scope_labels = {
        "input": "输入全文检查",
        "output_stream": "输出流式检查",
        "output_full_audit": "输出最终审计",
    }
    module_trace_by_scope = summary.get("case_module_trace_by_scope") or summary.get("module_trace_by_scope") or {}
    if isinstance(module_trace_by_scope, Mapping):
        for scope, label in scope_labels.items():
            rows = module_trace_by_scope.get(scope) or []
            lines.extend([f"### {label}", ""])
            if not rows:
                lines.extend(["本阶段没有模块执行记录。", ""])
                continue
            lines.extend(
                [
                    "| 模块 | 请求次数 | 执行样本 | 拦截样本 | 样本拦截率 | 平均耗时 | P95 耗时 | 异常 | 降级 | 跳过 |",
                    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
                ]
            )
            for item in rows:
                lines.append(
                    "| {module} | {calls} | {executed_samples} | {blocked_samples} | {sample_rate} | {avg} ms | {p95} ms | {errors} | {degraded} | {skipped} |".format(
                        module=_module_label(item.get("module")),
                        calls=item.get("calls", 0),
                        executed_samples=item.get("executed_samples", 0),
                        blocked_samples=item.get("blocked_samples", 0),
                        sample_rate=_format_rate(item.get("sample_block_rate")),
                        avg=item.get("avg_duration_ms", 0),
                        p95=item.get("p95_duration_ms", 0),
                        errors=item.get("errors", 0),
                        degraded=item.get("degraded", 0),
                        skipped=item.get("skipped", 0),
                    )
                )
            lines.append("")
    else:
        lines.append("本次报告未提供按阶段拆分的模块统计。")

    lines.extend(["", "## 最终实时拦截贡献", ""])
    lines.append("仅统计预期应拦截且实际实时拦截的攻击样本；输出最终审计属于事后发现，不计入实时拦截。")
    contribution = summary.get("terminal_detector_contribution") or {}
    contribution_labels = {
        "input": "输入",
        "output": "输出实时",
        "all": "全部实时",
    }
    if isinstance(contribution, Mapping):
        for scope, label in contribution_labels.items():
            scope_summary = contribution.get(scope) or {}
            if not isinstance(scope_summary, Mapping):
                continue
            attack_cases = int(
                scope_summary.get("attack_cases", scope_summary.get("attack_samples")) or 0
            )
            blocked_cases = int(
                scope_summary.get("blocked_cases", scope_summary.get("blocked_samples")) or 0
            )
            rate = blocked_cases / attack_cases if attack_cases else None
            lines.extend(
                [
                    f"### {label}：拦截攻击 Case {blocked_cases}/{attack_cases}（{_format_rate(rate)}）",
                    "",
                ]
            )
            items = scope_summary.get("items") or []
            if not items:
                lines.extend(["无实时拦截记录。", ""])
                continue
            lines.extend(
                [
                    "| 模块 | 检测器 | 拦截攻击 Case | 占已拦截攻击 Case |",
                    "| --- | --- | ---: | ---: |",
                ]
            )
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                lines.append(
                    "| {module} | {detector} | {attack_samples} | {share} |".format(
                        module=_module_label(item.get("module")),
                        detector=_module_label(item.get("detector")),
                        attack_samples=item.get("attack_samples", 0),
                        share=_format_rate(item.get("share_of_blocked_samples")),
                    )
                )
            lines.append("")
    else:
        lines.append("本次报告未提供最终实时拦截贡献统计。")

    lines.extend(["", "## 未通过项", ""])
    failures = [
        item
        for item in report.get("results") or []
        if item.get("outcome") not in {"PASS", "OBSERVED"}
    ]
    if not failures:
        lines.append("无。")
    for item in failures:
        lines.extend(
            [
                f"### {item.get('case_id')} · {_outcome_label(item.get('outcome'))}",
                "",
                f"- 来源：{item.get('source_case_id')}",
                f"- 阶段：{_direction_label(item.get('direction'))} · {_stage_label(item.get('stage'))}",
                f"- 预期：{_decision_label(item.get('expected_decision'))}",
                f"- 实际：{_decision_label(item.get('actual_decision'))}",
                f"- 检测模块：{_module_label(item.get('detector'))}",
                f"- 原因：{item.get('reason') or item.get('error') or ''}",
                f"- 最终审计：{_decision_label((item.get('full_audit') or {}).get('decision'))}",
                f"- 内容：{str(item.get('content') or '')[:1000]}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def override_case_agent(case: Mapping[str, Any], agent_id: str) -> dict[str, Any]:
    """Cross-profile execution is observation, not the original policy regression."""
    original = str(case.get("agent_id") or "default")
    if original == agent_id:
        return dict(case)
    return {**case, "source_agent_id": original,
            "source_expected_decision": case.get("expected_decision"),
            "agent_id": agent_id, "expected_decision": "OBSERVE"}


def run_guard_regression(
    args: Any,
    *,
    requester: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None,
    progress_callback: Callable[[Mapping[str, Any]], None] | None = None,
    cancel_callback: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    cases_path = Path(getattr(args, "guard_cases", None) or GUARD_CASES_PATH)
    library = load_guard_cases(cases_path)
    include_positive = bool(getattr(args, "guard_include_positive", False))
    positive_cases_path = Path(
        getattr(args, "guard_positive_cases", None)
        or BUSINESS_CASES_PATH
    )
    positive_case_limit = int(
        getattr(args, "guard_positive_case_limit", 0) or 0
    )
    raw_cases = list(library.get("cases") or [])
    positive_sample_count = int(library.get("positive_sample_count") or 0)
    if include_positive:
        positive_samples = build_positive_guard_cases(
            positive_cases_path,
            case_limit=positive_case_limit,
        )
        positive_sample_count += len(positive_samples)
        raw_cases.extend(positive_samples)
    selected_ids = {
        str(item).strip()
        for item in getattr(args, "guard_case", None) or []
        if str(item or "").strip()
    }
    directions = {
        str(item).strip()
        for item in getattr(args, "guard_direction", None) or []
        if str(item or "").strip()
    }
    cases = [
        dict(item)
        for item in raw_cases
        if str(item.get("status") or "active") == "active"
        and (not selected_ids or str(item.get("case_id") or "") in selected_ids)
        and (not directions or str(item.get("direction") or "") in directions)
    ]
    limit = int(getattr(args, "guard_limit", 0) or 0)
    if limit < 0:
        raise ValueError("--limit must not be negative")
    if limit:
        cases = cases[:limit]
    if selected_ids:
        found = {str(item.get("case_id") or "") for item in cases}
        missing = sorted(selected_ids - found)
        if missing:
            raise ValueError("Guard Cases not found: " + ", ".join(missing))

    agent_override = str(getattr(args, "guard_agent_override", "") or "").strip()
    if agent_override:
        cases = [override_case_agent(case, agent_override) for case in cases]

    def notify(event: Mapping[str, Any]) -> None:
        """把进度通知给工作台；进度写入失败不能影响实际回归。"""
        if progress_callback is None:
            return
        try:
            progress_callback({"updated_at": _now(), **dict(event)})
        except Exception:
            # 页面进度属于旁路能力，不能因为磁盘或回调异常中断护栏测试。
            return

    def cancelled() -> bool:
        if cancel_callback is None:
            return False
        try:
            return bool(cancel_callback())
        except Exception:
            # 取消状态属于旁路控制；读取状态失败时不把正常回归误判为取消。
            return False

    def raise_if_cancelled() -> None:
        if cancelled():
            raise GuardRegressionCancelled("护栏固定数据集回归已停止")

    notify({
        "phase": "preparing",
        "message": "已加载固定数据集，准备执行护栏请求。",
        "completed": 0,
        "total": len(cases),
        "percent": 0 if cases else 100,
        "indeterminate": not bool(cases),
    })

    run_id = str(getattr(args, "batch_id", None) or "").strip() or (
        datetime.now().strftime("GR-%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    )
    workers = max(1, int(getattr(args, "guard_workers", 5) or 5))
    workers = min(workers, max(1, len(cases)))
    base_url = str(getattr(args, "guard_base_url", "http://127.0.0.1:8091"))
    output_mode = str(getattr(args, "guard_output_mode", "stream") or "stream")
    chunk_size = int(getattr(args, "guard_stream_chunk_size", 32) or 32)
    window_size = int(getattr(args, "guard_stream_window_size", 500) or 500)
    if output_mode not in {"stream", "full"}:
        raise ValueError("--output-mode must be stream or full")
    if chunk_size < 1 or window_size < 1:
        raise ValueError("stream chunk/window size must be greater than 0")
    if bool(getattr(args, "dry_run", False)):
        return {
            "status": "READY",
            "run_id": run_id,
            "planned_case_count": len(cases),
            "direction_counts": dict(Counter(item.get("direction") for item in cases)),
            "guard_base_url": base_url,
            "output_mode": output_mode,
            "stream_chunk_size": chunk_size,
            "stream_window_size": window_size,
            "include_positive": include_positive,
            "positive_sample_count": positive_sample_count,
            "positive_cases": (
                str(positive_cases_path.resolve()) if include_positive else None
            ),
            "guard_cases": str(cases_path.resolve()),
        }

    api_client = None
    if requester is None:
        api_client = GuardApiClient(
            base_url,
            token=str(getattr(args, "guard_token", "") or ""),
            timeout=float(getattr(args, "guard_timeout", 30.0)),
            include_trace=bool(getattr(args, "guard_include_trace", False)),
        )
        requester = api_client.check

    notify({
        "phase": "running",
        "message": "开始并发调用护栏接口。",
        "completed": 0,
        "total": len(cases),
        "percent": 0 if cases else 100,
        "indeterminate": False,
    })

    def execute(case: Mapping[str, Any]) -> dict[str, Any]:
        raise_if_cancelled()
        expected = str(case.get("expected_decision") or "").upper()
        if expected not in {"ALLOW", "BLOCK", "OBSERVE"}:
            return {**case, "outcome": "ERROR", "error": "invalid expected_decision"}
        content = str(case.get("content") or "")
        base_payload = {
            "content": str(case.get("content") or ""),
            "direction": str(case.get("direction") or ""),
            "stage": str(case.get("stage") or "full"),
            "agent_id": str(case.get("agent_id") or "default"),
            "request_id": f"{run_id}:{case.get('case_id')}",
        }
        try:
            direction = str(case.get("direction") or "")
            if direction == "output" and output_mode == "stream":
                buffer = ""
                stream_checks: list[dict[str, Any]] = []
                chunks = _stream_chunks(content, chunk_size)
                selected: dict[str, Any] = {
                    "decision": "ALLOW",
                    "detector": "none",
                    "rule_id": "",
                    "reason": "stream completed without a block",
                    "checked_by": [],
                    "degraded": False,
                    "latency_ms": 0.0,
                    "engine_version": None,
                    "policy_version": None,
                }
                for index, chunk in enumerate(chunks, start=1):
                    buffer = (buffer + chunk)[-window_size:]
                    response = requester(
                        {
                            **base_payload,
                            "content": buffer,
                            "stage": "stream",
                            "request_id": f"{base_payload['request_id']}:stream:{index}",
                        }
                    )
                    current = _response_summary(response)
                    stream_checks.append(
                        {
                            "chunk_index": index,
                            "chunk_length": len(chunk),
                            "buffer_length": len(buffer),
                            **current,
                        }
                    )
                    selected = current
                    if current["decision"] == "BLOCK":
                        break

                full_audit = None
                if selected["decision"] != "BLOCK":
                    full_audit = _response_summary(
                        requester(
                            {
                                **base_payload,
                                "content": content,
                                "stage": "full",
                                "request_id": f"{base_payload['request_id']}:full-audit",
                            }
                        )
                    )
                actual = selected["decision"]
                execution = {
                    "stage": "stream",
                    "stream": {
                        "chunk_size": chunk_size,
                        "window_size": window_size,
                        "chunk_count": len(chunks),
                        "checks_executed": len(stream_checks),
                        "blocked_at_chunk": next(
                            (
                                item["chunk_index"]
                                for item in stream_checks
                                if item["decision"] == "BLOCK"
                            ),
                            None,
                        ),
                        "checks": stream_checks,
                    },
                    "full_audit": full_audit,
                    "latency_ms": sum(item["latency_ms"] for item in stream_checks),
                    **{key: selected.get(key) for key in (
                        "detector", "rule_id", "reason",
                        "engine_version", "policy_version",
                    )},
                    "checked_by": list(
                        dict.fromkeys(
                            checked
                            for item in stream_checks
                            for checked in item.get("checked_by") or []
                        )
                    ),
                    "degraded": any(
                        bool(item.get("degraded")) for item in stream_checks
                    ),
                }
            else:
                response = requester({**base_payload, "stage": "full"})
                selected = _response_summary(response)
                actual = selected["decision"]
                execution = {"stage": "full", "full_audit": None, **selected}
            return {
                **case,
                **execution,
                "actual_decision": actual,
                "outcome": (
                    "OBSERVED"
                    if expected == "OBSERVE"
                    else ("PASS" if actual == expected else "FAIL")
                ),
            }
        except GuardRegressionCancelled:
            raise
        except Exception as exc:
            return {
                **case,
                "outcome": "ERROR",
                "error": f"{type(exc).__name__}: {exc}",
            }

    try:
        # 用 as_completed 让工作台按真实完成顺序收到进度；最终结果仍按
        # 数据集原顺序写回，报告内容和历史行为保持不变。
        results: list[dict[str, Any] | None] = [None] * len(cases)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures: dict[Any, int] = {}
            for index, case in enumerate(cases):
                raise_if_cancelled()
                futures[pool.submit(execute, case)] = index
            completed = 0
            for future in as_completed(futures):
                if cancelled():
                    # 已经排入但尚未开始的请求可以安全取消；正在进行的
                    # HTTP 请求让其自己的 timeout 自然结束，避免强杀线程。
                    for pending in futures:
                        if not pending.done():
                            pending.cancel()
                    raise GuardRegressionCancelled("护栏固定数据集回归已停止")
                index = futures[future]
                try:
                    item = future.result()
                except CancelledError:
                    continue
                except GuardRegressionCancelled:
                    for pending in futures:
                        if not pending.done():
                            pending.cancel()
                    raise
                results[index] = item
                completed += 1
                notify({
                    "phase": "running",
                    "message": f"已完成 {completed}/{len(cases)} 条护栏样本。",
                    "completed": completed,
                    "total": len(cases),
                    "percent": round(completed / len(cases) * 100, 1) if cases else 100,
                    "indeterminate": False,
                    "current_case": item.get("case_id") or item.get("source_case_id"),
                    "current_outcome": item.get("outcome"),
                })
        results = [item for item in results if item is not None]
    finally:
        if api_client is not None:
            api_client.close()

    outcomes = Counter(str(item.get("outcome") or "ERROR") for item in results)
    true_positive = sum(
        item.get("expected_decision") == "BLOCK" and item.get("actual_decision") == "BLOCK"
        for item in results
    )
    false_negative = sum(
        item.get("expected_decision") == "BLOCK" and item.get("actual_decision") == "ALLOW"
        for item in results
    )
    false_positive = sum(
        item.get("expected_decision") == "ALLOW" and item.get("actual_decision") == "BLOCK"
        for item in results
    )
    true_negative = sum(
        item.get("expected_decision") == "ALLOW" and item.get("actual_decision") == "ALLOW"
        for item in results
    )
    latencies = [float(item.get("latency_ms") or 0) for item in results if item.get("outcome") != "ERROR"]
    attack_total = true_positive + false_negative
    normal_total = false_positive + true_negative
    attack_case_ids = {
        str(item.get("source_case_id") or "")
        for item in results
        if item.get("expected_decision") == "BLOCK"
        and str(item.get("source_case_id") or "")
    }
    input_attack_results = [
        item
        for item in results
        if item.get("direction") == "input"
        and item.get("expected_decision") == "BLOCK"
    ]
    output_attack_results = [
        item
        for item in results
        if item.get("direction") == "output"
        and item.get("expected_decision") == "BLOCK"
    ]
    input_blocked_ids = {
        str(item.get("source_case_id") or "")
        for item in input_attack_results
        if item.get("actual_decision") == "BLOCK"
    }
    output_realtime_blocked_ids = {
        str(item.get("source_case_id") or "")
        for item in output_attack_results
        if item.get("actual_decision") == "BLOCK"
    }
    blocked_case_ids = input_blocked_ids | output_realtime_blocked_ids
    input_attack_total = len(input_attack_results)
    output_attack_total = len(output_attack_results)
    input_blocked_total = sum(
        item.get("actual_decision") == "BLOCK" for item in input_attack_results
    )
    output_realtime_blocked_total = sum(
        item.get("actual_decision") == "BLOCK" for item in output_attack_results
    )
    output_post_audit_detected_total = sum(
        item.get("actual_decision") == "BLOCK"
        or (item.get("full_audit") or {}).get("decision") == "BLOCK"
        for item in output_attack_results
    )
    input_normal_results = [
        item
        for item in results
        if item.get("direction") == "input"
        and item.get("expected_decision") == "ALLOW"
    ]
    output_normal_results = [
        item
        for item in results
        if item.get("direction") == "output"
        and item.get("expected_decision") == "ALLOW"
    ]
    input_normal_blocked_total = sum(
        item.get("actual_decision") == "BLOCK" for item in input_normal_results
    )
    output_normal_realtime_blocked_total = sum(
        item.get("actual_decision") == "BLOCK" for item in output_normal_results
    )
    output_normal_post_audit_blocked_total = sum(
        item.get("actual_decision") == "BLOCK"
        or (item.get("full_audit") or {}).get("decision") == "BLOCK"
        for item in output_normal_results
    )
    normal_post_audit_false_positive_total = (
        input_normal_blocked_total + output_normal_post_audit_blocked_total
    )
    direction_summary = {
        direction: {
            "total": sum(item.get("direction") == direction for item in results),
            "PASS": sum(
                item.get("direction") == direction and item.get("outcome") == "PASS"
                for item in results
            ),
            "FAIL": sum(
                item.get("direction") == direction and item.get("outcome") == "FAIL"
                for item in results
            ),
            "ERROR": sum(
                item.get("direction") == direction and item.get("outcome") == "ERROR"
                for item in results
            ),
            "OBSERVED": sum(
                item.get("direction") == direction and item.get("outcome") == "OBSERVED"
                for item in results
            ),
        }
        for direction in ("input", "output")
    }
    advisories = [
        {
            "rule_id": str(response.get("rule_id") or ""),
            "detector": str(response.get("detector") or ""),
        }
        for item in results
        for response in (item, item.get("full_audit") or {})
        if response.get("decision") == "ALLOW" and response.get("rule_id")
    ]
    from .case_metrics import summarize_cases
    incomplete_cases = {
        str(issue.get("source_case_id") or "") for issue in library.get("issues", [])
        if ("output" in str(issue.get("issue")) and (not directions or "output" in directions))
        or ("input" in str(issue.get("issue")) and (not directions or "input" in directions))
    }
    report = {
        "schema_version": "1.1-guard-regression-report",
        "status": "COMPLETED",
        "run_id": run_id,
        "created_at": _now(),
        "guard_base_url": base_url,
        "output_mode": output_mode,
        "stream_chunk_size": chunk_size,
        "stream_window_size": window_size,
        "include_positive": include_positive,
        "positive_sample_count": positive_sample_count,
        "positive_cases": (
            str(positive_cases_path.resolve()) if include_positive else None
        ),
        "guard_cases": str(cases_path.resolve()),
        "summary": {
            "case_metrics": summarize_cases(results, incomplete_cases),
            "dataset_issues": library.get("issues", []),
            "case_module_trace_by_scope": _case_module_trace_by_scope(results),
            "total": len(results),
            "PASS": outcomes.get("PASS", 0),
            "FAIL": outcomes.get("FAIL", 0),
            "ERROR": outcomes.get("ERROR", 0),
            "OBSERVED": outcomes.get("OBSERVED", 0),
            "true_positive": true_positive,
            "false_negative": false_negative,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "attack_sample_count": attack_total,
            "normal_sample_count": normal_total,
            "attack_recall": (
                len(blocked_case_ids) / len(attack_case_ids)
                if attack_case_ids
                else None
            ),
            "attack_case_count": len(attack_case_ids),
            "blocked_case_count": len(blocked_case_ids),
            "input_or_output_overlap_count": len(
                input_blocked_ids & output_realtime_blocked_ids
            ),
            "input_only_blocked_case_count": len(
                input_blocked_ids - output_realtime_blocked_ids
            ),
            "output_only_blocked_case_count": len(
                output_realtime_blocked_ids - input_blocked_ids
            ),
            "attack_sample_recall": (
                true_positive / attack_total if attack_total else None
            ),
            "input_recall": (
                input_blocked_total / input_attack_total
                if input_attack_total
                else None
            ),
            "output_realtime_recall": (
                output_realtime_blocked_total / output_attack_total
                if output_attack_total
                else None
            ),
            "output_post_audit_detection_recall": (
                output_post_audit_detected_total / output_attack_total
                if output_attack_total
                else None
            ),
            "normal_false_positive_rate": (
                false_positive / normal_total if normal_total else None
            ),
            "positive_realtime_pass_rate": (
                true_negative / normal_total if normal_total else None
            ),
            "normal_post_audit_false_positive_rate": (
                normal_post_audit_false_positive_total / normal_total
                if normal_total
                else None
            ),
            "positive_post_audit_pass_rate": (
                1 - normal_post_audit_false_positive_total / normal_total
                if normal_total
                else None
            ),
            "input_false_positive_rate": (
                input_normal_blocked_total / len(input_normal_results)
                if input_normal_results
                else None
            ),
            "output_realtime_false_positive_rate": (
                output_normal_realtime_blocked_total / len(output_normal_results)
                if output_normal_results
                else None
            ),
            "output_post_audit_false_positive_rate": (
                output_normal_post_audit_blocked_total / len(output_normal_results)
                if output_normal_results
                else None
            ),
            "output_full_audit_alert_rate": (
                sum(
                    (item.get("full_audit") or {}).get("decision") == "BLOCK"
                    for item in output_normal_results
                )
                / len(output_normal_results)
                if output_normal_results
                else None
            ),
            "advisory_count": len(advisories),
            "advisory_rule_counts": dict(
                Counter(item["rule_id"] for item in advisories)
            ),
            "p50_latency_ms": _percentile(latencies, 0.50),
            "p95_latency_ms": _percentile(latencies, 0.95),
            "degraded": sum(bool(item.get("degraded")) for item in results),
            "stream_output_cases": sum(
                item.get("direction") == "output" and item.get("stage") == "stream"
                for item in results
            ),
            "audit_only_blocks": sum(
                item.get("direction") == "output"
                and item.get("actual_decision") == "ALLOW"
                and (item.get("full_audit") or {}).get("decision") == "BLOCK"
                for item in results
            ),
            "direction_counts": dict(Counter(item.get("direction") for item in results)),
            "by_direction": direction_summary,
            "detector_counts": dict(Counter(item.get("detector") or "none" for item in results)),
            # 旧总表继续保留，供已有报告消费者读取。新表按请求语义拆开，
            # 使前端能分别展示输入、输出流式和输出最终审计。
            "module_trace": _module_trace_summary(results),
            "module_trace_by_scope": _module_trace_by_scope(results),
            "terminal_detector_contribution": _terminal_detector_contribution(results),
        },
        # 逐模块明细已经汇总到 summary.module_trace；写盘前会移除每个流式
        # 分块的 trace，避免报告和浏览器存储被无谓放大。生成 Finding 时仍
        # 使用下面的完整结果，保留最后一次流式检查作为证据。
        "results": results,
    }
    notify({
        "phase": "finalizing",
        "message": "请求已完成，正在整理 JSON、Markdown 和 Finding 报告。",
        "completed": len(results),
        "total": len(cases),
        "percent": 100 if cases else 100,
        "indeterminate": False,
    })
    output_dir = Path(
        getattr(args, "guard_output_dir", None) or GUARD_REGRESSION_RESULTS_DIR
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}.json"
    markdown_path = output_dir / f"{run_id}.md"
    from .findings import generate_guard_findings

    finding_report = generate_guard_findings(report, output_dir=output_dir)
    report["results"] = [_without_trace(item) for item in results]
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(_markdown(report), encoding="utf-8")
    notify({
        "phase": "completed",
        "message": "护栏固定数据集回归和报告整理已完成。",
        "completed": len(results),
        "total": len(cases),
        "percent": 100,
        "indeterminate": False,
    })
    return {
        "status": "COMPLETED",
        "run_id": run_id,
        "case_count": len(results),
        "summary": report["summary"],
        "json": str(json_path.resolve()),
        "markdown": str(markdown_path.resolve()),
        "finding_report": finding_report,
    }


__all__ = ["GuardApiClient", "run_guard_regression"]
