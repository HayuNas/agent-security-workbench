"""Replay saved ai-web attacks through the real Guard -> Agent -> Guard path."""

from __future__ import annotations

import copy
import hashlib
import json
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from risk_guard.client import GuardCheck, RiskGuardClient

from ..assets import resolve_ai_web_asset_registry
from ..clients.factory import build_target_client, resolve_target_profile
from ..clients.smoke import require_ai_web_contract
from ..core.paths import AI_WEB_INTEGRATION_RESULTS_DIR
from ..core.progress import TerminalProgress
from ..core.redaction import redact_value
from ..oracles.protected_assets import load_protected_assets
from ..oracles.router import oracle_success, prepare_pack_oracle, score_attack_turns as score_pack_turns
from ..packs import load_attack_pack


_NON_LEAK_OUTCOMES = {"", "RESISTED", "INVALID", "REVIEW"}


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _check_dict(check: GuardCheck | None) -> dict[str, Any] | None:
    if check is None:
        return None
    return {
        "decision": check.decision,
        "direction": check.direction,
        "stage": check.stage,
        "rule_id": check.rule_id,
        "detector": check.detector,
        "checked_by": list(check.checked_by),
        "degraded": check.degraded,
        "latency_ms": check.latency_ms,
        "engine_version": check.engine_version,
        "source_revision": check.source_revision,
        "policy_version": check.policy_version,
    }


def _scenario_id(item: Mapping[str, Any], source: Path, index: int) -> str:
    return str(
        item.get("case_id")
        or item.get("query_id")
        or f"{source.stem}-{index:03d}"
    )


def _request_prefix(batch_id: str, app_id: str, scenario_id: str) -> str:
    """Keep derived stream request IDs below the API's 128-character limit."""

    digest = hashlib.sha256(str(scenario_id).encode("utf-8")).hexdigest()[:16]
    return f"{str(batch_id)[:32]}:{app_id}:{digest}"


def _merge_retry_results(
    previous: list[Mapping[str, Any]],
    retried: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    replacements = {
        (str(item.get("app_id") or ""), str(item.get("scenario_id") or "")): dict(item)
        for item in retried
    }
    return [
        replacements.get(
            (str(item.get("app_id") or ""), str(item.get("scenario_id") or "")),
            dict(item),
        )
        for item in previous
    ]


def _messages(item: Mapping[str, Any]) -> list[str]:
    values = item.get("messages") or item.get("customer_messages") or []
    return [str(value) for value in values if str(value).strip()]


def _source_reply(item: Mapping[str, Any]) -> str:
    turns = item.get("turns") or []
    if not isinstance(turns, list):
        return ""
    for turn in reversed(turns):
        if isinstance(turn, Mapping) and str(turn.get("reply") or "").strip():
            return str(turn.get("reply") or "")
    return ""


def load_ai_web_security_scenarios(paths: list[Path]) -> list[dict[str, Any]]:
    """Normalize regression and EPE reports into replayable, target-scoped cases."""

    scenarios: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for path in paths:
        report = json.loads(path.read_text(encoding="utf-8"))
        target = report.get("target") if isinstance(report, Mapping) else None
        app_id = str((target or {}).get("app_id") or "")
        if not app_id.isdigit():
            raise ValueError(f"{path} 不是有效的 ai-web 测试报告")
        results = report.get("results") if isinstance(report, Mapping) else None
        if not isinstance(results, list):
            raise ValueError(f"{path} 缺少 results")
        for index, item in enumerate(results, start=1):
            if not isinstance(item, Mapping):
                continue
            messages = _messages(item)
            if not messages:
                continue
            scenario_id = _scenario_id(item, path, index)
            identity = (app_id, scenario_id)
            if identity in seen:
                continue
            seen.add(identity)
            scenarios.append(
                {
                    "scenario_id": scenario_id,
                    "app_id": app_id,
                    "source_report": str(path.resolve()),
                    "source_run_id": str(
                        report.get("run_id") or report.get("experiment_id") or ""
                    ),
                    "pack_id": str(item.get("pack_id") or "prompt_leakage"),
                    "messages": messages,
                    "source_reply": _source_reply(item),
                    "source_outcome": str(item.get("outcome") or ""),
                }
            )
    return scenarios


def _check_stream(
    guard: RiskGuardClient,
    content: str,
    *,
    request_id: str,
    chunk_size: int,
) -> dict[str, Any]:
    if not content:
        return {"blocked": False, "stream": None, "final": None}
    stream = guard.output_stream(request_id=request_id)
    stream_decision: GuardCheck | None = None
    for start in range(0, len(content), chunk_size):
        decision = stream.push(content[start : start + chunk_size])
        if decision.blocked:
            stream_decision = decision
            break
    final = stream.finish()
    return {
        "blocked": bool(stream.blocked),
        "stream": _check_dict(stream_decision),
        "final": _check_dict(final),
    }


def _is_leak(outcome: str) -> bool:
    return str(outcome or "").upper() not in _NON_LEAK_OUTCOMES


def _summarize(results: list[Mapping[str, Any]]) -> dict[str, Any]:
    total = len(results)
    source_leaks = sum(
        _is_leak(str(item.get("source_outcome") or "")) for item in results
    )
    source_resisted = total - source_leaks
    input_blocks = sum(
        any(
            str(check.get("decision") or "") == "BLOCK"
            for check in item.get("input_checks") or []
        )
        for item in results
    )
    source_output_blocks = sum(
        bool((item.get("source_output_guard") or {}).get("blocked"))
        for item in results
    )
    source_leak_blocks = sum(
        _is_leak(str(item.get("source_outcome") or ""))
        and bool((item.get("source_output_guard") or {}).get("blocked"))
        for item in results
    )
    source_leak_combined_blocks = sum(
        _is_leak(str(item.get("source_outcome") or ""))
        and (
            any(
                str(check.get("decision") or "") == "BLOCK"
                for check in item.get("input_checks") or []
            )
            or bool((item.get("source_output_guard") or {}).get("blocked"))
        )
        for item in results
    )
    attributions = Counter(str(item.get("attribution") or "ERROR") for item in results)
    protected = sum(
        str(item.get("attribution") or "")
        in {"GUARD_INPUT_BLOCKED", "AGENT_RESISTED", "GUARD_OUTPUT_BLOCKED"}
        for item in results
    )
    return {
        "scenario_count": total,
        "source_leak_count": source_leaks,
        "source_bare_resisted_count": source_resisted,
        "source_bare_protection_rate": (
            round(source_resisted / total, 4) if total else 0.0
        ),
        "input_guard_block_count": input_blocks,
        "source_output_guard_block_count": source_output_blocks,
        "source_leak_output_guard_block_count": source_leak_blocks,
        "source_leak_output_guard_recall": (
            round(source_leak_blocks / source_leaks, 4) if source_leaks else None
        ),
        "source_leak_combined_guard_block_count": source_leak_combined_blocks,
        "source_leak_combined_guard_recall": (
            round(source_leak_combined_blocks / source_leaks, 4)
            if source_leaks
            else None
        ),
        "live_protected_count": protected,
        "live_protection_rate": round(protected / total, 4) if total else 0.0,
        "live_guard_block_count": (
            attributions["GUARD_INPUT_BLOCKED"]
            + attributions["GUARD_OUTPUT_BLOCKED"]
        ),
        "live_leak_passed_count": attributions["LEAK_PASSED_GUARD"],
        "live_attribution": dict(sorted(attributions.items())),
    }


def _markdown(report: Mapping[str, Any]) -> str:
    summary = report.get("summary") or {}
    attribution = summary.get("live_attribution") or {}
    lines = [
        "# ai-web 接入 Risk Guard 安全对比",
        "",
        f"- 批次：`{report.get('batch_id')}`",
        f"- 样本：{summary.get('scenario_count', 0)} 条",
        f"- 历史泄露：{summary.get('source_leak_count', 0)} 条",
        "- 裸 Agent 历史保护率："
        f"{summary.get('source_bare_resisted_count', 0)}/"
        f"{summary.get('scenario_count', 0)}",
        "- 历史泄露回复被输出护栏补拦："
        f"{summary.get('source_leak_output_guard_block_count', 0)}/"
        f"{summary.get('source_leak_count', 0)}",
        "- 历史泄露经输入或输出护栏合并保护："
        f"{summary.get('source_leak_combined_guard_block_count', 0)}/"
        f"{summary.get('source_leak_count', 0)}",
        "- 实际接入链路保护："
        f"{summary.get('live_protected_count', 0)}/"
        f"{summary.get('scenario_count', 0)}",
        "",
        "## 实际链路归因",
        "",
    ]
    labels = {
        "GUARD_INPUT_BLOCKED": "输入护栏拦截（未请求 Agent）",
        "AGENT_RESISTED": "Agent 自身抵抗",
        "GUARD_OUTPUT_BLOCKED": "输出护栏补拦",
        "LEAK_PASSED_GUARD": "泄露穿透护栏",
        "ERROR": "执行错误",
    }
    for key in (
        "GUARD_INPUT_BLOCKED",
        "AGENT_RESISTED",
        "GUARD_OUTPUT_BLOCKED",
        "LEAK_PASSED_GUARD",
        "ERROR",
    ):
        lines.append(f"- {labels[key]}：{attribution.get(key, 0)}")
    lines.extend(["", "## 分 Agent", ""])
    for app_id, item in sorted((report.get("by_agent") or {}).items()):
        lines.append(
            f"- `{app_id}`：保护 {item.get('live_protected_count', 0)}/"
            f"{item.get('scenario_count', 0)}；历史泄露输出补拦 "
            f"{item.get('source_leak_output_guard_block_count', 0)}/"
            f"{item.get('source_leak_count', 0)}"
        )
    return "\n".join(lines) + "\n"


def run_ai_web_guard_security(args: Any) -> dict[str, Any]:
    paths = [Path(value).resolve() for value in args.guard_ai_web_source_report]
    scenarios = load_ai_web_security_scenarios(paths)
    if not scenarios:
        raise ValueError("源报告中没有可重放的 ai-web 攻击")
    limit = int(args.guard_ai_web_limit or 0)
    if limit > 0:
        scenarios = scenarios[:limit]
    previous_results: list[Mapping[str, Any]] = []
    retry_path_value = getattr(args, "guard_ai_web_retry_errors_from", None)
    if retry_path_value:
        retry_report = json.loads(Path(retry_path_value).read_text(encoding="utf-8"))
        previous_results = [
            item
            for item in retry_report.get("results") or []
            if isinstance(item, Mapping)
        ]
        retry_identities = {
            (str(item.get("app_id") or ""), str(item.get("scenario_id") or ""))
            for item in previous_results
            if str(item.get("attribution") or "") == "ERROR"
        }
        scenarios = [
            item
            for item in scenarios
            if (str(item["app_id"]), str(item["scenario_id"])) in retry_identities
        ]
        if not scenarios:
            raise ValueError("指定报告中没有可重跑的 ERROR")
    batch_id = str(
        args.batch_id
        or "GAWS-" + datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    )
    if bool(args.dry_run):
        return {
            "status": "READY_NO_INTERFACE",
            "batch_id": batch_id,
            "scenario_count": len(scenarios),
            "by_agent": dict(sorted(Counter(item["app_id"] for item in scenarios).items())),
        }

    progress = TerminalProgress()
    clients: dict[str, Any] = {}
    runtimes: dict[str, tuple[dict[str, Any], Mapping[str, Any], str]] = {}
    for app_id in sorted({item["app_id"] for item in scenarios}):
        require_ai_web_contract(f"ai-web:{app_id}")
        target_args = copy.copy(args)
        target_args.target = f"ai-web:{app_id}"
        target_args.target_adapter = "ai-web"
        target_args.app_id = app_id
        profile = resolve_target_profile(target_args)
        client = build_target_client(target_args, profile)
        health = client.health()
        if not bool(health.get("target_visible")):
            raise ValueError(f"授权账号不可见 ai-web:{app_id}")
        registry_path = resolve_ai_web_asset_registry(app_id)
        assets = load_protected_assets(registry_path)
        pack = load_attack_pack("prompt_leakage")
        runtime = prepare_pack_oracle(
            pack,
            asset_registry=registry_path,
            selected_asset_ids=[],
            selected_marker_group_ids=[],
        )
        clients[app_id] = client
        runtimes[app_id] = (pack, runtime, str(assets.get("snapshot_id") or ""))

    guards = {
        app_id: RiskGuardClient(
            agent_id=app_id,
            base_url=str(args.guard_base_url),
            token=str(args.guard_token or ""),
            timeout=float(args.guard_timeout),
            fail_mode="closed",
        )
        for app_id in clients
    }
    guard_health = next(iter(guards.values())).health()
    chunk_size = int(args.guard_stream_chunk_size)
    if chunk_size < 1:
        raise ValueError("--stream-chunk-size 必须大于 0")
    workers = min(max(1, int(args.guard_workers)), len(scenarios))

    def execute(position: int, scenario: Mapping[str, Any]) -> dict[str, Any]:
        started = time.monotonic()
        app_id = str(scenario["app_id"])
        client = clients[app_id]
        guard = guards[app_id]
        pack, runtime, snapshot_id = runtimes[app_id]
        request_prefix = _request_prefix(
            batch_id,
            app_id,
            str(scenario["scenario_id"]),
        )
        result = dict(scenario)
        result.update(
            {
                "asset_snapshot_id": snapshot_id,
                "source_output_guard": None,
                "input_checks": [],
                "live_turns": [],
                "live_oracle": None,
                "live_outcome": "NOT_EXECUTED",
                "attribution": "ERROR",
                "error": None,
            }
        )
        progress.emit(
            "AIWEB-GUARD",
            f"{position}/{len(scenarios)} {scenario['scenario_id']} | {app_id}",
        )
        try:
            source_reply = str(scenario.get("source_reply") or "")
            result["source_output_guard"] = _check_stream(
                guard,
                source_reply,
                request_id=f"{request_prefix}:source-output",
                chunk_size=chunk_size,
            )
            blocked_input = False
            for turn_index, message in enumerate(scenario["messages"], start=1):
                input_check = guard.check_input(
                    str(message),
                    request_id=f"{request_prefix}:input:{turn_index}",
                )
                result["input_checks"].append(_check_dict(input_check))
                if input_check.blocked:
                    blocked_input = True
                    break
            if blocked_input:
                result["attribution"] = "GUARD_INPUT_BLOCKED"
                return result

            session = client.init_test(
                wx_account=f"{batch_id}-{position}-ACCOUNT",
                wx_contact=f"{batch_id}-{position}-CONTACT",
            )
            for turn_index, message in enumerate(scenario["messages"], start=1):
                trace = client.chat(session, str(message), allow_transport_retry=True)
                reply = str(trace.get("reply") or "")
                output_guard = _check_stream(
                    guard,
                    reply,
                    request_id=f"{request_prefix}:live-output:{turn_index}",
                    chunk_size=chunk_size,
                )
                result["live_turns"].append(
                    {
                        "turn_index": turn_index,
                        "session": asdict(session),
                        "message": str(message),
                        "reply": reply,
                        "trace": trace,
                        "output_guard": output_guard,
                    }
                )
                if output_guard["blocked"]:
                    break
            candidate = score_pack_turns(pack, result["live_turns"], runtime)
            result["live_oracle"] = candidate
            result["live_outcome"] = str(candidate.get("outcome") or "INVALID")
            output_blocked = any(
                bool((turn.get("output_guard") or {}).get("blocked"))
                for turn in result["live_turns"]
            )
            if not oracle_success(pack, candidate):
                result["attribution"] = "AGENT_RESISTED"
            elif output_blocked:
                result["attribution"] = "GUARD_OUTPUT_BLOCKED"
            else:
                result["attribution"] = "LEAK_PASSED_GUARD"
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {redact_value(str(exc))}"
            result["attribution"] = "ERROR"
        finally:
            result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    try:
        indexed = list(enumerate(scenarios, start=1))
        if workers == 1:
            retried_results = [execute(position, item) for position, item in indexed]
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                retried_results = list(pool.map(lambda pair: execute(*pair), indexed))
    finally:
        for guard in guards.values():
            guard.close()

    results = (
        _merge_retry_results(previous_results, retried_results)
        if previous_results
        else retried_results
    )

    by_agent = {
        app_id: _summarize([item for item in results if item["app_id"] == app_id])
        for app_id in sorted({item["app_id"] for item in results})
    }
    report = {
        "schema_version": "1.0-ai-web-guard-security",
        "status": "COMPLETED" if not any(item.get("error") for item in results) else "PARTIAL",
        "batch_id": batch_id,
        "created_at": _now(),
        "source_reports": [str(path) for path in paths],
        "guard_health": {
            key: guard_health.get(key)
            for key in (
                "status",
                "engine_version",
                "source_revision",
                "policy_version",
                "qwen_guard_enabled",
                "aliyun_guardrail_enabled",
            )
        },
        "summary": _summarize(results),
        "by_agent": by_agent,
        "results": results,
    }
    output_dir = Path(
        args.guard_ai_web_output_dir
        or AI_WEB_INTEGRATION_RESULTS_DIR / "guard" / "security"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{batch_id}.json"
    markdown_path = output_dir / f"{batch_id}.md"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(_markdown(report), encoding="utf-8")
    return {
        "status": report["status"],
        "batch_id": batch_id,
        "summary": report["summary"],
        "by_agent": by_agent,
        "json": str(json_path.resolve()),
        "markdown": str(markdown_path.resolve()),
    }


__all__ = ["load_ai_web_security_scenarios", "run_ai_web_guard_security"]
