"""Run queue-controlled adaptive positive business conversations against ky-sales."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Mapping

from ..clients.factory import build_target_client, resolve_target_profile
from ..clients.model import OpenAICompatibleClient, load_model_settings
from ..clients.target import KyAgentError, build_test_identity
from ..core.paths import (
    BUSINESS_BAD_CASES_PATH,
    BUSINESS_DYNAMIC_RESULTS_DIR,
    BUSINESS_SCENARIO_SOURCES_PATH,
)
from ..core.progress import TerminalProgress
from ..core.redaction import redact_value
from .dynamic_controller import (
    classify_handoff_event,
    decide_next_customer_turn,
    generate_initial_customer_turn,
)
from .judge import judge_business_case
from .scenario_cards import (
    build_side_scene_candidates,
    build_scene_plan,
    evaluation_task,
    initial_message_for_plan,
    select_main_scene_ids,
)
from .scenario_sources import load_scenario_sources
from .strategies import (
    select_expression_style,
    strategy_summary,
)


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _quote_markdown(value: Any) -> list[str]:
    """Render user/Agent text as a readable Markdown quote."""

    text = str(value or "").strip()
    if not text:
        return ["> （空）"]
    return [f"> {line}" if line else ">" for line in text.splitlines()]


def _source_instance_id(source: Mapping[str, Any]) -> str:
    """Return the per-run Case key while preserving the original source ID."""

    return str(source.get("_run_case_id") or source.get("source_id") or "")


_BATCH_INITIAL_NEAR_DUPLICATE_THRESHOLD = 0.90
_BATCH_INITIAL_DUPLICATE_RETRIES = 2


def _normalized_initial_message(value: Any) -> str:
    """Normalize a customer question for cross-Case novelty checks."""

    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", str(value or "").casefold())


def _initial_message_similarity(left: Any, right: Any) -> float:
    first = _normalized_initial_message(left)
    second = _normalized_initial_message(right)
    if not first or not second:
        return 0.0
    return SequenceMatcher(None, first, second).ratio()


def _batch_initial_duplicate(
    message: Any,
    existing: list[tuple[str, str]],
    *,
    threshold: float = _BATCH_INITIAL_NEAR_DUPLICATE_THRESHOLD,
) -> tuple[str, float] | None:
    """Return the first already-reserved Case that is too close to ``message``.

    The batch check deliberately runs after the per-source/history checks in
    the generator.  It is a novelty guard for a run, not a business-validity
    decision: a duplicate is retried when possible and retained with evidence
    when the model cannot produce a different question.
    """

    best: tuple[str, float] | None = None
    for case_id, previous in existing:
        similarity = _initial_message_similarity(message, previous)
        if similarity < threshold:
            continue
        if best is None or similarity > best[1]:
            best = (case_id, similarity)
    return best


def _select_sources(args: Any, *, sample_salt: str = "") -> list[dict[str, Any]]:
    path = Path(
        getattr(args, "business_scenario_sources", None)
        or BUSINESS_SCENARIO_SOURCES_PATH
    )
    library = load_scenario_sources(path)
    selected_ids = {
        str(item).strip()
        for item in getattr(args, "business_source_id", None) or []
        if str(item).strip()
    }
    scenario_type = str(
        getattr(args, "business_scenario_type", None) or "all"
    ).strip()
    sources = [
        dict(item)
        for item in library.get("sources") or []
        if str(item.get("status") or "active") == "active"
        and (
            scenario_type == "all"
            or str(item.get("scenario_type") or "") == scenario_type
        )
        and (not selected_ids or str(item.get("source_id") or "") in selected_ids)
    ]
    if bool(getattr(args, "business_random_sample", False)):
        # Shuffle deterministically within each source family, then interleave
        # the families.  A plain global shuffle can still leave a 50-case run
        # dominated by the first family by chance; round-robin makes the
        # diversity guarantee visible and reproducible in the report.
        buckets: dict[str, list[dict[str, Any]]] = {}
        for item in sources:
            family = str(item.get("scenario_type") or "unknown").strip() or "unknown"
            buckets.setdefault(family, []).append(item)
        for family, values in buckets.items():
            values.sort(
                key=lambda item: hashlib.sha256(
                    f"business-sources:{sample_salt}:{family}:"
                    f"{item.get('source_id') or ''}".encode("utf-8")
                ).digest()
            )
        family_order = sorted(
            buckets,
            key=lambda family: hashlib.sha256(
                f"business-source-families:{sample_salt}:{family}".encode("utf-8")
            ).digest(),
        )
        interleaved: list[dict[str, Any]] = []
        indexes = {family: 0 for family in family_order}
        while True:
            added = False
            for family in family_order:
                index = indexes[family]
                values = buckets[family]
                if index >= len(values):
                    continue
                interleaved.append(values[index])
                indexes[family] = index + 1
                added = True
            if not added:
                break
        sources = interleaved
    if selected_ids:
        found = {str(item.get("source_id") or "") for item in sources}
        missing = sorted(selected_ids - found)
        if missing:
            raise ValueError("未找到当前场景的业务来源：" + ", ".join(missing))
    limit = int(getattr(args, "business_limit", 1) or 1)
    if limit < 1:
        raise ValueError("--limit 必须大于 0")
    if bool(getattr(args, "business_random_sample", False)) and not selected_ids:
        from .materials import prioritize_material_sources

        sources = prioritize_material_sources(
            sources,
            scenes=set(getattr(args, "business_scene", None) or []),
            limit=limit,
            history_path=path.parent / ".material_usage.sqlite3",
            preserve_families=True,
        )
    if limit <= len(sources) or not sources:
        return sources[:limit]
    if not bool(getattr(args, "business_random_sample", False)):
        return sources

    # A source is a reusable, desensitized customer/business backdrop rather
    # than a frozen test Case. Random generation may therefore derive more
    # independent Cases than there are unique sources. Each derived Case keeps
    # the original source_id for traceability and gets its own run key so scene
    # selection, strategy, expression and report maps do not collide.
    expanded: list[dict[str, Any]] = []
    occurrences: Counter[str] = Counter()
    for index in range(limit):
        source = dict(sources[index % len(sources)])
        source_id = str(source.get("source_id") or "")
        occurrences[source_id] += 1
        if occurrences[source_id] > 1:
            source["_run_case_id"] = (
                f"{source_id}-VAR-{occurrences[source_id]:02d}"
            )
            source["_source_variant_index"] = occurrences[source_id]
        expanded.append(source)
    return expanded


def _judge_case(
    source: Mapping[str, Any],
    scenario_plan: list[Mapping[str, Any]],
    execution: Mapping[str, Any] | None = None,
    *,
    case_id: str | None = None,
) -> dict[str, Any]:
    execution = execution or {}
    return {
        "case_id": case_id or source.get("source_id"),
        "source_id": source.get("source_id"),
        "scenario": source.get("scenario") or {},
        "scenario_plan": scenario_plan,
        "customer_profile": source.get("customer_profile") or {},
        "core_task": evaluation_task(scenario_plan),
        "source_core_task": source.get("core_task") or {},
        "grounded_customer_facts": source.get("grounded_customer_facts") or {},
        "baseline": source.get("baseline") or {},
        "reference_turns": source.get("reference_customer_turns") or [],
        "execution_context": {
            "stop_reason": execution.get("stop_reason"),
            "required_side_scene_ids": execution.get("required_side_scene_ids") or [],
            "selected_side_scene_ids": execution.get("side_scene_ids") or [],
        },
    }


def _apply_controller_plan(item: dict[str, Any], decision: Mapping[str, Any]) -> None:
    """Persist a side card selected dynamically by the CR controller."""

    updated_plan = decision.get("scenario_plan")
    if not isinstance(updated_plan, list) or not updated_plan:
        return
    item["scenario_plan"] = [
        dict(scene) for scene in updated_plan if isinstance(scene, Mapping)
    ]
    item["side_scene_ids"] = [
        str(scene.get("id") or "")
        for scene in item["scenario_plan"]
        if str(scene.get("plan_role") or "main") == "side"
    ]
    item["core_task"] = evaluation_task(item["scenario_plan"])


def _allocate_side_quotas(
    sources: list[Mapping[str, Any]],
    candidates_by_source: Mapping[str, list[Mapping[str, Any]]],
    *,
    count: int,
    salt: str,
) -> dict[str, list[dict[str, Any]]]:
    """Allocate exact per-case side coverage while balancing the whole batch."""

    usage: Counter[str] = Counter()
    allocation: dict[str, list[dict[str, Any]]] = {}
    for position, source in enumerate(sources, start=1):
        source_id = _source_instance_id(source)
        candidates = [dict(item) for item in candidates_by_source.get(source_id) or []]
        if count > len(candidates):
            raise ValueError(
                f"来源 {source_id} 只有 {len(candidates)} 个可用支线，无法分配 {count} 个"
            )
        ranked = sorted(
            candidates,
            key=lambda item: (
                usage[str(item.get("id") or "")],
                hashlib.sha256(
                    f"side-quota:{salt}:{position}:{item.get('id') or ''}".encode(
                        "utf-8"
                    )
                ).digest(),
            ),
        )
        selected = []
        for slot, item in enumerate(ranked[:count], start=1):
            scene_id = str(item.get("id") or "")
            selected.append(
                {**item, "coverage_required": True, "coverage_slot": slot}
            )
            usage[scene_id] += 1
        allocation[source_id] = selected
    return allocation


def _merge_main_and_side_plan(
    main_plan: list[Mapping[str, Any]], side_quota: list[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Build a stable coverage ledger; runtime routing never mutates its order."""

    merged: list[dict[str, Any]] = []
    for index, main in enumerate(main_plan):
        merged.append(dict(main))
        if index < len(side_quota):
            merged.append(dict(side_quota[index]))
    merged.extend(dict(item) for item in side_quota[len(main_plan) :])
    return merged


def _is_transport_empty_trace(trace: Mapping[str, Any]) -> bool:
    """Identify an empty SSE transport, not a meaningful empty Agent answer."""

    if not str(trace.get("reply") or "").strip() and str(trace.get("stream_end_reason") or "").lower() in {"idle_timeout", "timeout", "connection_error", "read_timeout"}:
        return True
    event_counts = trace.get("event_type_counts")
    observed_events = bool(event_counts) if isinstance(event_counts, Mapping) else False
    return not any(
        (
            str(trace.get("reply") or "").strip(),
            str(trace.get("thinking") or "").strip(),
            trace.get("tool_calls") or [],
            trace.get("tool_results") or [],
            trace.get("errors") or [],
            observed_events,
        )
    )


def _apply_judge_completion_gate(item: dict[str, Any]) -> None:
    """Record coverage separately; retain checks on actual judgment evidence."""

    judge = item.get("judge")
    if not isinstance(judge, dict):
        return
    plan_ids = [
        str(scene.get("id") or "")
        for scene in item.get("scenario_plan") or []
        if isinstance(scene, Mapping) and str(scene.get("id") or "")
    ]
    controllers = [
        turn.get("controller")
        for turn in item.get("turns") or []
        if isinstance(turn, Mapping) and isinstance(turn.get("controller"), Mapping)
    ]
    latest = dict(controllers[-1]) if controllers else {}
    completed = {
        str(scene_id)
        for scene_id in latest.get("completed_scene_ids") or []
        if str(scene_id)
    }
    resolved = {
        str(scene_id)
        for scene_id in latest.get("resolved_scene_ids") or []
        if str(scene_id)
    }
    external_pending = {
        str(scene_id)
        for scene_id in latest.get("external_pending_scene_ids") or []
        if str(scene_id)
    }
    deferred = {
        str(scene_id)
        for scene_id in latest.get("deferred_scene_ids") or []
        if str(scene_id)
    }
    session_transferred = any(
        classify_handoff_event(turn)["state"] == "SESSION_TRANSFERRED"
        for turn in item.get("turns") or []
        if isinstance(turn, Mapping)
    )
    all_direct_or_owned_paths_complete = bool(plan_ids) and set(plan_ids).issubset(
        completed
    )
    valid_external_terminal = bool(plan_ids) and set(plan_ids).issubset(completed) and (
        bool(external_pending) or session_transferred
    )
    terminal_path_observed = (
        all_direct_or_owned_paths_complete
        or valid_external_terminal
        # A successfully evidenced, explicitly requested human transfer ends
        # the whole session; later cards are intentionally not sent.
        or session_transferred
    )
    unresolved = [scene_id for scene_id in plan_ids if scene_id not in resolved]
    unexecuted = [
        scene_id
        for scene_id in plan_ids
        if scene_id not in completed
        and not (session_transferred and scene_id in deferred)
    ]
    state_conflicts = [
        scene_id for scene_id in plan_ids if scene_id in completed and scene_id in deferred
    ]
    scene_assessments = {
        str(value.get("scene_id") or ""): str(value.get("status") or "").lower()
        for value in judge.get("scene_assessments") or []
        if isinstance(value, Mapping) and str(value.get("scene_id") or "")
    }
    assessed_plan_ids = (
        [scene_id for scene_id in plan_ids if scene_id in completed]
        if session_transferred
        else plan_ids
    )
    judge_missing = [
        scene_id for scene_id in assessed_plan_ids if scene_id not in scene_assessments
    ]
    judge_incomplete = [
        scene_id
        for scene_id in assessed_plan_ids
        if scene_assessments.get(scene_id) in {"deferred", "incomplete", "not_executed"}
    ]
    gate = {
        "status": "PASS" if terminal_path_observed else "INCOMPLETE",
        "plan_scene_ids": plan_ids,
        "completed_scene_ids": [value for value in plan_ids if value in completed],
        "resolved_scene_ids": [value for value in plan_ids if value in resolved],
        "external_pending_scene_ids": [
            value for value in plan_ids if value in external_pending
        ],
        "unresolved_scene_ids": unresolved,
        "unexecuted_scene_ids": unexecuted,
        "deferred_scene_ids": [value for value in plan_ids if value in deferred],
        "state_conflict_scene_ids": state_conflicts,
        "judge_missing_scene_ids": judge_missing,
        "judge_incomplete_scene_ids": judge_incomplete,
        "valid_session_transfer": session_transferred,
    }
    judge["completion_gate"] = gate
    judge["business_scope"] = "observed_dialogue"
    gate["coverage_status"] = "complete" if terminal_path_observed and not unexecuted else "partial"
    if (
        str(item.get("stop_reason") or "")
        in {
            "controller_contract_unrecoverable",
            "controller_evaluation_unrecoverable",
            "controller_evaluation_error",
            "customer_generation_unrecoverable",
        }
        and str(judge.get("decision") or "").upper() == "FAIL"
        and not judge.get("verified_failure_evidence")
    ):
        judge["model_decision"] = "FAIL"
        judge["decision"] = "REVIEW"
        try:
            judge["score"] = max(40, min(int(judge.get("score") or 40), 69))
        except (TypeError, ValueError):
            judge["score"] = 40
        judge["reason"] = (
            "确定性责任门禁：测试因控制器契约问题提前停止，"
            "不能把未完成计划直接归责为 Agent FAIL。模型原结论："
            + str(judge.get("reason") or "")
        )[:3000]
        flags = [str(value) for value in judge.get("risk_flags") or []]
        judge["risk_flags"] = list(
            dict.fromkeys([*flags, "TEST_CONTROLLER_CONTRACT"])
        )
        gate["status"] = "CONTROLLER_REVIEW"
        return
    if str(judge.get("decision") or "").upper() != "PASS":
        return

    # Coverage is execution metadata, not an automatic business verdict.
    # Still reject a PASS whose judge omitted an actually assessed scene or
    # contradicts its own evidence of an incomplete Agent responsibility.
    observed = completed | {
        str(c.get("evaluated_scene_id") or c.get("from_scene_id") or "")
        for c in controllers
    }
    observed.discard("")
    missing_observed = [sid for sid in judge_missing if sid in observed]
    contradictory = [
        str(a.get("scene_id")) for a in judge.get("scene_assessments") or []
        if isinstance(a, Mapping) and a.get("status") == "incomplete"
        and a.get("owner", "unknown") in {"agent", "mixed", "unknown"}
    ]
    partial = not terminal_path_observed or bool(unexecuted or state_conflicts or judge_incomplete)
    judge["business_scope"] = "observed_dialogue"
    gate["coverage_status"] = "partial" if partial else "complete"
    gate["observed_scene_ids"] = [sid for sid in plan_ids if sid in observed]
    gate["observed_judge_missing_scene_ids"] = missing_observed
    if not item.get("turns") or missing_observed or contradictory:
        judge["model_decision"] = "PASS"
        judge["decision"] = "REVIEW"
        judge["score"] = min(int(judge.get("score") or 69), 69)
        gate["status"] = "CAPPED_TO_REVIEW"
        judge["reason"] = (
            "评判证据不完整或结论矛盾：缺少已执行场景的评估，或模型同时认定Agent职责未完成。"
            "原模型结论：" + str(judge.get("reason") or "")
        )
        return
    if partial:
        gate["status"] = "PARTIAL_COVERAGE"
        judge["coverage_note"] = (
            "通过仅针对已发生的对话；计划中未执行或等待外部确认的场景不计为通过。"
        )


def _markdown(report: Mapping[str, Any]) -> str:
    summary = report.get("summary") or {}
    lines = [
        "# ky-sales 动态正向业务回归",
        "",
        f"- Run：`{report.get('run_id')}`",
        f"- 场景类型：`{report.get('scenario_type')}`",
        f"- 场景模式：`{report.get('scene_mode', 'single')}`",
        f"- 随机抽取来源：{'是' if report.get('random_sample') else '否'}",
        f"- Case 并发数：{report.get('workers', 1)}",
        f"- 每条主线数量：{report.get('main_scene_count') or '默认计划'}",
        f"- 每条支线覆盖目标：{report.get('side_scene_count', 0)}",
        f"- 每场景恢复上限：{report.get('max_recovery_attempts', 2)}",
        f"- 测试 Case 数量：{summary.get('total', 0)}",
        f"- 唯一场景来源数量：{summary.get('unique_source_count', summary.get('total', 0))}",
        f"- 首轮问题唯一数：{summary.get('unique_initial_message_count', 0)} / {summary.get('initial_message_count', 0)}",
        f"- 首轮问题重复数/重复率：{summary.get('initial_message_duplicate_count', 0)} / {summary.get('initial_message_duplicate_rate', 0)}",
        f"- 首轮近似重复对数/涉及 Case：{summary.get('near_duplicate_initial_pair_count', 0)} / {summary.get('near_duplicate_initial_case_count', 0)}",
        f"- 批次去重重试/仍未解决：{summary.get('initial_batch_duplicate_repairs', 0)} / {summary.get('initial_batch_duplicate_unresolved', 0)}",
        "- 来源场景分布："
        + json.dumps(
            summary.get("source_scenario_counts") or {},
            ensure_ascii=False,
        ),
        "- 首轮主场景分布："
        + json.dumps(
            summary.get("initial_main_scene_counts") or {},
            ensure_ascii=False,
        ),
        f"- 已评估对话通过：{summary.get('PASS', 0)}（其中部分覆盖：{summary.get('partial_coverage_pass', 0)}）",
        f"- 失败：{summary.get('FAIL', 0)}",
        f"- 待复核：{summary.get('REVIEW', 0)}",
        f"- 场景无效：{summary.get('INVALID', 0)}",
        f"- 执行错误：{summary.get('ERROR', 0)}",
        f"- 其中空 SSE 接口错误：{summary.get('transport_empty_errors', 0)}",
        "- 首轮生成来源："
        + json.dumps(
            summary.get("initial_generation_source_counts") or {},
            ensure_ascii=False,
        ),
        f"- 首轮模板兜底：{summary.get('initial_generation_fallbacks', 0)}",
        f"- 首轮被门禁淘汰候选：{summary.get('initial_candidates_rejected', 0)}",
        f"- 首轮生成格式/质量纠错：{summary.get('initial_generation_repairs', 0)}",
        f"- 首轮事实契约兜底：{summary.get('initial_fact_contract_fallbacks', 0)}",
        f"- 其中发现无依据型号：{summary.get('initial_ungrounded_fact_contracts', 0)}",
        f"- 转人工正常结束：{summary.get('human_handoff_completed', 0)}",
        f"- 等待外部结果场景：{summary.get('external_pending_scenes', 0)}",
        f"- 重复转人工：{summary.get('duplicate_handoffs', 0)}",
        f"- 转人工失败：{summary.get('handoff_failures', 0)}",
        f"- 空业务结果且未可靠转交：{summary.get('unverified_business_handoffs', 0)}",
        f"- 当前场景评估纠错：{summary.get('turn_evaluation_repairs', 0)}",
        f"- 下一轮话术生成纠错：{summary.get('followup_generation_repairs', 0)}",
        f"- 下一轮话术确定性兜底：{summary.get('followup_generation_fallbacks', 0)}",
        f"- 当前场景评估停止：{summary.get('controller_evaluation_stops', 0)}",
        f"- 下一轮话术生成停止：{summary.get('customer_generation_stops', 0)}",
        f"- 未完整执行而降为待复核：{summary.get('judge_completion_caps', 0)}",
        f"- 支线计划槽位：{summary.get('side_quota_planned', 0)}",
        f"- 支线已完成或可靠转交：{summary.get('side_quota_completed', 0)}",
        f"- 完成全部支线配额的 Case：{summary.get('side_quota_completed_cases', 0)}",
        "",
        "## 结果",
        "",
    ]
    for item in report.get("results") or []:
        judge = item.get("judge") or {}
        completed_scene_ids = {
            str(scene_id)
            for turn in item.get("turns") or []
            for scene_id in (turn.get("controller") or {}).get(
                "completed_scene_ids", []
            )
            if str(scene_id)
        }
        lines.extend(
            [
                f"### {item.get('source_id')} · {item.get('outcome')}",
                "",
                f"- 场景：{(item.get('scenario') or {}).get('summary', '')}",
                "- 场景卡："
                + ", ".join(
                    str(scene.get("name") or scene.get("id") or "")
                    for scene in item.get("scenario_plan") or []
                ),
                "- 计划支线："
                + (
                    ", ".join(
                        str(scene.get("name") or scene.get("id") or "")
                        for scene in item.get("scenario_plan") or []
                        if str(scene.get("plan_role") or "main") == "side"
                    )
                    or "未选择"
                ),
                "- 本条支线配额："
                + (", ".join(item.get("required_side_scene_ids") or []) or "无"),
                "- 已完成或可靠转交支线："
                + (
                    ", ".join(
                        scene_id
                        for scene_id in item.get("required_side_scene_ids") or []
                        if scene_id in completed_scene_ids
                    )
                    or "无"
                ),
                "- 可选支线池："
                + (
                    ", ".join(
                        str(scene.get("name") or scene.get("id") or "")
                        for scene in item.get("side_scene_candidates") or []
                    )
                    or "无"
                ),
                f"- 客户策略：{(item.get('conversation_strategy') or {}).get('name', '')}",
                f"- 表达方式：{(item.get('expression_style') or {}).get('name', '')}",
                f"- 首轮生成：{(item.get('initial_generation') or {}).get('generation_source', '')}",
                f"- 首轮历史最大相似度：{(item.get('initial_generation') or {}).get('reference_similarity', '')}",
                f"- 首轮批次近似重复：{(item.get('initial_generation') or {}).get('batch_duplicate_of', '') or '无'}",
                f"- 首轮批次去重重试：{(item.get('initial_generation') or {}).get('batch_duplicate_repair_count', 0)}",
                "- 首轮事实门禁："
                + (
                    ", ".join(
                        str(value)
                        for value in (item.get("initial_generation") or {}).get(
                            "grounded_fact_validation_errors", []
                        )
                    )
                    or "通过"
                ),
                f"- 实际轮数：{len(item.get('turns') or [])}",
                f"- 恢复动作数：{sum(1 for turn in item.get('turns') or [] if str((turn.get('controller') or {}).get('route') or '') in {'CLARIFY', 'REPHRASE', 'CORRECT'})}",
                f"- 停止原因：{item.get('stop_reason', '')}",
                "- 转人工状态："
                + ", ".join(
                    dict.fromkeys(
                        str((turn.get("controller") or {}).get("handoff_state") or "")
                        for turn in item.get("turns") or []
                        if str((turn.get("controller") or {}).get("handoff_state") or "")
                        not in {"", "NONE"}
                    )
                ),
                "- 等待外部结果场景："
                + ", ".join(
                    dict.fromkeys(
                        str(scene_id)
                        for turn in item.get("turns") or []
                        for scene_id in (turn.get("controller") or {}).get(
                            "external_pending_scene_ids", []
                        )
                    )
                ),
                "- 转人工后未执行场景："
                + ", ".join(
                    str(scene_id)
                    for turn in item.get("turns") or []
                    for scene_id in (turn.get("controller") or {}).get(
                        "deferred_scene_ids", []
                    )
                ),
                f"- 当前分数：{judge.get('score', '')}",
                f"- 完成门禁：{(judge.get('completion_gate') or {}).get('status', '')}",
                f"- 结论：{judge.get('reason') or item.get('error') or ''}",
                "",
            ]
        )
        turns = [
            turn for turn in item.get("turns") or [] if isinstance(turn, Mapping)
        ]
        if turns:
            lines.extend(["#### 多轮对话", ""])
            for turn in turns:
                controller = (
                    turn.get("controller")
                    if isinstance(turn.get("controller"), Mapping)
                    else {}
                )
                lines.extend(
                    [
                        f"**第 {turn.get('round', '')} 轮 · 客户**",
                        "",
                        *_quote_markdown(turn.get("customer_message")),
                        "",
                        f"**第 {turn.get('round', '')} 轮 · Agent**",
                        "",
                        *_quote_markdown(turn.get("agent_reply")),
                        "",
                        "- 控制结果："
                        f"已评估 `{controller.get('evaluated_scene_id') or controller.get('from_scene_id') or ''}`，"
                        f"队列下一项 `{controller.get('next_scene_id') or ''}`，"
                        f"动作 `{controller.get('route') or ''}`，"
                        f"转人工 `{controller.get('handoff_state') or 'NONE'}`",
                        "",
                    ]
                )
    from ..report_digest import concise_report
    return concise_report(report, "\n".join(lines) + "\n")


def run_dynamic_business(
    args: Any,
    *,
    target_builder: Callable[[Any, Any], Any] = build_target_client,
    model_builder: Callable[..., OpenAICompatibleClient] = OpenAICompatibleClient,
    initial_generator_function: Callable[..., dict[str, Any]] = generate_initial_customer_turn,
    controller_function: Callable[..., dict[str, Any]] = decide_next_customer_turn,
    judge_function: Callable[..., dict[str, Any]] = judge_business_case,
) -> dict[str, Any]:
    """Execute one or more isolated positive scenarios with dynamic follow-ups."""

    run_id = (
        str(getattr(args, "batch_id", None) or "").strip()
        or datetime.now().strftime("BD-%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    )
    random_sample = bool(getattr(args, "business_random_sample", False))
    sources = _select_sources(args, sample_salt=run_id)
    from .customer_needs import focus_customer_need

    sources = [focus_customer_need(source, salt=f"{run_id}:{index}") for index, source in enumerate(sources)]
    sources_path = Path(
        getattr(args, "business_scenario_sources", None)
        or BUSINESS_SCENARIO_SOURCES_PATH
    )
    scenario_type = str(
        getattr(args, "business_scenario_type", None) or "all"
    ).strip()
    max_turns = int(getattr(args, "business_max_turns", 7) or 7)
    if not 2 <= max_turns <= 12:
        raise ValueError("--turns 必须在 2 到 12 之间")
    max_recovery_attempts = int(
        getattr(args, "business_max_recovery_attempts", 2)
    )
    if not 0 <= max_recovery_attempts <= 4:
        raise ValueError("--recovery-attempts 必须在 0 到 4 之间")
    workers = int(getattr(args, "business_workers", 1) or 1)
    if workers < 1:
        raise ValueError("--workers 必须大于 0")
    workers = min(workers, max(1, len(sources)))
    profile = resolve_target_profile(args)
    if profile.adapter not in {"ky-agent", "ky-app"}:
        raise ValueError("动态正向业务测试仅支持旧销售 Agent 和 KY App sales-agent")
    requested_expression = str(
        getattr(args, "business_expression_style", None) or "auto"
    ).strip()
    scene_mode = str(getattr(args, "business_scene_mode", None) or "single").strip()
    requested_scenes = list(getattr(args, "business_scene", None) or [])
    configured_main_count = getattr(args, "business_main_count", None)
    main_count = int(configured_main_count) if configured_main_count is not None else None
    if main_count is not None and scene_mode != "multi":
        raise ValueError("--main-count 只能与 --scene-mode multi 一起使用")
    if main_count is not None and requested_scenes:
        raise ValueError("--main-count 与显式 --scene 不能同时使用")
    requested_side_scenes = list(
        getattr(args, "business_side_scene", None) or []
    )
    configured_side_count = getattr(args, "business_side_count", None)
    side_count = (
        int(configured_side_count)
        if configured_side_count is not None
        else max(len(requested_side_scenes), 2 if scene_mode == "multi" else 0)
    )
    if not 0 <= side_count <= 2:
        raise ValueError("--side-count 必须在 0 到 2 之间")
    if side_count > 0 and scene_mode != "multi":
        raise ValueError("--side-count/--side-scene 只能与 --scene-mode multi 一起使用")
    main_plan_by_source = {
        _source_instance_id(source): build_scene_plan(
            source_type=str(source.get("scenario_type") or ""),
            mode=scene_mode,
            requested=(
                select_main_scene_ids(
                    source_type=str(source.get("scenario_type") or ""),
                    source_id=_source_instance_id(source),
                    count=main_count,
                    salt=run_id,
                    source=source,
                    position=position,
                )
                if main_count is not None
                else requested_scenes
            ),
        )
        for position, source in enumerate(sources, start=1)
    }
    side_candidates_by_source: dict[str, list[dict[str, Any]]] = {}
    for source in sources:
        case_id = _source_instance_id(source)
        main_ids = [
            str(scene.get("id") or "")
            for scene in main_plan_by_source[case_id]
        ]
        side_candidates_by_source[case_id] = (
            build_side_scene_candidates(
                source_type=str(source.get("scenario_type") or ""),
                requested=requested_side_scenes,
                excluded=main_ids,
            )
            if side_count > 0
            else []
        )
    side_quota_by_source = _allocate_side_quotas(
        sources,
        side_candidates_by_source,
        count=side_count,
        salt=run_id,
    )
    scene_plan_by_source = {
        source_id: _merge_main_and_side_plan(
            main_plan,
            side_quota_by_source.get(source_id) or [],
        )
        for source_id, main_plan in main_plan_by_source.items()
    }
    strategy_plan = {
        _source_instance_id(source): {
            "id": "scene_driven", "name": "按所选场景推进",
            "instruction": "只推进当前场景，不增加未选择的业务目标。",
        }
        for position, source in enumerate(sources, start=1)
    }
    expression_plan = {
        _source_instance_id(source): select_expression_style(
            source_id=_source_instance_id(source),
            run_id=run_id,
            position=position,
            requested=requested_expression,
        )
        for position, source in enumerate(sources, start=1)
    }
    if bool(getattr(args, "dry_run", False)):
        return {
            "status": "READY_NO_INTERFACE",
            "run_id": run_id,
            "scenario_type": scenario_type,
            "planned_source_count": len(sources),
            "planned_case_count": len(sources),
            "unique_source_count": len(
                {str(item.get("source_id") or "") for item in sources}
            ),
            "source_ids": [item["source_id"] for item in sources],
            "case_ids": [_source_instance_id(item) for item in sources],
            "max_turns": max_turns,
            "max_recovery_attempts": max_recovery_attempts,
            "workers": workers,
            "scene_mode": scene_mode,
            "random_sample": random_sample,
            "main_scene_count": main_count,
            "side_scene_count": side_count,
            "requested_side_scenes": requested_side_scenes,
            "scenario_plans": scene_plan_by_source,
            "initial_messages": {
                _source_instance_id(source): initial_message_for_plan(
                    source,
                    scene_plan_by_source[_source_instance_id(source)],
                )
                for source in sources
            },
            "side_scene_candidates": side_candidates_by_source,
            "side_scene_quotas": side_quota_by_source,
            "coverage_queues": scene_plan_by_source,
            "conversation_strategies": {
                source_id: strategy_summary(strategy)
                for source_id, strategy in strategy_plan.items()
            },
            "expression_styles": expression_plan,
            "target": profile.safe_dict(),
            "business_scenario_sources": str(sources_path.resolve()),
        }
    if not sources:
        return {
            "status": "NO_SCENARIO_SOURCES",
            "run_id": run_id,
            "scenario_type": scenario_type,
            "source_count": 0,
        }

    controller_settings = load_model_settings(
        role="generic",
        model_override=getattr(args, "business_controller_model", None),
    )
    judge_settings = load_model_settings(
        role="judge", model_override=getattr(args, "judge_model", None)
    )
    controller = model_builder(
        controller_settings,
        timeout=float(getattr(args, "business_controller_timeout", 90.0)),
        retries=int(getattr(args, "judge_retries", 2)),
    )
    judge = model_builder(
        judge_settings,
        timeout=float(getattr(args, "judge_timeout", 120.0)),
        retries=int(getattr(args, "judge_retries", 2)),
    )
    target = target_builder(args, profile)
    progress = TerminalProgress()
    progress.emit(
        "BIZ-DYN",
        f"运行 {run_id} 开始 | Cases={len(sources)} | "
        f"唯一来源={len({str(item.get('source_id') or '') for item in sources})} "
        f"| Workers={workers}",
    )
    # Initial customer messages are generated inside each Case worker.  Keep a
    # small batch-level reservation ledger so parallel workers cannot silently
    # emit near-identical first turns.  The lock covers comparison and
    # reservation together; otherwise two workers could both pass the check.
    batch_initial_messages: list[tuple[str, str]] = []
    batch_initial_lock = Lock()

    def execute_source(
        position: int, source: Mapping[str, Any]
    ) -> dict[str, Any]:
        case_id = _source_instance_id(source)
        item: dict[str, Any] = {
            "case_id": case_id,
            "source_id": source.get("source_id"),
            "source_variant_index": int(source.get("_source_variant_index") or 1),
            "product_materials": source.get("product_materials") or [],
            "customer_need_selection": source.get("customer_need_selection") or {},
            "source_record_id": (source.get("source") or {}).get("record_id"),
            "scenario_type": source.get("scenario_type"),
            "scenario": source.get("scenario") or {},
            "scenario_plan": scene_plan_by_source[case_id],
            "side_scene_candidates": side_candidates_by_source[case_id],
            "side_scene_ids": [
                str(scene.get("id") or "")
                for scene in scene_plan_by_source[case_id]
                if str(scene.get("plan_role") or "main") == "side"
            ],
            "required_side_scene_ids": [
                str(scene.get("id") or "")
                for scene in side_quota_by_source[case_id]
            ],
            "source_core_task": source.get("core_task") or {},
            "core_task": evaluation_task(
                scene_plan_by_source[case_id]
            ),
            "conversation_strategy": strategy_summary(
                strategy_plan[case_id]
            ),
            "expression_style": expression_plan[case_id],
            "session": None,
            "turns": [],
            "stop_reason": "",
            "judge": None,
            "outcome": "ERROR",
            "error": None,
        }
        progress.emit(
            "BIZ-DYN",
            f"Case {position}/{len(sources)} {item['case_id']} | 开始",
        )
        try:
            runtime_source = dict(source)
            wx_account, wx_contact = build_test_identity(
                run_id=run_id,
                scenario_group_id="BUSINESS-DYNAMIC",
                case={"case_id": item["case_id"], "variant": scenario_type},
                repeat_index=position,
            )
            session = target.init_test(wx_account=wx_account, wx_contact=wx_contact)
            item["session"] = asdict(session)
            initial_generation: dict[str, Any] = {}
            next_message = ""
            batch_duplicate_of = ""
            batch_duplicate_similarity = 0.0
            batch_duplicate_repairs = 0
            for attempt in range(_BATCH_INITIAL_DUPLICATE_RETRIES + 1):
                generation_salt = f"{run_id}:{case_id}"
                if attempt:
                    generation_salt += f":batch-repair:{attempt}"
                candidate_generation = initial_generator_function(
                    controller,
                    runtime_source,
                    scenario_plan=item["scenario_plan"],
                    conversation_strategy=item["conversation_strategy"],
                    expression_style=item["expression_style"],
                    generation_salt=generation_salt,
                )
                candidate_message = str(
                    candidate_generation.get("customer_message") or ""
                ).strip()
                if not candidate_message:
                    raise ValueError("正向首轮生成器没有返回客户话术")
                with batch_initial_lock:
                    duplicate = _batch_initial_duplicate(
                        candidate_message, batch_initial_messages
                    )
                    if duplicate is None or attempt >= _BATCH_INITIAL_DUPLICATE_RETRIES:
                        batch_initial_messages.append((case_id, candidate_message))
                        batch_duplicate_of = duplicate[0] if duplicate else ""
                        batch_duplicate_similarity = (
                            round(duplicate[1], 4) if duplicate else 0.0
                        )
                        break
                # Do not reserve a duplicate candidate.  A changed salt gives
                # the model/template a chance to produce a distinct question.
                batch_duplicate_repairs += 1
            initial_generation = dict(candidate_generation)
            if batch_duplicate_of:
                initial_generation["batch_duplicate_of"] = batch_duplicate_of
                initial_generation["batch_duplicate_similarity"] = (
                    batch_duplicate_similarity
                )
            initial_generation["batch_duplicate_repair_count"] = (
                batch_duplicate_repairs
            )
            next_message = str(initial_generation.get("customer_message") or "").strip()
            if not next_message:
                raise ValueError("正向首轮生成器没有返回客户话术")
            item["initial_generation"] = initial_generation
            runtime_source["grounded_customer_facts"] = dict(
                initial_generation.get("grounded_facts") or {}
            )
            item["grounded_customer_facts"] = runtime_source[
                "grounded_customer_facts"
            ]
            item["initial_message"] = next_message

            for round_index in range(1, max_turns + 1):
                progress.emit(
                    "BIZ-DYN",
                    f"Case {position}/{len(sources)} {item['case_id']} "
                    f"| 第 {round_index}/{max_turns} 轮 | 请求目标 Agent",
                )
                trace = target.chat(session, next_message, allow_transport_retry=True)
                reply = str(trace.get("reply") or "")
                turn = {
                    "round": round_index,
                    "original_customer_message": next_message,
                    "customer_message": next_message,
                    "agent_reply": reply,
                    "adaptation": None,
                    "trace": trace,
                    "controller": None,
                }
                item["turns"].append(turn)
                if not reply.strip():
                    if _is_transport_empty_trace(trace):
                        item["stop_reason"] = "target_transport_empty"
                        raise KyAgentError(
                            "chat 未获得完整正文（空流或流超时/连接中断）；这是执行链路异常，"
                            "不直接归为业务能力失败。已触发副作用工具时不盲目重试，需核对工具执行状态。"
                        )
                    # A stream with observable events but no answer remains
                    # business evidence for the Judge.
                    item["stop_reason"] = "target_empty_reply"
                    break
                progress.emit(
                    "BIZ-DYN",
                    f"Case {position}/{len(sources)} {item['case_id']} "
                    f"| 第 {round_index}/{max_turns} 轮 | 评估本轮完成状态",
                )
                decision = controller_function(
                    controller,
                    runtime_source,
                    item["turns"],
                    max_turns=max_turns,
                    conversation_strategy=item["conversation_strategy"],
                    expression_style=item["expression_style"],
                    scenario_plan=item["scenario_plan"],
                    side_scene_candidates=item["side_scene_candidates"],
                    max_side_scenes=side_count,
                    max_recovery_attempts=max_recovery_attempts,
                    **({"stop_review_client": judge} if controller_function is decide_next_customer_turn else {}),
                )
                _apply_controller_plan(item, decision)
                turn["controller"] = decision
                action = str(decision.get("action") or "").upper()
                if action == "COMPLETE":
                    item["stop_reason"] = (
                        "controller_handoff"
                        if decision.get("completion_mode") == "human_handoff"
                        else "controller_complete"
                    )
                    break
                if action == "INVALID":
                    item["stop_reason"] = "controller_invalid"
                    item["outcome"] = "INVALID"
                    break
                if action == "STOP":
                    item["stop_reason"] = str(
                        decision.get("stop_kind") or "controller_stop"
                    )
                    break
                # Evaluate the final reply, but never send a turn beyond the budget,
                # even when a custom controller still returns CONTINUE.
                if round_index >= max_turns:
                    item["stop_reason"] = "max_turns"
                    break
                next_message = str(decision.get("customer_message") or "").strip()

            if item["outcome"] != "INVALID":
                judge_kwargs = (
                    {"include_reasoning": True}
                    if bool(getattr(args, "business_include_reasoning_eval", False))
                    else {}
                )
                item["judge"] = judge_function(
                    judge,
                    _judge_case(
                        runtime_source,
                        item["scenario_plan"],
                        item,
                        case_id=item["case_id"],
                    ),
                    item["turns"],
                    **judge_kwargs,
                )
                _apply_judge_completion_gate(item)
                item["outcome"] = str(item["judge"].get("decision") or "REVIEW")
        except Exception as exc:
            item["error"] = f"{type(exc).__name__}: {redact_value(str(exc))}"
            item["outcome"] = "ERROR"
            progress.emit(
                "BIZ-DYN",
                f"Case {position}/{len(sources)} {item['case_id']} "
                f"| 异常 | {item['error']}",
            )
        progress.emit(
            "BIZ-DYN",
            f"Case {position}/{len(sources)} {item['case_id']} "
            f"| 完成 | 结果={item['outcome']}",
        )
        return item

    indexed_sources = list(enumerate(sources, start=1))
    if workers == 1:
        results = [
            execute_source(position, source)
            for position, source in indexed_sources
        ]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(
                pool.map(
                    lambda pair: execute_source(pair[0], pair[1]),
                    indexed_sources,
                )
            )

    def completed_scene_ids(result: Mapping[str, Any]) -> set[str]:
        return {
            str(scene_id)
            for turn in result.get("turns") or []
            for scene_id in (turn.get("controller") or {}).get(
                "completed_scene_ids", []
            )
            if str(scene_id)
        }

    counts = Counter(str(item.get("outcome") or "ERROR") for item in results)
    initial_message_entries = [
        (str(item.get("case_id") or item.get("source_id") or ""), str(item.get("initial_message") or "").strip())
        for item in results
        if str(item.get("initial_message") or "").strip()
    ]
    initial_message_keys = [
        _normalized_initial_message(message)
        for _, message in initial_message_entries
    ]
    initial_message_counts = Counter(initial_message_keys)
    initial_message_total = len(initial_message_keys)
    unique_initial_message_count = len(initial_message_counts)
    initial_message_duplicate_count = max(
        0, initial_message_total - unique_initial_message_count
    )
    initial_message_duplicate_rate = round(
        initial_message_duplicate_count / initial_message_total, 4
    ) if initial_message_total else 0.0
    near_duplicate_pairs: list[dict[str, Any]] = []
    near_duplicate_case_ids: set[str] = set()
    for index, (case_id, message) in enumerate(initial_message_entries):
        for other_case_id, other_message in initial_message_entries[index + 1 :]:
            similarity = _initial_message_similarity(message, other_message)
            if similarity < _BATCH_INITIAL_NEAR_DUPLICATE_THRESHOLD:
                continue
            near_duplicate_pairs.append(
                {
                    "case_id": case_id,
                    "other_case_id": other_case_id,
                    "similarity": round(similarity, 4),
                }
            )
            near_duplicate_case_ids.update((case_id, other_case_id))
    initial_batch_duplicate_repairs = sum(
        int((item.get("initial_generation") or {}).get("batch_duplicate_repair_count") or 0)
        for item in results
    )
    initial_batch_duplicate_unresolved = sum(
        1
        for item in results
        if (item.get("initial_generation") or {}).get("batch_duplicate_of")
    )
    summary = {
        "total": len(results),
        "unique_source_count": len(
            {str(item.get("source_id") or "") for item in results}
        ),
        "initial_message_count": initial_message_total,
        "unique_initial_message_count": unique_initial_message_count,
        "initial_message_duplicate_count": initial_message_duplicate_count,
        "initial_message_duplicate_rate": initial_message_duplicate_rate,
        "near_duplicate_initial_pair_count": len(near_duplicate_pairs),
        "near_duplicate_initial_case_count": len(near_duplicate_case_ids),
        "near_duplicate_initial_case_rate": round(
            len(near_duplicate_case_ids) / initial_message_total, 4
        ) if initial_message_total else 0.0,
        "near_duplicate_threshold": _BATCH_INITIAL_NEAR_DUPLICATE_THRESHOLD,
        "initial_batch_duplicate_repairs": initial_batch_duplicate_repairs,
        "initial_batch_duplicate_unresolved": initial_batch_duplicate_unresolved,
        "near_duplicate_initial_pairs": near_duplicate_pairs[:100],
        "source_scenario_counts": dict(
            Counter(
                str(item.get("scenario_type") or "unknown")
                for item in results
            )
        ),
        "initial_main_scene_counts": dict(
            Counter(
                str((item.get("scenario_plan") or [{}])[0].get("id") or "unknown")
                for item in results
                if item.get("scenario_plan")
            )
        ),
        "PASS": counts.get("PASS", 0),
        "FAIL": counts.get("FAIL", 0),
        "REVIEW": counts.get("REVIEW", 0),
        "INVALID": counts.get("INVALID", 0),
        "ERROR": counts.get("ERROR", 0),
        "generated_followup_turns": sum(
            max(0, len(item.get("turns") or []) - 1) for item in results
        ),
        "initial_generation_source_counts": dict(
            Counter(
                str((item.get("initial_generation") or {}).get("generation_source") or "not_generated")
                for item in results
            )
        ),
        "initial_generation_fallbacks": sum(
            1
            for item in results
            if str((item.get("initial_generation") or {}).get("generation_source") or "")
            == "template_fallback"
        ),
        "initial_candidates_rejected": sum(
            len((item.get("initial_generation") or {}).get("validation_errors") or [])
            for item in results
        ),
        "initial_generation_repairs": sum(
            int(
                (item.get("initial_generation") or {}).get(
                    "generation_repair_count"
                )
                or 0
            )
            for item in results
        ),
        "initial_fact_contract_fallbacks": sum(
            1
            for item in results
            if (item.get("initial_generation") or {}).get(
                "grounded_fact_validation_errors"
            )
        ),
        "initial_ungrounded_fact_contracts": sum(
            1
            for item in results
            if any(
                str(value).startswith("ungrounded_named_fact:")
                for value in (item.get("initial_generation") or {}).get(
                    "grounded_fact_validation_errors", []
                )
            )
        ),
        "strategy_counts": dict(
            Counter(
                str((item.get("conversation_strategy") or {}).get("id") or "")
                for item in results
            )
        ),
        "expression_style_counts": dict(
            Counter(
                str((item.get("expression_style") or {}).get("id") or "")
                for item in results
            )
        ),
        "scene_counts": dict(
            Counter(
                str(scene.get("id") or "")
                for item in results
                for scene in item.get("scenario_plan") or []
            )
        ),
        "side_scene_counts": dict(
            Counter(
                str(scene.get("id") or "")
                for item in results
                for scene in item.get("scenario_plan") or []
                if str(scene.get("plan_role") or "") == "side"
            )
        ),
        "side_scene_completed_counts": dict(
            Counter(
                scene_id
                for item in results
                for scene_id in item.get("required_side_scene_ids") or []
                if scene_id in completed_scene_ids(item)
            )
        ),
        "side_quota_planned": sum(
            len(item.get("required_side_scene_ids") or []) for item in results
        ),
        "side_quota_completed": sum(
            len(
                set(item.get("required_side_scene_ids") or []).intersection(
                    completed_scene_ids(item)
                )
            )
            for item in results
        ),
        "side_quota_completed_cases": sum(
            1
            for item in results
            if item.get("required_side_scene_ids")
            and set(item.get("required_side_scene_ids") or []).issubset(
                completed_scene_ids(item)
            )
        ),
        "route_counts": dict(
            Counter(
                str((turn.get("controller") or {}).get("route") or "")
                for item in results
                for turn in item.get("turns") or []
                if str((turn.get("controller") or {}).get("route") or "")
            )
        ),
        "recovery_actions": sum(
            1
            for item in results
            for turn in item.get("turns") or []
            if str((turn.get("controller") or {}).get("route") or "")
            in {"CLARIFY", "REPHRASE", "CORRECT"}
        ),
        "recovery_exhausted": sum(
            1
            for item in results
            if item.get("stop_reason") == "recovery_exhausted"
        ),
        "turn_evaluation_repairs": sum(
            int((turn.get("controller") or {}).get("evaluation_repair_count") or 0)
            for item in results
            for turn in item.get("turns") or []
        ),
        "followup_generation_repairs": sum(
            int((turn.get("controller") or {}).get("generation_repair_count") or 0)
            for item in results
            for turn in item.get("turns") or []
        ),
        "followup_generation_fallbacks": sum(
            1
            for item in results
            for turn in item.get("turns") or []
            if str((turn.get("controller") or {}).get("generation_source") or "")
            == "deterministic_fallback"
        ),
        "controller_evaluation_stops": sum(
            1
            for item in results
            if item.get("stop_reason")
            in {"controller_evaluation_unrecoverable", "controller_evaluation_error"}
        ),
        "customer_generation_stops": sum(
            1
            for item in results
            if item.get("stop_reason") == "customer_generation_unrecoverable"
        ),
        "transport_empty_errors": sum(
            1
            for item in results
            if item.get("stop_reason") == "target_transport_empty"
        ),
        "partial_coverage_pass": sum(
            1 for item in results if item.get("outcome") == "PASS"
            and ((item.get("judge") or {}).get("completion_gate") or {}).get("coverage_status") == "partial"
        ),
        "judge_completion_caps": sum(
            1
            for item in results
            if str(
                ((item.get("judge") or {}).get("completion_gate") or {}).get(
                    "status"
                )
                or ""
            )
            == "CAPPED_TO_REVIEW"
        ),
        "human_handoff_completed": sum(
            1
            for item in results
            if item.get("stop_reason") == "controller_handoff"
        ),
        "handoff_state_counts": dict(
            Counter(
                str((turn.get("controller") or {}).get("handoff_state") or "NONE")
                for item in results
                for turn in item.get("turns") or []
                if str((turn.get("controller") or {}).get("handoff_state") or "NONE")
                != "NONE"
            )
        ),
        "external_pending_scenes": sum(
            len(
                {
                    str(scene_id)
                    for turn in item.get("turns") or []
                    for scene_id in (turn.get("controller") or {}).get(
                        "external_pending_scene_ids", []
                    )
                }
            )
            for item in results
        ),
        "duplicate_handoffs": sum(
            1
            for item in results
            for turn in item.get("turns") or []
            if int((turn.get("controller") or {}).get("duplicate_handoff_count") or 0)
            > 0
        ),
        "handoff_failures": sum(
            1
            for item in results
            if item.get("stop_reason") == "handoff_failed"
        ),
        "unverified_business_handoffs": sum(
            1
            for item in results
            if item.get("stop_reason") == "unverified_business_handoff"
        ),
        "deferred_scene_counts": dict(
            Counter(
                scene_id
                for item in results
                for scene_id in {
                    str(value)
                    for turn in item.get("turns") or []
                    for value in (turn.get("controller") or {}).get(
                        "deferred_scene_ids", []
                    )
                    if str(value)
                }
            )
        ),
    }
    report = {
        "schema_version": "1.0-dynamic-business-regression-report",
        "status": "COMPLETED",
        "run_id": run_id,
        "created_at": _now(),
        "scenario_type": scenario_type,
        "scene_mode": scene_mode,
        "random_sample": random_sample,
        "main_scene_count": main_count,
        "requested_scenes": requested_scenes,
        "side_scene_count": side_count,
        "requested_side_scenes": requested_side_scenes,
        "side_scene_quotas": side_quota_by_source,
        "coverage_queues": {
            str(item.get("case_id") or item.get("source_id") or ""): item.get(
                "scenario_plan"
            )
            or []
            for item in results
        },
        "target": profile.safe_dict(),
        "business_scenario_sources": str(sources_path.resolve()),
        "controller_model": controller_settings.safe_dict(),
        "judge_model": judge_settings.safe_dict(),
        "max_turns": max_turns,
        "max_recovery_attempts": max_recovery_attempts,
        "workers": workers,
        "include_reasoning_eval": bool(
            getattr(args, "business_include_reasoning_eval", False)
        ),
        "summary": summary,
        "results": results,
        "bad_case_candidates": [
            {
                "case_id": item.get("case_id"),
                "source_id": item.get("source_id"),
                "outcome": item.get("outcome"),
                "judge": item.get("judge"),
                "result_ref": f"results:{index}",
            }
            for index, item in enumerate(results)
            if item.get("outcome") in {"FAIL", "REVIEW"}
        ],
    }
    output_dir = Path(
        getattr(args, "business_output_dir", None) or BUSINESS_DYNAMIC_RESULTS_DIR
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}.json"
    markdown_path = output_dir / f"{run_id}.md"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    markdown_path.write_text(_markdown(report), encoding="utf-8")
    try:
        from .bad_cases import register_dynamic_bad_cases

        bad_case_registration = register_dynamic_bad_cases(
            report_path=json_path,
            scenario_sources_path=sources_path,
            output_path=Path(
                getattr(args, "business_bad_cases", None) or BUSINESS_BAD_CASES_PATH
            ),
        )
    except Exception as exc:
        bad_case_registration = {
            "status": "ERROR",
            "error": f"{type(exc).__name__}: {redact_value(str(exc))}",
        }
    report["bad_case_registration"] = bad_case_registration
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    # 工作台可关闭 Finding；原 CLI 未传开关时保持原来的自动分析行为。
    if not getattr(args, "auto_findings", True):
        finding_report = {"status": "SKIPPED_BY_OPTION"}
    else:
        try:
            from .findings import generate_business_findings

            finding_report = generate_business_findings(
                report_path=json_path,
                output_dir=output_dir.parent / "findings",
                model_override=getattr(args, "business_finding_model", None),
            )
        except Exception as exc:
            finding_report = {
                "status": "ERROR",
                "error": f"{type(exc).__name__}: {redact_value(str(exc))}",
            }
    report["finding_report"] = finding_report
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {
        "status": "COMPLETED",
        "run_id": run_id,
        "scenario_type": scenario_type,
        "source_count": len(results),
        "case_count": len(results),
        "unique_source_count": summary["unique_source_count"],
        "summary": summary,
        "json": str(json_path.resolve()),
        "markdown": str(markdown_path.resolve()),
        "bad_case_registration": bad_case_registration,
        "finding_report": finding_report,
    }


__all__ = ["run_dynamic_business"]
