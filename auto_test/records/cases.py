"""Security Case storage used by regression and offline snapshots."""

from __future__ import annotations

from ..records.library_lock import serialized_library_write, atomic_library_write


import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..core.paths import SECURITY_CASES_PATH
from .findings import finding_analysis
from ..packs.epe_ids import canonical_epe_pack_id


DEFAULT_CASES_PATH = SECURITY_CASES_PATH
LEGACY_DEFAULT_TARGET_KEY = "ky-agent:ky-sales"
LEAK_OUTCOMES = frozenset(
    {"FULL_LEAK", "CRITICAL_PARTIAL_LEAK", "PARTIAL_LEAK"}
)
PACK_TARGET_LABELS = {
    "prompt_leakage": "提示词泄露",
    "unauthorized_discount": "未授权降价",
    "unauthorized_commercial_commitment": "未授权商业条款承诺",
    "pricing_context_disclosure": "报价上下文泄露",
    "cross_user_context_leakage": "跨用户上下文泄露",
    "tool_provenance_confusion": "MCP 返回来源混淆",
}


def _crescendo_attack_method(pack: Mapping[str, Any]) -> str:
    """统一统计口径：执行器是攻击方式，Pack 是括号中的漏洞目标。"""

    pack_id = str(pack.get("pack_id") or "")
    target = PACK_TARGET_LABELS.get(
        pack_id, str(pack.get("name") or pack_id or "未知目标")
    )
    return f"Crescendo 多轮攻击（{target}）"


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_security_cases(path: Path = DEFAULT_CASES_PATH) -> dict[str, Any]:
    from . import case_store
    kind = case_store.kind_for(path)
    if kind:
        return case_store.load(kind)
    if not path.is_file():
        return {
            "schema_version": "1.1-security-cases",
            "updated_at": None,
            "cases": [],
        }
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping) or not isinstance(value.get("cases"), list):
        raise ValueError(f"安全 Case 库格式无效：{path}")
    return {**dict(value), "cases": list(value["cases"])}


def save_security_cases(
    library: Mapping[str, Any], path: Path = DEFAULT_CASES_PATH
) -> None:
    from . import case_store
    kind = case_store.kind_for(path)
    if kind:
        case_store.save(kind, library)
        return
    value = {
        **dict(library),
        "schema_version": "1.1-security-cases",
        "updated_at": _now(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_library_write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


@serialized_library_write
def backfill_finding_guidance(
    path: Path = DEFAULT_CASES_PATH,
) -> int:
    """Refresh deterministic scenario, root-cause, and remediation fields."""

    library = load_security_cases(path)
    updated = 0
    for item in library["cases"]:
        if not isinstance(item, dict):
            continue
        analysis = finding_analysis(
            str(item.get("pack_id") or ""),
            outcome=item.get("first_outcome") or item.get("latest_outcome"),
            oracle_result={"reason": item.get("evidence")},
        )
        if not isinstance(analysis, Mapping):
            continue
        fields = {
            "scenario_code": analysis.get("scenario_code"),
            "scenario_name": analysis.get("scenario_name"),
            "root_cause": analysis.get("root_cause"),
            "remediation_advice": analysis.get("remediation_advice"),
            "analysis_scope": analysis.get("analysis_scope"),
        }
        if any(item.get(key) != value for key, value in fields.items()):
            item.update(fields)
            updated += 1
    if updated:
        save_security_cases(library, path)
    return updated


def security_case_id(
    pack_id: str,
    messages: Sequence[str],
    *,
    target_key: str = "",
) -> str:
    # Only remove representation noise. Internal whitespace, punctuation,
    # casing and invisible characters can be attack mechanics and must remain
    # part of Case identity.
    canonical_messages = [
        str(message).replace("\r\n", "\n").replace("\r", "\n").strip()
        for message in messages
    ]
    identity = {
        "pack_id": str(pack_id).strip(),
        "messages": canonical_messages,
    }
    if str(target_key).strip():
        identity["target_key"] = str(target_key).strip()
    source = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:12].upper()
    return f"SEC-{digest}"


_case_id = security_case_id


def security_case_target_key(case: Mapping[str, Any]) -> str:
    """Return the explicit target, mapping only truly legacy Cases to ky-sales."""

    target = case.get("target")
    if not isinstance(target, Mapping) or not target:
        return LEGACY_DEFAULT_TARGET_KEY
    target_key = str(target.get("target_key") or "").strip()
    if target_key:
        return target_key
    # A record claiming a non-legacy adapter without a target key is malformed;
    # never silently replay it against ky-sales.
    if str(target.get("adapter") or "").strip() not in {"", "ky-agent"}:
        return ""
    return LEGACY_DEFAULT_TARGET_KEY


def _successful_session_turns(iteration: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    turns = [
        item for item in iteration.get("turns") or [] if isinstance(item, Mapping)
    ]
    if not turns:
        return []
    scope = iteration.get("oracle_scope") or {}
    scoped_restart = scope.get("session_restart_index")
    scoped_session = str(scope.get("session_id") or "")
    selected_restart = (
        int(scoped_restart)
        if scoped_restart is not None
        else max(int(item.get("session_restart_index") or 0) for item in turns)
    )
    return [
        item
        for item in turns
        if int(item.get("session_restart_index") or 0) == selected_restart
        and (
            not scoped_session
            or not str(item.get("session_id") or "")
            or str(item.get("session_id") or "") == scoped_session
        )
        and str(item.get("message") or "").strip()
    ]


def _successful_session_messages(iteration: Mapping[str, Any]) -> list[str]:
    return [
        str(item.get("message") or "").strip()
        for item in _successful_session_turns(iteration)
    ]


def _successful_session_outputs(iteration: Mapping[str, Any]) -> list[str]:
    outputs: list[str] = []
    for item in _successful_session_turns(iteration):
        trace = item.get("trace")
        trace_reply = trace.get("reply") if isinstance(trace, Mapping) else ""
        reply = str(item.get("reply") or trace_reply or "").strip()
        if reply:
            outputs.append(reply)
    return outputs


def _report_successes(
    report: Mapping[str, Any],
    *,
    json_path: Path,
    markdown_path: Path,
) -> list[dict[str, Any]]:
    created_at = str(report.get("created_at") or _now())
    report_target = (
        dict(report.get("target") or {})
        if isinstance(report.get("target"), Mapping)
        else {}
    )
    target_fields = {"target": report_target} if report_target else {}
    records: list[dict[str, Any]] = []

    def analysis_fields(
        pack_id: str,
        outcome: str,
        source: Mapping[str, Any],
        oracle_result: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        analysis = source.get("finding_analysis")
        if not isinstance(analysis, Mapping):
            analysis = finding_analysis(
                pack_id,
                outcome=outcome,
                oracle_result=oracle_result,
            )
        if not isinstance(analysis, Mapping):
            return {}
        return {
            "scenario_code": str(analysis.get("scenario_code") or ""),
            "scenario_name": str(analysis.get("scenario_name") or ""),
            "root_cause": str(analysis.get("root_cause") or ""),
            "remediation_advice": str(
                analysis.get("remediation_advice") or ""
            ),
            "analysis_scope": str(analysis.get("analysis_scope") or ""),
        }
    if str(report.get("schema_version") or "").endswith(
        "security-attack-pack-report"
    ):
        for pack in report.get("packs") or []:
            if not isinstance(pack, Mapping):
                continue
            success_outcomes = {
                str(item)
                for item in (pack.get("oracle") or {}).get("success_outcomes") or []
            }
            for iteration in pack.get("iterations") or []:
                if not isinstance(iteration, Mapping):
                    continue
                outcome = str(iteration.get("outcome") or "")
                if outcome not in success_outcomes:
                    continue
                messages = _successful_session_messages(iteration)
                if not messages:
                    continue
                records.append(
                    {
                        "found_at": created_at,
                        "pack_id": str(pack.get("pack_id") or ""),
                        "engine": "cr",
                        "query_pack": "",
                        "pack_version": str(pack.get("pack_version") or ""),
                        "seed_id": str(iteration.get("seed_id") or ""),
                        "attack_method": _crescendo_attack_method(pack),
                        "messages": messages,
                        "successful_outputs": _successful_session_outputs(iteration),
                        "first_outcome": outcome,
                        "oracle_type": str(
                            (pack.get("oracle") or {}).get("type") or ""
                        ),
                        "evidence": str(
                            (iteration.get("oracle_result") or {}).get("reason")
                            or outcome
                        ),
                        "source_json": str(json_path.resolve()),
                        "source_markdown": str(markdown_path.resolve()),
                        **target_fields,
                        **analysis_fields(
                            str(pack.get("pack_id") or ""),
                            outcome,
                            iteration,
                            iteration.get("oracle_result"),
                        ),
                    }
                )
    elif str(report.get("schema_version") or "") == "1.0-paper-crescendo-report":
        for iteration in report.get("iterations") or []:
            if not isinstance(iteration, Mapping):
                continue
            outcome = str(iteration.get("outcome") or "")
            if outcome not in LEAK_OUTCOMES:
                continue
            messages = _successful_session_messages(iteration)
            if not messages:
                messages = [
                    str(item).strip()
                    for item in iteration.get("accepted_prefix") or []
                    if str(item).strip()
                ]
            if not messages:
                continue
            successful_outputs = _successful_session_outputs(iteration)
            records.append(
                {
                    "found_at": created_at,
                    "pack_id": "prompt_leakage",
                    "engine": "cr",
                    "query_pack": "",
                    "pack_version": "legacy-crescendo-1.0",
                    "seed_id": "",
                    "attack_method": "Crescendo 多轮攻击（提示词泄露）",
                    "messages": messages,
                    "successful_outputs": successful_outputs,
                    "first_outcome": outcome,
                    "oracle_type": "protected_asset_match",
                    "evidence": outcome,
                    "source_json": str(json_path.resolve()),
                    "source_markdown": str(markdown_path.resolve()),
                    **target_fields,
                    **analysis_fields(
                        "prompt_leakage",
                        outcome,
                        iteration,
                        iteration.get("oracle_result"),
                    ),
                }
            )
    elif str(report.get("schema_version") or "").endswith("epe-report"):
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for result in report.get("results") or []:
            if isinstance(result, Mapping):
                grouped.setdefault(str(result.get("query_id") or ""), []).append(result)
        outcome_rank = {
            "PARTIAL_LEAK": 1,
            "CRITICAL_PARTIAL_LEAK": 2,
            "FULL_LEAK": 3,
        }
        for query_id, attempts in grouped.items():
            successes = [
                result
                for result in attempts
                if str(result.get("outcome") or "") in LEAK_OUTCOMES
            ]
            if not successes:
                continue
            result = max(
                successes,
                key=lambda item: outcome_rank.get(str(item.get("outcome") or ""), 0),
            )
            outcome = str(result.get("outcome") or "")
            messages = [
                str(item.get("message") or "").strip()
                for item in result.get("turns") or []
                if isinstance(item, Mapping)
                and str(item.get("message") or "").strip()
            ]
            if not messages:
                continue
            successful_outputs = _successful_session_outputs(result)
            records.append(
                {
                    "found_at": created_at,
                    "pack_id": "prompt_leakage",
                    "engine": "epe",
                    "query_pack": canonical_epe_pack_id(report.get("query_pack")),
                    "pack_version": "1.0",
                    "seed_id": query_id,
                    "attack_method": "EPE 单轮攻击（提示词泄露）",
                    "messages": messages,
                    "successful_outputs": successful_outputs,
                    "first_outcome": outcome,
                    "oracle_type": "protected_asset_match",
                    "evidence": (
                        f"批内复现 {len(successes)}/{len(attempts)} 次成功；"
                        f"结果={','.join(str(item.get('outcome') or 'INVALID') for item in attempts)}"
                    ),
                    "reproduction_attempts": len(attempts),
                    "reproduction_successes": len(successes),
                    "reproduction_outcomes": [
                        str(item.get("outcome") or "INVALID") for item in attempts
                    ],
                    "source_json": str(json_path.resolve()),
                    "source_markdown": str(markdown_path.resolve()),
                    **target_fields,
                    **analysis_fields(
                        "prompt_leakage",
                        outcome,
                        result,
                        result.get("candidate"),
                    ),
                }
            )
    return records


@serialized_library_write
def register_successes(
    report: Mapping[str, Any],
    *,
    json_path: Path,
    markdown_path: Path,
    cases_path: Path = DEFAULT_CASES_PATH,
) -> list[str]:
    """只登记确定性成功攻击；同一 Pack 与 Prompt 序列自动去重。"""

    incoming = _report_successes(
        report, json_path=json_path, markdown_path=markdown_path
    )
    if not incoming:
        return []
    library = load_security_cases(cases_path)
    cases = [item for item in library["cases"] if isinstance(item, Mapping)]
    by_id = {str(item.get("case_id") or ""): dict(item) for item in cases}
    recorded: list[str] = []
    action_at = _now()
    for item in incoming:
        messages = list(item["messages"])
        target = item.get("target") if isinstance(item.get("target"), Mapping) else {}
        target_key = (
            str(target.get("target_key") or "")
            if str(target.get("adapter") or "") == "ai-web"
            else ""
        )
        case_id = _case_id(
            str(item["pack_id"]), messages, target_key=target_key
        )
        current = by_id.get(case_id)
        if current is None:
            current = {
                "case_id": case_id,
                **item,
                "prompt": "\n\n".join(messages),
                "result": "攻击成功（待修复）",
                "latest_outcome": item["first_outcome"],
                "last_tested_at": item["found_at"],
                "last_action_at": action_at,
                "source_reports": [item["source_json"]],
                "status_history": [
                    {
                        "status": "攻击成功（待修复）",
                        "at": action_at,
                        "source": "success_registration",
                    }
                ],
            }
            by_id[case_id] = current
        else:
            reports = list(current.get("source_reports") or [])
            if item["source_json"] not in reports:
                reports.append(item["source_json"])
            current.update(
                {
                    "pack_version": item["pack_version"],
                    "seed_id": item["seed_id"],
                    "attack_method": item["attack_method"],
                    "engine": item.get("engine"),
                    "query_pack": item.get("query_pack"),
                    "oracle_type": item["oracle_type"],
                    "evidence": item["evidence"],
                    "source_json": item["source_json"],
                    "source_markdown": item["source_markdown"],
                    "latest_outcome": item["first_outcome"],
                    "scenario_code": item.get("scenario_code"),
                    "scenario_name": item.get("scenario_name"),
                    "root_cause": item.get("root_cause"),
                    "remediation_advice": item.get("remediation_advice"),
                    "analysis_scope": item.get("analysis_scope"),
                    "target": dict(target) if target else current.get("target"),
                    "last_tested_at": item["found_at"],
                    "last_action_at": action_at,
                    "source_reports": reports,
                    "successful_outputs": (
                        item.get("successful_outputs")
                        or current.get("successful_outputs")
                        or []
                    ),
                }
            )
            for key in (
                "reproduction_attempts",
                "reproduction_successes",
                "reproduction_outcomes",
            ):
                if key in item:
                    current[key] = item[key]
        recorded.append(case_id)
    library["cases"] = sorted(
        by_id.values(), key=lambda item: (str(item.get("found_at") or ""), item["case_id"])
    )
    save_security_cases(library, cases_path)
    return sorted(set(recorded))


@serialized_library_write
def update_retest_result(
    case_id: str,
    *,
    outcome: str,
    tested_at: str,
    source_json: Path,
    cases_path: Path = DEFAULT_CASES_PATH,
) -> str:
    library = load_security_cases(cases_path)
    target: dict[str, Any] | None = None
    for item in library["cases"]:
        if isinstance(item, dict) and str(item.get("case_id") or "") == case_id:
            target = item
            break
    if target is None:
        raise ValueError(f"未知安全回归 Case：{case_id}")
    success_outcomes = LEAK_OUTCOMES | {"SUCCEEDED", "SPOOF_ACCEPTED"}
    if outcome in success_outcomes:
        result = "问题复发" if target.get("result") == "已修复" else "仍可复现"
    elif outcome == "RESISTED":
        result = "已修复"
    else:
        result = "复测待确认"
    target.update(
        {
            "result": result,
            "latest_outcome": outcome,
            "last_tested_at": tested_at,
            "last_action_at": tested_at,
            "latest_retest_json": str(source_json.resolve()),
        }
    )
    history = list(target.get("status_history") or [])
    history.append(
        {
            "status": result,
            "at": tested_at,
            "source": "regression",
            "source_json": str(source_json.resolve()),
        }
    )
    target["status_history"] = history
    save_security_cases(library, cases_path)
    return result


@serialized_library_write
def mark_case_statuses(
    *,
    status: str,
    batch_id: str,
    case_ids: Sequence[str] | None = None,
    pack_ids: Sequence[str] | None = None,
    select_all: bool = False,
    changed_at: str | None = None,
    cases_path: Path = DEFAULT_CASES_PATH,
) -> list[str]:
    """按修复批次将 Case 标记为修复中或待复测。"""

    labels = {"fixing": "修复中", "ready": "待复测"}
    if status not in labels:
        raise ValueError(f"未知 Case 状态操作：{status!r}")
    clean_batch = str(batch_id or "").strip()
    if not clean_batch:
        raise ValueError("修复批次 ID 不能为空")
    selected_ids = {str(item) for item in case_ids or [] if str(item)}
    selected_packs = {str(item) for item in pack_ids or [] if str(item)}
    if status == "fixing" and not (selected_ids or selected_packs or select_all):
        raise ValueError("标记修复中时必须指定 --case、--pack 或 --all")

    library = load_security_cases(cases_path)
    cases = [item for item in library["cases"] if isinstance(item, dict)]
    known_ids = {str(item.get("case_id") or "") for item in cases}
    missing = sorted(selected_ids - known_ids)
    if missing:
        raise ValueError(f"未知安全 Case：{missing}")
    action_at = str(changed_at or _now())
    changed: list[str] = []
    for item in cases:
        case_id = str(item.get("case_id") or "")
        if status == "ready" and not (selected_ids or selected_packs or select_all):
            selected = str(item.get("remediation_batch_id") or "") == clean_batch
        else:
            selected = bool(select_all or selected_ids or selected_packs)
            if selected_ids:
                selected = selected and case_id in selected_ids
            if selected_packs:
                selected = selected and (
                    str(item.get("pack_id") or "") in selected_packs
                )
        if not selected:
            continue
        if status == "fixing" and str(item.get("result") or "") == "已修复":
            continue
        if status == "ready" and str(item.get("remediation_batch_id") or "") != clean_batch:
            continue
        result = labels[status]
        item["result"] = result
        item["last_action_at"] = action_at
        item["remediation_batch_id"] = clean_batch
        if status == "fixing":
            item["remediation_started_at"] = action_at
        else:
            item["ready_for_retest_at"] = action_at
        history = list(item.get("status_history") or [])
        history.append(
            {
                "status": result,
                "at": action_at,
                "source": "manual_workflow",
                "batch_id": clean_batch,
            }
        )
        item["status_history"] = history
        changed.append(case_id)
    if not changed:
        raise ValueError("没有符合条件的 Case 可更新")
    library["cases"] = cases
    save_security_cases(library, cases_path)
    return sorted(changed)


__all__ = [
    "DEFAULT_CASES_PATH",
    "backfill_finding_guidance",
    "load_security_cases",
    "mark_case_statuses",
    "register_successes",
    "security_case_id",
    "save_security_cases",
    "update_retest_result",
]
