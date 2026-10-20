"""Freeze attributable dynamic business failures into a regression library."""

from __future__ import annotations

from ..records.library_lock import serialized_library_write, atomic_library_write


import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..core.paths import BUSINESS_BAD_CASES_PATH, BUSINESS_SCENARIO_SOURCES_PATH
from ..core.redaction import redact_value
from .cases import load_business_cases
from .scenario_sources import load_scenario_sources


SCHEMA_VERSION = "1.0-business-bad-case-library"


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _case_id(source_id: str, messages: list[str]) -> str:
    value = json.dumps(
        {"source_id": source_id, "messages": messages},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "BIZBAD-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12].upper()


def _evidence_turn(turn: Mapping[str, Any]) -> dict[str, Any]:
    trace = turn.get("trace") if isinstance(turn.get("trace"), Mapping) else {}
    return {
        "round": turn.get("round"),
        "customer_message": turn.get("customer_message"),
        "agent_reply": turn.get("agent_reply"),
        "tool_calls": [
            {"name": item.get("name"), "arguments": item.get("arguments")}
            for item in (trace.get("tool_calls") or [])
            if isinstance(item, Mapping)
        ],
        "errors": list(trace.get("errors") or []),
    }


def _build_case(
    report: Mapping[str, Any],
    result: Mapping[str, Any],
    source: Mapping[str, Any],
) -> dict[str, Any]:
    turns = [
        {
            "round": int(turn.get("round") or index),
            "customer_message": str(turn.get("customer_message") or "").strip(),
            # The failed Agent answer is evidence, never the expected answer.
            "reference_reply": "",
        }
        for index, turn in enumerate(result.get("turns") or [], start=1)
        if isinstance(turn, Mapping) and str(turn.get("customer_message") or "").strip()
    ]
    if not turns:
        raise ValueError(f"{result.get('source_id')} 没有可冻结的实际客户消息")
    source_id = str(result.get("source_id") or "").strip()
    messages = [turn["customer_message"] for turn in turns]
    registered_at = _now()
    return redact_value(
        {
            "case_id": _case_id(source_id if (report.get("target") or {}).get("adapter") != "ky-app" else "ky-app:sales-agent:" + source_id, messages),
            "case_type": "positive_business_bad_case",
            "status": "active",
            "agent_type": "sales-agent" if (report.get("target") or {}).get("adapter") == "ky-app" else "ky-sales",
            "target": report.get("target") or {"adapter": "ky-agent", "target_key": "ky-agent:ky-sales"},
            "source": {
                "kind": "dynamic_business_report",
                "source_id": source_id,
                "record_id": (source.get("source") or {}).get("record_id"),
                "run_id": report.get("run_id"),
                "registered_at": registered_at,
            },
            "scenario": source.get("scenario") or result.get("scenario") or {},
            "scenario_plan": result.get("scenario_plan") or [],
            "customer_profile": source.get("customer_profile") or {},
            "customer_speech_style": source.get("customer_speech_style") or {},
            "core_task": result.get("core_task") or source.get("core_task") or {},
            "source_core_task": result.get("source_core_task") or source.get("core_task") or {},
            "reference_turns": turns,
            "baseline": {
                "score": None,
                "grade": "",
                "expected_outcome": "PASS",
            },
            "failure_evidence": {
                "outcome": result.get("outcome"),
                "judge": result.get("judge") or {},
                "turns": [
                    _evidence_turn(turn)
                    for turn in result.get("turns") or []
                    if isinstance(turn, Mapping)
                ],
            },
        }
    )


@serialized_library_write
def register_dynamic_bad_cases(
    *,
    report_path: Path,
    scenario_sources_path: Path = BUSINESS_SCENARIO_SOURCES_PATH,
    output_path: Path = BUSINESS_BAD_CASES_PATH,
    source_ids: Sequence[str] | None = None,
    include_review: bool = False,
) -> dict[str, Any]:
    """Register real system failures; never freeze test-data/controller defects."""

    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, Mapping) or not str(report.get("schema_version") or "").endswith(
        "dynamic-business-regression-report"
    ):
        raise ValueError("只支持动态正向业务回归 JSON 报告")
    selected_ids = {
        str(item).strip() for item in source_ids or [] if str(item).strip()
    }
    outcomes = {"FAIL", "REVIEW"} if include_review else {"FAIL"}
    candidates = [
        item
        for item in report.get("results") or []
        if isinstance(item, Mapping)
        and str(item.get("outcome") or "").upper() in outcomes
        and str(item.get("stop_reason") or "")
        not in {
            "controller_contract_unrecoverable",
            "controller_evaluation_unrecoverable",
            "controller_evaluation_error",
            "customer_generation_unrecoverable",
        }
        and str(
            (
                item.get("judge")
                if isinstance(item.get("judge"), Mapping)
                else {}
            ).get("issue_owner")
            or ""
        ).strip().lower()
        not in {"test_data", "test_controller"}
        and (not selected_ids or str(item.get("source_id") or "") in selected_ids)
    ]
    if selected_ids:
        found = {str(item.get("source_id") or "") for item in candidates}
        missing = sorted(selected_ids - found)
        if missing:
            raise ValueError("指定来源不是可登记的 FAIL/REVIEW：" + ", ".join(missing))
    source_library = load_scenario_sources(scenario_sources_path)
    sources = {
        str(item.get("source_id") or ""): item
        for item in source_library.get("sources") or []
        if isinstance(item, Mapping)
    }
    cases = []
    for result in candidates:
        source_id = str(result.get("source_id") or "")
        if source_id not in sources:
            raise ValueError(f"场景来源库缺少 {source_id}")
        cases.append(_build_case(report, result, sources[source_id]))

    result_summary = {
        "status": "REGISTERED",
        "report": str(report_path.resolve()),
        "candidate_count": len(cases),
        "case_ids": [item["case_id"] for item in cases],
        "source_ids": [item["source"]["source_id"] for item in cases],
        "include_review": include_review,
        "business_bad_cases": str(output_path.resolve()),
    }
    if not cases:
        return {
            **result_summary,
            "status": "NO_FAILURES",
            "added": 0,
            "updated": 0,
        }

    library = load_business_cases(output_path)
    existing = {
        str(item.get("case_id") or ""): item
        for item in library.get("cases") or []
        if isinstance(item, Mapping)
    }
    added = 0
    updated = 0
    for case in cases:
        case_id = str(case["case_id"])
        if case_id in existing:
            if existing[case_id].get("finding_ids"):
                case["finding_ids"] = list(existing[case_id]["finding_ids"])
            case["source"]["registered_at"] = (
                existing[case_id].get("source") or {}
            ).get("registered_at") or case["source"]["registered_at"]
            updated += 1
        else:
            added += 1
        existing[case_id] = case
    written_at = _now()
    output = {
        **library,
        "schema_version": SCHEMA_VERSION,
        "updated_at": written_at,
        "cases": list(existing.values()),
    }
    from .cases import save_business_cases
    save_business_cases(output, output_path)
    return {
        **result_summary,
        "added": added,
        "updated": updated,
        "total": len(existing),
        "updated_at": written_at,
    }


__all__ = ["SCHEMA_VERSION", "register_dynamic_bad_cases"]
