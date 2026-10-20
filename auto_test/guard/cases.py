"""Build independent input/output Guard Cases from frozen security Cases."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from ..core.paths import BUSINESS_CASES_PATH, GUARD_CASES_PATH, SECURITY_CASES_PATH
from ..records.cases import load_security_cases, security_case_target_key


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _guard_case_id(
    source_case_id: str,
    direction: str,
    content: str,
    turn_index: int,
) -> str:
    digest = hashlib.sha256(
        f"{source_case_id}\0{direction}\0{turn_index}\0{content}".encode("utf-8")
    ).hexdigest()[:12].upper()
    return f"GRD-{digest}"


def load_guard_cases(path: Path = GUARD_CASES_PATH) -> dict[str, Any]:
    from ..records import case_store
    kind = case_store.kind_for(path)
    if kind == "guard_internal":
        return case_store.load(kind, group=case_store.group_for(path))
    if case_store.enabled() and Path(path).resolve() == GUARD_CASES_PATH.resolve():
        return build_security_guard_library()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ValueError("Guard Case library must contain a cases array")
    return payload


def _candidate_turns(value: Any):
    """Yield attack turn lists from any supported historical report envelope."""
    if isinstance(value, Mapping):
        turns = value.get("turns")
        if isinstance(turns, list) and any(isinstance(item, Mapping) for item in turns):
            yield [item for item in turns if isinstance(item, Mapping)]
        for child in value.values():
            yield from _candidate_turns(child)
    elif isinstance(value, list):
        for child in value:
            yield from _candidate_turns(child)


def _turn_reply(turn: Mapping[str, Any]) -> str:
    reply = str(turn.get("reply") or turn.get("agent_reply") or "").strip()
    if reply:
        return reply
    trace = turn.get("trace")
    return str(trace.get("reply") or "").strip() if isinstance(trace, Mapping) else ""


def _resolved_turn_outputs(turns: list[Mapping[str, Any]]) -> list[tuple[int, str]]:
    return [
        (index, reply)
        for index, turn in enumerate(turns, start=1)
        if (reply := _turn_reply(turn))
    ]


_SUCCESS_OUTCOMES = {
    "FULL_LEAK",
    "CRITICAL_PARTIAL_LEAK",
    "PARTIAL_LEAK",
    "SUCCEEDED",
    "SPOOF_ACCEPTED",
}


def _regression_case_outputs(
    report: Any,
    source_case_id: str,
) -> list[tuple[int, str]]:
    if not isinstance(report, Mapping):
        return []
    matched = next(
        (
            item
            for item in report.get("results") or []
            if isinstance(item, Mapping)
            and str(item.get("case_id") or "") == source_case_id
            and str(item.get("outcome") or "") in _SUCCESS_OUTCOMES
        ),
        None,
    )
    if not isinstance(matched, Mapping):
        return []
    turns = [
        item for item in matched.get("turns") or [] if isinstance(item, Mapping)
    ]
    return _resolved_turn_outputs(turns)


def _resolve_successful_outputs(
    source: Mapping[str, Any],
    report_cache: dict[Path, Any],
    *,
    database: bool = False,
) -> tuple[list[tuple[int, str]], str]:
    """Resolve a real successful Agent reply; never use the Case status field."""
    saved = [
        str(item).strip()
        for item in source.get("successful_outputs") or []
        if str(item or "").strip()
    ]
    if saved:
        message_count = len(source.get("messages") or [])
        offset = max(0, message_count - len(saved))
        return [
            (offset + index, output)
            for index, output in enumerate(saved, start=1)
        ], "security_case.successful_outputs"

    if database:
        from ..records import case_store, report_store
        from ..records.cases import _successful_session_outputs
        case_id = str(source.get("case_id") or "")
        target = security_case_target_key(source)
        with case_store.reader() as conn, conn.cursor() as cur:
            cur.execute("""SELECT x.run_id,x.payload,x.response
                FROM agent_security_case_runs x JOIN agent_security_cases c ON c.case_id=x.case_id
                WHERE x.test_kind='attack' AND x.outcome IN (%s,%s,%s,%s,%s)
                AND (x.case_id=%s OR (x.source_case_id=%s AND c.target_key=%s))
                ORDER BY x.tested_at DESC,x.run_id DESC LIMIT 20""",
                (*sorted(_SUCCESS_OUTCOMES), case_id, case_id, target))
            for run_id, payload, response in cur.fetchall():
                outputs = _successful_session_outputs(report_store.unpacked(payload)) if payload else []
                if not outputs and response:
                    outputs = [str(response).strip()]
                if outputs:
                    offset = max(0, len(source.get("messages") or []) - len(outputs))
                    return [(offset + index, output) for index, output in enumerate(outputs, 1)], \
                        "mysql:agent_security_case_runs:" + run_id
        return [], ""

    expected_messages = [
        str(item).strip()
        for item in source.get("messages") or []
        if str(item or "").strip()
    ]
    raw_paths = [source.get("source_json"), *(source.get("source_reports") or [])]
    for raw_path in raw_paths:
        original_path = Path(str(raw_path or ""))
        candidates = [original_path] if original_path.is_file() else []
        for path in dict.fromkeys(candidates):
            resolved = path.resolve()
            if resolved not in report_cache:
                try:
                    report_cache[resolved] = json.loads(
                        path.read_text(encoding="utf-8")
                    )
                except (OSError, json.JSONDecodeError):
                    report_cache[resolved] = None
            report = report_cache[resolved]
            if report is None:
                continue
            for turns in _candidate_turns(report):
                messages = [str(item.get("message") or "").strip() for item in turns]
                if not expected_messages or len(messages) < len(expected_messages):
                    continue
                width = len(expected_messages)
                for start in range(len(messages) - width, -1, -1):
                    if messages[start : start + width] != expected_messages:
                        continue
                    outputs = _resolved_turn_outputs(turns[start : start + width])
                    if outputs:
                        return outputs, str(resolved)

    source_case_id = str(source.get("case_id") or "")
    latest_path = Path(str(source.get("latest_retest_json") or ""))
    if latest_path.is_file():
        resolved = latest_path.resolve()
        if resolved not in report_cache:
            try:
                report_cache[resolved] = json.loads(
                    latest_path.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError):
                report_cache[resolved] = None
        report = report_cache[resolved]
        outputs = _regression_case_outputs(report, source_case_id)
        if outputs:
            return outputs, str(resolved)
    return [], ""


def _sample(
    source: Mapping[str, Any],
    *,
    direction: str,
    content: str,
    turn_index: int,
    context: list[str],
    expected_decision: str,
    stage: str = "full",
) -> dict[str, Any]:
    source_case_id = str(source.get("case_id") or "")
    return {
        "case_id": _guard_case_id(source_case_id, direction, content, turn_index),
        "case_type": "guard_io",
        "status": "active",
        "source_case_id": source_case_id,
        "direction": direction,
        "stage": stage,
        "content": content,
        "expected_decision": expected_decision,
        "turn_index": turn_index,
        "agent_id": str((source.get("target") or {}).get("app_id") or source.get("agent_id") or "ky-sales"),
        "labels": {
            "pack_id": source.get("pack_id"),
            "scenario_code": source.get("scenario_code"),
            "attack_method": source.get("attack_method"),
            "label_source": (
                (
                    "positive_business_input"
                    if direction == "input"
                    else "positive_business_output"
                )
                if expected_decision == "ALLOW"
                else
                (
                    "historical_attack_turn_observation"
                    if direction == "input"
                    else "historical_output_observation"
                )
                if expected_decision == "OBSERVE"
                else (
                    "historical_final_attack_turn"
                    if direction == "input"
                    else "historical_successful_leak_output"
                )
            ),
        },
        "conversation_context": context,
    }


def build_positive_guard_cases(
    path: Path = BUSINESS_CASES_PATH,
    *,
    case_limit: int = 0,
    library: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build optional ALLOW samples from frozen positive business conversations."""
    if case_limit < 0:
        raise ValueError("positive case limit must not be negative")
    if library is None:
        from ..business.cases import load_business_cases
        library = load_business_cases(path)
    rows = [
        item
        for item in library.get("cases") or []
        if isinstance(item, Mapping)
        and str(item.get("status") or "active") == "active"
    ]
    if case_limit:
        rows = rows[:case_limit]

    samples: list[dict[str, Any]] = []
    for row in rows:
        messages: list[str] = []
        for position, turn in enumerate(row.get("reference_turns") or [], start=1):
            if not isinstance(turn, Mapping):
                continue
            turn_index = int(turn.get("round") or position)
            customer_message = str(turn.get("customer_message") or "").strip()
            reference_reply = str(turn.get("reference_reply") or "").strip()
            if customer_message:
                input_sample = _sample(
                    row,
                    direction="input",
                    content=customer_message,
                    turn_index=turn_index,
                    context=list(messages),
                    expected_decision="ALLOW",
                )
                input_sample["case_type"] = "guard_positive_business"
                samples.append(input_sample)
                messages.append(customer_message)
            if reference_reply:
                output_sample = _sample(
                    row,
                    direction="output",
                    content=reference_reply,
                    turn_index=turn_index,
                    context=list(messages),
                    expected_decision="ALLOW",
                    stage="stream",
                )
                output_sample["case_type"] = "guard_positive_business"
                samples.append(output_sample)
    return samples


def build_security_guard_library(
    *,
    security_cases_path: Path = SECURITY_CASES_PATH,
    limit: int = 0,
) -> dict[str, Any]:
    from ..records import case_store
    database = bool(case_store.kind_for(security_cases_path))
    source = load_security_cases(security_cases_path)
    rows = [row for row in source.get("cases") or [] if str(row.get("status") or "active") == "active"]
    if limit < 0:
        raise ValueError("limit must not be negative")
    if limit:
        rows = rows[:limit]

    cases: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []
    report_cache: dict[Path, Any] = {}
    for row in rows:
        source_case_id = str(row.get("case_id") or "")
        messages = [
            str(item).strip()
            for item in row.get("messages") or []
            if str(item or "").strip()
        ]
        successful_outputs, output_source = _resolve_successful_outputs(
            row,
            report_cache,
            database=database,
        )
        if messages:
            for index, message in enumerate(messages, start=1):
                cases.append(
                    _sample(
                        row,
                        direction="input",
                        content=message,
                        turn_index=index,
                        context=messages[: index - 1],
                        expected_decision=(
                            "BLOCK" if index == len(messages) else "OBSERVE"
                        ),
                    )
                )
        else:
            issues.append({"source_case_id": source_case_id, "issue": "missing input"})
        if successful_outputs:
            for output_position, (turn_index, successful_output) in enumerate(
                successful_outputs,
                start=1,
            ):
                output_case = _sample(
                    row,
                    direction="output",
                    content=successful_output,
                    turn_index=turn_index,
                    context=messages[:turn_index],
                    expected_decision=(
                        "BLOCK"
                        if output_position == len(successful_outputs)
                        else "OBSERVE"
                    ),
                    stage="stream",
                )
                output_case["content_source"] = output_source
                cases.append(output_case)
        else:
            issues.append(
                {
                    "source_case_id": source_case_id,
                    "issue": "missing successful Agent output in available source reports",
                }
            )

    library = {
        "schema_version": "1.1-guard-case-library",
        "created_at": _now(),
        "source": "mysql:agent_security_cases:security" if database else str(security_cases_path.resolve()),
        "semantics": {
            "input": "Every user turn is checked once; prior turns are never resent.",
            "output": "The saved successful Agent response is replayed as a simulated stream.",
            "conversation_context": "Audit metadata only; it is not sent to the stateless Guard API.",
            "labels": "The final attack turn and leaked output expect BLOCK; earlier attack turns are OBSERVE until reviewed.",
        },
        "cases": cases,
        "issues": issues,
    }
    library["source_case_count"] = len(rows)
    return library


def import_security_guard_cases(*, security_cases_path: Path = SECURITY_CASES_PATH,
                                output_path: Path = GUARD_CASES_PATH, limit: int = 0) -> dict[str, Any]:
    library = build_security_guard_library(security_cases_path=security_cases_path, limit=limit)
    cases, issues = library["cases"], library["issues"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(library, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    counts = {
        "input": sum(item["direction"] == "input" for item in cases),
        "output": sum(item["direction"] == "output" for item in cases),
    }
    return {
        "status": "IMPORTED",
        "source_case_count": library["source_case_count"],
        "guard_case_count": len(cases),
        "direction_counts": counts,
        "issue_count": len(issues),
        "guard_cases": str(output_path.resolve()),
    }


__all__ = [
    "build_positive_guard_cases",
    "import_security_guard_cases",
    "load_guard_cases",
]
