"""从历史评测报告构建独立、可重放的 ky-sales 正向业务 Case 库。"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from ..core.paths import BUSINESS_CASES_PATH


SOURCE_TABLE = "t_a_i_adversarial_json_parsing"
SOURCE_FILTER = "type = 1 AND status = 2"
SCHEMA_VERSION = "1.0-business-case-library"


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _utf8(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value or "")


def _json_object(value: Any) -> dict[str, Any]:
    parsed = json.loads(_utf8(value))
    if not isinstance(parsed, dict):
        raise ValueError("json_content 必须是 JSON object")
    return parsed


def _case_id(source_id: Any, customer_messages: list[str]) -> str:
    fingerprint = json.dumps(
        {"source_id": str(source_id), "messages": customer_messages},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "BIZ-" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:12].upper()


def _reference_turns(
    conversation: Any,
    *,
    customer_roles: tuple[str, ...] = ("customer",),
) -> list[dict[str, Any]]:
    if not isinstance(conversation, list) or not conversation:
        raise ValueError("conversation_log 为空")
    turns: list[dict[str, Any]] = []
    pending: dict[str, Any] | None = None
    for entry in conversation:
        if not isinstance(entry, Mapping):
            continue
        role = str(entry.get("role") or "").strip().casefold()
        message = str(entry.get("message") or "").strip()
        if role in customer_roles and message:
            if pending is not None:
                raise ValueError("conversation_log 中客户消息缺少对应 AI 回复")
            pending = {
                "round": int(entry.get("round") or len(turns) + 1),
                "customer_message": message,
                "reference_reply": "",
            }
        elif role == "ai" and message and pending is not None:
            pending["reference_reply"] = message
            turns.append(pending)
            pending = None
    if pending is not None:
        raise ValueError("conversation_log 最后一条客户消息缺少 AI 回复")
    if not turns:
        raise ValueError("conversation_log 没有可重放的客户/AI对话对")
    return turns


def build_business_case(row: Mapping[str, Any]) -> dict[str, Any]:
    """把一条历史评测记录转换为稳定的 BIZ Case。"""

    report = _json_object(row["json_content"])
    turns = _reference_turns(report.get("conversation_log"))
    customer_messages = [item["customer_message"] for item in turns]
    source_id = str(row["id"])
    score = float(row.get("scoring_total_score") or 0)
    return {
        "case_id": _case_id(source_id, customer_messages),
        "case_type": "positive_business",
        "status": "active",
        "agent_type": "ky-sales",
        "source": {
            "table": SOURCE_TABLE,
            "record_id": source_id,
            "created_at": str(row.get("create_time") or ""),
            "training_round": int(row.get("current_training_round") or 0),
            "training_version": _utf8(row.get("current_training_version")),
            "app_id": str(row.get("a_i_apps_id") or ""),
            "app_name": _utf8(row.get("a_i_apps_name")),
            "agent_name": _utf8(row.get("adversarial_agent_name")),
        },
        "scenario": report.get("business_scenario") or {
            "summary": _utf8(row.get("business_scenario_summary"))
        },
        "customer_profile": report.get("customer_profile") or {},
        "customer_speech_style": report.get("customer_speech_style") or {},
        "core_task": report.get("core_task") or {},
        "reference_turns": turns,
        "baseline": {
            "score": score,
            "grade": str((report.get("scoring") or {}).get("grade") or ""),
            "scoring": report.get("scoring") or {},
            "requirement_coverage": report.get("requirement_coverage") or [],
            "known_bad_cases": report.get("bad_cases") or [],
            "summary": report.get("summary") or {},
        },
    }


def load_business_cases(path: Path = BUSINESS_CASES_PATH) -> dict[str, Any]:
    from ..records import case_store
    kind = case_store.kind_for(path)
    if kind:
        return case_store.load(kind)
    if not path.is_file():
        return {"schema_version": SCHEMA_VERSION, "cases": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        raise ValueError(f"业务 Case 库结构无效：{path}")
    case_ids = [str(item.get("case_id") or "") for item in data["cases"]]
    if not all(case_ids) or len(case_ids) != len(set(case_ids)):
        raise ValueError("业务 Case ID 为空或重复")
    return data


def save_business_cases(library, path):
    from ..records import case_store
    from ..records.library_lock import atomic_library_write
    kind = case_store.kind_for(path)
    if kind:
        return case_store.save(kind, library)
    atomic_library_write(path, json.dumps(library, ensure_ascii=False, indent=2))


def import_business_cases(
    *,
    limit: int = 100,
    output_path: Path = BUSINESS_CASES_PATH,
    connection_factory: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """读取最近源记录，默认写入 MySQL；显式离线路径输出快照。"""

    if limit < 1 or limit > 1000:
        raise ValueError("limit 必须在 1 到 1000 之间")
    if connection_factory is None:
        from ..records.mysql import _connect

        connection_factory = _connect
    connection = connection_factory()
    columns = (
        "id,business_scenario_summary,scoring_total_score,bad_case_count,"
        "json_content,current_training_round,current_training_version,create_time,"
        "adversarial_agent_name,a_i_apps_id,a_i_apps_name"
    ).split(",")
    select_columns = ",".join(
        f"CAST({name} AS BINARY) AS {name}"
        if name in {
            "business_scenario_summary",
            "json_content",
            "current_training_version",
            "adversarial_agent_name",
            "a_i_apps_name",
        }
        else name
        for name in columns
    )
    query = (
        f"SELECT {select_columns} FROM {SOURCE_TABLE} "
        f"WHERE {SOURCE_FILTER} ORDER BY id DESC LIMIT %s"
    )
    try:
        cursor = connection.cursor()
        try:
            cursor.execute(query, (limit,))
            raw_rows = cursor.fetchall()
        finally:
            cursor.close()
    finally:
        connection.close()

    cases: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []
    for values in raw_rows:
        row = dict(zip(columns, values))
        try:
            cases.append(build_business_case(row))
        except Exception as exc:
            issues.append(
                {
                    "source_record_id": str(row.get("id") or ""),
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            )

    imported_at = _now()
    library = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": imported_at,
        "source_snapshot": {
            "database": "dm_data",
            "table": SOURCE_TABLE,
            "filter": SOURCE_FILTER,
            "order": "id DESC",
            "requested_limit": limit,
            "source_row_count": len(raw_rows),
            "runnable_case_count": len(cases),
            "import_issue_count": len(issues),
            "issues": issues,
        },
        "cases": cases,
    }
    from ..records import case_store
    kind = case_store.kind_for(output_path)
    inserted = case_store.import_library(kind, library) if kind else None
    if not kind:
        save_business_cases(library, output_path)
    return {
        "status": "IMPORTED" if cases else "NO_RUNNABLE_CASES",
        "source_row_count": len(raw_rows),
        "case_count": len(cases),
        "issue_count": len(issues),
        "issues": issues,
        "business_cases": f"mysql:agent_security_cases:{kind}" if kind else str(output_path.resolve()),
        "inserted_case_count": inserted if kind else len(cases),
        "updated_at": imported_at,
    }


__all__ = [
    "SCHEMA_VERSION",
    "SOURCE_FILTER",
    "SOURCE_TABLE",
    "build_business_case",
    "import_business_cases",
    "load_business_cases",
]
