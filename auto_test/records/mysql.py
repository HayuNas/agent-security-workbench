"""Persist scenarios, Cases, and executions to MySQL."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..core.paths import AUTO_TEST_ROOT
from ..packs.epe_ids import canonical_epe_pack_id
from ..core.redaction import redact_report_text
from .findings import (
    SCENARIO_GUIDANCE,
    finding_analysis,
    guidance_for_pack,
    is_success_outcome,
)
from .cases import load_security_cases, security_case_id


PROJECT_ROOT = AUTO_TEST_ROOT.parent
FALSE_VALUES = frozenset({"0", "false", "no", "off", "disabled"})


def _dotenv_values() -> dict[str, str]:
    path = PROJECT_ROOT / ".env_develop"
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return values


def _setting(name: str, fallback: Mapping[str, str]) -> str:
    return str(os.getenv(name) or fallback.get(name) or "").strip()


def mysql_enabled() -> bool:
    value = str(os.getenv("KY_SECURITY_MYSQL_ENABLED", "1")).strip().casefold()
    return value not in FALSE_VALUES


def _connect():
    try:
        import pymysql
    except ImportError as exc:
        raise RuntimeError("缺少 PyMySQL，无法同步安全测试数据库") from exc
    fallback = _dotenv_values()
    required = {
        name: _setting(name, fallback)
        for name in (
            "DM_DATA_MYSQL_HOST",
            "DM_DATA_MYSQL_USER",
            "DM_DATA_MYSQL_PASSWORD",
            "DM_DATA_MYSQL_DB",
        )
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise RuntimeError(f"缺少 MySQL 配置：{missing}")
    if required["DM_DATA_MYSQL_DB"] != "dm_data":
        raise RuntimeError("安全测试记录只允许写入 dm_data")
    return pymysql.connect(
        host=required["DM_DATA_MYSQL_HOST"],
        port=int(_setting("DM_DATA_MYSQL_PORT", fallback) or 3306),
        user=required["DM_DATA_MYSQL_USER"],
        password=required["DM_DATA_MYSQL_PASSWORD"],
        database=required["DM_DATA_MYSQL_DB"],
        charset="utf8mb4",
        connect_timeout=8,
        autocommit=False,
    )


def _mysql_datetime(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text[:19].replace("T", " ")


def _selected_messages(iteration: Mapping[str, Any]) -> list[str]:
    turns = [
        item for item in iteration.get("turns") or [] if isinstance(item, Mapping)
    ]
    if not turns:
        return []
    scope = iteration.get("oracle_scope") or {}
    selected_restart = scope.get("session_restart_index")
    if selected_restart is None:
        selected_restart = max(
            int(item.get("session_restart_index") or 0) for item in turns
        )
    selected_session = str(scope.get("session_id") or "")
    return [
        str(item.get("message") or "").strip()
        for item in turns
        if int(item.get("session_restart_index") or 0) == int(selected_restart)
        and (
            not selected_session
            or not str(item.get("session_id") or "")
            or str(item.get("session_id") or "") == selected_session
        )
        and str(item.get("message") or "").strip()
    ]


def _agent_code(item: Mapping[str, Any], default: str = "ky-sales") -> str:
    session = item.get("session")
    if isinstance(session, Mapping) and session.get("agent_type"):
        return str(session["agent_type"])
    sessions = item.get("sessions") or []
    for session_item in reversed(sessions):
        if isinstance(session_item, Mapping) and session_item.get("agent_type"):
            return str(session_item["agent_type"])
    return default


def _report_case_target_key(report: Mapping[str, Any]) -> str:
    target = report.get("target")
    if not isinstance(target, Mapping):
        return ""
    if str(target.get("adapter") or "") != "ai-web":
        return ""
    return str(target.get("target_key") or "").strip()


def _evidence(oracle: Mapping[str, Any] | None, outcome: str) -> str:
    value = oracle if isinstance(oracle, Mapping) else {}
    summary = str(
        value.get("reason")
        or value.get("status")
        or value.get("evidence")
        or outcome
    )
    return str(redact_report_text(summary))[:6000]


def _reply_excerpt(item: Mapping[str, Any]) -> str:
    turns = [
        turn for turn in item.get("turns") or [] if isinstance(turn, Mapping)
    ]
    if not turns:
        return ""
    oracle = item.get("oracle_result") or item.get("candidate") or {}
    evidence_index = oracle.get("evidence_turn_index")
    selected: Mapping[str, Any] = turns[-1]
    if evidence_index is not None:
        for position, turn in enumerate(turns, start=1):
            if position == int(evidence_index):
                selected = turn
                break
    return str(redact_report_text(selected.get("reply") or ""))[:6000]


def _run_code(experiment_id: str, discriminator: str) -> str:
    digest = hashlib.sha256(
        f"{experiment_id}|{discriminator}".encode("utf-8")
    ).hexdigest()[:20].upper()
    return f"RUN-{digest}"


def _repair_status(item: Mapping[str, Any], outcome: str, source: str) -> int | None:
    if source == "regression":
        record_result = str(item.get("record_result") or "")
        if record_result == "已修复":
            return 1
        if record_result in {"仍可复现", "问题复发"}:
            return 2
        if record_result in {"攻击成功（待修复）", "修复中", "待复测"}:
            return 0
        return None
    return 0 if is_success_outcome(outcome) else None


def _case_rows(report: Mapping[str, Any]) -> Iterable[dict[str, Any]]:
    schema = str(report.get("schema_version") or "")
    created_at = _mysql_datetime(report.get("created_at"))
    experiment_id = str(
        report.get("experiment_id") or report.get("run_id") or "security-run"
    )
    case_target_key = _report_case_target_key(report)
    if schema.endswith("security-attack-pack-report"):
        for pack in report.get("packs") or []:
            if not isinstance(pack, Mapping):
                continue
            pack_id = str(pack.get("pack_id") or "")
            guidance = guidance_for_pack(pack_id)
            for iteration in pack.get("iterations") or []:
                if not isinstance(iteration, Mapping):
                    continue
                messages = _selected_messages(iteration)
                if not messages:
                    initial_message = str(
                        iteration.get("initial_message") or ""
                    ).strip()
                    messages = [initial_message] if initial_message else []
                if not messages:
                    continue
                outcome = str(iteration.get("outcome") or "INVALID")
                oracle = iteration.get("oracle_result") or {}
                analysis = iteration.get("finding_analysis")
                if not isinstance(analysis, Mapping):
                    analysis = finding_analysis(
                        pack_id, outcome=outcome, oracle_result=oracle
                    )
                yield {
                    "scenario": guidance,
                    "case_id": security_case_id(pack_id, messages),
                    "agent_code": _agent_code(iteration),
                    "engine": "cr",
                    "pack_id": pack_id,
                    "prompt": "\n\n".join(messages),
                    "tested_at": created_at,
                    "outcome": outcome,
                    "oracle": oracle,
                    "analysis": analysis,
                    "repair_status": _repair_status(iteration, outcome, "exploration"),
                    "run_id": _run_code(
                        experiment_id, str(iteration.get("iteration_id") or "")
                    ),
                    "reply_excerpt": _reply_excerpt(iteration),
                    "source": "exploration",
                }
    elif schema.endswith("epe-report"):
        guidance = guidance_for_pack("prompt_leakage")
        query_pack = canonical_epe_pack_id(report.get("query_pack"))
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for result in report.get("results") or []:
            if isinstance(result, Mapping):
                grouped.setdefault(str(result.get("query_id") or ""), []).append(result)
        outcome_rank = {
            "RESISTED": 0,
            "PARTIAL_LEAK": 1,
            "CRITICAL_PARTIAL_LEAK": 2,
            "FULL_LEAK": 3,
        }
        for query_id, attempts in grouped.items():
            attempts = sorted(
                attempts, key=lambda item: int(item.get("execution_index") or 1)
            )
            successful = [
                item
                for item in attempts
                if is_success_outcome(str(item.get("outcome") or ""))
            ]
            result = (
                max(
                    successful,
                    key=lambda item: outcome_rank.get(
                        str(item.get("outcome") or ""), 0
                    ),
                )
                if successful
                else attempts[0]
            )
            messages = [
                str(turn.get("message") or "").strip()
                for turn in result.get("turns") or []
                if isinstance(turn, Mapping)
                and str(turn.get("message") or "").strip()
            ]
            if not messages:
                messages = [
                    str(item).strip()
                    for item in result.get("customer_messages") or []
                    if str(item).strip()
                ]
            if not messages:
                messages = [
                    str(message).strip()
                    for message in result.get("messages") or []
                    if str(message).strip()
                ]
            if not messages:
                continue
            outcome = str(result.get("outcome") or "INVALID")
            outcomes = [str(item.get("outcome") or "INVALID") for item in attempts]
            candidate = result.get("candidate")
            oracle = {
                **(dict(candidate) if isinstance(candidate, Mapping) else {}),
                "reason": (
                    f"EPE 批内复现：{len(successful)}/{len(attempts)} 次成功；"
                    f"结果={','.join(outcomes)}"
                ),
                "reproduction_attempts": len(attempts),
                "reproduction_successes": len(successful),
                "reproduction_outcomes": outcomes,
            }
            analysis = result.get("finding_analysis")
            if not isinstance(analysis, Mapping):
                analysis = finding_analysis(
                    "prompt_leakage", outcome=outcome, oracle_result=oracle
                )
            yield {
                "scenario": guidance,
                "case_id": security_case_id(
                    "prompt_leakage", messages, target_key=case_target_key
                ),
                "agent_code": _agent_code(result),
                "engine": "epe",
                "pack_id": query_pack,
                "prompt": "\n\n".join(messages),
                "tested_at": created_at,
                "outcome": outcome,
                "oracle": oracle,
                "analysis": analysis,
                "repair_status": _repair_status(result, outcome, "exploration"),
                "run_id": _run_code(experiment_id, query_id),
                "reply_excerpt": _reply_excerpt(result),
                "source": "exploration",
                "reproduction_attempts": len(attempts),
                "reproduction_successes": len(successful),
            }
    elif schema.endswith("security-regression-report"):
        for result in report.get("results") or []:
            if not isinstance(result, Mapping):
                continue
            pack_id = str(result.get("pack_id") or "")
            guidance = guidance_for_pack(pack_id)
            messages = [
                str(turn.get("message") or "").strip()
                for turn in result.get("turns") or []
                if isinstance(turn, Mapping)
                and str(turn.get("message") or "").strip()
            ]
            if not messages:
                messages = [
                    str(message).strip()
                    for message in result.get("messages") or []
                    if str(message).strip()
                ]
            if not messages:
                continue
            outcome = str(result.get("outcome") or "INVALID")
            tested_at = _mysql_datetime(result.get("tested_at") or created_at)
            analysis = result.get("finding_analysis")
            yield {
                "scenario": guidance,
                "case_id": str(result.get("case_id") or security_case_id(pack_id, messages)),
                "agent_code": _agent_code(result),
                "engine": str(result.get("engine") or "cr"),
                "pack_id": (
                    canonical_epe_pack_id(result.get("query_pack"))
                    if str(result.get("engine") or "") == "epe"
                    else pack_id
                ),
                "prompt": "\n\n".join(messages),
                "tested_at": tested_at,
                "outcome": outcome,
                "oracle": result.get("oracle_result") or {},
                "analysis": analysis,
                "repair_status": _repair_status(result, outcome, "regression"),
                "run_id": _run_code(
                    experiment_id, str(result.get("case_id") or "")
                ),
                "reply_excerpt": _reply_excerpt(result),
                "source": "regression",
            }


def sync_report_to_mysql(report: Mapping[str, Any]) -> dict[str, Any]:
    if not mysql_enabled():
        return {
            "enabled": False,
            "synced": False,
            "case_count": 0,
            "run_count": 0,
            "case_ids": [],
        }
    catalog = sync_scenario_catalog_to_mysql()
    rows = list(_case_rows(report))
    if not rows:
        return {
            "enabled": True,
            "synced": True,
            "scenario_count": catalog["scenario_count"],
            "case_count": 0,
            "run_count": 0,
            "case_ids": [],
        }
    connection = _connect()
    case_ids: set[str] = set()
    try:
        with connection.cursor() as cursor:
            for row in rows:
                scenario = row["scenario"]
                cursor.execute(
                    """
                    INSERT INTO agent_security_scenarios (
                        scenario_code, scenario_name, scope_type,
                        agent_code, description, enabled
                    ) VALUES (%s, %s, %s, %s, %s, 1)
                    ON DUPLICATE KEY UPDATE
                        scenario_code=VALUES(scenario_code)
                    """,
                    (
                        scenario["scenario_code"],
                        scenario["scenario_name"],
                        scenario["scope_type"],
                        scenario["scenario_agent_code"],
                        scenario["description"],
                    ),
                )
                cursor.execute(
                    "SELECT id FROM agent_security_scenarios WHERE scenario_code=%s",
                    (scenario["scenario_code"],),
                )
                scenario_id = cursor.fetchone()[0]
                analysis = row.get("analysis")
                root_cause = (
                    str(analysis.get("root_cause") or "")
                    if isinstance(analysis, Mapping)
                    else None
                )
                remediation = (
                    str(analysis.get("remediation_advice") or "")
                    if isinstance(analysis, Mapping)
                    else None
                )
                first_vulnerable = (
                    row["tested_at"] if is_success_outcome(row["outcome"]) else None
                )
                status_update = (
                    "status=COALESCE(VALUES(status), status)"
                    if row.get("source") == "regression"
                    else "status=COALESCE(status, VALUES(status))"
                )
                cursor.execute(
                    f"""
                    INSERT INTO agent_security_cases (
                        case_id, scenario_id, agent_code, engine, pack_id,
                        prompt, found_at, root_cause,
                        advice, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        scenario_id=VALUES(scenario_id),
                        agent_code=VALUES(agent_code),
                        engine=VALUES(engine),
                        pack_id=VALUES(pack_id),
                        prompt=VALUES(prompt),
                        found_at=COALESCE(
                            found_at, VALUES(found_at)
                        ),
                        root_cause=COALESCE(
                            NULLIF(VALUES(root_cause), ''), root_cause
                        ),
                        advice=COALESCE(
                            NULLIF(VALUES(advice), ''), advice
                        ),
                        {status_update}
                    """,
                    (
                        row["case_id"],
                        scenario_id,
                        row["agent_code"],
                        row["engine"],
                        row["pack_id"],
                        row["prompt"],
                        first_vulnerable,
                        root_cause,
                        remediation,
                        row["repair_status"],
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO agent_security_case_runs (
                        run_id, case_id, tested_at, result,
                        outcome, evidence, response
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        case_id=VALUES(case_id),
                        tested_at=VALUES(tested_at),
                        result=VALUES(result),
                        outcome=VALUES(outcome),
                        evidence=VALUES(evidence),
                        response=VALUES(response)
                    """,
                    (
                        row["run_id"],
                        row["case_id"],
                        row["tested_at"],
                        1
                        if is_success_outcome(row["outcome"])
                        else (0 if row["outcome"] == "RESISTED" else 2),
                        row["outcome"],
                        _evidence(row.get("oracle"), row["outcome"]),
                        row["reply_excerpt"],
                    ),
                )
                case_ids.add(str(row["case_id"]))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {
        "enabled": True,
        "synced": True,
        "scenario_count": catalog["scenario_count"],
        "case_count": len(case_ids),
        "run_count": len(rows),
        "case_ids": sorted(case_ids),
    }


def sync_report_to_mysql_safely(report: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return sync_report_to_mysql(report)
    except Exception as exc:
        summary = {
            "enabled": mysql_enabled(),
            "synced": False,
            "case_count": 0,
            "run_count": 0,
            "case_ids": [],
            "error": f"{type(exc).__name__}: {exc}",
        }
        print(f"[mysql] 安全测试记录同步失败：{summary['error']}", file=sys.stderr)
        return summary


def _dict_rows(cursor: Any) -> list[dict[str, Any]]:
    columns = [str(item[0]) for item in cursor.description or ()]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def load_finding_candidates(
    *,
    statuses: Sequence[int] = (0, 2),
    agent_code: str | None = None,
    pack_ids: Sequence[str] = (),
    case_ids: Sequence[str] = (),
    found_date: str | None = None,
    before_date: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Read Case facts and execution history for an explicit Finding run."""

    selected_statuses = tuple(sorted({int(value) for value in statuses}))
    if not selected_statuses or any(value not in {0, 1, 2} for value in selected_statuses):
        raise ValueError("Finding 状态只能是 0、1、2")
    if found_date and before_date:
        raise ValueError("Finding 不能同时使用 --date 和 --before-date")
    if not 1 <= int(limit) <= 1000:
        raise ValueError("Finding --limit 必须在 1 到 1000 之间")

    conditions = [
        "c.status IN (" + ",".join(["%s"] * len(selected_statuses)) + ")"
    ]
    parameters: list[Any] = list(selected_statuses)
    if agent_code:
        conditions.append("c.agent_code=%s")
        parameters.append(str(agent_code))
    if pack_ids:
        values = tuple(dict.fromkeys(str(value) for value in pack_ids if str(value)))
        if values:
            conditions.append("c.pack_id IN (" + ",".join(["%s"] * len(values)) + ")")
            parameters.extend(values)
    if case_ids:
        values = tuple(dict.fromkeys(str(value) for value in case_ids if str(value)))
        if values:
            conditions.append("c.case_id IN (" + ",".join(["%s"] * len(values)) + ")")
            parameters.extend(values)
    if found_date:
        conditions.append("DATE(c.found_at)=%s")
        parameters.append(str(found_date))
    if before_date:
        conditions.append("DATE(c.found_at)<%s")
        parameters.append(str(before_date))

    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT
                    c.case_id, c.scenario_id, s.scenario_code, s.scenario_name,
                    c.agent_code, c.engine, c.pack_id, c.prompt, c.found_at,
                    c.status, c.finding_id, c.root_cause AS legacy_root_cause,
                    c.advice AS legacy_advice
                FROM agent_security_cases c
                JOIN agent_security_scenarios s ON s.id=c.scenario_id
                WHERE {' AND '.join(conditions)}
                ORDER BY c.agent_code, s.scenario_code, c.found_at, c.case_id
                LIMIT %s
                """,
                (*parameters, int(limit)),
            )
            cases = _dict_rows(cursor)
            if not cases:
                return []
            selected_ids = [str(item["case_id"]) for item in cases]
            cursor.execute(
                """
                SELECT case_id, run_id, tested_at, result, outcome, evidence,
                       response AS agent_response_excerpt
                FROM agent_security_case_runs
                WHERE case_id IN ("""
                + ",".join(["%s"] * len(selected_ids))
                + ") ORDER BY case_id, tested_at, id",
                selected_ids,
            )
            runs = _dict_rows(cursor)
    finally:
        connection.close()

    by_case: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        by_case.setdefault(str(run["case_id"]), []).append(run)
    for case in cases:
        case["runs"] = by_case.get(str(case["case_id"]), [])
    return cases


def save_finding_batch(
    *,
    batch_id: str,
    findings: Sequence[Mapping[str, Any]],
    batch: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist validated Findings and attach each Case transactionally."""

    if not mysql_enabled():
        return {"enabled": False, "synced": False, "finding_count": 0, "case_count": 0}
    connection = _connect()
    linked_cases: set[str] = set()
    batch_value = dict(batch or {})
    derived_target = next(
        (
            str(item.get("target_key") or item.get("agent_code") or "")
            for item in findings
            if str(item.get("target_key") or item.get("agent_code") or "")
        ),
        "",
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO agent_security_finding_batches (
                    batch_id, source_run_ids, target_key, asset_snapshot_id,
                    analysis_status, case_count, finding_count, model_name,
                    classification_version, report_json_path, error_message
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    source_run_ids=VALUES(source_run_ids),
                    target_key=VALUES(target_key),
                    asset_snapshot_id=VALUES(asset_snapshot_id),
                    analysis_status=VALUES(analysis_status),
                    case_count=VALUES(case_count),
                    finding_count=VALUES(finding_count),
                    model_name=VALUES(model_name),
                    classification_version=VALUES(classification_version),
                    report_json_path=VALUES(report_json_path),
                    error_message=VALUES(error_message)
                """,
                (
                    batch_id,
                    json.dumps(batch_value.get("source_run_ids") or [], ensure_ascii=False),
                    str(batch_value.get("target_key") or derived_target),
                    batch_value.get("asset_snapshot_id") or None,
                    str(batch_value.get("analysis_status") or "COMPLETED"),
                    int(batch_value.get("case_count") or 0),
                    int(batch_value.get("finding_count") or len(findings)),
                    batch_value.get("model_name") or None,
                    str(
                        batch_value.get("classification_version")
                        or "finding-taxonomy-v1"
                    ),
                    batch_value.get("report_json_path") or None,
                    batch_value.get("error_message") or None,
                ),
            )
            for finding in findings:
                cursor.execute(
                    """
                    INSERT INTO agent_security_findings (
                        finding_id, batch_id, scenario_id, agent_code,
                        target_key, asset_snapshot_id, title, issue_type,
                        primary_trigger_type, trigger_types, remediation_type,
                        remediation_scope, root_cause_family, finding_fingerprint,
                        tested_deployment_commit, analysis_source_branch,
                        analysis_source_commit, root_cause, evidence,
                        remediation, acceptance, confidence, severity,
                        analysis_status, source_run_id, classification_version,
                        model_name, status, first_seen_at, last_seen_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON DUPLICATE KEY UPDATE
                        batch_id=VALUES(batch_id),
                        scenario_id=VALUES(scenario_id),
                        agent_code=VALUES(agent_code),
                        target_key=VALUES(target_key),
                        asset_snapshot_id=VALUES(asset_snapshot_id),
                        title=VALUES(title),
                        issue_type=VALUES(issue_type),
                        primary_trigger_type=VALUES(primary_trigger_type),
                        trigger_types=VALUES(trigger_types),
                        remediation_type=VALUES(remediation_type),
                        remediation_scope=VALUES(remediation_scope),
                        root_cause_family=VALUES(root_cause_family),
                        finding_fingerprint=VALUES(finding_fingerprint),
                        tested_deployment_commit=VALUES(tested_deployment_commit),
                        analysis_source_branch=VALUES(analysis_source_branch),
                        analysis_source_commit=VALUES(analysis_source_commit),
                        root_cause=VALUES(root_cause),
                        evidence=VALUES(evidence),
                        remediation=VALUES(remediation),
                        acceptance=VALUES(acceptance),
                        confidence=VALUES(confidence),
                        severity=VALUES(severity),
                        analysis_status=VALUES(analysis_status),
                        source_run_id=VALUES(source_run_id),
                        classification_version=VALUES(classification_version),
                        model_name=VALUES(model_name),
                        status=VALUES(status),
                        last_seen_at=VALUES(last_seen_at)
                    """,
                    (
                        finding["finding_id"],
                        batch_id,
                        finding["scenario_id"],
                        finding["agent_code"],
                        finding.get("target_key") or finding["agent_code"],
                        finding.get("asset_snapshot_id") or None,
                        finding["title"],
                        finding.get("issue_type") or finding.get("scenario_code") or "",
                        finding.get("primary_trigger_type") or "OTHER",
                        json.dumps(finding.get("trigger_types") or ["OTHER"], ensure_ascii=False),
                        finding.get("remediation_type") or "NEEDS_TRIAGE",
                        finding.get("remediation_scope") or "MIXED",
                        finding.get("root_cause_family") or "UNKNOWN",
                        finding.get("finding_fingerprint") or "",
                        finding.get("tested_deployment_commit") or None,
                        finding["analysis_source_branch"],
                        finding["analysis_source_commit"],
                        finding["root_cause"],
                        json.dumps(finding["evidence"], ensure_ascii=False),
                        json.dumps(finding["remediation"], ensure_ascii=False),
                        json.dumps(finding["acceptance"], ensure_ascii=False),
                        finding["confidence"],
                        int(finding.get("severity") or 0),
                        finding.get("analysis_status") or "COMPLETED",
                        finding.get("source_run_id") or None,
                        finding.get("classification_version") or "finding-taxonomy-v1",
                        finding["model_name"],
                        finding["status"],
                        _mysql_datetime(finding.get("first_seen_at")),
                        _mysql_datetime(finding.get("last_seen_at")),
                    ),
                )
                case_ids = [str(value) for value in finding.get("case_ids") or []]
                if not case_ids:
                    raise ValueError("Finding 缺少关联 Case")
                cursor.execute(
                    "SELECT COUNT(*) FROM agent_security_cases WHERE case_id IN ("
                    + ",".join(["%s"] * len(case_ids))
                    + ")",
                    case_ids,
                )
                if int(cursor.fetchone()[0]) != len(case_ids):
                    raise RuntimeError(
                        f"Finding {finding['finding_id']} 包含不存在的 Case"
                    )
                cursor.executemany(
                    """
                    INSERT INTO agent_security_finding_cases (
                        finding_id, case_id, first_batch_id, last_batch_id
                    ) VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        last_batch_id=VALUES(last_batch_id)
                    """,
                    [
                        (finding["finding_id"], case_id, batch_id, batch_id)
                        for case_id in case_ids
                    ],
                )
                cursor.execute(
                    "UPDATE agent_security_cases SET finding_id=%s WHERE case_id IN ("
                    + ",".join(["%s"] * len(case_ids))
                    + ")",
                    (finding["finding_id"], *case_ids),
                )
                linked_cases.update(case_ids)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {
        "enabled": True,
        "synced": True,
        "finding_count": len(findings),
        "case_count": len(linked_cases),
    }


def refresh_finding_statuses(case_ids: Sequence[str]) -> dict[str, Any]:
    """Refresh linked Finding status after a regression without calling a model."""

    values = tuple(dict.fromkeys(str(value) for value in case_ids if str(value)))
    if not values or not mysql_enabled():
        return {"enabled": mysql_enabled(), "synced": False, "finding_count": 0}
    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT DISTINCT finding_id FROM agent_security_finding_cases "
                "WHERE case_id IN (" + ",".join(["%s"] * len(values)) + ")",
                values,
            )
            finding_ids = [str(row[0]) for row in cursor.fetchall() if row[0]]
            for finding_id in finding_ids:
                cursor.execute(
                    """
                    SELECT c.status
                    FROM agent_security_finding_cases fc
                    JOIN agent_security_cases c ON c.case_id=fc.case_id
                    WHERE fc.finding_id=%s AND c.status IS NOT NULL
                    """,
                    (finding_id,),
                )
                statuses = [int(row[0]) for row in cursor.fetchall()]
                if not statuses:
                    continue
                status = 2 if 2 in statuses else (0 if 0 in statuses else 1)
                cursor.execute(
                    "UPDATE agent_security_findings SET status=%s WHERE finding_id=%s",
                    (status, finding_id),
                )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {
        "enabled": True,
        "synced": True,
        "finding_count": len(finding_ids),
        "finding_ids": finding_ids,
    }


def sync_scenario_catalog_to_mysql() -> dict[str, Any]:
    """Upsert every registered scenario, including scenarios with no finding yet."""

    connection = _connect()
    try:
        with connection.cursor() as cursor:
            for scenario in SCENARIO_GUIDANCE.values():
                cursor.execute(
                    """
                    INSERT INTO agent_security_scenarios (
                        scenario_code, scenario_name, scope_type,
                        agent_code, description, enabled
                    ) VALUES (%s, %s, %s, %s, %s, 1)
                    ON DUPLICATE KEY UPDATE
                        scenario_code=VALUES(scenario_code)
                    """,
                    (
                        scenario["scenario_code"],
                        scenario["scenario_name"],
                        scenario["scope_type"],
                        scenario["scenario_agent_code"],
                        scenario["description"],
                    ),
                )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {"synced": True, "scenario_count": len(SCENARIO_GUIDANCE)}


def update_case_aggregate_statuses(
    statuses: Mapping[str, int],
) -> dict[str, Any]:
    """Update only Case current status; raw regression runs remain untouched."""

    values = {str(key): int(value) for key, value in statuses.items() if str(key)}
    if any(value not in {0, 1, 2} for value in values.values()):
        raise ValueError("Case 聚合状态只能是 0、1、2")
    if not values:
        return {"enabled": True, "synced": True, "case_count": 0}
    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT case_id FROM agent_security_cases WHERE case_id IN ("
                + ",".join(["%s"] * len(values))
                + ")",
                tuple(values),
            )
            existing = {str(row[0]) for row in cursor.fetchall()}
            missing = sorted(set(values) - existing)
            if missing:
                raise RuntimeError(f"MySQL 缺少待聚合 Case：{missing}")
            for case_id, status in values.items():
                cursor.execute(
                    "UPDATE agent_security_cases SET status=%s WHERE case_id=%s",
                    (status, case_id),
                )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {"enabled": True, "synced": True, "case_count": len(values)}


def sync_existing_success_library_to_mysql(
    cases_path: Path,
) -> dict[str, Any]:
    """Seed local Cases that do not already have any MySQL execution history.

    A backfill row is only a migration fallback.  If a Case already has a raw
    exploration or regression run, creating another summary run would duplicate
    the same historical event and make per-Case history misleading.
    """

    if not mysql_enabled():
        return {"enabled": False, "synced": False, "case_count": 0, "run_count": 0}

    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT DISTINCT case_id FROM agent_security_case_runs")
            existing_run_case_ids = {str(row[0]) for row in cursor.fetchall()}
    finally:
        connection.close()

    library = load_security_cases(cases_path)
    results: list[dict[str, Any]] = []
    for case in library["cases"]:
        if not isinstance(case, Mapping):
            continue
        case_id = str(case.get("case_id") or "")
        if not case_id or case_id in existing_run_case_ids:
            continue
        turns = [
            {"turn_index": index, "message": message, "reply": ""}
            for index, message in enumerate(case.get("messages") or [], start=1)
            if str(message).strip()
        ]
        results.append(
            {
                "case_id": case_id,
                "pack_id": case.get("pack_id"),
                "engine": case.get("engine") or "cr",
                "query_pack": case.get("query_pack") or "",
                "turns": turns,
                "outcome": case.get("first_outcome") or case.get("latest_outcome"),
                "oracle_result": {"reason": case.get("evidence")},
                "finding_analysis": {
                    "scenario_code": case.get("scenario_code"),
                    "scenario_name": case.get("scenario_name"),
                    "analysis_scope": case.get("analysis_scope"),
                    "root_cause": case.get("root_cause"),
                    "remediation_advice": case.get("remediation_advice"),
                },
                "record_result": case.get("result"),
                "tested_at": case.get("found_at"),
            }
        )
    return sync_report_to_mysql(
        {
            "schema_version": "1.0-security-regression-report",
            "run_id": "BACKFILL-SECURITY-CASES-V1",
            "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "results": results,
        }
    )


__all__ = [
    "load_finding_candidates",
    "mysql_enabled",
    "refresh_finding_statuses",
    "save_finding_batch",
    "sync_report_to_mysql",
    "sync_report_to_mysql_safely",
    "sync_scenario_catalog_to_mysql",
    "sync_existing_success_library_to_mysql",
    "update_case_aggregate_statuses",
]
