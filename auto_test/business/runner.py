"""重放 BIZ Case 并生成独立的 ky-sales 正向业务回归报告。"""

from __future__ import annotations

import json
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from ..clients.factory import build_target_client, resolve_target_profile
from ..clients.model import OpenAICompatibleClient, load_model_settings
from ..clients.target import build_test_identity
from ..core.paths import (
    BUSINESS_BAD_CASES_PATH,
    BUSINESS_CASES_PATH,
    BUSINESS_REGRESSION_RESULTS_DIR,
)
from ..core.progress import TerminalProgress
from ..core.redaction import redact_value
from .cases import load_business_cases
from .judge import judge_business_case
from .turn_adapter import adapt_customer_turn, detect_script_drift_signals


_OUTCOME_LABELS = {
    "PASS": "通过",
    "FAIL": "失败",
    "REVIEW": "待复核",
    "SCRIPT_DRIFT": "脚本漂移",
    "ADAPTER_ERROR": "话术适配错误",
    "ERROR": "执行错误",
}


def _outcome_label(value: Any) -> str:
    code = str(value or "ERROR").upper()
    return _OUTCOME_LABELS.get(code, code)


def _summary_zh(summary: Mapping[str, Any]) -> dict[str, int]:
    return {
        "业务案例总数": int(summary.get("total", 0) or 0),
        "通过": int(summary.get("PASS", 0) or 0),
        "失败": int(summary.get("FAIL", 0) or 0),
        "待复核": int(summary.get("REVIEW", 0) or 0),
        "脚本漂移": int(summary.get("SCRIPT_DRIFT", 0) or 0),
        "话术适配错误": int(summary.get("ADAPTER_ERROR", 0) or 0),
        "执行错误": int(summary.get("ERROR", 0) or 0),
        "已适配话术轮数": int(summary.get("adapted_turns", 0) or 0),
    }


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _select_cases(args: Any) -> list[dict[str, Any]]:
    path = Path(getattr(args, "business_cases", None) or BUSINESS_CASES_PATH)
    library = load_business_cases(path)
    revisions = dict(library.get("_caseRevisions") or {})
    all_cases = list(library.get("cases") or [])
    bad_ids = {str(item.get("case_id")) for item in all_cases} if (
        ("_libraryVersion" in library and library.get("_libraryKind") != "business")
        or path.resolve() == BUSINESS_BAD_CASES_PATH.resolve()) else set()
    if bool(getattr(args, "business_include_bad_cases", False)):
        bad_cases_path = Path(
            getattr(args, "business_bad_cases", None) or BUSINESS_BAD_CASES_PATH
        )
        bad_library = load_business_cases(bad_cases_path)
        all_cases.extend(bad_library.get("cases") or [])
        revisions.update(bad_library.get("_caseRevisions") or {})
        bad_ids.update(str(item.get("case_id")) for item in bad_library.get("cases") or [])
    unique_cases = {
        str(item.get("case_id") or ""): item
        for item in all_cases
        if isinstance(item, Mapping) and str(item.get("case_id") or "")
    }
    selected_ids = {
        str(item).strip()
        for item in getattr(args, "business_case", None) or []
        if str(item or "").strip()
    }
    target_key = resolve_target_profile(args).target_key
    cases = [
        {**dict(item), "_case_revision": revisions.get(str(item.get("case_id") or ""))}
        for item in unique_cases.values()
        if str(item.get("status") or "active") == "active"
        and (str(item.get("case_id")) not in bad_ids and not (item.get("target") or {}).get("target_key") or
             ((item.get("target") or {}).get("target_key") or "ky-agent:ky-sales") == target_key)
        and (not selected_ids or str(item.get("case_id") or "") in selected_ids)
    ]
    if selected_ids:
        found = {str(item.get("case_id") or "") for item in cases}
        missing = sorted(selected_ids - found)
        if missing:
            raise ValueError("未找到业务 Case：" + ", ".join(missing))
    limit = int(getattr(args, "business_limit", 0) or 0)
    if limit < 0:
        raise ValueError("--limit 不能小于 0")
    return cases[:limit] if limit else cases


def _markdown(report: Mapping[str, Any]) -> str:
    summary = report.get("summary") or {}
    lines = [
        "# ky-sales 正向业务回归",
        "",
        f"- Run：`{report.get('run_id')}`",
        f"- 时间：`{report.get('created_at')}`",
        f"- 业务案例总数：{summary.get('total', 0)}",
        f"- 通过：{summary.get('PASS', 0)}",
        f"- 失败：{summary.get('FAIL', 0)}",
        f"- 待复核：{summary.get('REVIEW', 0)}",
        f"- 脚本漂移：{summary.get('SCRIPT_DRIFT', 0)}",
        f"- 话术适配错误：{summary.get('ADAPTER_ERROR', 0)}",
        f"- 执行错误：{summary.get('ERROR', 0)}",
        f"- 已适配话术轮数：{summary.get('adapted_turns', 0)}",
        "",
        "## 结果",
        "",
    ]
    for item in report.get("results") or []:
        judge = item.get("judge") or {}
        lines.extend(
            [
                f"### {item.get('case_id')} · {_outcome_label(item.get('outcome'))}",
                "",
                f"- 场景：{(item.get('scenario') or {}).get('summary', '')}",
                f"- 历史分数：{item.get('baseline_score')}",
                f"- 当前分数：{judge.get('score', '')}",
                f"- 结论：{judge.get('reason') or item.get('error') or ''}",
                f"- 轮数：{len(item.get('turns') or [])}/{item.get('planned_turns', 0)}",
                f"- 话术适配：{item.get('adapted_turn_count', 0)}",
                f"- 脚本漂移：{(item.get('script_drift') or {}).get('reason', '')}",
                f"- 话术适配错误：{(item.get('adapter_error') or {}).get('reason', '')}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def run_business_regression(
    args: Any,
    *,
    target_builder: Callable[[Any, Any], Any] = build_target_client,
    judge_builder: Callable[..., OpenAICompatibleClient] | None = None,
    judge_function: Callable[..., dict[str, Any]] = judge_business_case,
    adapter_builder: Callable[..., OpenAICompatibleClient] | None = None,
    adapter_function: Callable[..., dict[str, Any]] = adapt_customer_turn,
) -> dict[str, Any]:
    cases = _select_cases(args)
    cases_path = Path(getattr(args, "business_cases", None) or BUSINESS_CASES_PATH)
    bad_cases_path = Path(
        getattr(args, "business_bad_cases", None) or BUSINESS_BAD_CASES_PATH
    )
    profile = resolve_target_profile(args)
    if profile.adapter not in {"ky-agent", "ky-app"}:
        raise ValueError("正向业务回归仅支持旧销售 Agent 和 KY App sales-agent")
    run_id = (
        str(getattr(args, "batch_id", None) or "").strip()
        or datetime.now().strftime("BR-%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    )
    workers = int(getattr(args, "business_workers", 3) or 3)
    if workers < 1:
        raise ValueError("--workers 必须大于 0")
    workers = min(workers, max(1, len(cases)))
    if bool(getattr(args, "dry_run", False)):
        return {
            "status": "READY_NO_INTERFACE",
            "run_id": run_id,
            "planned_case_count": len(cases),
            "case_ids": [item["case_id"] for item in cases],
            "workers": workers,
            "adapt_turns": bool(getattr(args, "business_adapt_turns", True)),
            "include_reasoning_eval": bool(
                getattr(args, "business_include_reasoning_eval", False)
            ),
            "target": profile.safe_dict(),
            "business_cases": str(cases_path.resolve()),
            "business_bad_cases": (
                str(bad_cases_path.resolve())
                if bool(getattr(args, "business_include_bad_cases", False))
                else None
            ),
        }
    if not cases:
        return {
            "status": "NO_BUSINESS_CASES",
            "run_id": run_id,
            "case_count": 0,
            "business_cases": str(cases_path.resolve()),
        }

    progress = TerminalProgress()
    target = target_builder(args, profile)
    settings = load_model_settings(
        role="judge", model_override=getattr(args, "judge_model", None)
    )
    if judge_builder is None:
        judge_builder = OpenAICompatibleClient
    judge_client = judge_builder(
        settings,
        timeout=float(getattr(args, "judge_timeout", 120.0)),
        retries=int(getattr(args, "judge_retries", 2)),
    )
    adapt_turns = bool(getattr(args, "business_adapt_turns", True))
    adapter_settings = None
    adapter_client = None
    if adapt_turns:
        adapter_settings = load_model_settings(
            role="judge",
            model_override=(
                getattr(args, "turn_adapter_model", None)
                or getattr(args, "judge_model", None)
            ),
        )
        if adapter_builder is None:
            adapter_builder = judge_builder
        adapter_client = adapter_builder(
            adapter_settings,
            timeout=float(getattr(args, "turn_adapter_timeout", 60.0)),
            retries=int(getattr(args, "judge_retries", 2)),
        )
    progress.emit(
        "BIZ",
        f"运行 {run_id} 开始 | Cases={len(cases)} | Workers={workers}",
    )

    def execute_case(position: int, case: Mapping[str, Any]) -> dict[str, Any]:
        reference_turns = list(case.get("reference_turns") or [])
        item: dict[str, Any] = {
            "case_id": case.get("case_id"),
            "case_revision": case.get("_case_revision"),
            "source_record_id": (case.get("source") or {}).get("record_id"),
            "scenario": case.get("scenario") or {},
            "core_task": case.get("core_task") or {},
            "baseline_score": (case.get("baseline") or {}).get("score"),
            "planned_turns": len(reference_turns),
            "session": None,
            "turns": [],
            "judge": None,
            "outcome": "ERROR",
            "error": None,
            "adapted_turn_count": 0,
            "script_drift": None,
            "adapter_error": None,
        }
        progress.emit(
            "BIZ",
            f"Case {position}/{len(cases)} {case['case_id']} | 开始",
        )
        try:
            wx_account, wx_contact = build_test_identity(
                run_id=run_id,
                scenario_group_id="BUSINESS-REGRESSION",
                case={"case_id": case["case_id"], "variant": "business"},
                repeat_index=position,
            )
            session = target.init_test(
                wx_account=wx_account, wx_contact=wx_contact
            )
            item["session"] = asdict(session)
            for turn in reference_turns:
                original_message = str(turn.get("customer_message") or "")
                adaptation = {
                    "action": "KEEP",
                    "message": original_message,
                    "reason": "首轮话术无需适配",
                    "signals": [],
                    "checked_by_model": False,
                }
                if adapt_turns and item["turns"]:
                    try:
                        adaptation = adapter_function(
                            adapter_client,
                            case,
                            turn,
                            item["turns"],
                        )
                    except Exception as exc:
                        signals = detect_script_drift_signals(
                            original_message,
                            item["turns"],
                        )
                        adaptation = {
                            "action": "ADAPTER_ERROR",
                            "message": "",
                            "reason": (
                                "检测到上下文依赖，但辅助适配失败："
                                f"{type(exc).__name__}: {redact_value(str(exc))}"
                            )[:1000],
                            "signals": signals,
                            "checked_by_model": True,
                        }

                action = str(adaptation.get("action") or "KEEP").upper()
                if action == "ADAPTER_ERROR":
                    item["adapter_error"] = {
                        "round": int(turn.get("round") or len(item["turns"]) + 1),
                        "original_customer_message": original_message,
                        **adaptation,
                    }
                    item["outcome"] = "ADAPTER_ERROR"
                    break
                if action == "SCRIPT_DRIFT":
                    item["script_drift"] = {
                        "round": int(turn.get("round") or len(item["turns"]) + 1),
                        "original_customer_message": original_message,
                        **adaptation,
                    }
                    item["outcome"] = "SCRIPT_DRIFT"
                    break
                message = str(adaptation.get("message") or original_message)
                if action == "REWRITE":
                    item["adapted_turn_count"] += 1
                trace = target.chat(
                    session, message, allow_transport_retry=True
                )
                reply = str(trace.get("reply") or "")
                item["turns"].append(
                    {
                        "round": int(turn.get("round") or len(item["turns"]) + 1),
                        "original_customer_message": original_message,
                        "customer_message": message,
                        "reference_reply": str(turn.get("reference_reply") or ""),
                        "agent_reply": reply,
                        "adaptation": adaptation,
                        "trace": trace,
                    }
                )
                if not reply.strip():
                    raise ValueError("目标 Agent 返回空回复")
            if item["outcome"] not in {"SCRIPT_DRIFT", "ADAPTER_ERROR"}:
                judge_kwargs = (
                    {"include_reasoning": True}
                    if bool(getattr(args, "business_include_reasoning_eval", False))
                    else {}
                )
                item["judge"] = judge_function(
                    judge_client, case, item["turns"], **judge_kwargs
                )
                item["outcome"] = str(item["judge"].get("decision") or "REVIEW")
        except Exception as exc:
            item["error"] = f"{type(exc).__name__}: {redact_value(str(exc))}"
        progress.emit(
            "BIZ",
            f"Case {position}/{len(cases)} {case['case_id']} "
            f"| 完成 | 结果={_outcome_label(item['outcome'])}",
        )
        return item

    indexed = list(enumerate(cases, start=1))
    if workers == 1:
        results = [execute_case(position, case) for position, case in indexed]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda pair: execute_case(*pair), indexed))
    counts = Counter(str(item.get("outcome") or "ERROR") for item in results)
    adapted_turns = sum(int(item.get("adapted_turn_count") or 0) for item in results)
    summary = {
        "total": len(results),
        "PASS": counts.get("PASS", 0),
        "FAIL": counts.get("FAIL", 0),
        "REVIEW": counts.get("REVIEW", 0),
        "SCRIPT_DRIFT": counts.get("SCRIPT_DRIFT", 0),
        "ADAPTER_ERROR": counts.get("ADAPTER_ERROR", 0),
        "ERROR": counts.get("ERROR", 0),
        "adapted_turns": adapted_turns,
    }
    report = {
        "schema_version": "1.2-business-regression-report",
        "status": "COMPLETED",
        "run_id": run_id,
        "created_at": _now(),
        "target": profile.safe_dict(),
        "business_cases": str(cases_path.resolve()),
        "business_bad_cases": (
            str(bad_cases_path.resolve())
            if bool(getattr(args, "business_include_bad_cases", False))
            else None
        ),
        "judge_model": settings.safe_dict(),
        "turn_adapter_model": (
            adapter_settings.safe_dict() if adapter_settings is not None else None
        ),
        "adapt_turns": adapt_turns,
        "include_reasoning_eval": bool(
            getattr(args, "business_include_reasoning_eval", False)
        ),
        "workers": workers,
        "summary": summary,
        "summary_zh": _summary_zh(summary),
        "results": results,
    }
    output_dir = Path(
        getattr(args, "business_output_dir", None)
        or BUSINESS_REGRESSION_RESULTS_DIR
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}.json"
    markdown_path = output_dir / f"{run_id}.md"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    markdown_path.write_text(_markdown(report), encoding="utf-8")
    try:
        from ..workbench.review_findings import record_positive_retest
        record_positive_retest(report, json_path)
    except Exception as exc:
        report["review_finding_update_error"] = str(redact_value(str(exc)))[:500]
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
    progress.emit(
        "BIZ",
        f"运行完成 | Cases={len(results)} | JSON={json_path} | Markdown={markdown_path}",
    )
    return {
        "status": "COMPLETED",
        "run_id": run_id,
        "case_count": len(results),
        "summary": report["summary"],
        "summary_zh": report["summary_zh"],
        "json": str(json_path.resolve()),
        "markdown": str(markdown_path.resolve()),
        "business_cases": str(cases_path.resolve()),
        "target": profile.safe_dict(),
        "finding_report": finding_report,
    }


__all__ = ["run_business_regression"]
