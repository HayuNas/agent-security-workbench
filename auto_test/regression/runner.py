"""原样重放成功攻击，判断问题是否已修复。"""

from __future__ import annotations

import json
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import date, datetime
from pathlib import Path
from typing import Any, Mapping

from ..packs import load_attack_pack
from ..core.paths import AUTO_TEST_ROOT, REGRESSION_RESULTS_DIR
from ..core.progress import TerminalProgress
from ..core.messages import apply_message_prefix, normalize_message_prefix
from ..core.redaction import redact_report_text, redact_value
from ..records.findings import finding_analysis
from ..packs.epe_ids import canonical_epe_pack_id
from ..records.mysql import sync_report_to_mysql_safely
from ..oracles.router import (
    bind_user_context_canary,
    oracle_success,
    prepare_pack_oracle,
    score_attack_turns as score_pack_turns,
)
from ..records.cases import (
    DEFAULT_CASES_PATH,
    load_security_cases,
    security_case_target_key,
    update_retest_result,
)
from ..clients.factory import build_target_client, resolve_target_profile
from ..clients.smoke import require_ai_web_contract
from ..clients.target import KyAgentClient, build_test_identity
from ..assets import resolve_ai_web_asset_registry
from ..oracles.protected_assets import load_protected_assets
from ..fixtures.user_context import (
    build_user_context_fixture,
    is_paired_user_context_pack,
)


# 兼容旧模块级常量；默认路径统一由 core.paths 定义。
AUTO_TEST_DIR = AUTO_TEST_ROOT
DEFAULT_OUTPUT_DIR = REGRESSION_RESULTS_DIR


def _string_set(value: Any) -> set[str]:
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return {str(item).strip() for item in values if str(item or "").strip()}


def _regression_date(args: Any) -> str:
    value = str(getattr(args, "regression_date", None) or "").strip()
    if not value:
        return ""
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise ValueError("--date 必须使用 YYYY-MM-DD 格式") from exc


def _regression_before_date(args: Any) -> str:
    value = str(getattr(args, "regression_before_date", None) or "").strip()
    if not value:
        return ""
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise ValueError("--before-date 必须使用 YYYY-MM-DD 格式") from exc


def _markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# 安全攻击回归复测",
        "",
        f"- 运行 ID：`{report.get('run_id')}`",
        f"- 日期：{report.get('created_at')}",
        "",
    ]
    for result in report.get("results") or []:
        analysis = result.get("finding_analysis") or {}
        lines.extend(
            [
                f"## {result.get('case_id')} · {result.get('record_result')}",
                "",
                f"攻击方式：{result.get('attack_method')}  ",
                f"Oracle 结果：`{result.get('outcome')}`",
                "",
            ]
        )
        from ..judges.attack_consensus import consensus_markdown
        lines.extend(consensus_markdown(result.get('oracle_result') or {}))
        if analysis:
            lines.extend(
                [
                    "### 原问题归因与修改建议",
                    "",
                    "归因范围：黑盒组件级分析，不宣称已定位服务器具体代码行。",
                    "",
                    f"问题归因：{analysis.get('root_cause')}",
                    "",
                    f"修改建议：{analysis.get('remediation_advice')}",
                    "",
                ]
            )
        for turn in result.get("turns") or []:
            lines.extend(
                [
                    f"### 第 {turn.get('turn_index')} 轮",
                    "",
                    f"客户：{redact_report_text(turn.get('message'))}",
                    "",
                    f"Agent：{redact_report_text(turn.get('reply'))}",
                    "",
                ]
            )
    return "\n".join(lines)


def _select_cases(args: Any) -> list[dict[str, Any]]:
    library = load_security_cases(
        Path(getattr(args, "security_cases", None) or DEFAULT_CASES_PATH)
    )
    cases = [dict(item) for item in library["cases"] if isinstance(item, Mapping) and item.get("status", "active") == "active"]
    target_profile = resolve_target_profile(args)
    selected = {
        str(item) for item in getattr(args, "regression_case", None) or [] if str(item)
    }
    if selected:
        known = {str(item.get("case_id") or "") for item in cases}
        missing = sorted(selected - known)
        if missing:
            raise ValueError(f"未知安全回归 Case：{missing}")
        cases = [item for item in cases if str(item.get("case_id") or "") in selected]
    target_case_ids = {
        str(item.get("case_id") or "")
        for item in cases
        if security_case_target_key(item) == target_profile.target_key
    }
    mismatched = sorted(selected - target_case_ids)
    if mismatched:
        raise ValueError(
            f"指定 Case 不属于目标 {target_profile.target_key}：{mismatched}"
        )
    cases = [
        item
        for item in cases
        if security_case_target_key(item) == target_profile.target_key
    ]
    if bool(getattr(args, "regression_unresolved", False)):
        cases = [
            item
            for item in cases
            if str(item.get("result") or "")
            in {"仍可复现", "问题复发", "复测待确认"}
        ]
    pack_ids = _string_set(getattr(args, "regression_pack", None))
    legacy_pack_id = str(
        getattr(args, "regression_pack_id", None) or ""
    ).strip()
    if legacy_pack_id:
        pack_ids.add(legacy_pack_id)
    if pack_ids:
        cases = [
            item
            for item in cases
            if str(item.get("pack_id") or "") in pack_ids
        ]
    engine = str(getattr(args, "regression_engine", None) or "").strip()
    if engine:
        if engine not in {"cr", "epe"}:
            raise ValueError(f"未知回归执行引擎：{engine!r}")
        cases = [item for item in cases if _case_engine(item) == engine]
    query_packs = _string_set(
        getattr(args, "regression_query_pack", None)
    )
    if query_packs:
        cases = [
            item
            for item in cases
            if _case_epe_query_pack(item) in query_packs
        ]
    any_packs = _string_set(getattr(args, "regression_any_pack", None))
    if any_packs:
        cases = [
            item
            for item in cases
            if str(item.get("pack_id") or "") in any_packs
            or _case_epe_query_pack(item) in any_packs
        ]
    fix_batch = str(
        getattr(args, "regression_fix_batch", None) or ""
    ).strip()
    if fix_batch:
        cases = [
            item
            for item in cases
            if str(item.get("remediation_batch_id") or "") == fix_batch
        ]
    found_date = _regression_date(args)
    before_date = _regression_before_date(args)
    if found_date and before_date:
        raise ValueError("--date 与 --before-date 不能同时使用")
    if found_date:
        cases = [
            item
            for item in cases
            if str(item.get("found_at") or "")[:10] == found_date
        ]
    if before_date:
        cases = [
            item
            for item in cases
            if str(item.get("found_at") or "")[:10]
            and str(item.get("found_at") or "")[:10] < before_date
        ]
    return cases


def _case_engine(case: Mapping[str, Any]) -> str:
    explicit = str(case.get("engine") or "").strip().casefold()
    if explicit in {"cr", "epe"}:
        return explicit
    method = str(case.get("attack_method") or "").strip().casefold()
    return "epe" if method.startswith("epe") else "cr"


def _case_epe_query_pack(case: Mapping[str, Any]) -> str:
    explicit = str(case.get("query_pack") or "").strip()
    if explicit:
        return canonical_epe_pack_id(explicit)
    seed_id = str(case.get("seed_id") or "").upper()
    if seed_id.startswith("EPE-DIRECT-"):
        return "paper_direct"
    if seed_id.startswith("EPE-PROJECT-"):
        return "project_generated"
    if seed_id.startswith("EPE-V2-"):
        return "project_generated"
    if seed_id.startswith("EPE-CORPUS-"):
        return "prompt_leakage_corpus_v1"
    return ""


def run_security_regression(args: Any) -> dict[str, Any]:
    cases = _select_cases(args)
    target_profile = resolve_target_profile(args)
    target = target_profile.safe_dict()
    message_prefix = normalize_message_prefix(
        getattr(args, "message_prefix", None)
    )
    found_date = _regression_date(args)
    before_date = _regression_before_date(args)
    run_id = (
        str(getattr(args, "batch_id", None) or "").strip()
        or datetime.now().strftime("SR-%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    )
    progress = TerminalProgress()
    if bool(getattr(args, "dry_run", False)):
        progress.emit("REG", f"Dry-run {run_id} | Cases={len(cases)}")
        by_engine = Counter(_case_engine(item) for item in cases)
        by_pack = Counter(str(item.get("pack_id") or "") for item in cases)
        return {
            "status": "READY_NO_INTERFACE",
            "run_id": run_id,
            "pack_ids": sorted(
                _string_set(getattr(args, "regression_pack", None))
                | _string_set(getattr(args, "regression_any_pack", None))
                | _string_set(getattr(args, "regression_pack_id", None))
            ),
            "engine": str(getattr(args, "regression_engine", None) or ""),
            "query_packs": sorted(
                _string_set(getattr(args, "regression_query_pack", None))
            ),
            "fix_batch": str(
                getattr(args, "regression_fix_batch", None) or ""
            ),
            "date": found_date,
            "before_date": before_date,
            "unresolved": bool(getattr(args, "regression_unresolved", False)),
            "workers": int(getattr(args, "attack_workers", 3) or 3),
            "planned_case_count": len(cases),
            "case_ids": [item["case_id"] for item in cases],
            "case_count_by_engine": dict(sorted(by_engine.items())),
            "case_count_by_pack": dict(sorted(by_pack.items())),
            "target": target,
        }
    if not cases:
        progress.emit("REG", f"运行 {run_id} | 没有已登记的成功 Case")
        return {
            "status": "NO_REGISTERED_SUCCESS",
            "run_id": run_id,
            "case_count": 0,
            "target": target,
        }
    asset_registry_path = (
        Path(args.asset_registry)
        if getattr(args, "asset_registry", None)
        else None
    )
    if target_profile.adapter == "ai-web":
        if asset_registry_path is None:
            asset_registry_path = resolve_ai_web_asset_registry(
                target_profile.app_id
            )
        require_ai_web_contract(target_profile.target_key)
        unsupported = [
            str(item.get("case_id") or "")
            for item in cases
            if _case_engine(item) != "epe"
            or len(list(item.get("messages") or [])) != 1
        ]
        if unsupported:
            raise ValueError(
                "ai-web 第一阶段只支持单轮 EPE Case：" + ", ".join(unsupported)
            )
    asset_snapshot_id = ""
    if asset_registry_path is not None:
        asset_snapshot_id = str(
            load_protected_assets(asset_registry_path).get("snapshot_id") or ""
        )
    workers = int(getattr(args, "attack_workers", 3) or 3)
    if workers < 1:
        raise ValueError("--workers 必须大于 0")
    workers = min(workers, len(cases))
    progress.emit(
        "REG",
        f"运行 {run_id} 开始 | Target={target_profile.target_key} "
        f"| Cases={len(cases)} | Workers={workers}",
    )
    try:
        client = build_target_client(
            args,
            target_profile,
            ky_agent_client_class=KyAgentClient,
        )
        health = (
            client.health()
            if target_profile.adapter == "ai-web"
            else {"ok": True, "adapter": "ky-agent", "checked": False}
        )
    except Exception as exc:
        raise ValueError(
            f"目标连通性检查失败：{type(exc).__name__}: "
            f"{redact_value(str(exc))}"
        ) from exc
    if target_profile.adapter == "ai-web" and not bool(
        health.get("target_visible")
    ):
        raise ValueError(
            f"授权账号的 Agent 列表中未找到 appId {target_profile.app_id}"
        )
    created_at = datetime.now().astimezone().isoformat(timespec="seconds")
    def execute_case(position: int, case: Mapping[str, Any]) -> dict[str, Any]:
        pack = load_attack_pack(str(case.get("pack_id") or ""))
        if (pack.get("risk_policy") or {}).get("risk_flags"):
            raise ValueError(f"回归 Case {case['case_id']} 含副作用风险，拒绝自动执行")
        runtime = prepare_pack_oracle(
            pack,
            asset_registry=asset_registry_path,
            selected_asset_ids=(
                getattr(args, "asset_id", None)
                if target_profile.adapter != "ai-web"
                or getattr(args, "asset_id", None) is not None
                else []
            ),
            selected_marker_group_ids=(
                [] if target_profile.adapter == "ai-web" else None
            ),
        )
        wx_account, wx_contact = build_test_identity(
            run_id=run_id,
            scenario_group_id="SECURITY-REGRESSION",
            case={"case_id": case["case_id"], "variant": "attack"},
            repeat_index=position,
        )
        item: dict[str, Any] = {
            "case_id": case["case_id"],
            "target": target,
            "engine": _case_engine(case),
            "query_pack": _case_epe_query_pack(case),
            "messages": [
                apply_message_prefix(message, message_prefix)
                for message in case.get("messages") or []
            ],
            "original_messages": list(case.get("messages") or []),
            "input_transform": (
                {"type": "message_prefix", "prefix": message_prefix}
                if message_prefix
                else None
            ),
            "attack_method": case.get("attack_method"),
            "pack_id": pack["pack_id"],
            "fixture_setup": None,
            "session": None,
            "turns": [],
            "oracle_result": {},
            "finding_analysis": None,
            "outcome": "INVALID",
            "error": None,
        }
        progress.emit(
            "REG",
            f"Case {position}/{len(cases)} {case['case_id']} "
            f"| Pack={pack['pack_id']} | 开始",
        )
        try:
            victim_user_id = ""
            if is_paired_user_context_pack(pack):
                progress.emit(
                    "REG",
                    f"Case {position}/{len(cases)} {case['case_id']} "
                    "| 预置受害用户 Canary",
                )
                fixture = build_user_context_fixture(
                    pack,
                    run_id=run_id,
                    scope_id=f"regression-{case['case_id']}",
                )
                victim_account, victim_contact = build_test_identity(
                    run_id=run_id,
                    scenario_group_id="SECURITY-REGRESSION",
                    case={"case_id": case["case_id"], "variant": "victim"},
                    repeat_index=position,
                )
                victim_session = client.init_test(
                    wx_account=victim_account,
                    wx_contact=victim_contact,
                )
                victim_user_id = str(victim_session.user_id)
                victim_trace = client.chat(
                    victim_session,
                    fixture["victim_seed_message"],
                    allow_transport_retry=True,
                )
                victim_reply = str(victim_trace.get("reply") or "")
                item["fixture_setup"] = {
                    "type": fixture["type"],
                    "status": "READY" if victim_reply.strip() else "INVALID",
                    "victim_session": asdict(victim_session),
                    "victim_seed_message": fixture["victim_seed_message"],
                    "victim_reply": victim_reply,
                    "trace": victim_trace,
                }
                if not victim_reply.strip():
                    raise ValueError("受害用户 B 的 Canary 预置未获得有效回复")
                runtime = bind_user_context_canary(runtime, fixture["canary"])
            session = client.init_test(
                wx_account=wx_account, wx_contact=wx_contact
            )
            if victim_user_id and session.user_id == victim_user_id:
                raise ValueError("安全回归生成了相同的攻击与受害 user_id")
            item["session"] = asdict(session)
            for turn_index, message in enumerate(item["messages"], start=1):
                progress.emit(
                    "REG",
                    f"Case {position}/{len(cases)} {case['case_id']} "
                    f"| 第 {turn_index}/{len(case.get('messages') or [])} 轮 "
                    "| 请求目标 Agent",
                )
                trace = client.chat(
                    session, str(message), allow_transport_retry=True
                )
                turn = {
                    "turn_index": turn_index,
                    "session_restart_index": 0,
                    "session_id": str(session.session_id),
                    "message": str(message),
                    "reply": str(trace.get("reply") or ""),
                    "trace": trace,
                }
                item["turns"].append(turn)
                candidate = score_pack_turns(pack, item["turns"], runtime)
                item["oracle_result"] = candidate
                if oracle_success(pack, candidate):
                    break
            item["outcome"] = str(
                (item.get("oracle_result") or {}).get("outcome") or "INVALID"
            )
        except Exception as exc:
            item["error"] = f"{type(exc).__name__}: {redact_value(str(exc))}"
        current_analysis = finding_analysis(
            str(pack.get("pack_id") or ""),
            outcome=item.get("outcome"),
            oracle_result=item.get("oracle_result"),
        )
        if current_analysis is None and (
            case.get("root_cause") or case.get("remediation_advice")
        ):
            current_analysis = {
                "scenario_code": case.get("scenario_code"),
                "scenario_name": case.get("scenario_name"),
                "analysis_scope": case.get("analysis_scope")
                or "black_box_component",
                "root_cause": case.get("root_cause"),
                "remediation_advice": case.get("remediation_advice"),
            }
        item["finding_analysis"] = current_analysis
        progress.emit(
            "REG",
            f"Case {position}/{len(cases)} {case['case_id']} "
            f"| 完成 | outcome={item['outcome']}",
        )
        return item

    indexed_cases = list(enumerate(cases, start=1))
    if workers == 1:
        results = [execute_case(position, case) for position, case in indexed_cases]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(
                pool.map(
                    lambda pair: execute_case(pair[0], pair[1]),
                    indexed_cases,
                )
            )
    report = {
        "schema_version": "1.0-security-regression-report",
        "status": "COMPLETED",
        "run_id": run_id,
        "created_at": created_at,
        "engine": str(getattr(args, "regression_engine", None) or ""),
        "target": target,
        "asset_snapshot_id": asset_snapshot_id or None,
        "input_transform": (
            {"type": "message_prefix", "prefix": message_prefix}
            if message_prefix
            else None
        ),
        "health": health,
        "pack_ids": sorted(
            _string_set(getattr(args, "regression_pack", None))
            | _string_set(getattr(args, "regression_any_pack", None))
            | _string_set(getattr(args, "regression_pack_id", None))
        ),
        "query_packs": sorted(
            _string_set(getattr(args, "regression_query_pack", None))
        ),
        "fix_batch": str(
            getattr(args, "regression_fix_batch", None) or ""
        ),
        "date": found_date,
        "before_date": before_date,
        "unresolved": bool(getattr(args, "regression_unresolved", False)),
        "workers": workers,
        "results": results,
    }
    output_dir = Path(
        getattr(args, "security_output_dir", None) or DEFAULT_OUTPUT_DIR
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}.json"
    markdown_path = output_dir / f"{run_id}.md"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    cases_path = Path(
        getattr(args, "security_cases", None) or DEFAULT_CASES_PATH
    )
    for item in results:
        item["record_result"] = update_retest_result(
            str(item["case_id"]),
            outcome=str(item.get("outcome") or "INVALID"),
            tested_at=created_at,
            source_json=json_path,
            cases_path=cases_path,
        )
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    markdown_path.write_text(_markdown(report), encoding="utf-8")
    mysql_sync = (
        sync_report_to_mysql_safely(report)
        if cases_path.resolve() == DEFAULT_CASES_PATH.resolve()
        else {
            "enabled": False,
            "synced": False,
            "case_count": 0,
            "run_count": 0,
            "reason": "custom_cases_path",
        }
    )
    progress.emit(
        "REG",
        "MySQL 同步 "
        f"| synced={mysql_sync.get('synced')} "
        f"| Cases={mysql_sync.get('case_count', 0)} "
        f"| Runs={mysql_sync.get('run_count', 0)}",
    )
    progress.emit(
        "REG",
        f"运行完成 | Cases={len(results)} | JSON={json_path} | Markdown={markdown_path}",
    )
    return {
        "status": report["status"],
        "run_id": run_id,
        "case_count": len(results),
        "json": str(json_path.resolve()),
        "markdown": str(markdown_path.resolve()),
        "security_cases": str(cases_path.resolve()),
        "mysql_sync": mysql_sync,
        "target": target,
    }


__all__ = ["DEFAULT_OUTPUT_DIR", "run_security_regression"]
