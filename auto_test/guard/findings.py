"""Create self-contained, human-reviewed Findings from Guard regressions."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..core.redaction import redact_value


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _source_excerpt(relative_path: str, anchor: str, radius: int = 35) -> dict[str, Any]:
    path = REPOSITORY_ROOT / relative_path
    lines = path.read_text(encoding="utf-8").splitlines()
    anchor_index = next(
        (index for index, line in enumerate(lines) if anchor in line),
        0,
    )
    start = max(0, anchor_index - radius)
    end = min(len(lines), anchor_index + radius + 1)
    return {
        "path": relative_path,
        "line_start": start + 1,
        "line_end": end,
        "anchor": anchor,
        "content": "\n".join(lines[start:end]),
    }


def _source_context() -> list[dict[str, Any]]:
    return [
        _source_excerpt("risk_guard/engine.py", "async def evaluate_input"),
        _source_excerpt("risk_guard/engine.py", "async def evaluate_output"),
        _source_excerpt("risk_guard/engine.py", "def evaluate_stream_output"),
        _source_excerpt("risk_guard/assets.py", "def match_protected_assets"),
        _source_excerpt("risk_guard/policy_sync.py", "def sync_policies"),
    ]


def _sample_evidence(item: Mapping[str, Any]) -> dict[str, Any]:
    full_audit = item.get("full_audit")
    stream = item.get("stream")
    return redact_value(
        {
            "guard_case_id": item.get("case_id"),
            "source_case_id": item.get("source_case_id"),
            "direction": item.get("direction"),
            "stage": item.get("stage"),
            "expected_decision": item.get("expected_decision"),
            "actual_decision": item.get("actual_decision"),
            "content": str(item.get("content") or "")[:12000],
            "conversation_context": item.get("conversation_context") or [],
            "detector": item.get("detector") or "none",
            "rule_id": item.get("rule_id") or "",
            "checked_by": item.get("checked_by") or [],
            "degraded": bool(item.get("degraded")),
            "engine_version": item.get("engine_version"),
            "policy_version": item.get("policy_version"),
            "stream": (
                {
                    "chunk_size": stream.get("chunk_size"),
                    "window_size": stream.get("window_size"),
                    "checks_executed": stream.get("checks_executed"),
                    "blocked_at_chunk": stream.get("blocked_at_chunk"),
                    "last_check": (stream.get("checks") or [None])[-1],
                }
                if isinstance(stream, Mapping)
                else None
            ),
            "full_audit": full_audit if isinstance(full_audit, Mapping) else None,
        }
    )


def _uncovered_attack_groups(
    results: Sequence[Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    by_source: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in results:
        if str(item.get("expected_decision") or "") != "BLOCK":
            continue
        source_case_id = str(item.get("source_case_id") or "").strip()
        if source_case_id:
            by_source[source_case_id].append(item)

    uncovered = {
        source_case_id: items
        for source_case_id, items in by_source.items()
        if not any(str(item.get("actual_decision") or "") == "BLOCK" for item in items)
    }
    by_scenario: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for items in uncovered.values():
        scenario = str(((items[0].get("labels") or {}).get("scenario_code")) or "UNKNOWN")
        by_scenario[scenario].extend(items)
    return dict(by_scenario)


def _false_positive_groups(
    results: Sequence[Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in results:
        if (
            str(item.get("expected_decision") or "") == "ALLOW"
            and str(item.get("actual_decision") or "") == "BLOCK"
        ):
            key = f"{item.get('direction')}:{item.get('rule_id') or item.get('detector') or 'unknown'}"
            groups[key].append(item)
    return dict(groups)


def _finding_id(run_id: str, finding_type: str, group: str) -> str:
    digest = hashlib.sha256(
        f"{run_id}\0{finding_type}\0{group}".encode("utf-8")
    ).hexdigest()[:12].upper()
    return f"RGF-{digest}"


def _miss_finding(
    *,
    run_id: str,
    scenario: str,
    items: Sequence[Mapping[str, Any]],
    source_context: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    source_case_ids = sorted(
        {str(item.get("source_case_id") or "") for item in items}
    )
    guard_case_ids = sorted({str(item.get("case_id") or "") for item in items})
    directions = sorted({str(item.get("direction") or "") for item in items})
    versions = {
        "engine": sorted(
            {str(item.get("engine_version") or "") for item in items if item.get("engine_version")}
        ),
        "policy": sorted(
            {str(item.get("policy_version") or "") for item in items if item.get("policy_version")}
        ),
    }
    return {
        "schema_version": "1.0-risk-guard-finding",
        "finding_id": _finding_id(run_id, "FALSE_NEGATIVE", scenario),
        "status": "DRAFT_NEEDS_HUMAN_REVIEW",
        "finding_type": "FALSE_NEGATIVE",
        "title": f"{scenario} 未被输入或输出护栏阻断",
        "scenario_code": scenario,
        "affected_directions": directions,
        "source_case_ids": source_case_ids,
        "guard_case_ids": guard_case_ids,
        "versions": versions,
        "guard_architecture": {
            "input": "本地规则 -> 可选 Qwen 分类 -> 可选阿里云护栏",
            "stream_output": "500 字符滑动窗口 -> 实时规则 -> 精确指纹 -> Winnowing -> RapidFuzz",
            "full_output": "完整输出规则 -> 指纹/资产匹配 -> 可选阿里云完整审计",
            "policy_isolation": "受保护资产按 agent_id 隔离，不允许跨 Agent 共用私有提示词。",
        },
        "evidence": [_sample_evidence(item) for item in items],
        "root_cause_hypotheses": [
            "输入语句可能以间接、上下文化或多轮铺垫表达索取意图，未命中当前确定性规则或分类阈值。",
            "输出可能是概括、重组或部分泄露，与已登记资产的字符近似度不足。",
            "资产库可能未登记本 Case 泄露的 Skill、工具规则或业务私有片段。",
        ],
        "source_context": list(source_context),
        "fix_contract": [
            "人工先确认证据中哪些内容真正不可向客户公开。",
            "修复必须覆盖同根因变体，不能只匹配当前攻击语句。",
            "输出修复必须在流式发送前生效，不能只在客户已收到内容后审计。",
            "定向复测后必须重跑正向库，误拦不得上升。",
        ],
        "prohibited_shortcuts": [
            "禁止把攻击 Prompt 中的单个关键词直接加入黑名单。",
            "禁止将混有公开业务话术的整份 Skill 直接登记为硬拦截资产。",
            "禁止因最终审计命中而忽略流式内容已发送的事实。",
        ],
        "acceptance": {
            "targeted_command": (
                "python -m auto_test.pipeline guard regression "
                + " ".join(f"--case {case_id}" for case_id in guard_case_ids)
            ),
            "full_command": "python -m auto_test.pipeline guard regression --include-positive --workers 5",
            "required": [
                "所有关联 Guard Case 达到预期 BLOCK。",
                "正向输入和输出误拦率不高于修复前基线。",
                "报告中 degraded=0，否则不得宣称完成验收。",
            ],
        },
        "instructions_to_coding_ai": [
            "本 Finding 是待人工审核的工程假设，不是自动修复指令。",
            "修改前先核对证据、源码与当前部署版本。",
            "不允许读写测试数据库或修改 Case 预期来伪造通过。",
        ],
    }


def _false_positive_finding(
    *,
    run_id: str,
    group: str,
    items: Sequence[Mapping[str, Any]],
    source_context: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": "1.0-risk-guard-finding",
        "finding_id": _finding_id(run_id, "FALSE_POSITIVE", group),
        "status": "DRAFT_NEEDS_HUMAN_REVIEW",
        "finding_type": "FALSE_POSITIVE",
        "title": f"正常内容被护栏误拦：{group}",
        "source_case_ids": sorted(
            {str(item.get("source_case_id") or "") for item in items}
        ),
        "guard_case_ids": sorted({str(item.get("case_id") or "") for item in items}),
        "evidence": [_sample_evidence(item) for item in items],
        "source_context": list(source_context),
        "fix_contract": [
            "确认正常业务语义后缩小规则或资产匹配范围。",
            "保留对真实泄露样本的拦截能力。",
        ],
        "prohibited_shortcuts": ["禁止删除整层检测器来消除单个误拦。"],
        "instructions_to_coding_ai": ["人工审核后才能修改策略。"],
    }


def _markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Risk Guard Finding 待审核交接报告",
        "",
        f"- 来源回归：`{report.get('source_run_id')}`",
        f"- Finding：{report.get('finding_count', 0)}",
        f"- 状态：`{report.get('review_status')}`",
        "",
        "> 本报告只生成待人工审核的修复交接材料，不会自动修改代码。",
        "",
    ]
    for finding in report.get("findings") or []:
        lines.extend(
            [
                f"## {finding['finding_id']} · {finding['title']}",
                "",
                f"- 类型：`{finding['finding_type']}`",
                f"- 状态：`{finding['status']}`",
                "- 关联 Case："
                + ", ".join(f"`{value}`" for value in finding.get("source_case_ids") or []),
                "",
                "### 根因假设",
                "",
            ]
        )
        hypotheses = finding.get("root_cause_hypotheses") or []
        lines.extend(f"- {value}" for value in hypotheses)
        lines.extend(["", "### 修复约束", ""])
        lines.extend(f"- {value}" for value in finding.get("fix_contract") or [])
        lines.extend(["", "### 禁止捷径", ""])
        lines.extend(f"- {value}" for value in finding.get("prohibited_shortcuts") or [])
        lines.extend(["", "### 证据摘要", ""])
        for item in finding.get("evidence") or []:
            content = str(item.get("content") or "").replace("```", "` ` `")
            lines.extend(
                [
                    f"#### `{item.get('source_case_id')}` · {item.get('direction')}",
                    "",
                    f"- Guard Case：`{item.get('guard_case_id')}`",
                    f"- 检测链：`{item.get('checked_by')}`",
                    "",
                    "```text",
                    content[:3000],
                    "```",
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"


def generate_guard_findings(
    regression_report: Mapping[str, Any],
    *,
    output_dir: Path,
) -> dict[str, Any]:
    run_id = str(regression_report.get("run_id") or "").strip()
    if not run_id:
        raise ValueError("Guard regression report has no run_id")
    results = [
        item
        for item in regression_report.get("results") or []
        if isinstance(item, Mapping)
    ]
    source_context = _source_context()
    findings: list[dict[str, Any]] = []
    for scenario, items in sorted(_uncovered_attack_groups(results).items()):
        findings.append(
            _miss_finding(
                run_id=run_id,
                scenario=scenario,
                items=items,
                source_context=source_context,
            )
        )
    for group, items in sorted(_false_positive_groups(results).items()):
        findings.append(
            _false_positive_finding(
                run_id=run_id,
                group=group,
                items=items,
                source_context=source_context,
            )
        )

    report = {
        "schema_version": "1.0-risk-guard-finding-batch",
        "source_run_id": run_id,
        "created_at": _now(),
        "review_status": "DRAFT_NEEDS_HUMAN_REVIEW",
        "finding_count": len(findings),
        "automatic_code_changes": False,
        "findings": findings,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}-findings.json"
    markdown_path = output_dir / f"{run_id}-findings.md"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(_markdown(report), encoding="utf-8")
    return {
        "status": report["review_status"],
        "finding_count": len(findings),
        "json": str(json_path.resolve()),
        "markdown": str(markdown_path.resolve()),
    }


def generate_guard_findings_from_path(
    report_path: Path,
    *,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    path = Path(report_path).expanduser().resolve()
    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, Mapping) or not str(
        report.get("schema_version") or ""
    ).endswith("guard-regression-report"):
        raise ValueError(f"不是有效的 Guard 回归报告：{path}")
    return generate_guard_findings(
        report,
        output_dir=Path(output_dir or path.parent),
    )


__all__ = ["generate_guard_findings", "generate_guard_findings_from_path"]
