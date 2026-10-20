"""Generate grouped, AI-ready Findings from positive business test reports."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..clients.model import OpenAICompatibleClient, load_model_settings
from ..core.paths import (
    AUTO_TEST_ROOT,
    BUSINESS_FINDING_RESULTS_DIR,
    REPOSITORY_ROOT,
    WORKSPACE_ROOT,
)
from ..core.redaction import redact_value
from .dynamic_controller import classify_handoff_event
from .scenario_cards import SCENARIO_CARDS


SCHEMA_VERSION = "1.0-business-finding-report"
PROMPT_PATH = AUTO_TEST_ROOT / "judges" / "prompts" / "business_finding.md"

_DIAGNOSIS_CATEGORIES = frozenset(
    {
        "EVALUATION_CONTRACT",
        "FACTUAL_GROUNDING",
        "TOOL_OR_INTEGRATION",
        "HUMAN_HANDOFF",
        "UNSUPPORTED_COMMITMENT",
        "CONVERSATION_PROGRESS",
        "SCENARIO_DATA",
        "TASK_COMPLETION",
        "TEST_HARNESS",
        "BUSINESS_LOGIC",
    }
)
_ISSUE_OWNERS = frozenset(
    {
        "agent",
        "skill",
        "tool_or_integration",
        "handoff",
        "test_controller",
        "evaluation_contract",
        "test_data",
        "unknown",
    }
)

_CATEGORY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("FACTUAL_GROUNDING", ("幻觉", "虚构", "编造", "事实错误", "halluc")),
    ("TOOL_OR_INTEGRATION", ("工具", "tool", "接口", "调用失败")),
    ("HUMAN_HANDOFF", ("转人工", "人工", "handoff", "外部依赖")),
    ("UNSUPPORTED_COMMITMENT", ("承诺", "promise", "sla", "一定回复")),
    ("CONVERSATION_PROGRESS", ("重复", "循环", "搪塞", "答非所问")),
    ("SCENARIO_DATA", ("script_drift", "脚本漂移", "历史事实")),
    ("TASK_COMPLETION", ("未完成", "遗漏", "incomplete", "核心任务")),
    (
        "TEST_HARNESS",
        ("controller", "控制器", "覆盖队列", "状态图", "valueerror", "执行错误"),
    ),
)

_INFRASTRUCTURE_ERROR_MARKERS = (
    "kyagenterror",
    "init_test",
    "timeout",
    "timed out",
    "connection",
    "连接",
    "网络",
    "http ",
    "urlerror",
    "鉴权",
    "unauthorized",
    "forbidden",
)

_MANDATORY_PROHIBITED_SHORTCUTS = (
    "没有当前工具结果或配置依据时，不得承诺具体答复时间、价格、库存、交期、折扣、订单或授权结果。",
    "不得建议预留、锁定或保留库存，除非当前工具明确支持且已返回成功证据。",
    "不得把合法的等待外部结果或测试控制器错误改造成目标 Agent 的固定话术。",
)
_UNSUPPORTED_REMEDIATION_RE = re.compile(
    r"(?:明确.{0,8}(?:答复|回复|反馈)时间|最晚.{0,12}(?:答复|回复|反馈)|"
    r"(?:今天|明天|本周|上午|下午)?\s*\d{1,2}\s*[点时].{0,12}(?:答复|回复|反馈)|"
    r"(?:保证|承诺|确保).{0,16}(?:今天|明天|\d+\s*(?:分钟|小时|天)).{0,16}(?:答复|回复|反馈)|"
    r"(?:预留|锁定|保留).{0,8}库存)",
    re.I,
)

_CATEGORY_GUIDANCE: dict[str, dict[str, Any]] = {
    "EVALUATION_CONTRACT": {
        "title": "评测没有识别合法完成路径",
        "root_cause": "Agent 已按现有能力成功转人工并避免编造，但旧控制器或评判规则仍要求立即获得外部业务结果。",
        "remediation": "修正场景卡完成路径、CR 停止条件和评判契约；不要凭空为 Agent 增加测试环境中不存在的库存工具。",
        "code_scope": ["auto_test/business/dynamic_controller.py", "auto_test/judges/prompts/business_regression.md"],
    },
    "FACTUAL_GROUNDING": {
        "title": "业务事实缺少可靠依据",
        "root_cause": "Agent 的客户可见结论与当前工具结果或客户已提供事实没有可靠对应。",
        "remediation": "收紧事实来源：动态价格、库存、交期和订单状态只允许来自当前工具或明确人工回填；证据不足时应说明待核实。",
        "code_scope": ["ky_agent 的业务 Skill", "工具结果到客户回复的映射层"],
    },
    "TOOL_OR_INTEGRATION": {
        "title": "业务工具调用或结果承接异常",
        "root_cause": "目标 Agent 没有正确调用所需工具，或调用后没有把有效结果用于当前业务步骤。",
        "remediation": "核对工具路由、参数契约、失败降级和结果解析，并用关联 Case 做定向复测。",
        "code_scope": ["ky_agent 工具路由", "MCP 客户端或中间件"],
    },
    "HUMAN_HANDOFF": {
        "title": "转人工业务闭环异常",
        "root_cause": "转人工路径、完成边界或人工结果回填没有形成可验证闭环。",
        "remediation": "区分通知已发送与外部结果已确认；记录交接状态，并在人工结果回填后恢复机器处理。",
        "code_scope": ["ky_agent 转人工工具", "会话状态与人工回填链路"],
    },
    "UNSUPPORTED_COMMITMENT": {
        "title": "Agent 作出无依据的业务承诺",
        "root_cause": "回复给出了缺少 SLA、工具结果或授权依据的确定性时效或业务承诺。",
        "remediation": "将具体承诺绑定到可验证证据；没有依据时使用待确认表述，不硬编码某个 Case 的话术。",
        "code_scope": ["ky_agent 销售 Skill", "回复前业务合规检查"],
    },
    "CONVERSATION_PROGRESS": {
        "title": "多轮对话未有效推进",
        "root_cause": "Agent 在连续轮次中重复相同动作或话术，没有推进当前场景目标。",
        "remediation": "增加已处理事项状态，避免重复调用和重复承诺；无法推进时明确结束或转交。",
        "code_scope": ["ky_agent 会话状态", "销售 Skill 的多轮路由"],
    },
    "SCENARIO_DATA": {
        "title": "测试场景或历史脚本不适配",
        "root_cause": "客户话术依赖当前对话中不存在的历史动态事实，不能归责于目标 Agent。",
        "remediation": "修正场景卡、Seed 或动态控制器，不要通过修改 Agent 来迎合失效测试脚本。",
        "code_scope": ["auto_test/business/scenario_cards.py", "auto_test/business/dynamic_controller.py"],
    },
    "TASK_COMPLETION": {
        "title": "选定业务场景未完成",
        "root_cause": "Agent 未满足本次 scenario_plan 中的一个或多个必要交付物。",
        "remediation": "根据缺失交付物定位业务路由、工具证据或结束条件，并对同一原子场景定向回归。",
        "code_scope": ["ky_agent 业务 Skill", "相关工具链"],
    },
    "TEST_HARNESS": {
        "title": "正向测试框架执行异常",
        "root_cause": "目标测试接口、会话初始化、动态控制器、状态迁移或报告流程发生异常，当前结果不能归责于被测 Agent。",
        "remediation": "先修复测试框架并重跑关联来源；不得把执行异常登记成 Agent 业务 Bad Case。",
        "code_scope": [
            "auto_test/clients/target.py",
            "auto_test/business/dynamic_controller.py",
            "auto_test/business/dynamic_runner.py",
            "ky-agent 测试服务 /api/init_test",
        ],
    },
    "BUSINESS_LOGIC": {
        "title": "业务行为需要人工复核",
        "root_cause": "现有证据显示业务结果异常，但尚不能稳定归入更具体的根因族。",
        "remediation": "先核对完整对话、工具轨迹和场景成功契约，再决定修改 Agent、工具还是测试数据。",
        "code_scope": ["ky_agent 业务实现", "auto_test 正向评判契约"],
    },
}


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _category(result: Mapping[str, Any]) -> str:
    if str(result.get("outcome") or "").upper() == "ERROR":
        return "TEST_HARNESS"
    stop_reason = str(result.get("stop_reason") or "").strip()
    stop_categories = {
        "target_empty_reply": "TASK_COMPLETION",
        "controller_contract_unrecoverable": "TEST_HARNESS",
        "controller_evaluation_unrecoverable": "TEST_HARNESS",
        "controller_evaluation_error": "TEST_HARNESS",
        "customer_generation_unrecoverable": "TEST_HARNESS",
        "controller_invalid": "TEST_HARNESS",
        "recovery_exhausted": "TEST_HARNESS",
        "handoff_failed": "TOOL_OR_INTEGRATION",
    }
    if stop_reason in stop_categories:
        return stop_categories[stop_reason]
    judge = result.get("judge") if isinstance(result.get("judge"), Mapping) else {}
    issue_owner = str(judge.get("issue_owner") or "").strip().lower()
    owner_categories = {
        "test_data": "SCENARIO_DATA",
        "test_controller": "TEST_HARNESS",
        "tool_or_integration": "TOOL_OR_INTEGRATION",
        "handoff": "HUMAN_HANDOFF",
        "evaluation_contract": "EVALUATION_CONTRACT",
    }
    if issue_owner in owner_categories:
        return owner_categories[issue_owner]
    text = " ".join(
        [
            str(judge.get("reason") or ""),
            *(str(item) for item in judge.get("risk_flags") or []),
            *(str(item) for item in judge.get("failed_requirements") or []),
        ]
    ).casefold()
    for category, keywords in _CATEGORY_RULES:
        if any(keyword.casefold() in text for keyword in keywords):
            return category
    return "BUSINESS_LOGIC"


def _fallback_issue_owner(finding: Mapping[str, Any]) -> str:
    """Keep deterministic attribution useful when the analysis model times out."""

    evidence_owners = {
        str(evidence.get("issue_owner") or "").strip().lower()
        for evidence in finding.get("evidence") or []
        if isinstance(evidence, Mapping)
        and str(evidence.get("issue_owner") or "").strip().lower()
        in _ISSUE_OWNERS - {"unknown"}
    }
    if len(evidence_owners) == 1:
        return next(iter(evidence_owners))
    category_defaults = {
        "SCENARIO_DATA": "test_data",
        "TEST_HARNESS": "test_controller",
        "EVALUATION_CONTRACT": "evaluation_contract",
        "TOOL_OR_INTEGRATION": "tool_or_integration",
        "HUMAN_HANDOFF": "handoff",
        "FACTUAL_GROUNDING": "agent",
        "UNSUPPORTED_COMMITMENT": "agent",
        "CONVERSATION_PROGRESS": "agent",
        "TASK_COMPLETION": "agent",
    }
    return category_defaults.get(str(finding.get("category") or ""), "unknown")


def _fallback_confidence(finding: Mapping[str, Any]) -> tuple[str, str]:
    stop_reasons = {
        str(evidence.get("stop_reason") or "").strip()
        for evidence in finding.get("evidence") or []
        if isinstance(evidence, Mapping)
    }
    if "target_empty_reply" in stop_reasons:
        return "high", "high"
    if stop_reasons & {
        "controller_contract_unrecoverable",
        "controller_evaluation_unrecoverable",
        "controller_evaluation_error",
        "customer_generation_unrecoverable",
        "controller_invalid",
        "recovery_exhausted",
        "handoff_failed",
    }:
        return "medium", "high"
    return "medium", "medium"


def _is_finding_candidate(result: Mapping[str, Any]) -> bool:
    outcome = str(result.get("outcome") or "").upper()
    if outcome in {"FAIL", "REVIEW"}:
        return True
    if outcome != "ERROR":
        return False
    error = str(result.get("error") or "").casefold()
    # Transient target/model/network failures belong in execution diagnostics,
    # not business remediation or the Agent Bad Case library.
    return not any(marker in error for marker in _INFRASTRUCTURE_ERROR_MARKERS)


def _finding_id(run_id: str, category: str, scenes: Sequence[str]) -> str:
    # Scene order is part of the grouping key. Sorting here made two distinct
    # groups overwrite the same AI-task file.
    value = f"{run_id}|{category}|{'|'.join(scenes)}"
    return "BIZFIND-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:14].upper()


def _evidence(result: Mapping[str, Any]) -> dict[str, Any]:
    judge = result.get("judge") if isinstance(result.get("judge"), Mapping) else {}
    turns = [item for item in result.get("turns") or [] if isinstance(item, Mapping)]
    selected_turns = turns[-3:]
    return {
        "case_id": result.get("case_id") or result.get("source_id"),
        "source_id": result.get("source_id") or result.get("case_id"),
        "outcome": result.get("outcome"),
        "score": judge.get("score"),
        "judge_reason": judge.get("reason"),
        "issue_owner": judge.get("issue_owner"),
        "scene_assessments": list(judge.get("scene_assessments") or []),
        "execution_error": result.get("error"),
        "stop_reason": result.get("stop_reason"),
        "failed_requirements": list(judge.get("failed_requirements") or []),
        "risk_flags": list(judge.get("risk_flags") or []),
        "scenario_plan": [
            dict(item)
            for item in result.get("scenario_plan") or []
            if isinstance(item, Mapping)
        ],
        "turns": [
            {
                "round": turn.get("round"),
                "customer_message": turn.get("customer_message"),
                "agent_reply": turn.get("agent_reply"),
                "tool_names": [
                    item.get("name")
                    for item in ((turn.get("trace") or {}).get("tool_calls") or [])
                    if isinstance(item, Mapping)
                ],
                "handoff_event": classify_handoff_event(turn),
                "errors": list((turn.get("trace") or {}).get("errors") or []),
                "controller": dict(turn.get("controller") or {})
                if isinstance(turn.get("controller"), Mapping)
                else None,
            }
            for turn in selected_turns
        ],
    }


def _text_list(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"业务 Finding {field} 必须是数组")
    result = [str(item).strip()[:1000] for item in value if str(item).strip()]
    if not result:
        raise ValueError(f"业务 Finding {field} 不能为空")
    return result


def _required_text(value: Any, *, field: str, limit: int = 5000) -> str:
    result = str(value or "").strip()
    if not result:
        raise ValueError(f"业务 Finding {field} 不能为空")
    return result[:limit]


def _validate_remediation_boundaries(remediation: Mapping[str, Any]) -> None:
    """Reject model advice that invents operational promises absent from evidence."""

    values = [str(remediation.get("fix_contract") or "")]
    if isinstance(remediation.get("implementation_steps"), list):
        values.extend(str(item) for item in remediation["implementation_steps"])
    for value in values:
        if _UNSUPPORTED_REMEDIATION_RE.search(value) and not any(
            marker in value
            for marker in ("禁止", "不得", "不能", "避免", "有依据", "工具支持", "配置依据")
        ):
            raise ValueError("业务 Finding 建议包含无依据的时效或库存承诺")


def _analyze_with_model(
    findings: list[dict[str, Any]],
    *,
    client: OpenAICompatibleClient,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not PROMPT_PATH.is_file():
        raise FileNotFoundError(f"缺少正向业务 Finding 提示词：{PROMPT_PATH}")
    model_groups = [
        {
            "group_key": item["group_key"],
            "category": item["category"],
            "scene_ids": item["scene_ids"],
            "source_ids": item["source_ids"],
            "deterministic_attribution": {
                "title": item["title"],
                "root_cause_hypothesis": item["root_cause_hypothesis"],
                "code_scope_candidates": item["code_scope_candidates"],
            },
            "evidence": item["evidence"],
        }
        for item in findings
    ]
    parsed, response = client.chat_json(
        [
            {"role": "system", "content": PROMPT_PATH.read_text(encoding="utf-8")},
            {
                "role": "user",
                "content": "以下是已脱敏的正向业务失败分组：\n"
                + json.dumps(redact_value({"groups": model_groups}), ensure_ascii=False),
            },
        ],
        temperature=0.0,
        max_tokens=5000,
        seed=42,
    )
    if not isinstance(parsed, Mapping) or not isinstance(parsed.get("findings"), list):
        raise ValueError("业务 Finding 模型必须返回 findings 数组")
    by_key = {
        str(item.get("group_key") or ""): item
        for item in parsed["findings"]
        if isinstance(item, Mapping)
    }
    raw_items = [
        item for item in parsed["findings"] if isinstance(item, Mapping)
    ]
    # Models occasionally rewrite an opaque group_key. The associated Case
    # scope is the real immutable boundary, so recover a unique group by its
    # exact source_ids instead of throwing away every otherwise valid analysis.
    normalized_by_key: dict[str, Mapping[str, Any]] = {}
    for finding in findings:
        expected_key = finding["group_key"]
        raw = by_key.get(expected_key)
        if raw is None:
            matches = [
                item
                for item in raw_items
                if isinstance(item.get("source_ids"), list)
                and {
                    str(value).strip()
                    for value in item.get("source_ids") or []
                    if str(value).strip()
                }
                == set(finding["source_ids"])
            ]
            raw = matches[0] if len(matches) == 1 else None
        if raw is None:
            raise ValueError(
                f"业务 Finding 模型遗漏分组 {expected_key!r}"
            )
        normalized_by_key[expected_key] = raw

    merged = []
    for finding in findings:
        raw = normalized_by_key[finding["group_key"]]
        source_ids = _text_list(raw.get("source_ids"), field="source_ids")
        if set(source_ids) != set(finding["source_ids"]):
            raise ValueError("业务 Finding 模型修改了关联 Case 范围")
        remediation = raw.get("remediation")
        acceptance = raw.get("acceptance")
        if not isinstance(remediation, Mapping) or not isinstance(acceptance, Mapping):
            raise ValueError("业务 Finding remediation/acceptance 必须是 object")
        _validate_remediation_boundaries(remediation)
        targeted = _text_list(
            acceptance.get("targeted_source_ids"), field="targeted_source_ids"
        )
        if set(targeted) != set(finding["source_ids"]):
            raise ValueError("业务 Finding 验收范围与关联 Case 不一致")
        severity = str(raw.get("severity") or "").strip().lower()
        confidence = str(raw.get("confidence") or "").strip().lower()
        diagnosis_category = str(raw.get("diagnosis_category") or "").strip().upper()
        issue_owner = str(raw.get("issue_owner") or "").strip().lower()
        if severity not in {"low", "medium", "high"}:
            raise ValueError("业务 Finding severity 无效")
        if confidence not in {"low", "medium", "high"}:
            raise ValueError("业务 Finding confidence 无效")
        if diagnosis_category not in _DIAGNOSIS_CATEGORIES:
            raise ValueError("业务 Finding diagnosis_category 无效")
        if issue_owner not in _ISSUE_OWNERS:
            raise ValueError("业务 Finding issue_owner 无效")
        merged.append(
            {
                **finding,
                "rule_category": finding["category"],
                "category": diagnosis_category,
                "issue_owner": issue_owner,
                "title": _required_text(raw.get("title"), field="title", limit=300),
                "severity": severity,
                "confidence": confidence,
                "problem_statement": _required_text(
                    raw.get("problem_statement"), field="problem_statement"
                ),
                "root_cause_hypothesis": _required_text(
                    raw.get("root_cause_hypothesis"), field="root_cause_hypothesis"
                ),
                "evidence_summary": _text_list(
                    raw.get("evidence_summary"), field="evidence_summary"
                ),
                "source_checks": _text_list(raw.get("source_checks"), field="source_checks"),
                "remediation": {
                    "fix_contract": _required_text(
                        remediation.get("fix_contract"), field="remediation.fix_contract"
                    ),
                    "implementation_steps": _text_list(
                        remediation.get("implementation_steps"), field="implementation_steps"
                    ),
                    "prohibited_shortcuts": list(
                        dict.fromkeys(
                            [
                                *_text_list(
                                    remediation.get("prohibited_shortcuts"),
                                    field="prohibited_shortcuts",
                                ),
                                *_MANDATORY_PROHIBITED_SHORTCUTS,
                            ]
                        )
                    ),
                },
                "acceptance": {
                    "targeted_source_ids": targeted,
                    "variant_tests": _text_list(
                        acceptance.get("variant_tests"), field="variant_tests"
                    ),
                    "normal_business_tests": _text_list(
                        acceptance.get("normal_business_tests"), field="normal_business_tests"
                    ),
                },
                "analysis_source": "model",
            }
        )
    return merged, {
        "provider": "openai-compatible",
        "model": response.model,
        "request_id": response.request_id,
        "usage": response.usage,
    }


def _git_metadata(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    result: dict[str, Any] = {"path": str(resolved), "available": False}
    if not (resolved / ".git").exists():
        return result

    def run(*args: str) -> str:
        completed = subprocess.run(
            ["git", "-c", f"safe.directory={resolved}", *args],
            cwd=resolved,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
        return completed.stdout.strip() if completed.returncode == 0 else ""

    return {
        "path": str(resolved),
        "available": True,
        "branch": run("branch", "--show-current"),
        "head_commit": run("rev-parse", "HEAD"),
        "dirty": bool(run("status", "--porcelain")),
    }


def _source_manifest(
    *, source_report: Mapping[str, Any], report_path: Path
) -> dict[str, Any]:
    repositories = {
        "test_harness": _git_metadata(REPOSITORY_ROOT),
        "agent": _git_metadata(WORKSPACE_ROOT / "ky_agent"),
        "agent_skills": _git_metadata(WORKSPACE_ROOT / "ky_agent_skill"),
    }
    return {
        "repositories": repositories,
        "tested_target": redact_value(source_report.get("target") or {}),
        "source_report": {
            "path": str(report_path.resolve()),
            "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
            "created_at": source_report.get("created_at"),
        },
        "deployment_commit": None,
        "version_status": "NEEDS_ALIGNMENT",
        "version_rule": (
            "修复前必须确认被测部署版本与本地 Agent/Skill 版本；"
            "版本未知时，Finding 中的根因只能作为待验证假设。"
        ),
    }


def _write_ai_tasks(
    *, output_dir: Path, run_id: str, findings: list[dict[str, Any]], source: Mapping[str, Any]
) -> dict[str, Any]:
    task_dir = output_dir / "ai_tasks" / run_id
    task_dir.mkdir(parents=True, exist_ok=True)
    task_paths = []
    for finding in findings:
        task = {
            "schema_version": "1.0-business-remediation-task",
            "task_type": "business_agent_remediation",
            "finding_id": finding["finding_id"],
            "title": finding["title"],
            "source": source,
            "problem": {
                "category": finding["category"],
                "rule_category": finding.get("rule_category") or finding["category"],
                "issue_owner": finding.get("issue_owner") or "unknown",
                "scene_ids": finding["scene_ids"],
                "problem_statement": finding.get("problem_statement"),
                "root_cause_hypothesis": finding["root_cause_hypothesis"],
                "source_checks": finding.get("source_checks") or [],
            },
            "affected_cases": {
                "source_ids": finding["source_ids"],
                "evidence": finding["evidence"],
            },
            "remediation": finding.get("remediation") or {
                "fix_contract": finding["remediation_guidance"],
                "implementation_steps": finding["code_scope_candidates"],
                "prohibited_shortcuts": finding["do_not_fix"],
            },
            "acceptance": finding.get("acceptance") or {
                "targeted_source_ids": finding["source_ids"],
                "variant_tests": ["同一场景更换客户画像、策略和表达方式复测"],
                "normal_business_tests": ["固定正向库回归无新增失败"],
            },
            "external_validation": {
                "retest_before_fix": True,
                "targeted_command": finding["reproduction"],
            },
            "instructions_to_coding_agent": [
                "先核对 source 中的版本和 dirty 状态，再检查源码，不要把根因假设当成已证实事实。",
                "先运行 targeted_command；如果当前版本已经通过，应关闭或更新 Finding，不要重复修改已修复逻辑。",
                "先判断问题属于 Agent、Skill、工具/人工闭环还是测试框架，再实施最小修复。",
                "不得针对当前客户原话硬编码；完成定向复测和正常业务回归后再宣称修复。",
                "没有当前工具或配置证据时，不得新增具体时效、库存、价格、折扣、交期或订单承诺。",
            ],
        }
        task_path = task_dir / f"{finding['finding_id']}.json"
        task_path.write_text(
            json.dumps(redact_value(task), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        task_paths.append(str(task_path.resolve()))
    index_path = task_dir / "index.json"
    index_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0-business-remediation-task-index",
                "source_run_id": run_id,
                "task_count": len(task_paths),
                "tasks": task_paths,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return {"task_count": len(task_paths), "index": str(index_path.resolve()), "tasks": task_paths}


def _markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# 正向业务 Finding",
        "",
        f"- 来源 Run：`{report.get('source_run_id')}`",
        f"- Finding 数量：{report.get('finding_count', 0)}",
        f"- 分析状态：`{report.get('analysis_status', '')}`",
        "",
    ]
    for item in report.get("findings") or []:
        lines.extend(
            [
                f"## {item.get('finding_id')} · {item.get('title')}",
                "",
                f"- 分类：`{item.get('category')}`",
                f"- 规则初始分类：`{item.get('rule_category') or item.get('category')}`",
                f"- 问题归属：`{item.get('issue_owner') or 'unknown'}`",
                f"- 场景：{', '.join(item.get('scene_ids') or [])}",
                f"- 关联 Case：{', '.join(item.get('source_ids') or [])}",
                f"- 问题：{item.get('problem_statement') or ''}",
                f"- 根因假设：{item.get('root_cause_hypothesis')}",
                f"- 修复要求：{(item.get('remediation') or {}).get('fix_contract') or item.get('remediation_guidance')}",
                f"- 验收命令：`{item.get('reproduction')}`",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def generate_business_findings(
    *,
    report_path: Path,
    output_dir: Path = BUSINESS_FINDING_RESULTS_DIR,
    use_model: bool = True,
    model_override: str | None = None,
    model_builder: type[OpenAICompatibleClient] = OpenAICompatibleClient,
) -> dict[str, Any]:
    """Group FAIL/REVIEW/ERROR results without changing test outcomes."""

    source_report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    if not isinstance(source_report, Mapping) or not str(
        source_report.get("schema_version") or ""
    ).endswith("business-regression-report"):
        raise ValueError("只支持正向业务回归报告")
    run_id = str(source_report.get("run_id") or Path(report_path).stem)
    is_dynamic = "dynamic" in str(source_report.get("schema_version") or "")
    candidates = [
        item
        for item in source_report.get("results") or []
        if isinstance(item, Mapping)
        and _is_finding_candidate(item)
    ]
    groups: dict[tuple[str, tuple[str, ...]], list[Mapping[str, Any]]] = defaultdict(list)
    for item in candidates:
        scenes = tuple(
            str(scene.get("id") or "")
            for scene in item.get("scenario_plan") or []
            if isinstance(scene, Mapping) and str(scene.get("id") or "")
        ) or (str(item.get("scenario_type") or source_report.get("scenario_type") or "unknown"),)
        groups[(_category(item), scenes)].append(item)

    findings = []
    for (category, scenes), items in sorted(groups.items()):
        guidance = _CATEGORY_GUIDANCE[category]
        source_ids = [str(item.get("source_id") or item.get("case_id") or "") for item in items]
        group_key = f"{category}|{'|'.join(scenes)}"
        if is_dynamic:
            plan = [
                item
                for item in items[0].get("scenario_plan") or []
                if isinstance(item, Mapping)
            ]
            main_scenes = [
                str(scene.get("id") or "")
                for scene in plan
                if str(scene.get("plan_role") or "main") != "side"
            ]
            side_scenes = [
                str(scene.get("id") or "")
                for scene in plan
                if str(scene.get("plan_role") or "main") == "side"
            ]
            reproduce = (
                "python -m auto_test.pipeline business dynamic "
                f"--scenario-type {source_report.get('scenario_type') or 'sales_order'} "
                f"--scene-mode {'multi' if len(plan) > 1 else 'single'} "
                + " ".join(f"--scene {scene}" for scene in main_scenes)
                + " "
                + " ".join(f"--side-scene {scene}" for scene in side_scenes)
                + (f" --side-count {len(side_scenes)}" if side_scenes else "")
                + f" --recovery-attempts {int(source_report.get('max_recovery_attempts') or 2)}"
                + " "
                + " ".join(f"--source-id {source_id}" for source_id in source_ids)
            ).strip()
        else:
            reproduce = (
                "python -m auto_test.pipeline business regression "
                + " ".join(f"--case {source_id}" for source_id in source_ids)
            ).strip()
        findings.append(
            {
                "finding_id": _finding_id(run_id, category, scenes),
                "group_key": group_key,
                "category": category,
                "title": guidance["title"],
                "scene_ids": list(scenes),
                "source_ids": source_ids,
                "occurrence_count": len(items),
                "root_cause_hypothesis": guidance["root_cause"],
                "problem_statement": guidance["title"],
                "remediation_guidance": guidance["remediation"],
                "code_scope_candidates": guidance["code_scope"],
                "evidence": [_evidence(item) for item in items],
                "do_not_fix": [
                    "不要针对某条客户原话硬编码答案或关键词。",
                    "不要用历史价格、库存、交期或旧 Agent 回复替代当前工具事实。",
                    "先确认问题归属 Agent、工具、人工闭环还是测试数据。",
                    *_MANDATORY_PROHIBITED_SHORTCUTS,
                ],
                "acceptance_criteria": (
                    "关联 Case 定向复测通过，且固定正向回归无新增失败；"
                    "若修改安全防御，同时要求正向护栏误拦不增加。"
                ),
                "reproduction": reproduce,
            }
        )

    model_info: dict[str, Any] | None = None
    analysis_status = "NO_FINDINGS" if not findings else "DETERMINISTIC_FALLBACK"
    analysis_error = None
    if findings and use_model:
        try:
            settings = load_model_settings(role="finding", model_override=model_override)
            client = model_builder(settings, timeout=120.0, retries=2)
            findings, model_info = _analyze_with_model(findings, client=client)
            analysis_status = "MODEL_ANALYZED"
        except Exception as exc:
            analysis_error = f"{type(exc).__name__}: {redact_value(str(exc))}"[:1000]
    if findings and analysis_status != "MODEL_ANALYZED":
        for finding in findings:
            rule_category = finding["category"]
            severity, confidence = _fallback_confidence(finding)
            finding.update(
                {
                    "rule_category": rule_category,
                    "issue_owner": _fallback_issue_owner(finding),
                    "severity": severity,
                    "confidence": confidence,
                    "evidence_summary": [
                        str(evidence.get("judge_reason") or "")[:1000]
                        for evidence in finding["evidence"]
                        if str(evidence.get("judge_reason") or "").strip()
                    ]
                    or [
                        str(evidence.get("execution_error") or "")[:1000]
                        for evidence in finding["evidence"]
                        if str(evidence.get("execution_error") or "").strip()
                    ]
                    or ["测试已给出 FAIL/REVIEW/ERROR，需结合源码复核。"],
                    "source_checks": list(finding["code_scope_candidates"]),
                    "remediation": {
                        "fix_contract": finding["remediation_guidance"],
                        "implementation_steps": list(finding["code_scope_candidates"]),
                        "prohibited_shortcuts": list(finding["do_not_fix"]),
                    },
                    "acceptance": {
                        "targeted_source_ids": list(finding["source_ids"]),
                        "variant_tests": ["同一场景更换客户画像、策略和表达方式复测"],
                        "normal_business_tests": ["固定正向库回归无新增失败"],
                    },
                    "analysis_source": "deterministic_fallback",
                }
            )

    generated_at = _now()
    source_manifest = _source_manifest(
        source_report=source_report,
        report_path=Path(report_path),
    )
    output = redact_value(
        {
            "schema_version": SCHEMA_VERSION,
            "generated_at": generated_at,
            "source_run_id": run_id,
            "source_report": str(Path(report_path).resolve()),
            "analysis_status": analysis_status,
            "analysis_error": analysis_error,
            "model": model_info,
            "source_manifest": source_manifest,
            "finding_count": len(findings),
            "findings": findings,
        }
    )
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"BF-{run_id}.json"
    markdown_path = output_dir / f"BF-{run_id}.md"
    json_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(_markdown(output), encoding="utf-8")
    ai_tasks = _write_ai_tasks(
        output_dir=output_dir,
        run_id=run_id,
        findings=findings,
        source=source_manifest,
    )
    return {
        "status": "GENERATED",
        "analysis_status": analysis_status,
        "analysis_error": analysis_error,
        "source_run_id": run_id,
        "finding_count": len(findings),
        "json": str(json_path.resolve()),
        "markdown": str(markdown_path.resolve()),
        "ai_tasks": ai_tasks,
    }


__all__ = ["SCHEMA_VERSION", "generate_business_findings"]
