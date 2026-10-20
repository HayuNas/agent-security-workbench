"""精简的安全漏洞测试 CLI 实现。"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from ..core.paths import (
    AI_WEB_CONTRACTS_PATH,
    AI_WEB_INTEGRATION_RESULTS_DIR,
    AI_WEB_PRIVATE_ASSET_INDEX,
    BUSINESS_CASES_PATH,
    BUSINESS_BAD_CASES_PATH,
    BUSINESS_DYNAMIC_RESULTS_DIR,
    BUSINESS_FINDING_RESULTS_DIR,
    BUSINESS_REGRESSION_RESULTS_DIR,
    BUSINESS_SCENARIO_SOURCES_PATH,
    CRESCENDO_RESULTS_DIR,
    EPE_RESULTS_DIR,
    FINDING_RESULTS_DIR,
    GUARD_CASES_PATH,
    GUARD_REGRESSION_RESULTS_DIR,
    REGRESSION_RESULTS_DIR,
    RESCORE_RESULTS_DIR,
    RESULTS_ROOT,
)
from ..clients.target import DEFAULT_BASE_URL


def run_security_strategy(args: argparse.Namespace) -> dict[str, Any]:
    if args.security_strategy == "crescendo":
        from ..generation.workflow import _finalize_epe_review
        from ..runners.crescendo import run_crescendo
        from ..records.finding_workflow import run_automatic_findings

        result = _finalize_epe_review(args, run_crescendo(args))
        result["finding_report"] = run_automatic_findings(args, result)
        return result
    if args.security_strategy == "regression":
        from ..generation.workflow import _finalize_epe_review
        from ..regression.runner import run_security_regression
        from ..records.finding_workflow import run_automatic_findings

        result = run_security_regression(args)
        result = _finalize_epe_review(args, result)
        result["finding_report"] = run_automatic_findings(args, result)
        return result
    if args.security_strategy == "rescore":
        from ..regression.rescore import rescore_security_report

        return rescore_security_report(args)
    if args.security_strategy == "aggregate":
        from ..regression.aggregate import aggregate_regression_reports
        from ..records.cases import DEFAULT_CASES_PATH as cases_default_path

        return aggregate_regression_reports(
            args.report,
            cases_path=Path(args.security_cases or cases_default_path),
            sync_mysql=not bool(args.no_mysql),
        )
    if args.security_strategy == "review":
        from ..judges.prompt_leakage import review_regression_reports
        from ..records.cases import DEFAULT_CASES_PATH as cases_default_path

        return review_regression_reports(
            args.report,
            asset_registry=Path(args.asset_registry) if args.asset_registry else None,
            target_config=(
                Path(args.target_config) if args.target_config else None
            ),
            output_dir=Path(args.security_output_dir),
            workers=int(args.judge_workers),
            register_confirmed=bool(args.register_confirmed),
            cases_path=Path(args.security_cases or cases_default_path),
        )
    if args.security_strategy == "cases":
        from ..records.cases import DEFAULT_CASES_PATH, mark_case_statuses

        changed = mark_case_statuses(
            status=args.case_status,
            batch_id=args.remediation_batch,
            case_ids=args.case_id,
            pack_ids=args.case_pack,
            select_all=bool(args.case_all),
            cases_path=Path(args.security_cases or DEFAULT_CASES_PATH),
        )
        return {
            "status": "UPDATED",
            "workflow": "security_case_status",
            "case_status": args.case_status,
            "remediation_batch_id": args.remediation_batch,
            "case_count": len(changed),
            "case_ids": changed,
        }
    raise ValueError(f"未知安全命令：{args.security_strategy}")


def run_paper_reproduction(args: argparse.Namespace) -> dict[str, Any]:
    if args.paper_reproduction == "epe":
        from ..generation.workflow import _finalize_epe_review
        from ..records.finding_workflow import run_automatic_findings
        from ..runners.epe import run_prompt_extraction

        result = run_prompt_extraction(args)
        result = _finalize_epe_review(args, result)
        result["finding_report"] = run_automatic_findings(args, result)
        return result
    raise ValueError(f"未知论文复现：{args.paper_reproduction}")


def run_corpus_workflow(args: argparse.Namespace) -> dict[str, Any]:
    """语料工作流只做本地静态审计；执行测试仍通过 paper epe 入口。"""

    if args.corpus_action != "audit":
        raise ValueError(f"未知语料命令：{args.corpus_action}")
    from ..corpus import (
        DEFAULT_CORPUS_PATH,
        audit_corpus,
        compile_epe_query_pack,
        load_corpus,
    )

    corpus = load_corpus(args.corpus_source or DEFAULT_CORPUS_PATH)
    audit = audit_corpus(corpus)
    compiled = compile_epe_query_pack(corpus)
    return {
        "status": "READY_NO_INTERFACE",
        "workflow": "corpus_audit",
        "corpus_id": corpus["corpus_id"],
        "source_file": corpus["source_file"],
        "snapshot_sha256": corpus["snapshot_sha256"],
        "compiled_query_pack": compiled["query_pack"],
        "compiled_query_count": len(compiled["queries"]),
        "audit": audit,
    }


def run_automation_workflow(args: argparse.Namespace) -> dict[str, Any]:
    from ..generation import run_automation

    return run_automation(args)


def run_finding_command(args: argparse.Namespace) -> dict[str, Any]:
    from ..records.finding_workflow import run_finding_export, run_finding_workflow

    if args.finding_action == "generate":
        return run_finding_workflow(args)
    if args.finding_action == "export":
        return run_finding_export(args)
    raise ValueError(f"未知 Finding 命令：{args.finding_action}")


def run_target_command(args: argparse.Namespace) -> dict[str, Any]:
    if args.target_action == "smoke":
        from ..clients.smoke import run_target_smoke

        return run_target_smoke(args)
    if args.target_action == "assets-sync":
        from ..assets import sync_ai_web_assets

        return sync_ai_web_assets(args)
    raise ValueError(f"未知目标命令：{args.target_action}")


def run_business_command(args: argparse.Namespace) -> dict[str, Any]:
    """导入或重放独立的 ky-sales 正向业务 Case。"""

    if args.business_action == "import":
        from ..business.cases import import_business_cases

        return import_business_cases(
            limit=int(args.business_limit),
            output_path=Path(args.business_cases),
        )
    if args.business_action == "import-scenarios":
        from ..business.scenario_sources import import_scenario_sources

        return import_scenario_sources(
            limit=int(args.business_limit),
            scenario_types=args.business_scenario_types,
            output_path=Path(args.business_scenario_sources),
        )
    if args.business_action == "regression":
        from ..business.runner import run_business_regression

        return run_business_regression(args)
    if args.business_action == "dynamic":
        from ..clients.factory import resolve_target_profile
        if resolve_target_profile(args).adapter == 'ai-web':
            from ..business.internal_runner import run_internal_positive
            return run_internal_positive(args)
        from ..business.dynamic_runner import run_dynamic_business

        return run_dynamic_business(args)
    if args.business_action == "register-bad-cases":
        from ..business.bad_cases import register_dynamic_bad_cases

        return register_dynamic_bad_cases(
            report_path=Path(args.report),
            scenario_sources_path=Path(args.business_scenario_sources),
            output_path=Path(args.business_bad_cases),
            source_ids=args.business_source_id,
            include_review=bool(args.include_review),
        )
    if args.business_action == "findings":
        from ..business.findings import generate_business_findings

        return generate_business_findings(
            report_path=Path(args.report),
            output_dir=Path(args.output_dir),
            use_model=not bool(args.no_model),
            model_override=args.business_finding_model,
        )
    raise ValueError(f"未知业务回归命令：{args.business_action}")


def run_guard_command(args: argparse.Namespace) -> dict[str, Any]:
    """Import or execute the standalone Risk Guard dataset."""
    if args.guard_action == "import-security":
        from ..guard.cases import import_security_guard_cases
        from ..core.paths import SECURITY_CASES_PATH

        return import_security_guard_cases(
            security_cases_path=Path(args.security_cases or SECURITY_CASES_PATH),
            output_path=Path(args.guard_cases),
            limit=int(args.guard_limit),
        )
    if args.guard_action == "regression":
        from ..guard.runner import run_guard_regression

        return run_guard_regression(args)
    if args.guard_action == "ai-web-acceptance":
        from ..guard.ai_web_acceptance import run_ai_web_guard_acceptance

        return run_ai_web_guard_acceptance(args)
    if args.guard_action == "ai-web-security":
        from ..guard.ai_web_security import run_ai_web_guard_security

        return run_ai_web_guard_security(args)
    if args.guard_action == "findings":
        from ..guard.findings import generate_guard_findings_from_path

        return generate_guard_findings_from_path(
            Path(args.guard_finding_report),
            output_dir=args.guard_finding_output_dir,
        )
    raise ValueError(f"未知护栏命令：{args.guard_action}")


def _add_connection_arguments(parser: argparse.ArgumentParser) -> None:
    hidden = argparse.SUPPRESS
    parser.add_argument("--ky-app-base-url", default=os.getenv("KY_APP_BASE_URL"), help="新销售 Agent 服务地址")
    parser.add_argument(
        "--target",
        default=os.getenv("KY_TARGET"),
        help="一键选择目标：ky-agent 或 ai-web:<appId>；优先于旧参数",
    )
    parser.add_argument(
        "--target-adapter",
        choices=("ky-agent", "ky-app", "ai-web"),
        default=os.getenv("KY_TARGET_ADAPTER", "ky-agent"),
        help="目标接口适配器；默认 ky-agent",
    )
    parser.add_argument(
        "--app-id",
        default=os.getenv("KY_AI_WEB_APP_ID"),
        help="ai-web 被测智能体 appId；使用 ai-web 时必填",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("KY_AGENT_BASE_URL", DEFAULT_BASE_URL),
        help=hidden,
    )
    parser.add_argument(
        "--ai-web-base-url",
        default=os.getenv("KY_AI_WEB_BASE_URL", "https://service.example"),
        help=hidden,
    )
    parser.add_argument(
        "--ai-web-poll-interval", type=float, default=1.0, help=hidden
    )
    parser.add_argument("--request-timeout", type=float, default=60.0, help=hidden)
    parser.add_argument("--chat-timeout", type=float, default=240.0, help=hidden)
    parser.add_argument("--chat-retries", type=int, default=3, help=hidden)
    parser.add_argument("--idle-timeout", type=float, default=90.0, help=hidden)
    parser.add_argument("--init-interval", type=float, default=2.1, help=hidden)
    parser.add_argument(
        "--artifact-char-limit", type=int, default=200_000, help=hidden
    )
    parser.add_argument("--save-raw-events", action="store_true", help=hidden)


def _add_asset_arguments(parser: argparse.ArgumentParser) -> None:
    hidden = argparse.SUPPRESS
    parser.add_argument("--asset-id", action="append", help=hidden)
    parser.add_argument(
        "--asset-registry",
        type=Path,
        help="受保护资产指纹文件；ai-web 默认自动使用该 appId 最新私有快照",
    )


def _add_auto_finding_arguments(parser: argparse.ArgumentParser) -> None:
    hidden = argparse.SUPPRESS
    parser.set_defaults(auto_findings=True)
    parser.add_argument(
        "--no-auto-findings",
        dest="auto_findings",
        action="store_false",
        help="跳过测试结束后的自动 Finding 归并",
    )
    parser.add_argument("--finding-model", help=hidden)
    parser.add_argument("--finding-timeout", type=float, default=180.0, help=hidden)
    parser.add_argument("--finding-max-tokens", type=int, default=7000, help=hidden)
    parser.add_argument("--finding-source-branch", default="develop", help=hidden)
    parser.add_argument(
        "--finding-no-fetch-source", action="store_true", help=hidden
    )
    parser.add_argument("--finding-deployment-commit", help=hidden)
    parser.add_argument("--finding-output-dir", type=Path, help=hidden)


def _add_auto_review_arguments(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(auto_review=True)
    parser.add_argument(
        "--no-auto-review",
        dest="auto_review",
        action="store_false",
        help="跳过提示词泄露 REVIEW 的辅助模型离线裁决",
    )
    parser.add_argument(
        "--review-workers",
        type=int,
        default=3,
        help="REVIEW 辅助模型并发数",
    )


def _add_crescendo_arguments(parser: argparse.ArgumentParser) -> None:
    hidden = argparse.SUPPRESS
    packs = parser.add_argument_group("Attack Pack")
    packs.add_argument(
        "--pack",
        dest="attack_pack",
        action="append",
        help="选择 Attack Pack；可重复。默认 prompt_leakage",
    )
    packs.add_argument(
        "--all",
        dest="all_packs",
        action="store_true",
        help="依次运行全部 Attack Pack",
    )
    packs.add_argument(
        "--seed-id",
        "--seed",
        dest="seed_id",
        help="只执行单个 Pack 中的指定起始消息",
    )
    packs.add_argument(
        "--seed-range",
        help="按 Pack 顺序执行闭区间 Seed，例如 10-30（也接受 10--30）",
    )
    run = parser.add_argument_group("执行预算覆盖")
    run.add_argument("--iterations", type=int)
    run.add_argument("--turns", dest="adaptive_max_turns", type=int)
    run.add_argument("--budget", dest="query_budget", type=int)
    run.add_argument(
        "--workers",
        dest="attack_workers",
        type=int,
        default=3,
        help="并行执行的独立 Seed 数；默认 3，设为 1 可串行",
    )
    run.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--output-dir",
        dest="security_output_dir",
        type=Path,
        default=CRESCENDO_RESULTS_DIR,
        help=hidden,
    )
    parser.add_argument("--batch-id", help=hidden)
    parser.add_argument("--attack-model", help=hidden)
    parser.add_argument("--attack-timeout", type=float, default=90.0, help=hidden)
    parser.add_argument(
        "--attack-temperature", type=float, default=0.6, help=hidden
    )
    parser.add_argument("--attack-max-tokens", type=int, default=900, help=hidden)
    parser.add_argument("--attack-seed", type=int, help=hidden)
    parser.add_argument(
        "--attack-decision-retries", type=int, default=2, help=hidden
    )
    parser.add_argument("--judge-model", help=hidden)
    parser.add_argument("--judge-timeout", type=float, default=120.0, help=hidden)
    parser.add_argument("--assessment-max-tokens", type=int, default=None, help=hidden)
    parser.add_argument("--assessment-timeout", type=float, default=None, help=hidden)
    _add_asset_arguments(parser)
    _add_connection_arguments(parser)
    _add_auto_review_arguments(parser)
    _add_auto_finding_arguments(parser)


def _add_regression_arguments(parser: argparse.ArgumentParser) -> None:
    hidden = argparse.SUPPRESS
    parser.add_argument(
        "--case",
        dest="regression_case",
        action="append",
        help="只复测指定成功攻击 Case；默认全部",
    )
    parser.add_argument(
        "--pack",
        dest="regression_pack",
        action="append",
        help="只复测指定 Attack Pack；可重复",
    )
    parser.add_argument(
        "--engine",
        dest="regression_engine",
        choices=("cr", "epe"),
        help="只复测指定引擎；默认由每条 Case 自动分流",
    )
    parser.add_argument(
        "--query-pack",
        dest="regression_query_pack",
        action="append",
        help="只复测指定 EPE Query Pack；可重复",
    )
    parser.add_argument(
        "--fix-batch",
        dest="regression_fix_batch",
        help="只复测指定修复批次的 Case",
    )
    parser.add_argument(
        "--date",
        dest="regression_date",
        help="只复测该首次发现日期的 Case，格式 YYYY-MM-DD",
    )
    parser.add_argument(
        "--before-date",
        dest="regression_before_date",
        help="只复测首次发现日期早于该日期的 Case，格式 YYYY-MM-DD（不含当天）",
    )
    parser.add_argument(
        "--unresolved",
        dest="regression_unresolved",
        action="store_true",
        help="只复测仍可复现、问题复发或复测待确认的 Case",
    )
    parser.add_argument("--workers", dest="attack_workers", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--output-dir",
        dest="security_output_dir",
        type=Path,
        default=REGRESSION_RESULTS_DIR,
        help=hidden,
    )
    parser.add_argument("--security-cases", type=Path, help=hidden)
    parser.add_argument("--batch-id", help=hidden)
    _add_asset_arguments(parser)
    _add_connection_arguments(parser)
    _add_auto_review_arguments(parser)
    _add_auto_finding_arguments(parser)


def _add_epe_arguments(parser: argparse.ArgumentParser) -> None:
    hidden = argparse.SUPPRESS
    run = parser.add_argument_group("Effective Prompt Extraction")
    run.add_argument(
        "--query-pack",
        default="paper_direct",
        help="选择 EPE Query Pack；默认 paper_direct",
    )
    run.add_argument("--queries", dest="query_budget", type=int, default=10)
    run.add_argument("--reproduce", dest="repeat_successes", type=int, default=3)
    run.add_argument("--workers", dest="attack_workers", type=int, default=3)
    run.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--output-dir",
        dest="paper_output_dir",
        type=Path,
        default=EPE_RESULTS_DIR,
        help=hidden,
    )
    parser.add_argument("--batch-id", help=hidden)
    _add_asset_arguments(parser)
    _add_connection_arguments(parser)
    _add_auto_review_arguments(parser)
    _add_auto_finding_arguments(parser)


def _add_automation_arguments(parser: argparse.ArgumentParser) -> None:
    hidden = argparse.SUPPRESS
    parser.add_argument(
        "--engine",
        dest="automation_engine",
        choices=("cr", "epe"),
        help="执行引擎；回归时可省略并由 Case 自动分流",
    )
    parser.add_argument(
        "--pack",
        dest="automation_pack",
        action="append",
        help="Pack ID；回归时可重复或省略以执行全库",
    )
    parser.add_argument(
        "--mode",
        dest="automation_mode",
        choices=("generate-run", "run-pack", "regression"),
        required=True,
        help="Qwen 重新生成并测试、运行现有 Pack、或按引擎/Pack 回归成功库",
    )
    parser.add_argument(
        "--count",
        dest="generation_count",
        type=int,
        help="generate-run 的生成数量；run-pack 中限制现有 Seed/Query 数",
    )
    parser.add_argument(
        "--tactic",
        dest="automation_tactic",
        action="append",
        help="generate-run 使用的一个 Tencent 单轮策略 ID；省略时使用该引擎首个默认策略",
    )
    parser.add_argument("--workers", dest="attack_workers", type=int, default=3)
    parser.add_argument(
        "--provenance-mode",
        choices=("dynamic", "known-format", "context-aligned"),
        default="dynamic",
        help="MCP 来源混淆 Pack：动态窃取可见格式、已知脱敏格式对照、或客户可见事实对齐对照",
    )
    parser.add_argument("--turns", dest="adaptive_max_turns", type=int)
    parser.add_argument("--budget", dest="query_budget", type=int)
    parser.add_argument("--reproduce", dest="repeat_successes", type=int, default=3)
    parser.add_argument(
        "--message-prefix",
        dest="message_prefix",
        default="",
        help="发送时统一添加到每条用户输入前；源 Pack/Case 内容保持不变",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--case",
        dest="automation_case",
        action="append",
        help="回归时只执行指定 Case；可重复",
    )
    parser.add_argument(
        "--fix-batch",
        dest="automation_fix_batch",
        help="回归时只执行指定修复批次",
    )
    parser.add_argument(
        "--date",
        dest="automation_date",
        help="回归时只执行该首次发现日期的 Case，格式 YYYY-MM-DD",
    )
    parser.add_argument(
        "--before-date",
        dest="automation_before_date",
        help="回归时只执行首次发现日期早于该日期的 Case，格式 YYYY-MM-DD（不含当天）",
    )
    parser.add_argument(
        "--unresolved",
        dest="automation_unresolved",
        action="store_true",
        help="回归时只执行仍可复现、问题复发或复测待确认的 Case",
    )
    parser.set_defaults(iterations=None)
    parser.add_argument(
        "--output-dir", dest="automation_output_dir", type=Path, help=hidden
    )
    parser.add_argument("--security-cases", type=Path, help=hidden)
    parser.add_argument("--batch-id", help=hidden)
    parser.add_argument("--generation-model")
    parser.add_argument("--generation-timeout", type=float, default=120.0, help=hidden)
    parser.add_argument(
        "--generation-temperature", type=float, default=0.8, help=hidden
    )
    parser.add_argument(
        "--generation-max-tokens", type=int, default=6000, help=hidden
    )
    parser.add_argument("--generation-seed", type=int, help=hidden)
    parser.add_argument("--attack-model", help=hidden)
    parser.add_argument("--attack-timeout", type=float, default=90.0, help=hidden)
    parser.add_argument(
        "--attack-temperature", type=float, default=0.6, help=hidden
    )
    parser.add_argument("--attack-max-tokens", type=int, default=900, help=hidden)
    parser.add_argument("--attack-seed", type=int, help=hidden)
    parser.add_argument(
        "--attack-decision-retries", type=int, default=2, help=hidden
    )
    parser.add_argument("--judge-model", help=hidden)
    parser.add_argument("--judge-timeout", type=float, default=120.0, help=hidden)
    parser.add_argument("--assessment-max-tokens", type=int, default=None, help=hidden)
    parser.add_argument("--assessment-timeout", type=float, default=None, help=hidden)
    _add_asset_arguments(parser)
    _add_connection_arguments(parser)
    _add_auto_review_arguments(parser)
    _add_auto_finding_arguments(parser)


def _add_finding_arguments(parser: argparse.ArgumentParser) -> None:
    hidden = argparse.SUPPRESS
    parser.add_argument(
        "--status",
        dest="finding_status",
        type=int,
        choices=(0, 1, 2),
        action="append",
        help="筛选 Case 修复状态；可重复，默认 0 和 2",
    )
    parser.add_argument("--agent", dest="finding_agent", help="只分析指定 Agent")
    parser.add_argument(
        "--pack", dest="finding_pack", action="append", help="只分析指定 Pack；可重复"
    )
    parser.add_argument(
        "--case", dest="finding_case", action="append", help="只分析指定 Case；可重复"
    )
    parser.add_argument(
        "--date", dest="finding_date", help="只分析该首次发现日期，格式 YYYY-MM-DD"
    )
    parser.add_argument(
        "--before-date",
        dest="finding_before_date",
        help="只分析首次发现日期早于该日期的 Case（不含当天）",
    )
    parser.add_argument("--limit", dest="finding_limit", type=int, default=200)
    parser.add_argument(
        "--source-branch", dest="finding_source_branch", default="develop"
    )
    parser.add_argument(
        "--source-repo", dest="finding_source_repo", type=Path, help=hidden
    )
    parser.add_argument(
        "--no-fetch-source",
        dest="finding_no_fetch_source",
        action="store_true",
        help="使用本地已有 origin/<branch>，不执行 git fetch",
    )
    parser.add_argument(
        "--deployment-commit",
        dest="finding_deployment_commit",
        help="已知时填写本次测试接口对应的部署 Commit",
    )
    parser.add_argument("--model", dest="finding_model", help=hidden)
    parser.add_argument("--timeout", dest="finding_timeout", type=float, default=180.0, help=hidden)
    parser.add_argument(
        "--max-tokens", dest="finding_max_tokens", type=int, default=7000, help=hidden
    )
    parser.add_argument("--batch-id", dest="finding_batch_id", help=hidden)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--output-dir",
        dest="finding_output_dir",
        type=Path,
        default=FINDING_RESULTS_DIR,
        help=hidden,
    )


def _add_finding_export_arguments(parser: argparse.ArgumentParser) -> None:
    hidden = argparse.SUPPRESS
    parser.add_argument(
        "--batch",
        dest="finding_export_batch",
        default="latest",
        help="Finding 批次编号；默认 latest，导出最新批次",
    )
    parser.add_argument(
        "--report", dest="finding_export_report", type=Path, help=hidden
    )
    parser.add_argument(
        "--output-dir",
        dest="finding_export_output_dir",
        type=Path,
        help=hidden,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ky-sales 安全漏洞对抗测试")
    commands = parser.add_subparsers(dest="command", required=True)

    security = commands.add_parser("security", help="安全漏洞测试与复测")
    security_modes = security.add_subparsers(
        dest="security_strategy", required=True
    )
    crescendo = security_modes.add_parser(
        "crescendo", help="Pack 驱动的动态多轮攻击"
    )
    _add_crescendo_arguments(crescendo)
    regression = security_modes.add_parser(
        "regression", help="原样重放已成功攻击，检查是否修复"
    )
    _add_regression_arguments(regression)
    rescore = security_modes.add_parser(
        "rescore", help="使用当前硬规则与独立判定模型重评历史报告（不调用目标 Agent）"
    )
    rescore.add_argument("--report", type=Path, required=True)
    rescore.add_argument("--register-successes", action="store_true")
    rescore.add_argument(
        "--output-dir",
        dest="security_output_dir",
        type=Path,
        default=RESCORE_RESULTS_DIR,
    )
    rescore.add_argument("--security-cases", type=Path)
    rescore.add_argument(
        "--review-decisions",
        type=Path,
        help="EPE REVIEW 结果的人工裁决 JSON；仅覆盖仍为 REVIEW 的保存回复",
    )
    _add_asset_arguments(rescore)
    aggregate = security_modes.add_parser(
        "aggregate", help="聚合多份同批回归报告并更新 Case 当前状态"
    )
    aggregate.add_argument("--report", type=Path, action="append", required=True)
    aggregate.add_argument("--security-cases", type=Path)
    aggregate.add_argument("--no-mysql", action="store_true")
    review = security_modes.add_parser(
        "review", help="使用辅助大模型离线裁决 EPE/CR/回归报告中的提示词泄露 REVIEW"
    )
    review.add_argument("--report", type=Path, action="append", required=True)
    review.add_argument("--asset-registry", type=Path)
    review.add_argument("--target-config", type=Path)
    review.add_argument(
        "--security-output-dir",
        type=Path,
        default=RESULTS_ROOT / "security" / "reviewed",
    )
    review.add_argument("--workers", dest="judge_workers", type=int, default=3)
    review.add_argument("--register-confirmed", action="store_true")
    review.add_argument("--security-cases", type=Path)
    cases = security_modes.add_parser(
        "cases", help="按修复批次维护成功 Case 状态"
    )
    case_actions = cases.add_subparsers(dest="case_action", required=True)
    mark = case_actions.add_parser("mark", help="标记修复中或待复测")
    mark.add_argument("--status", dest="case_status", choices=("fixing", "ready"), required=True)
    mark.add_argument("--batch", dest="remediation_batch", required=True)
    mark.add_argument("--case", dest="case_id", action="append")
    mark.add_argument("--pack", dest="case_pack", action="append")
    mark.add_argument("--all", dest="case_all", action="store_true")
    mark.add_argument("--security-cases", type=Path)

    paper = commands.add_parser("paper", help="独立论文复现")
    paper_modes = paper.add_subparsers(dest="paper_reproduction", required=True)
    epe = paper_modes.add_parser("epe", help="Effective Prompt Extraction")
    _add_epe_arguments(epe)

    corpus = commands.add_parser("corpus", help="候选语料静态审阅与编译检查")
    corpus_modes = corpus.add_subparsers(dest="corpus_action", required=True)
    audit = corpus_modes.add_parser("audit", help="校验、去重并预览晋级结果")
    audit.add_argument("--source", dest="corpus_source", type=Path)

    target = commands.add_parser("target", help="目标接口连通性与契约验证")
    target_actions = target.add_subparsers(dest="target_action", required=True)
    smoke = target_actions.add_parser(
        "smoke", help="用一个正常问题验证 ai-web 两段式聊天契约"
    )
    smoke.add_argument(
        "--message",
        dest="smoke_message",
        default="请用一句话介绍你可以提供哪些帮助。",
    )
    smoke.add_argument(
        "--output-dir",
        dest="smoke_output_dir",
        type=Path,
        default=AI_WEB_INTEGRATION_RESULTS_DIR,
        help=argparse.SUPPRESS,
    )
    smoke.add_argument(
        "--contract-registry",
        type=Path,
        default=AI_WEB_CONTRACTS_PATH,
        help=argparse.SUPPRESS,
    )
    _add_connection_arguments(smoke)
    smoke.set_defaults(target_adapter="ai-web")

    assets_sync = target_actions.add_parser(
        "assets-sync", help="只读同步 ai-web 目标的系统提示词和 Skill 指纹"
    )
    assets_sync.add_argument(
        "--asset-sync-root", type=Path, help=argparse.SUPPRESS
    )
    assets_sync.add_argument(
        "--asset-sync-index", type=Path, help=argparse.SUPPRESS
    )
    _add_connection_arguments(assets_sync)
    assets_sync.set_defaults(target_adapter="ai-web")

    business = commands.add_parser("business", help="ky-sales 正向业务 Case 与版本回归")
    business_actions = business.add_subparsers(
        dest="business_action", required=True
    )
    business_import = business_actions.add_parser(
        "import", help="从 dm_data 历史评测表导入最近的正向业务 Case"
    )
    business_import.add_argument(
        "--limit", dest="business_limit", type=int, default=100
    )
    business_import.add_argument(
        "--business-cases", type=Path, default=BUSINESS_CASES_PATH
    )
    business_scenario_import = business_actions.add_parser(
        "import-scenarios",
        help="从 status=2 历史多轮报告均衡整理正向业务场景来源",
    )
    business_scenario_import.add_argument(
        "--limit", dest="business_limit", type=int, default=100
    )
    business_scenario_import.add_argument(
        "--scenario-type",
        dest="business_scenario_types",
        action="append",
        choices=(
            "all",
            "sales_order",
            "product_recommendation",
            "market_qa",
            "formulation_optimization",
            "technical_qa",
        ),
        help="只导入指定场景；可重复，默认五类均衡抽样",
    )
    business_scenario_import.add_argument(
        "--scenario-sources",
        dest="business_scenario_sources",
        type=Path,
        default=BUSINESS_SCENARIO_SOURCES_PATH,
    )
    business_regression = business_actions.add_parser(
        "regression", help="原样重放 BIZ Case，检查新版 ky-sales 业务能力"
    )
    business_regression.add_argument("--case", dest="business_case", action="append")
    business_regression.add_argument(
        "--limit", dest="business_limit", type=int, default=0
    )
    business_regression.add_argument("--workers", dest="business_workers", type=int, default=3)
    business_regression.add_argument("--business-cases", type=Path, default=BUSINESS_CASES_PATH)
    business_regression.add_argument(
        "--include-bad-cases",
        dest="business_include_bad_cases",
        action="store_true",
        help="在固定正向库后追加人工确认的动态 Bad Case",
    )
    business_regression.add_argument(
        "--business-bad-cases", type=Path, default=BUSINESS_BAD_CASES_PATH
    )
    business_regression.add_argument(
        "--output-dir",
        dest="business_output_dir",
        type=Path,
        default=BUSINESS_REGRESSION_RESULTS_DIR,
    )
    business_regression.add_argument("--batch-id")
    business_regression.add_argument("--dry-run", action="store_true")
    business_regression.add_argument("--judge-model")
    business_regression.add_argument("--judge-timeout", type=float, default=120.0)
    business_regression.add_argument("--judge-retries", type=int, default=2)
    business_regression.add_argument(
        "--finding-model", dest="business_finding_model"
    )
    business_regression.add_argument(
        "--include-reasoning-eval",
        dest="business_include_reasoning_eval",
        action="store_true",
        help="可选评估接口返回的 Thinking/决策轨迹；默认关闭",
    )
    business_regression.add_argument(
        "--no-adapt-turns",
        dest="business_adapt_turns",
        action="store_false",
        help="关闭历史客户后续话术的上下文适配（默认开启）",
    )
    business_regression.add_argument(
        "--turn-adapter-model",
        help="后续客户话术适配模型；未指定时跟随业务评判模型",
    )
    business_regression.add_argument(
        "--turn-adapter-timeout",
        type=float,
        default=60.0,
    )
    business_regression.set_defaults(business_adapt_turns=True)
    _add_connection_arguments(business_regression)
    business_regression.set_defaults(target="ky-agent", target_adapter="ky-agent")

    business_dynamic = business_actions.add_parser(
        "dynamic",
        help="用历史首轮 Seed 和正向业务 Skill 动态执行多轮正常业务场景",
    )
    business_dynamic.add_argument(
        "--scenario-type",
        dest="business_scenario_type",
        choices=(
            "sales_order",
            "product_recommendation",
            "market_qa",
            "formulation_optimization",
            "technical_qa",
        ),
        default="all",
        help="仅用于可选的历史来源筛选；默认 all，不限制场景卡选择",
    )
    business_dynamic.add_argument(
        "--source-id", dest="business_source_id", action="append"
    )
    business_dynamic.add_argument(
        "--limit", dest="business_limit", type=int, default=1
    )
    business_dynamic.add_argument(
        "--turns", dest="business_max_turns", type=int, default=7
    )
    business_dynamic.add_argument(
        "--recovery-attempts",
        dest="business_max_recovery_attempts",
        type=int,
        choices=(0, 1, 2, 3, 4),
        default=2,
        help="每张场景卡最多允许的正常澄清、改述或纠错次数；默认2",
    )
    business_dynamic.add_argument(
        "--scene-mode",
        dest="business_scene_mode",
        choices=("single", "multi"),
        default="single",
        help="single 只测一张原子场景卡；multi 选择多张卡并由 CR 按对话自然顺序覆盖",
    )
    business_dynamic.add_argument(
        "--scene",
        dest="business_scene",
        action="append",
        choices=(
            "internal_workflow",
            "inquiry",
            "negotiation",
            "stock_delivery",
            "order_confirmation",
            "product_recommendation",
            "market_qa",
            "formulation_optimization",
            "technical_qa",
            "product_documentation",
            "sample_request",
            "payment_terms",
        ),
        help="选择原子场景卡；multi 模式可重复，默认使用来源类型的标准计划",
    )
    business_dynamic.add_argument(
        "--main-count",
        dest="business_main_count",
        type=int,
        choices=(1, 2),
        default=None,
        help="从预设合法主线组合中均衡选择1或2张主线场景；仅用于 multi",
    )
    business_dynamic.add_argument(
        "--random-sample",
        dest="business_random_sample",
        action="store_true",
        help="随机抽取 --limit 条场景来源；指定相同 Run ID 可复现",
    )
    business_dynamic.add_argument(
        "--side-scene",
        dest="business_side_scene",
        action="append",
        choices=(
            "technical_qa",
            "product_documentation",
            "product_recommendation",
            "market_qa",
            "sample_request",
            "payment_terms",
        ),
        help="限制 CR 可动态选择的正常客户支线候选；可重复指定",
    )
    business_dynamic.add_argument(
        "--side-count",
        dest="business_side_count",
        type=int,
        choices=(0, 1, 2),
        default=None,
        help=(
            "每条 Case 必须覆盖的支线数；批次内会均衡分配不同支线，"
            "multi 默认2，single 只能为0"
        ),
    )
    business_dynamic.add_argument(
        "--workers",
        dest="business_workers",
        type=int,
        default=1,
        help="并发执行的动态业务 Case 数；每个 Case 内的多轮对话仍串行",
    )
    business_dynamic.add_argument(
        "--conversation-strategy",
        dest="business_conversation_strategy",
        choices=(
            "auto",
            "direct_transaction",
            "price_sensitive_comparison",
            "cautious_verification",
            "constraint_first",
            "progress_urgent",
            "professional_detailed",
        ),
        default="auto",
        help="整段多轮保持一致的正常客户沟通策略；默认按运行与来源稳定轮换",
    )
    business_dynamic.add_argument(
        "--scenario-sources",
        dest="business_scenario_sources",
        type=Path,
        default=BUSINESS_SCENARIO_SOURCES_PATH,
    )
    business_dynamic.add_argument(
        "--expression-style",
        dest="business_expression_style",
        choices=("auto", "concise", "contextual", "structured", "colloquial", "formal", "plain", "detailed"),
        default="auto",
        help="客户表达方式；与业务场景和沟通策略相互独立",
    )
    business_dynamic.add_argument(
        "--output-dir",
        dest="business_output_dir",
        type=Path,
        default=BUSINESS_DYNAMIC_RESULTS_DIR,
    )
    business_dynamic.add_argument("--batch-id")
    business_dynamic.add_argument("--dry-run", action="store_true")
    business_dynamic.add_argument("--controller-model", dest="business_controller_model")
    business_dynamic.add_argument(
        "--controller-timeout", dest="business_controller_timeout", type=float, default=90.0
    )
    business_dynamic.add_argument("--judge-model")
    business_dynamic.add_argument("--judge-timeout", type=float, default=120.0)
    business_dynamic.add_argument("--judge-retries", type=int, default=2)
    business_dynamic.add_argument(
        "--finding-model", dest="business_finding_model"
    )
    business_dynamic.add_argument(
        "--include-reasoning-eval",
        dest="business_include_reasoning_eval",
        action="store_true",
        help="可选评估接口返回的 Thinking/决策轨迹；默认关闭",
    )
    business_dynamic.add_argument(
        "--business-bad-cases", type=Path, default=BUSINESS_BAD_CASES_PATH
    )
    _add_connection_arguments(business_dynamic)
    business_dynamic.set_defaults(target="ky-agent", target_adapter="ky-agent")

    business_bad_cases = business_actions.add_parser(
        "register-bad-cases",
        help="把辅助模型判定的动态 FAIL 冻结为独立正向 Bad Case",
    )
    business_bad_cases.add_argument("--report", type=Path, required=True)
    business_bad_cases.add_argument(
        "--source-id", dest="business_source_id", action="append"
    )
    business_bad_cases.add_argument(
        "--include-review",
        action="store_true",
        help="同时登记 REVIEW；默认只登记明确 FAIL",
    )
    business_bad_cases.add_argument(
        "--scenario-sources",
        dest="business_scenario_sources",
        type=Path,
        default=BUSINESS_SCENARIO_SOURCES_PATH,
    )
    business_bad_cases.add_argument(
        "--business-bad-cases",
        type=Path,
        default=BUSINESS_BAD_CASES_PATH,
    )

    business_findings = business_actions.add_parser(
        "findings", help="从正向动态测试报告生成归并后的业务 Finding"
    )
    business_findings.add_argument("--report", type=Path, required=True)
    business_findings.add_argument(
        "--finding-model", dest="business_finding_model"
    )
    business_findings.add_argument(
        "--no-model",
        action="store_true",
        help="只使用确定性归类生成降级版 Finding，不调用辅助分析模型",
    )
    business_findings.add_argument(
        "--output-dir",
        type=Path,
        default=BUSINESS_FINDING_RESULTS_DIR,
    )

    guard = commands.add_parser("guard", help="独立 Risk Guard 数据集构建与直接回归")
    guard_actions = guard.add_subparsers(dest="guard_action", required=True)
    guard_import = guard_actions.add_parser(
        "import-security",
        help="把历史成功攻击 Case 转成最终输入/泄露输出护栏 Case 对",
    )
    guard_import.add_argument("--security-cases", type=Path)
    guard_import.add_argument("--guard-cases", type=Path, default=GUARD_CASES_PATH)
    guard_import.add_argument("--limit", dest="guard_limit", type=int, default=0)

    guard_regression = guard_actions.add_parser(
        "regression",
        help="不调用 Agent，直接用输入/输出数据集回归 Risk Guard API",
    )
    guard_regression.add_argument("--case", dest="guard_case", action="append")
    guard_regression.add_argument(
        "--direction",
        dest="guard_direction",
        action="append",
        choices=("input", "output"),
    )
    guard_regression.add_argument("--limit", dest="guard_limit", type=int, default=0)
    guard_regression.add_argument("--workers", dest="guard_workers", type=int, default=5)
    guard_regression.add_argument("--guard-cases", type=Path, default=GUARD_CASES_PATH)
    guard_regression.add_argument(
        "--include-positive",
        dest="guard_include_positive",
        action="store_true",
        help="同时加入正向业务输入/输出 ALLOW 样本（默认关闭）",
    )
    guard_regression.add_argument(
        "--positive-cases",
        dest="guard_positive_cases",
        type=Path,
        default=BUSINESS_CASES_PATH,
    )
    guard_regression.add_argument(
        "--positive-case-limit",
        dest="guard_positive_case_limit",
        type=int,
        default=0,
        help="最多加入多少个正向业务 Case，0 表示全部",
    )
    guard_regression.add_argument(
        "--base-url",
        dest="guard_base_url",
        default=os.getenv("RISK_GUARD_BASE_URL", "http://127.0.0.1:8091"),
    )
    guard_regression.add_argument(
        "--token",
        dest="guard_token",
        default=os.getenv("RISK_GUARD_API_TOKEN", ""),
    )
    guard_regression.add_argument("--timeout", dest="guard_timeout", type=float, default=30.0)
    guard_regression.add_argument(
        "--output-mode",
        dest="guard_output_mode",
        choices=("stream", "full"),
        default="stream",
        help="输出样本执行方式；默认模拟线上流式输出",
    )
    guard_regression.add_argument(
        "--stream-chunk-size",
        dest="guard_stream_chunk_size",
        type=int,
        default=32,
        help="流式模拟的确定性 chunk 字符数，默认 32",
    )
    guard_regression.add_argument(
        "--stream-window-size",
        dest="guard_stream_window_size",
        type=int,
        default=500,
        help="流式检测滑动窗口字符数，默认与 ky-agent 一致为 500",
    )
    guard_regression.add_argument(
        "--output-dir",
        dest="guard_output_dir",
        type=Path,
        default=GUARD_REGRESSION_RESULTS_DIR,
    )
    guard_regression.add_argument("--batch-id")
    guard_regression.add_argument("--dry-run", action="store_true")

    guard_ai_web = guard_actions.add_parser(
        "ai-web-acceptance",
        help="批量验证 ai-web 的护栏输入前置、正常问答和输出后置",
    )
    guard_ai_web.add_argument(
        "--ai-web-agent",
        dest="guard_ai_web_app_id",
        action="append",
        help="指定一个 appId；可重复，默认测试全部已登记 Agent",
    )
    guard_ai_web.add_argument(
        "--message",
        dest="guard_ai_web_message",
        default="请用一句话介绍你可以提供哪些帮助。",
    )
    guard_ai_web.add_argument(
        "--guard-base-url",
        default=os.getenv("RISK_GUARD_BASE_URL", "http://127.0.0.1:8091"),
    )
    guard_ai_web.add_argument(
        "--guard-token",
        default=os.getenv("RISK_GUARD_API_TOKEN", ""),
    )
    guard_ai_web.add_argument("--guard-timeout", type=float, default=30.0)
    guard_ai_web.add_argument(
        "--contracts",
        dest="guard_ai_web_contracts",
        type=Path,
        default=AI_WEB_CONTRACTS_PATH,
        help=argparse.SUPPRESS,
    )
    guard_ai_web.add_argument(
        "--asset-index",
        dest="guard_ai_web_asset_index",
        type=Path,
        default=AI_WEB_PRIVATE_ASSET_INDEX,
        help=argparse.SUPPRESS,
    )
    guard_ai_web.add_argument(
        "--output-dir",
        dest="guard_ai_web_output_dir",
        type=Path,
        default=AI_WEB_INTEGRATION_RESULTS_DIR / "guard",
    )
    guard_ai_web.add_argument("--batch-id")
    _add_connection_arguments(guard_ai_web)
    guard_ai_web.set_defaults(target_adapter="ai-web")

    guard_ai_web_security = guard_actions.add_parser(
        "ai-web-security",
        help="用既有 ai-web 攻击报告对比裸 Agent 与 Guard 前后置链路",
    )
    guard_ai_web_security.add_argument(
        "--source-report",
        dest="guard_ai_web_source_report",
        action="append",
        type=Path,
        required=True,
        help="既有 ai-web security regression 或 EPE JSON；可重复",
    )
    guard_ai_web_security.add_argument(
        "--guard-base-url",
        default=os.getenv("RISK_GUARD_BASE_URL", "http://127.0.0.1:8091"),
    )
    guard_ai_web_security.add_argument(
        "--guard-token",
        default=os.getenv("RISK_GUARD_API_TOKEN", ""),
    )
    guard_ai_web_security.add_argument("--guard-timeout", type=float, default=30.0)
    guard_ai_web_security.add_argument(
        "--stream-chunk-size",
        dest="guard_stream_chunk_size",
        type=int,
        default=32,
    )
    guard_ai_web_security.add_argument(
        "--workers",
        dest="guard_workers",
        type=int,
        default=3,
    )
    guard_ai_web_security.add_argument(
        "--limit",
        dest="guard_ai_web_limit",
        type=int,
        default=0,
    )
    guard_ai_web_security.add_argument(
        "--retry-errors-from",
        dest="guard_ai_web_retry_errors_from",
        type=Path,
        help="只重跑指定 ai-web-security 报告中的 ERROR，并合并生成完整新报告",
    )
    guard_ai_web_security.add_argument(
        "--output-dir",
        dest="guard_ai_web_output_dir",
        type=Path,
        default=AI_WEB_INTEGRATION_RESULTS_DIR / "guard" / "security",
    )
    guard_ai_web_security.add_argument("--batch-id")
    guard_ai_web_security.add_argument("--dry-run", action="store_true")
    _add_connection_arguments(guard_ai_web_security)
    guard_ai_web_security.set_defaults(target_adapter="ai-web")

    guard_findings = guard_actions.add_parser(
        "findings",
        help="从已完成的护栏回归生成待人工审核 Finding",
    )
    guard_findings.add_argument(
        "--report",
        dest="guard_finding_report",
        type=Path,
        required=True,
    )
    guard_findings.add_argument(
        "--output-dir",
        dest="guard_finding_output_dir",
        type=Path,
    )

    automation = commands.add_parser(
        "automation", help="一 Skill 多 Pack：生成、执行或成功库回归"
    )
    _add_automation_arguments(automation)
    findings = commands.add_parser("findings", help="把已确认失败归并为源码感知 Finding")
    finding_actions = findings.add_subparsers(dest="finding_action", required=True)
    generate_findings = finding_actions.add_parser(
        "generate", help="生成一批可直接交给开发的修复 Finding"
    )
    _add_finding_arguments(generate_findings)
    export_findings = finding_actions.add_parser(
        "export", help="一个 Finding 一个 JSON，导出为 AI 修复任务"
    )
    _add_finding_export_arguments(export_findings)
    return parser


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    try:
        args = _parse_args()
        from ..workbench.cli_execution import database_execution, database_inputs
        with database_inputs(args), database_execution(args) as finish:
            if args.command == "security":
                result = run_security_strategy(args)
            elif args.command == "paper":
                result = run_paper_reproduction(args)
            elif args.command == "corpus":
                result = run_corpus_workflow(args)
            elif args.command == "findings":
                result = run_finding_command(args)
            elif args.command == "target":
                result = run_target_command(args)
            elif args.command == "business":
                result = run_business_command(args)
            elif args.command == "guard":
                result = run_guard_command(args)
            else:
                result = run_automation_workflow(args)
            result = finish(result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"pipeline failed: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "_parse_args",
    "build_parser",
    "main",
    "run_automation_workflow",
    "run_business_command",
    "run_corpus_workflow",
    "run_finding_command",
    "run_paper_reproduction",
    "run_security_strategy",
    "run_target_command",
]


if __name__ == "__main__":
    raise SystemExit(main())
