"""项目路径的唯一默认定义。

这里仅定义默认位置，不创建目录，也不读写文件。各模块仍可通过 CLI 参数或
既有环境变量覆盖输出路径。
"""

from __future__ import annotations

import os
from pathlib import Path


AUTO_TEST_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = AUTO_TEST_ROOT.parent
WORKSPACE_ROOT = REPOSITORY_ROOT.parent

RESULTS_ROOT = AUTO_TEST_ROOT / "results"
CRESCENDO_RESULTS_DIR = RESULTS_ROOT / "security" / "crescendo"
REGRESSION_RESULTS_DIR = RESULTS_ROOT / "security" / "regression"
RESCORE_RESULTS_DIR = RESULTS_ROOT / "security" / "rescored"
FINDING_RESULTS_DIR = RESULTS_ROOT / "security" / "findings"
EPE_RESULTS_DIR = RESULTS_ROOT / "paper" / "epe"
AI_WEB_INTEGRATION_RESULTS_DIR = RESULTS_ROOT / "integration" / "ai_web"
BUSINESS_REGRESSION_RESULTS_DIR = RESULTS_ROOT / "business" / "regression"
BUSINESS_DYNAMIC_RESULTS_DIR = RESULTS_ROOT / "business" / "dynamic"
BUSINESS_FINDING_RESULTS_DIR = RESULTS_ROOT / "business" / "findings"
GUARD_REGRESSION_RESULTS_DIR = RESULTS_ROOT / "guard" / "regression"

SECURITY_CASES_PATH = AUTO_TEST_ROOT / "data" / "security_cases.json"
BUSINESS_CASES_PATH = AUTO_TEST_ROOT / "data" / "business_cases.json"
BUSINESS_BAD_CASES_PATH = AUTO_TEST_ROOT / "data" / "business_bad_cases.json"
BUSINESS_SCENARIO_SOURCES_PATH = AUTO_TEST_ROOT / "data" / "business_scenario_sources.json"
GUARD_CASES_PATH = AUTO_TEST_ROOT / "data" / "guard_cases.json"
INTERNAL_POSITIVE_PATHS = tuple(AUTO_TEST_ROOT / "data" / name for name in (
    "guard_internal_positive_cases.json",
    "guard_internal_positive_edge_cases.json",
    "guard_internal_workflow_positive_cases.json",
    "guard_internal_workflow_positive_extension_cases.json",
))
AI_WEB_CONTRACTS_PATH = AUTO_TEST_ROOT / "data" / "ai_web_contracts.json"
AI_WEB_PRIVATE_ASSET_ROOT = Path(os.getenv("KY_AI_WEB_ASSET_ROOT") or AUTO_TEST_ROOT / ".private" / "ai_web_assets")
AI_WEB_PRIVATE_ASSET_INDEX = AI_WEB_PRIVATE_ASSET_ROOT / "index.json"


__all__ = [
    "AUTO_TEST_ROOT",
    "AI_WEB_CONTRACTS_PATH",
    "AI_WEB_INTEGRATION_RESULTS_DIR",
    "AI_WEB_PRIVATE_ASSET_INDEX",
    "AI_WEB_PRIVATE_ASSET_ROOT",
    "BUSINESS_CASES_PATH",
    "BUSINESS_BAD_CASES_PATH",
    "BUSINESS_DYNAMIC_RESULTS_DIR",
    "BUSINESS_FINDING_RESULTS_DIR",
    "BUSINESS_REGRESSION_RESULTS_DIR",
    "BUSINESS_SCENARIO_SOURCES_PATH",
    "CRESCENDO_RESULTS_DIR",
    "EPE_RESULTS_DIR",
    "FINDING_RESULTS_DIR",
    "GUARD_CASES_PATH",
    "GUARD_REGRESSION_RESULTS_DIR",
    "INTERNAL_POSITIVE_PATHS",
    "REGRESSION_RESULTS_DIR",
    "RESCORE_RESULTS_DIR",
    "REPOSITORY_ROOT",
    "RESULTS_ROOT",
    "SECURITY_CASES_PATH",
    "WORKSPACE_ROOT",
]
