"""护栏固定数据集工作台的请求模型与受限数据集工具。

这里的接口只允许选择项目内置的数据集。浏览器不能传入本地路径、命令或
护栏令牌；护栏服务地址和令牌统一从本地服务进程环境变量读取。
"""

from __future__ import annotations

import hashlib
import json
import os
from copy import deepcopy
from threading import Lock
from time import monotonic
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from .service_config import guard_base_url

from ..core.paths import (
    BUSINESS_CASES_PATH,
    SECURITY_CASES_PATH,
    INTERNAL_POSITIVE_PATHS,
)


class GuardTaskConfig(BaseModel):
    """前端可以选择的护栏固定数据集参数。"""

    model_config = ConfigDict(extra="forbid")

    # 保留旧数据集 ID，历史任务仍按各自的快照执行。
    dataset: Literal["combined", "attack", "normal", "positive", "internal_positive"] = Field(default="combined", description='数据集：combined 综合测试，attack 攻击拦截，normal 正常放行（业务与内部样本）；positive/internal_positive 兼容旧任务。')
    guardMode: Literal["dataset", "single"] = Field(default="dataset", description='dataset 为固定数据集回归；single 为单条内容检查。')
    direction: Literal["all", "input", "output"] = Field(default="all", description='检查方向：all 输入与输出，input 仅输入，output 仅输出。')
    workers: int = Field(default=5, ge=1, le=32, description='本次任务内部并发请求数。')
    outputMode: Literal["stream", "full"] = Field(default="stream", description='输出检查方式：stream 模拟流式分块，full 全文检查。')
    streamChunkSize: int = Field(default=32, ge=1, le=10000, description='模拟流式输出时每个分块的字符数。')
    streamWindowSize: int = Field(default=500, ge=1, le=100000, description='流式检查窗口的字符数。')
    limit: int = Field(default=0, ge=0, le=100000, description='主数据集用例数量上限，0 表示不限制。')
    positiveLimit: int = Field(default=0, ge=0, le=100000, description='正常源用例数量上限（业务与内部样本合计），0 表示不限制。')
    timeout: int = Field(default=30, ge=1, le=600, description='单次护栏请求超时，单位秒。')
    agentId: str = Field(default="ky-sales", min_length=1, max_length=128, description='被保护 Agent 的编号，用于匹配资产保护策略。')
    useSampleAgent: bool = Field(default=True, description='固定库使用样本自身 agent_id；false 时统一使用 agentId。')
    content: str = Field(default="", max_length=100000, description='单条检查模式待检测的文本。')
    expected: Literal["", "ALLOW", "BLOCK", "OBSERVE"] = Field(default="", description='单条用例预期结果：ALLOW 放行、BLOCK 拦截、OBSERVE 观察；空值未指定。')

    @model_validator(mode="after")
    def validate_mode(self) -> "GuardTaskConfig":
        self.agentId = self.agentId.strip()
        if not self.agentId:
            raise ValueError("护栏 Agent 标识不能为空")
        if self.guardMode == "single" and not self.content.strip():
            raise ValueError("单条护栏测试需要填写 content")
        return self


class GuardTaskSubmission(BaseModel):
    """创建固定数据集护栏任务的请求体。"""

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(description='任务 UUID；相同 ID 和相同配置重复提交不会创建新的运行。')
    name: str = Field(default='', max_length=100, description='护栏任务显示名称，留空自动编号。')
    config: GuardTaskConfig = Field(default_factory=GuardTaskConfig, description='本次护栏回归或单条检查的参数。')


def _read(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return default


def _payload(path: Path) -> dict[str, Any]:
    value = _read(path, {})
    return value if isinstance(value, dict) else {}


def _cases(path: Path) -> list[dict[str, Any]]:
    value = _payload(path).get("cases")
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _version(paths: list[Path]) -> str:
    from ..records import case_store
    digest = hashlib.sha256()
    kinds = {path: case_store.kind_for(path) for path in paths}
    revisions = {}
    if any(kinds.values()):
        with case_store.reader() as conn, conn.cursor() as cur:
            for kind in sorted(set(kinds.values()) - {None}):
                revisions[kind] = case_store.metadata(cur, kind)[0]
    for path in paths:
        kind = kinds[path]
        if kind:
            digest.update(f"mysql:{kind}:{revisions[kind]}".encode("utf-8"))
            continue
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(str(path).encode("utf-8"))
    return digest.hexdigest()


def internal_positive_cases() -> list[dict[str, Any]]:
    """默认加载数据库内部护栏样本，离线模式才读取原文件。"""
    from ..records import case_store
    if case_store.enabled():
        return case_store.load("guard_internal")["cases"]
    rows: list[dict[str, Any]] = []
    for path in INTERNAL_POSITIVE_PATHS:
        rows.extend(_cases(path))
    return rows


def attack_library() -> dict[str, Any]:
    # 使用与 Agent 复测相同的当前回归库，不改写共享快照。
    from ..guard.cases import build_security_guard_library
    return build_security_guard_library(security_cases_path=SECURITY_CASES_PATH)


def normal_guard_cases(business: list[dict[str, Any]] | None = None,
                       internal: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    from ..guard.cases import build_positive_guard_cases
    business = build_positive_guard_cases(BUSINESS_CASES_PATH) if business is None else business
    internal = internal_positive_cases() if internal is None else internal
    return [dict(row, dataset_source=kind) for kind, rows in (
        ("business", business), ("guard_internal", internal)
    ) for row in _active(rows)]


def _limited_cases(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    if not limit:
        return rows
    def key(row):
        return (row.get("dataset_source"), row.get("source_case_id") or row["case_id"])
    selected = set(list(dict.fromkeys(key(row) for row in rows))[:limit])
    return [row for row in rows if key(row) in selected]


_catalog_lock = Lock()
_catalog_cache: dict[str, Any] = {}


def dataset_catalog() -> list[dict[str, Any]]:
    """Cache display counts briefly; execution always builds a fresh database snapshot."""
    from ..records import case_store
    if not case_store.enabled():
        return _dataset_catalog()
    # Library edits invalidate immediately. The TTL also picks up newly saved run evidence.
    version = _version([SECURITY_CASES_PATH, BUSINESS_CASES_PATH, *INTERNAL_POSITIVE_PATHS])
    with _catalog_lock:
        if _catalog_cache.get("version") == version and monotonic() < _catalog_cache.get("expires", 0):
            return deepcopy(_catalog_cache["items"])
        items = _dataset_catalog()
        _catalog_cache.update(version=version, expires=monotonic()+30, items=items)
        return deepcopy(items)


def _dataset_catalog() -> list[dict[str, Any]]:
    """返回前端展示用的固定库元数据，不泄漏本机绝对路径。"""
    attack_payload = attack_library()
    attack = attack_payload["cases"]
    # 延迟导入，避免只打开工作台 API 时初始化业务构造逻辑。
    from ..guard.cases import build_positive_guard_cases

    try:
        positive = build_positive_guard_cases(BUSINESS_CASES_PATH)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        from ..records import case_store
        if case_store.enabled():
            raise
        positive = []
    internal = _active(internal_positive_cases())
    normal = normal_guard_cases(positive, internal)
    return [
        {
            "id": "combined",
            "name": "综合测试：攻击拦截 + 正常放行",
            "description": "攻击回归库、正常业务与内部 Agent 样本；每次运行冻结独立快照。",
            "sourceCaseCount": attack_payload["source_case_count"],
            "missingOutputCount": sum("output" in i["issue"] for i in attack_payload["issues"]),
            "attackCount": sum(str(row.get("status", "active")) == "active" for row in attack),
            "positiveCount": len(normal),
            "caseCount": len(attack) + len(normal),
            "inputCount": sum(
                str(row.get("status", "active")) == "active"
                and str(row.get("direction") or "") == "input"
                for row in attack + normal
            ),
            "outputCount": sum(
                str(row.get("status", "active")) == "active"
                and str(row.get("direction") or "") == "output"
                for row in attack + normal
            ),
            "version": _version([SECURITY_CASES_PATH, BUSINESS_CASES_PATH, *INTERNAL_POSITIVE_PATHS]),
        },
        {
            "id": "attack",
            "name": "攻击成功回归库（实时）",
            "description": "读取最新攻击回归库，运行时冻结快照；数量为输入输出检查条目。",
            "attackCount": len(attack),
            "sourceCaseCount": attack_payload["source_case_count"],
            "missingOutputCount": sum("output" in i["issue"] for i in attack_payload["issues"]),
            "positiveCount": 0,
            "caseCount": len(attack),
            "inputCount": sum(str(row.get("direction") or "") == "input" for row in attack),
            "outputCount": sum(str(row.get("direction") or "") == "output" for row in attack),
            "version": _version([SECURITY_CASES_PATH]),
        },
        {
            "id": "normal",
            "name": "正常放行",
            "description": "合并正常业务对话与内部 Agent 的正常、边界样本，检查误拦截。",
            "attackCount": 0,
            "positiveCount": len(normal),
            "caseCount": len(normal),
            "inputCount": sum(row.get("direction") == "input" for row in normal),
            "outputCount": sum(row.get("direction") == "output" for row in normal),
            "version": _version([BUSINESS_CASES_PATH, *INTERNAL_POSITIVE_PATHS]),
        },
        {
            "id": "positive",
            "name": "固定正向业务数据集",
            "description": "只回归业务正常输入和参考输出，检查误拦截。",
            "attackCount": 0,
            "positiveCount": len(positive),
            "caseCount": len(positive),
            "inputCount": sum(str(row.get("direction") or "") == "input" for row in positive),
            "outputCount": sum(str(row.get("direction") or "") == "output" for row in positive),
            "version": _version([BUSINESS_CASES_PATH]),
        },
        {
            "id": "internal_positive",
            "name": "内部 Agent 正常输入集",
            "description": "回归仓库内置的护栏边界和工作流正向样本。",
            "attackCount": 0,
            "positiveCount": len(internal),
            "caseCount": len(internal),
            "inputCount": sum(str(row.get("direction") or "") == "input" for row in internal),
            "outputCount": sum(str(row.get("direction") or "") == "output" for row in internal),
            "version": _version(list(INTERNAL_POSITIVE_PATHS)),
        },
    ]


def _active(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if str(row.get("status") or "active") == "active"]


def prepare_dataset(config: GuardTaskConfig, directory: Path) -> dict[str, Any]:
    """把所选固定库复制到任务目录，形成运行时不可变快照。"""
    directory.mkdir(parents=True, exist_ok=True)
    if config.guardMode == "single":
        expected = config.expected or "OBSERVE"
        rows = [{
            "case_id": f"single:{config.agentId}",
            "case_type": "guard_workbench_single",
            "status": "active",
            "direction": config.direction if config.direction != "all" else "input",
            "stage": "full",
            "content": config.content,
            "expected_decision": expected,
            "agent_id": config.agentId,
        }]
        payload = {"schema_version": "workbench-guard-single", "cases": rows}
        path = directory / "guard-cases.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"guard_cases": path, "positive_cases": None, "include_positive": False}

    attack_snapshot = attack_library() if config.dataset in {"combined", "attack"} else {}
    attack_rows = _active(attack_snapshot.get("cases", []))
    positive_rows: list[dict[str, Any]] = []
    positive_path: Path | None = None
    include_positive = False
    if config.dataset == "positive":
        from ..guard.cases import build_positive_guard_cases
        from ..business.cases import load_business_cases
        positive_library = load_business_cases(BUSINESS_CASES_PATH)
        positive_rows = build_positive_guard_cases(BUSINESS_CASES_PATH, case_limit=config.positiveLimit, library=positive_library)
        positive_path = directory / "business-cases.json"
        positive_path.write_text(
            json.dumps(positive_library, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        include_positive = True
    normal_rows = _limited_cases(normal_guard_cases(), config.positiveLimit) if config.dataset in {"combined", "normal"} else []
    if config.dataset in {"attack", "combined"}:
        rows = _limited_cases(attack_rows, config.limit) + normal_rows
    elif config.dataset == "normal":
        rows = normal_rows
    elif config.dataset == "positive":
        rows = []
    elif config.dataset == "internal_positive":
        rows = _active(internal_positive_cases())
    if config.limit and config.dataset == "internal_positive":
        rows = rows[: config.limit]
    # 方向筛选由 runner 执行；提交前先拒绝筛选后为空的任务，避免生成 0 样本的假成功报告。
    if config.direction != "all":
        candidates = rows + positive_rows
        if not any(str(row.get("direction") or "") == config.direction for row in candidates):
            direction_name = "输入" if config.direction == "input" else "输出"
            raise ValueError(f"所选固定数据集没有可执行的{direction_name}样本")
    if config.guardMode == "dataset" and config.dataset == "positive" and not positive_rows:
        raise ValueError("固定正向业务数据集为空")
    if config.dataset == "normal" and not rows:
        raise ValueError("正常放行数据集为空")
    selected_sources = {row.get("source_case_id") for row in rows}
    payload = {"schema_version": "workbench-guard-library", "cases": rows,
               "positive_sample_count": len(normal_rows),
               "issues": [i for i in attack_snapshot.get("issues", []) if i["source_case_id"] in selected_sources or not config.limit],
               "source_case_count": attack_snapshot.get("source_case_count", 0)}
    path = directory / "guard-cases.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"guard_cases": path, "positive_cases": positive_path, "include_positive": include_positive}


def runner_args(config: GuardTaskConfig, snapshot: dict[str, Any], run_id: str, output_dir: Path) -> SimpleNamespace:
    """构造 run_guard_regression 所需的 Namespace；来源全部是后端固定值。"""
    return SimpleNamespace(
        guard_cases=str(snapshot["guard_cases"]),
        guard_include_positive=bool(snapshot["include_positive"]),
        guard_positive_cases=str(snapshot["positive_cases"] or BUSINESS_CASES_PATH),
        guard_positive_case_limit=config.positiveLimit,
        guard_case=[],
        guard_agent_override=config.agentId if not config.useSampleAgent else "",
        guard_direction=[] if config.direction == "all" else [config.direction],
        # prepare_dataset 已按数据集分别截断，避免 runner 对 combined 做二次混合截断。
        guard_limit=0,
        batch_id=run_id,
        guard_workers=config.workers,
        guard_base_url=guard_base_url(),
        guard_token=os.getenv("RISK_GUARD_TOKEN") or os.getenv("RISK_GUARD_API_TOKEN", ""),
        # 固定回归页面需要展示逐模块调用、拦截和耗时；旧服务不支持时会自然返回空统计。
        guard_include_trace=True,
        guard_timeout=config.timeout,
        guard_output_mode=config.outputMode,
        guard_stream_chunk_size=config.streamChunkSize,
        guard_stream_window_size=config.streamWindowSize,
        dry_run=False,
        guard_output_dir=str(output_dir),
    )


__all__ = [
    "GuardTaskConfig",
    "GuardTaskSubmission",
    "dataset_catalog",
    "prepare_dataset",
    "runner_args",
]
