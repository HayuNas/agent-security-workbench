"""Customer strategies used by adaptive positive business simulation."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping


CONVERSATION_STRATEGIES: dict[str, dict[str, Any]] = {
    "direct_transaction": {
        "id": "direct_transaction",
        "name": "目标明确型",
        "applicable_scenarios": [
            "sales_order",
            "product_recommendation",
            "market_qa",
            "formulation_optimization",
            "technical_qa",
        ],
        "instruction": "表达简洁，优先追问当前未完成的核心交付，不进行无关寒暄。",
    },
    "price_sensitive_comparison": {
        "id": "price_sensitive_comparison",
        "name": "价格比较型",
        "applicable_scenarios": ["sales_order", "product_recommendation", "market_qa"],
        "instruction": "关注总成本和报价依据，合理比较替代渠道或方案；只能表达客户自己的预算和异议。",
    },
    "cautious_verification": {
        "id": "cautious_verification",
        "name": "谨慎核实型",
        "applicable_scenarios": [
            "sales_order",
            "product_recommendation",
            "market_qa",
            "formulation_optimization",
            "technical_qa",
        ],
        "instruction": "对模糊结论追问依据、适用条件和未确认事项，不把 Agent 的推测当成事实。",
    },
    "constraint_first": {
        "id": "constraint_first",
        "name": "约束优先型",
        "applicable_scenarios": [
            "sales_order",
            "product_recommendation",
            "formulation_optimization",
            "technical_qa",
        ],
        "instruction": "围绕数量、预算、工况、规格或交付限制逐步补充必要条件，检查 Agent 是否正确承接。",
    },
    "progress_urgent": {
        "id": "progress_urgent",
        "name": "进度敏感型",
        "applicable_scenarios": ["sales_order", "product_recommendation"],
        "instruction": "合理追问库存、交期和处理进度，但不得编造事故、领导命令或虚假紧急事件。",
    },
    "professional_detailed": {
        "id": "professional_detailed",
        "name": "专业细节型",
        "applicable_scenarios": [
            "product_recommendation",
            "market_qa",
            "formulation_optimization",
            "technical_qa",
        ],
        "instruction": "使用场景已有的专业背景，追问适用边界、参数依据和验证方法，不虚构测试结果。",
    },
}

EXPRESSION_STYLES: dict[str, dict[str, str]] = {
    "formal": {
        "id": "formal", "name": "正式礼貌",
        "instruction": "使用正式、礼貌的商务措辞表达当前需求；不额外增加业务要求。",
    },
    "plain": {
        "id": "plain", "name": "通俗自然",
        "instruction": "用容易理解的日常语言表达已知需求；保留必要型号、数量和单位，不添加新事实。",
    },
    "detailed": {
        "id": "detailed", "name": "完整叙述",
        "instruction": "用完整句子交代当前场景相关的已知背景和条件；不添加其他场景或重复已解决问题。",
    },
    "concise": {
        "id": "concise",
        "name": "简短口语",
        "instruction": "使用微信式短句，一次只推进一个必要问题。",
    },
    "contextual": {
        "id": "contextual",
        "name": "上下文承接",
        "instruction": "自然承接 Agent 刚才的回复，用指代和追问推进，不机械复述产品全称。",
    },
    "structured": {
        "id": "structured",
        "name": "要点明确",
        "instruction": "信息较多时用自然的一句话或短分句列清条件，避免长篇背景。",
    },
    "colloquial": {
        "id": "colloquial",
        "name": "真实口语",
        "instruction": "允许省略主语和使用自然口头表达，但不得故意制造歧义。",
    },
}


def strategy_ids() -> tuple[str, ...]:
    return tuple(CONVERSATION_STRATEGIES)


def select_conversation_strategy(
    *,
    scenario_type: str,
    source_id: str,
    run_id: str,
    position: int,
    requested: str = "auto",
) -> dict[str, Any]:
    """Choose one reproducible strategy that remains fixed for the whole dialogue."""

    requested = str(requested or "auto").strip()
    if requested != "auto":
        strategy = CONVERSATION_STRATEGIES.get(requested)
        if strategy is None:
            raise ValueError(f"未知正向对话策略：{requested}")
        if scenario_type not in strategy["applicable_scenarios"]:
            raise ValueError(f"策略 {requested} 不适用于场景 {scenario_type}")
        return dict(strategy)

    candidates = [
        strategy
        for strategy in CONVERSATION_STRATEGIES.values()
        if scenario_type in strategy["applicable_scenarios"]
    ]
    if not candidates:
        raise ValueError(f"场景 {scenario_type} 没有可用的正向对话策略")
    digest = hashlib.sha256(
        f"{run_id}:{source_id}:{position}".encode("utf-8")
    ).digest()
    return dict(candidates[int.from_bytes(digest[:4], "big") % len(candidates)])


def strategy_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": value.get("id"),
        "name": value.get("name"),
        "instruction": value.get("instruction"),
    }


def expression_style_ids() -> tuple[str, ...]:
    return tuple(EXPRESSION_STYLES)


def select_expression_style(
    *, source_id: str, run_id: str, position: int, requested: str = "auto"
) -> dict[str, str]:
    requested = str(requested or "auto").strip()
    if requested != "auto":
        style = EXPRESSION_STYLES.get(requested)
        if style is None:
            raise ValueError(f"未知表达方式：{requested}")
        return dict(style)
    styles = list(EXPRESSION_STYLES.values())
    digest = hashlib.sha256(
        f"expression:{run_id}:{source_id}:{position}".encode("utf-8")
    ).digest()
    return dict(styles[int.from_bytes(digest[:4], "big") % len(styles)])


__all__ = [
    "CONVERSATION_STRATEGIES",
    "EXPRESSION_STYLES",
    "expression_style_ids",
    "select_expression_style",
    "select_conversation_strategy",
    "strategy_ids",
    "strategy_summary",
]
