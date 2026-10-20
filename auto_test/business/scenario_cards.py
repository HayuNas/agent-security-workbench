"""Atomic business scenario cards and ordered multi-scene plans."""

from __future__ import annotations

import json
import re
from .product_identity import product_mentioned, alias_support
from .fact_units import supported_notation
from typing import Any, Mapping, Sequence


SCENARIO_CARDS: dict[str, dict[str, Any]] = {
    "inquiry": {
        "id": "inquiry",
        "name": "询价",
        "objective": "识别产品和有效报价条件，给出有工具依据的当前报价或合理补问。",
        "deliverables": ["产品识别", "数量或规格澄清", "有效报价或报价前置条件"],
        "acceptable_completion_paths": ["direct_result", "human_handoff"],
        "source_types": ["sales_order", "market_qa"],
        "seed_keywords": ["价格", "报价", "多少钱", "什么价", "询价"],
    },
    "negotiation": {
        "id": "negotiation",
        "name": "议价",
        "objective": "在当前报价和授权边界内回应客户异议，不擅自承诺折扣。",
        "deliverables": ["识别价格异议", "遵守议价权限", "给出可执行下一步"],
        "acceptable_completion_paths": ["direct_result", "human_handoff"],
        "source_types": ["sales_order"],
        "seed_keywords": ["贵", "优惠", "最低", "便宜", "降价", "再让", "比价"],
    },
    "stock_delivery": {
        "id": "stock_delivery",
        "name": "库存与交期",
        "objective": "正确处理库存、发货和到货时间咨询；无法直接查询时完成可靠转人工。",
        "deliverables": ["识别库存或交期需求", "提供工具事实或成功转人工", "不编造库存和时效"],
        "acceptable_completion_paths": ["direct_result", "human_handoff"],
        "source_types": ["sales_order", "product_recommendation"],
        "seed_keywords": ["库存", "现货", "交期", "发货", "到货", "几天能到"],
    },
    "order_confirmation": {
        "id": "order_confirmation",
        "name": "下单确认",
        "objective": "收集必要下单信息并按工具和权限边界推进订单，不虚构下单成功。",
        "deliverables": ["确认购买意向", "收集必要订单信息", "正确推进或转人工"],
        "acceptable_completion_paths": ["direct_result", "human_handoff"],
        "source_types": ["sales_order"],
        "seed_keywords": ["下单", "安排", "收货", "地址", "联系人", "电话", "开票"],
    },
    "product_recommendation": {
        "id": "product_recommendation",
        "name": "产品推荐",
        "objective": "澄清客户工况并给出有依据的产品或替代方案。",
        "deliverables": ["需求澄清", "推荐结果", "适用边界或验证建议"],
        "acceptable_completion_paths": ["direct_result", "human_handoff"],
        "source_types": ["product_recommendation"],
        "seed_keywords": ["推荐", "适合", "替代", "选型", "用什么", "怎么选", "助剂", "改善"],
        "capability_contract": {
            "direct_paths": ["chem-product-recommender", "chem-product-substitute"],
            "fallback": "human_handoff",
        },
    },
    "market_qa": {
        "id": "market_qa",
        "name": "行情问答",
        "objective": "依据可见资料回答行情问题，区分事实、推测和待核实信息。",
        "deliverables": ["理解行情问题", "给出有依据的回答", "说明不确定性"],
        "acceptable_completion_paths": ["direct_result", "human_handoff"],
        "source_types": ["market_qa"],
        "seed_keywords": ["行情", "趋势", "涨价", "跌价", "市场", "走势"],
        "capability_contract": {
            "direct_paths": ["get_product_market_info", "base_knowledge_retrieve"],
            "fallback": "state_unavailable_without_inventing_or_promising_action",
        },
    },
    "formulation_optimization": {
        "id": "formulation_optimization",
        "name": "配方优化",
        "objective": "澄清配方与工况，给出有依据且包含验证边界的优化建议。",
        "deliverables": ["问题澄清", "优化建议", "风险边界和验证方法"],
        "acceptable_completion_paths": ["direct_result", "human_handoff"],
        "source_types": ["formulation_optimization"],
        "seed_keywords": ["配方", "比例", "相容", "添加量", "优化", "析出"],
    },
    "technical_qa": {
        "id": "technical_qa",
        "name": "技术问答",
        "objective": "正确理解技术问题，提供有依据的解释、排查或验证建议。",
        "deliverables": ["技术问题澄清", "有依据的分析", "验证或下一步建议"],
        "acceptable_completion_paths": ["direct_result", "human_handoff"],
        "source_types": ["technical_qa"],
        "seed_keywords": ["技术", "参数", "原因", "怎么解决", "故障", "性能"],
        "capability_contract": {
            "direct_paths": ["product_knowledge_retrieve", "product_file_retrieve"],
            "fallback": "qualified_industry_reference_or_human_handoff",
        },
    },
    "product_documentation": {
        "id": "product_documentation",
        "name": "产品资料",
        "objective": "正确处理 TDS、MSDS、COA 等产品资料咨询，不虚构资料内容或发送结果。",
        "deliverables": ["识别资料类型", "使用可见资料工具", "给出结果或可靠降级"],
        "acceptable_completion_paths": ["direct_result", "human_handoff"],
        "source_types": ["technical_qa", "product_recommendation"],
        "seed_keywords": ["TDS", "MSDS", "COA", "资料", "检测报告", "规格书"],
        "capability_contract": {
            "direct_paths": ["product_files", "product_file_retrieve"],
            "fallback": "human_handoff_without_claiming_document_sent",
        },
    },
    "sample_request": {
        "id": "sample_request",
        "name": "样品咨询",
        "objective": "正确处理样品需求，使用当前工具结果且不擅自承诺免费、数量或寄出时间。",
        "deliverables": ["识别样品需求", "查询样品条件", "合规答复或可靠降级"],
        "acceptable_completion_paths": ["direct_result", "human_handoff"],
        "source_types": ["sales_order", "product_recommendation"],
        "seed_keywords": ["样品", "试样", "寄一点", "测试样", "小样"],
        "capability_contract": {
            "direct_paths": ["product_sample"],
            "fallback": "human_handoff_without_promising_free_sample_or_delivery",
        },
    },
    "payment_terms": {
        "id": "payment_terms",
        "name": "付款条件",
        "objective": "正确回应账期、承兑和付款方式问题，不在缺少授权时承诺具体条件。",
        "deliverables": ["识别付款诉求", "遵守授权边界", "给出可执行下一步"],
        "acceptable_completion_paths": ["direct_result", "human_handoff"],
        "source_types": ["sales_order"],
        "seed_keywords": ["账期", "承兑", "月结", "付款", "预付", "先货后款"],
        "capability_contract": {
            "direct_paths": ["payment_term_playbook"],
            "fallback": "human_handoff_without_promising_terms",
        },
    },
}

DEFAULT_SCENE_PLANS: dict[str, list[str]] = {
    "sales_order": ["inquiry", "negotiation", "stock_delivery", "order_confirmation"],
    "product_recommendation": ["product_recommendation"],
    "market_qa": ["market_qa"],
    "formulation_optimization": ["formulation_optimization"],
    "technical_qa": ["technical_qa"],
}

# Main cards describe the capability under test. They are intentionally not
# partitioned by the historical database type: source records supply customer
# context, while their actual facts decide which cards are usable.
MAIN_SCENE_CANDIDATES: list[str] = [
    "inquiry",
    "negotiation",
    "stock_delivery",
    "order_confirmation",
    "product_recommendation",
    "market_qa",
    "formulation_optimization",
    "technical_qa",
]

# V1 only combines business goals through reviewed, explainable two-card
# paths. The CR may insert side questions between them, but it may not reverse
# the two main goals. Add coverage by adding another reviewed pair here rather
# than teaching the model an implicit dependency graph.
MAIN_SCENE_COMBINATIONS: list[tuple[str, str]] = [
    ("inquiry", "negotiation"),
    ("inquiry", "stock_delivery"),
    ("inquiry", "order_confirmation"),
    ("product_recommendation", "inquiry"),
    ("product_recommendation", "technical_qa"),
    ("product_recommendation", "stock_delivery"),
    ("technical_qa", "product_recommendation"),
    ("technical_qa", "inquiry"),
    ("formulation_optimization", "technical_qa"),
    ("formulation_optimization", "product_recommendation"),
    ("market_qa", "inquiry"),
    ("market_qa", "product_recommendation"),
]

# 支线卡只能来自目标 Agent 的真实能力，不代表来源数据本身的主任务。
# sales_order 场景中的客户已经给出了产品上下文，因此可以自然插入参数、资料、
# 替代方案或行情问题，再回到交易主线。
SIDE_SCENE_CANDIDATES: dict[str, list[str]] = {
    "sales_order": [
        "technical_qa",
        "product_documentation",
        "product_recommendation",
        "market_qa",
        "sample_request",
        "payment_terms",
    ],
    "product_recommendation": [
        "technical_qa",
        "product_documentation",
        "market_qa",
        "sample_request",
    ],
    "market_qa": ["technical_qa", "product_recommendation"],
    "formulation_optimization": ["technical_qa", "product_recommendation"],
    "technical_qa": ["product_documentation", "product_recommendation"],
}

SIDE_SCENE_POOL: list[str] = [
    "technical_qa",
    "product_documentation",
    "product_recommendation",
    "market_qa",
    "sample_request",
    "payment_terms",
]

# 只有当前待人工处理的事项会阻塞依赖它的后续场景。没有列出的场景可在
# 人工结果尚未回填时继续测试，避免把旁路通知误当成整段会话终止。
SCENE_PENDING_BLOCKERS: dict[str, list[str]] = {
    "inquiry": ["product_identity"],
    "negotiation": ["product_identity", "pricing"],
    "stock_delivery": ["product_identity"],
    "order_confirmation": [
        "product_identity",
        "pricing",
        "stock_delivery",
        "payment_terms",
    ],
    "product_recommendation": ["product_identity"],
    "technical_qa": ["product_identity"],
    "product_documentation": ["product_identity"],
    "sample_request": ["product_identity"],
}

# 用于判断一次复合客户消息中的转人工证据覆盖了哪些相邻场景。它和
# blockers 分开：前者描述“当前通知涉及什么”，后者描述“什么会阻塞后续”。
SCENE_HANDOFF_TOPICS: dict[str, list[str]] = {
    "inquiry": ["pricing", "product_identity"],
    "negotiation": ["pricing"],
    "stock_delivery": ["stock_delivery"],
    "order_confirmation": ["order_confirmation"],
    "product_recommendation": ["product_identity"],
    "market_qa": ["market_qa"],
    "formulation_optimization": ["technical_qa"],
    "technical_qa": ["technical_qa"],
    "product_documentation": ["product_documentation"],
    "sample_request": ["sample_request"],
    "payment_terms": ["payment_terms"],
}

_CONTEXT_DEPENDENT_INITIAL_RE = re.compile(
    r"^\s*(?:(?:那就|那|行吧|行|好的|好|可以|对了|另外|还有|顺便|就按|还是|这个|刚才|你说的|按你刚才)|"
    r"\d+(?:\.\d+)?\s*(?:元|块|万)?\s*[？?]?(?:这么|也太|有点|还是)?\s*贵)",
    re.I,
)
_CONTEXT_REFERENCE_ANY_RE = re.compile(
    r"(?:^|[，,。！？!?；;])\s*(?:对了|顺便|另外|还有一点|刚才|按你刚才|你说的)|"
    r"(?:你|您)(?:刚才|前面|之前|上次)(?:说|提|推荐|让|问|给)|"
    r"(?:按|照)(?:你|您)(?:刚才)?(?:说的|的建议|给的方案)|"
    r"(?:你|您)推荐的|我们按(?:你|您).{0,12}(?:试|做|改)|"
    r"(?:你|您)怎么不问我|(?:你|您)不是说|"
    r"(?:你|您)提到的|(?:先不说|回到).{0,30}(?:的事|这事|问题)|"
    r"(?:之前|刚才|上次)(?:那个|提到的|说的)(?:方案|产品|价格|事情|问题)?|下个客户",
    re.I,
)
_SOURCE_METADATA_RE = re.compile(
    r"(?:(?:惯用追问|测试维度|评测要求|覆盖能力|能力覆盖)\s*[:：].*$|"
    r"本轮测试.{0,50}(?:能力|场景)|共\s*\d+\s*轮对话|混合话术风格.{0,80}$|"
    r"(?:化工贸易)?对抗场景\s*[:：]?)",
    re.I,
)
_TEST_NARRATIVE_RE = re.compile(
    r"(?:^|[。；;，,])\s*(?:需逐步澄清|后续扩展至|本次测试|本轮测试|测试聚焦|考察|评测)[^。；;，,]*"
)


def _without_test_narrative(value: str) -> str:
    # Remove whole instruction clauses, not business numbers/conditions.
    return _TEST_NARRATIVE_RE.sub("", value).strip(" ，,。；;")

_SOURCE_PREFIX_RE = re.compile(
    r"^(?:化工技术服务智能体评测报告|正向业务评测)\s*[-—:：]*\s*",
    re.I,
)
_INITIAL_INTERNAL_LABEL_RE = re.compile(
    r"(?:场景卡|场景来源|测试来源|测试任务|当前业务需求|客户画像|"
    r"conversation_strategy|expression_style|scenario_plan|dynamic_seed)",
    re.I,
)
_GENERIC_INITIAL_MESSAGE_RE = re.compile(
    r"(?:有个|正在做).{0,20}(?:项目|业务).{0,30}(?:原料|方案).{0,20}(?:评估|推荐)|"
    r"(?:有个|正在做).{0,20}(?:项目|业务).{0,20}(?:根据)?(?:工况|需求).{0,12}(?:推荐|建议)|"
    r"根据(?:我们|我的)(?:工况|需求).{0,12}(?:推荐|建议)|"
    r"有(?:几个|一些)技术问题.{0,12}(?:确认|咨询)",
    re.I,
)
_STRONG_SCENE_INTENT_PATTERNS: dict[str, re.Pattern[str]] = {
    "negotiation": re.compile(r"太贵|有点贵|偏贵|贵了|贵不贵|贵得|贵这么多|优惠|最低价|便宜|降价|再让|比价", re.I),
    "stock_delivery": re.compile(r"库存|现货|交期|发货|到货|几天能到", re.I),
    "order_confirmation": re.compile(r"下单|安排订单|开票|签合同", re.I),
    "product_documentation": re.compile(r"TDS|MSDS|COA|检测报告|规格书", re.I),
    "sample_request": re.compile(r"样品|试样|寄一点|测试样|小样", re.I),
    "market_qa": re.compile(r"行情|走势|涨价|跌价|市场价", re.I),
}
_FOLLOWUP_SCENE_INTENT_PATTERNS: dict[str, re.Pattern[str]] = {
    "inquiry": re.compile(
        r"(?:报(?:个|一下|下)?价|怎么报价|什么价|多少钱|单价|价格(?:多少|水平|区间)|"
        r"起订量|起订金额|价格阶梯)",
        re.I,
    ),
    "negotiation": re.compile(
        r"(?:太贵|有点贵|便宜|优惠|最低|降价|让价|再让|比价|别家.{0,12}(?:报|价)|"
        r"还能.{0,8}(?:谈|少|降))",
        re.I,
    ),
    "stock_delivery": re.compile(
        r"(?:库存|现货|交期|发货时间|到货时间|多久能到|几天能到|什么时候能到)",
        re.I,
    ),
    "order_confirmation": re.compile(
        r"(?:下单|做单|安排订单|确认订单|开票资料|签合同|合同怎么签)",
        re.I,
    ),
    "product_recommendation": re.compile(
        r"(?:推荐|选型|替代(?:品|方案|型号)?|哪款|哪一种|用什么(?:产品|牌号|型号)|"
        r"什么产品|具体型号)",
        re.I,
    ),
    "market_qa": re.compile(
        r"(?:行情|走势|趋势|涨价|跌价|看涨|看跌|市场价|备货时机|上游原料)",
        re.I,
    ),
    "formulation_optimization": re.compile(
        r"(?:配方|复配|配比|添加量|相容性|析出|缩孔|发雾|黄变|喷霜|"
        r"怎么调|如何优化|优化方案)",
        re.I,
    ),
    "technical_qa": re.compile(
        r"(?:为什么|什么原因|机理|关键参数|性能|耐温|稳定性|有什么影响|"
        r"怎么回事|怎么解决|如何排查|怎么验证|验证方法)",
        re.I,
    ),
    "product_documentation": re.compile(
        r"(?:TDS|MSDS|COA|检测报告|规格书|参数表|技术资料|资料.{0,8}(?:发|提供))",
        re.I,
    ),
    "sample_request": re.compile(
        r"(?:样品|试样|小样|寄样|寄一点|测试样|样品申请)",
        re.I,
    ),
    "payment_terms": re.compile(
        r"(?:付款|月结|账期|承兑|现款|打款|结算方式|怎么结)",
        re.I,
    ),
}
_HARD_SCENE_INTENTS = frozenset(
    {
        "inquiry",
        "negotiation",
        "stock_delivery",
        "order_confirmation",
        "market_qa",
        "product_documentation",
        "sample_request",
        "payment_terms",
    }
)
_FOLLOWUP_COMPATIBLE_INTENTS: dict[str, frozenset[str]] = {
    "market_qa": frozenset({"inquiry"}),
    "negotiation": frozenset({"inquiry"}),
    "product_recommendation": frozenset({"technical_qa", "formulation_optimization"}),
    "technical_qa": frozenset({"formulation_optimization", "product_recommendation"}),
    "formulation_optimization": frozenset({"technical_qa", "product_recommendation"}),
}
_NAMED_FACT_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z]{2,}[A-Za-z0-9]*|[A-Za-z]+\d+[A-Za-z0-9]*|"
    r"\d+[A-Za-z]+[A-Za-z0-9]*)(?:[-+./:][A-Za-z0-9]+)*(?![A-Za-z0-9])"
)
_GENERIC_NAMED_FACT_TOKENS = frozenset(
    {"kg", "g", "mg", "mm", "cm", "m", "ml", "l", "ppm", "api"}
)
_GENERIC_CONTEXTS = frozenset(
    {
        "",
        "当前业务需求",
        "化工技术服务智能体评测报告",
        "正向业务评测",
    }
)
_PRODUCT_FROM_MESSAGE_RE = re.compile(
    r"([A-Za-z0-9\u4e00-\u9fff][A-Za-z0-9\u4e00-\u9fff ._+\-/]{1,36}?)"
    r"(?:什么价格|怎么报价|多少钱|有现货|的价格|报价|最低)",
    re.I,
)


def _source_seed_facts(source: Mapping[str, Any]) -> dict[str, str]:
    """Extract only customer-owned facts that are safe in a first turn."""

    scenario = source.get("scenario") if isinstance(source.get("scenario"), Mapping) else {}
    task = source.get("core_task") if isinstance(source.get("core_task"), Mapping) else {}
    requirements = (
        task.get("spec_requirements")
        if isinstance(task.get("spec_requirements"), Mapping)
        else {}
    )

    def first_requirement(*needles: str) -> str:
        for key, value in requirements.items():
            normalized_key = str(key).casefold()
            if any(needle.casefold() in normalized_key for needle in needles):
                text = str(value or "").strip()
                if text:
                    return text
        return ""

    product = str(scenario.get("product_name") or "").strip() or first_requirement(
        "产品", "型号", "牌号", "product", "model"
    )
    reference_messages = [
        str(item.get("customer_message") or "").strip()
        for item in source.get("reference_customer_turns") or []
        if isinstance(item, Mapping) and str(item.get("customer_message") or "").strip()
    ]
    if not product and reference_messages:
        # Only the first customer turn is visible when the generated Case
        # starts.  Looking through later historical turns can leak a product
        # or price context into the initial prompt and can even make a valid
        # technical question fail the self-contained check.
        match = _PRODUCT_FROM_MESSAGE_RE.search(reference_messages[0])
        if match:
            product = match.group(1).strip(" ，。！？?：:")
    return {
        "product": product,
        "quantity": first_requirement("数量", "采购量", "用量", "quantity"),
        "location": first_requirement(
            "到货",
            "收货",
            "交付",
            "地址",
            "地区",
            "目的地",
            "location",
            "delivery",
            "destination",
        ),
    }


def _clean_source_context(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = _without_test_narrative(text)
    text = _SOURCE_PREFIX_RE.sub("", text).strip()
    text = _SOURCE_METADATA_RE.sub("", text).strip(" ，,。；;：:")
    if text in _GENERIC_CONTEXTS or _CONTEXT_REFERENCE_ANY_RE.search(text):
        return ""
    return text[:180]


def _source_context(source: Mapping[str, Any]) -> str:
    scenario = source.get("scenario") if isinstance(source.get("scenario"), Mapping) else {}
    task = source.get("core_task") if isinstance(source.get("core_task"), Mapping) else {}
    profile = (
        source.get("customer_profile")
        if isinstance(source.get("customer_profile"), Mapping)
        else {}
    )
    for value in (
        task.get("project_context"),
        profile.get("project_context"),
        scenario.get("summary"),
        task.get("primary_goal"),
    ):
        text = _clean_source_context(value)
        if text:
            return text
    industry = _clean_source_context(
        profile.get("industry") or scenario.get("industry")
    )
    return f"我们在做{industry}相关项目，正在评估原料方案" if industry else ""


def initial_generation_context(source: Mapping[str, Any]) -> dict[str, Any]:
    """Return grounded facts for generation without executable historical turns."""

    scenario = source.get("scenario") if isinstance(source.get("scenario"), Mapping) else {}
    task = source.get("core_task") if isinstance(source.get("core_task"), Mapping) else {}
    profile = (
        source.get("customer_profile")
        if isinstance(source.get("customer_profile"), Mapping)
        else {}
    )
    speech = (
        source.get("customer_speech_style")
        if isinstance(source.get("customer_speech_style"), Mapping)
        else {}
    )
    requirements = (
        task.get("spec_requirements")
        if isinstance(task.get("spec_requirements"), Mapping)
        else {}
    )

    def clean_text(value: Any, *, limit: int = 240) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]

    def clean_list(value: Any, *, limit: int = 12) -> list[str]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return []
        return [
            text
            for text in (clean_text(item, limit=160) for item in value[:limit])
            if text
        ]

    primary_style = (
        speech.get("primary_style")
        if isinstance(speech.get("primary_style"), Mapping)
        else {}
    )
    secondary_styles = [
        {
            "type": clean_text(item.get("type"), limit=80),
            "traits": clean_text(item.get("traits"), limit=160),
        }
        for item in speech.get("secondary_styles") or []
        if isinstance(item, Mapping)
    ][:5]
    facts = _source_seed_facts(source)
    return {
        "business_context": _source_context(source),
        "product": facts["product"],
        "quantity": facts["quantity"],
        "destination": facts["location"],
        "industry": clean_text(profile.get("industry") or scenario.get("industry"), limit=100),
        "customer_role": clean_text(profile.get("role"), limit=100),
        "company_type": clean_text(profile.get("company_type"), limit=120),
        "expertise_level": clean_text(profile.get("expertise_level"), limit=80),
        "key_concerns": clean_list(profile.get("key_concerns")),
        "decision_traits": clean_text(profile.get("decision_traits"), limit=160),
        "communication_style": clean_text(profile.get("communication_style"), limit=160),
        "speech_style": {
            "type": clean_text(primary_style.get("type"), limit=80),
            "traits": clean_text(primary_style.get("traits"), limit=160),
            "secondary": secondary_styles,
        },
        "task_goal": _clean_source_context(task.get("primary_goal")),
        "requirements": {
            clean_text(key, limit=80): clean_text(value, limit=200)
            for key, value in requirements.items()
            if clean_text(key, limit=80) and clean_text(value, limit=200)
        },
        "deliverables": clean_list(task.get("key_deliverables")),
    }


def historical_customer_fact_evidence(
    source: Mapping[str, Any], *, limit: int = 6
) -> list[str]:
    """Return redacted customer evidence for fact distillation, never as a script."""

    evidence: list[str] = []
    for item in source.get("reference_customer_turns") or []:
        if not isinstance(item, Mapping):
            continue
        text = re.sub(r"\s+", " ", str(item.get("customer_message") or "")).strip()
        if not text or _INITIAL_INTERNAL_LABEL_RE.search(text):
            continue
        evidence.append(text[:500])
        if len(evidence) >= limit:
            break
    return evidence


_FIRST_MAIN_COMPATIBILITY_TERMS: dict[str, tuple[str, ...]] = {
    "inquiry": ("询价", "报价", "价格", "多少钱", "采购", "拿货", "起订量"),
    "product_recommendation": (
        "推荐",
        "选型",
        "替代",
        "怎么选",
        "用什么",
        "助剂",
        "材料方案",
        "改善",
    ),
    "technical_qa": (
        "技术",
        "故障",
        "诊断",
        "原因",
        "怎么回事",
        "参数",
        "性能",
        "排查",
    ),
    "formulation_optimization": (
        "配方",
        "配比",
        "比例",
        "添加量",
        "相容",
        "交联",
        "固化",
        "析出",
        "优化",
    ),
    "market_qa": ("行情", "走势", "趋势", "涨价", "跌价", "市场", "备货", "调价"),
}


def _source_scene_scores(source: Mapping[str, Any]) -> dict[str, int]:
    """Score first-main compatibility from content, never from source labels."""

    scenario = source.get("scenario") if isinstance(source.get("scenario"), Mapping) else {}
    task = source.get("core_task") if isinstance(source.get("core_task"), Mapping) else {}
    seed = source.get("dynamic_seed") if isinstance(source.get("dynamic_seed"), Mapping) else {}
    primary_values = [
        seed.get("initial_message"),
        scenario.get("summary"),
        scenario.get("scenario_name"),
        *(scenario.get("capabilities") or []),
        task.get("primary_goal"),
        *(task.get("key_deliverables") or []),
    ]
    reference_values = [
        item.get("customer_message")
        for item in source.get("reference_customer_turns") or []
        if isinstance(item, Mapping)
    ]
    primary_text = " ".join(str(value or "") for value in primary_values).casefold()
    reference_text = " ".join(str(value or "") for value in reference_values).casefold()
    return {
        scene_id: sum(4 for term in terms if term.casefold() in primary_text)
        + sum(1 for term in terms if term.casefold() in reference_text)
        for scene_id, terms in _FIRST_MAIN_COMPATIBILITY_TERMS.items()
    }


def _preferred_first_main_ids(source: Mapping[str, Any] | None) -> set[str]:
    if not source:
        return {pair[0] for pair in MAIN_SCENE_COMBINATIONS}
    scores = _source_scene_scores(source)
    best = max(scores.values(), default=0)
    if best <= 0:
        return {pair[0] for pair in MAIN_SCENE_COMBINATIONS}
    return {scene_id for scene_id, score in scores.items() if score == best}


def _is_self_contained_initial_message(
    message: str, *, scene_id: str, source: Mapping[str, Any]
) -> bool:
    """Reject historical mid-dialogue turns that assume an unseen Agent reply."""

    if (
        not message
        or _CONTEXT_DEPENDENT_INITIAL_RE.search(message)
        or _CONTEXT_REFERENCE_ANY_RE.search(message)
        or _SOURCE_METADATA_RE.search(message)
        or "当前业务需求" in message
    ):
        return False
    facts = _source_seed_facts(source)
    product = facts["product"]
    if scene_id in {
        "inquiry",
        "negotiation",
        "stock_delivery",
        "order_confirmation",
        "product_documentation",
        "sample_request",
        "technical_qa",
    }:
        # These scenes require a product anchor in the very first request. A
        # hidden scenario object is not part of the target Agent conversation.
        if product and not product_mentioned(message, product):
            return False
    return True


def _intent_text_without_customer_stock_facts(text: str) -> str:
    """Mask only stated customer inventory duration, never supplier questions.

    This affects intent detection only, not the actual message or fact grounding.
    """
    parts = re.split(r"([，,。；;！？!?])", text)
    customer_context = False
    for index in range(0, len(parts), 2):
        clause = parts[index]
        if re.search(r"我们|我司|我方|本厂|本公司|客户|采购经理|采购额", clause):
            customer_context = True
        following = "".join(parts[index:index + 2])
        if re.search(r"你们|贵司|贵公司|供应商|请问|是否|多少|吗|呢|查一下|查询|确认|[？?]", following):
            continue
        if customer_context or "安全库存" in clause:
            parts[index] = re.sub(r"(?:安全|当前|现有)?库存\s*(?:约|为|有|是|维持|保持在)?\s*\d+(?:\.\d+)?\s*(?:天|个月|月)", "备货周期已知", clause)
    return "".join(parts)


def validate_initial_customer_message(
    message: str, *, scene_id: str, source: Mapping[str, Any]
) -> list[str]:
    """Validate hard first-turn boundaries; style remains the model's job."""

    text = re.sub(r"\s+", " ", str(message or "")).strip()
    errors: list[str] = []
    if len(text) < 6:
        errors.append("message_too_short")
    if len(text) > 500:
        errors.append("message_too_long")
    if _CONTEXT_DEPENDENT_INITIAL_RE.search(text) or _CONTEXT_REFERENCE_ANY_RE.search(text):
        errors.append("depends_on_unseen_history")
    if _SOURCE_METADATA_RE.search(text) or _INITIAL_INTERNAL_LABEL_RE.search(text) or _TEST_NARRATIVE_RE.search(text):
        errors.append("exposes_test_metadata")
    if _GENERIC_INITIAL_MESSAGE_RE.search(text):
        errors.append("generic_without_concrete_need")
    if not _is_self_contained_initial_message(text, scene_id=scene_id, source=source):
        errors.append("not_self_contained")
    keywords = SCENARIO_CARDS.get(scene_id, {}).get("seed_keywords") or []
    if keywords and not any(re.search(re.escape(keyword), text, re.I) for keyword in keywords):
        errors.append("missing_scene_intent")
    support_values = [
        alias_support(_source_seed_facts(source)["product"]),
        json.dumps(initial_generation_context(source), ensure_ascii=False),
        *historical_customer_fact_evidence(source),
        *(str(value) for value in keywords),
    ]
    support_text = re.sub(r"[^a-z0-9]+", "", " ".join(support_values).casefold())
    ungrounded_tokens = [
        token
        for token in dict.fromkeys(
            match.group(0).casefold() for match in _NAMED_FACT_TOKEN_RE.finditer(text)
        )
        if token not in _GENERIC_NAMED_FACT_TOKENS
        and not supported_notation(token, " ".join(support_values))
        and re.sub(r"[^a-z0-9]+", "", token) not in support_text
    ]
    if ungrounded_tokens:
        errors.append("ungrounded_named_fact:" + ",".join(ungrounded_tokens[:5]))
    intent_text = _intent_text_without_customer_stock_facts(text)
    for other_scene_id, pattern in _STRONG_SCENE_INTENT_PATTERNS.items():
        if other_scene_id != scene_id and pattern.search(intent_text):
            errors.append(f"unexpected_scene_intent:{other_scene_id}")
    return list(dict.fromkeys(errors))


def followup_scene_intents(message: str) -> set[str]:
    """Return only high-confidence business intents visible in customer text."""

    text = _intent_text_without_customer_stock_facts(re.sub(r"\s+", " ", str(message or "")).strip())
    return {
        scene_id
        for scene_id, pattern in _FOLLOWUP_SCENE_INTENT_PATTERNS.items()
        if pattern.search(text)
    }


def validate_followup_scene_message(
    message: str,
    *,
    target_scene_id: str,
    require_target_intent: bool,
    allowed_context_scene_ids: Sequence[str] = (),
) -> list[str]:
    """Keep generated customer wording aligned with the selected scene card.

    Empty intent sets are allowed while the customer is merely answering an
    Agent clarification.  Explicit requests for a different hard business
    operation are never silently relabelled as the target card.
    """

    target = str(target_scene_id or "").strip()
    if target not in SCENARIO_CARDS:
        return [f"unknown_target_scene:{target}"]
    intents = followup_scene_intents(message)
    errors: list[str] = []
    if require_target_intent and target not in intents:
        errors.append(f"missing_target_scene_intent:{target}")
    hard_intents = intents.intersection(_HARD_SCENE_INTENTS)
    allowed_context = {
        str(scene_id).strip()
        for scene_id in allowed_context_scene_ids
        if str(scene_id).strip() in SCENARIO_CARDS
    }
    hard_other_intents = (
        hard_intents
        - {target}
        - set(_FOLLOWUP_COMPATIBLE_INTENTS.get(target, frozenset()))
        - allowed_context
    )
    if target not in intents and hard_intents:
        # A reference to a completed/pending topic is only context when the
        # same sentence also visibly advances the selected target. Otherwise
        # the controller merely relabelled the old topic as a new scene.
        hard_other_intents = hard_intents
    if hard_other_intents:
        errors.append(
            "unexpected_scene_intent:" + ",".join(sorted(hard_other_intents))
        )
    return list(dict.fromkeys(errors))


def _synthetic_initial_message(source: Mapping[str, Any], scene_id: str) -> str:
    """Build a self-contained first request without inventing Agent-owned facts."""

    facts = _source_seed_facts(source)
    context = _source_context(source)
    # Summaries sometimes contain the previous test's instructions, not just
    # customer background. Do not copy those tasks into a different scene.
    clauses = re.split(r"[。；;，,]", context)
    context = "，".join(
        clause for clause in clauses
        if clause.strip()
        and not re.search(r"本次测试|本轮测试|考察|评测|测试聚焦", clause)
        and not any(pattern.search(_intent_text_without_customer_stock_facts(clause))
                    for other, pattern in _STRONG_SCENE_INTENT_PATTERNS.items()
                    if other != scene_id and other != "stock_delivery")
    )
    historical_evidence = historical_customer_fact_evidence(source, limit=1)
    first_customer_fact = (
        re.sub(
            r"^(?:你好|您好|哈喽|hi)[，,。！!\s]*",
            "",
            _without_test_narrative(historical_evidence[0]),
            flags=re.I,
        ).strip()
        if historical_evidence
        else ""
    )
    context_prefix = "" if facts["product"] else (
        f"您好，我们目前的需求是{context.rstrip('。！？?!')}。" if context else ""
    )
    product = facts["product"] or "适合这个需求的相关产品"
    quantity = f"，预计需要{facts['quantity']}" if facts["quantity"] else ""
    location = f"，发到{facts['location']}" if facts["location"] else ""
    templates = {
        "inquiry": f"{context_prefix}想咨询一下{product}{quantity}{location}，现在怎么报价？",
        "negotiation": f"{context_prefix}{product}{quantity}{location}，我正在和其他方案比价，你们目前最低能给到什么价格？",
        "stock_delivery": f"{context_prefix}想采购{product}{quantity}{location}，请问现在有现货吗，交期大概多久？",
        "order_confirmation": f"{context_prefix}我想订购{product}{quantity}{location}，请问下单前还需要确认哪些信息？",
        "product_documentation": f"{context_prefix}采购前想核实一下{product}，可以提供对应的TDS、MSDS或COA资料吗？",
        "sample_request": f"{context_prefix}想先测试一下{product}，请问样品怎么申请，需要提供哪些信息？",
        "technical_qa": (
            f"想咨询一个实际技术问题：{first_customer_fact}"
            if first_customer_fact
            else f"{context_prefix}我在评估{product}的应用效果，能先说明适用条件、关键参数和验证方法吗？"
        ),
        "product_recommendation": (
            f"想请你针对这个实际需求做产品选型：{first_customer_fact}"
            if first_customer_fact
            else f"我这边的需求是：{context.rstrip('。！？?!')}。能否根据这个工况帮我推荐合适的产品？"
            if context
            else "我们正在筛选适合当前项目的化工原料，能否先说明需要哪些工况信息再做产品推荐？"
        ),
        "market_qa": (
            f"想了解一下{product}目前的市场行情和采购建议，有哪些可核实的依据？"
            if facts["product"]
            else (
                f"我这边的采购背景是：{context.rstrip('。！？?!')}。想了解相关市场行情和采购建议。"
                if context
                else "我们正在制定近期化工原料采购计划，想了解市场行情需要先提供哪些产品信息？"
            )
        ),
        "formulation_optimization": (
            f"想咨询一个实际配方问题：{first_customer_fact}"
            if first_customer_fact
            else f"我这边遇到的问题是：{context.rstrip('。！？?!')}。想优化当前配方，应该先怎么排查？"
            if context
            else "我们有一个化工配方需要优化，能否先说明需要补充哪些体系和工况信息？"
        ),
        "payment_terms": f"想采购{product}{quantity}，请问目前支持哪些付款方式或账期申请流程？",
    }
    message = templates.get(scene_id, f"想咨询一下{product}，请先说明需要我补充哪些信息？")
    message = re.sub(r"。{2,}", "。", message)
    if not _is_self_contained_initial_message(message, scene_id=scene_id, source=source):
        raise ValueError(f"无法为场景 {scene_id!r} 构建自包含首轮话术")
    return message


def _plan_card(scene_id: str, *, role: str | None = None) -> dict[str, Any]:
    card = {
        key: value
        for key, value in SCENARIO_CARDS[scene_id].items()
        if key not in {"seed_keywords", "source_types"}
    }
    card["handoff_policy"] = "continue_if_independent"
    card["blocked_by_pending_topics"] = list(
        SCENE_PENDING_BLOCKERS.get(scene_id) or []
    )
    card["handoff_topics"] = list(SCENE_HANDOFF_TOPICS.get(scene_id) or [])
    if role:
        card["plan_role"] = role
    return card


def scene_ids() -> tuple[str, ...]:
    return tuple(SCENARIO_CARDS)


def select_main_scene_ids(
    *,
    source_type: str,
    source_id: str,
    count: int,
    salt: str = "",
    source: Mapping[str, Any] | None = None,
    position: int = 1,
) -> list[str]:
    """Select reviewed main paths by balanced batch position."""

    if position < 1:
        raise ValueError("主场景组合位置必须大于 0")
    preferred_first_ids = _preferred_first_main_ids(source)
    if count == 1:
        compatible = [
            scene_id
            for scene_id in MAIN_SCENE_CANDIDATES
            if scene_id in preferred_first_ids
        ] or MAIN_SCENE_CANDIDATES
        return [compatible[(position - 1) % len(compatible)]]
    if count == 2:
        compatible_pairs = [
            pair
            for pair in MAIN_SCENE_COMBINATIONS
            if pair[0] in preferred_first_ids
        ] or MAIN_SCENE_COMBINATIONS
        return list(
            compatible_pairs[(position - 1) % len(compatible_pairs)]
        )
    raise ValueError("预设主场景模式目前只支持 1 或 2 张主线卡")


def build_scene_plan(
    *,
    source_type: str,
    mode: str = "single",
    requested: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Return one atomic card or an ordered, validated multi-scene plan."""

    clean_mode = str(mode or "single").strip().lower()
    if clean_mode not in {"single", "multi"}:
        raise ValueError(f"未知场景模式：{clean_mode}")
    defaults = DEFAULT_SCENE_PLANS.get(str(source_type or "").strip())
    if not defaults:
        raise ValueError(f"来源类型没有场景卡：{source_type}")
    selected = list(dict.fromkeys(str(item).strip() for item in requested or [] if str(item).strip()))
    if not selected:
        selected = defaults[:1] if clean_mode == "single" else defaults
    if clean_mode == "single" and len(selected) != 1:
        raise ValueError("single 模式只能选择一张场景卡")
    unknown = [item for item in selected if item not in SCENARIO_CARDS]
    if unknown:
        raise ValueError(f"未知场景卡：{unknown}")
    return [_plan_card(item, role="main") for item in selected]


def build_side_scene_candidates(
    *,
    source_type: str,
    requested: Sequence[str] | None = None,
    excluded: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Return global capability-backed side cards independent of source type."""

    available = list(SIDE_SCENE_POOL)
    excluded_ids = {str(item).strip() for item in excluded or [] if str(item).strip()}
    available = [item for item in available if item not in excluded_ids]
    requested_ids = list(
        dict.fromkeys(str(item).strip() for item in requested or [] if str(item).strip())
    )
    invalid = [item for item in requested_ids if item not in available]
    if invalid:
        raise ValueError(f"支线场景不适用于来源 {source_type}：{invalid}")
    selected = requested_ids or available
    return [
        {**_plan_card(scene_id, role="side"), "return_to_main": True}
        for scene_id in selected
    ]


def initial_message_for_plan(
    source: Mapping[str, Any], plan: Sequence[Mapping[str, Any]]
) -> str:
    """Build the deterministic fallback; never execute a historical utterance."""

    if not plan:
        raise ValueError("场景计划不能为空")
    scene_id = str(plan[0].get("id") or "")
    return _synthetic_initial_message(source, scene_id)


def evaluation_task(plan: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "primary_goal": "；".join(str(item.get("objective") or "") for item in plan),
        "key_deliverables": [
            deliverable
            for item in plan
            for deliverable in item.get("deliverables") or []
        ],
        "acceptable_completion_paths": {
            str(item.get("id") or ""): list(item.get("acceptable_completion_paths") or [])
            for item in plan
        },
    }


__all__ = [
    "DEFAULT_SCENE_PLANS",
    "MAIN_SCENE_CANDIDATES",
    "MAIN_SCENE_COMBINATIONS",
    "SCENARIO_CARDS",
    "SCENE_PENDING_BLOCKERS",
    "SCENE_HANDOFF_TOPICS",
    "SIDE_SCENE_CANDIDATES",
    "SIDE_SCENE_POOL",
    "build_side_scene_candidates",
    "build_scene_plan",
    "evaluation_task",
    "followup_scene_intents",
    "historical_customer_fact_evidence",
    "initial_generation_context",
    "initial_message_for_plan",
    "scene_ids",
    "select_main_scene_ids",
    "validate_followup_scene_message",
    "validate_initial_customer_message",
]
