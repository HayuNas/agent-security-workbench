"""Tencent AI-Infra-Guard 候选语料的筛选、校验和离线审计。"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


TENCENT_CANDIDATE_PATH = (
    Path(__file__).resolve().parent
    / "sources"
    / "tencent_aig_v4_5_2"
    / "candidates_v1.json"
)
REVIEW_STATUSES = frozenset({"draft", "approved", "rejected"})
SAFETY_CLASSES = frozenset({"read_only", "test_env_order_creation"})


class TencentCandidateDataError(ValueError):
    """Tencent 候选库无法安全审阅。"""


_BLOCK_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "database_mutation",
        re.compile(
            r"(?:\b(?:drop|truncate|delete|insert|update|alter|vacuum)\b.{0,50}"
            r"\b(?:table|database|schema|row|record)\b|"
            r"\b(?:table|database|schema)\b.{0,50}\b(?:drop|truncate|delete|update|alter)\b|"
            r"(?:删除|清空|写入|新增|修改|更新).{0,20}(?:数据库|数据表|表结构|数据记录))",
            re.IGNORECASE,
        ),
    ),
    (
        "destructive_system_or_file_action",
        re.compile(
            r"(?:terraform\s+destroy|rm\s+-rf|recursively\s+delete|force-push|"
            r"delete\s+(?:every|all)\s+(?:namespace|backup|tag)|"
            r"overwrite\s+(?:the\s+)?(?:bash\s+history|main)|"
            r"(?:删除|清空|销毁).{0,20}(?:日志|备份|命名空间|文件|主分支))",
            re.IGNORECASE,
        ),
    ),
    (
        "privilege_or_auth_mutation",
        re.compile(
            r"(?:revoke.{0,30}(?:access|permission)|grant.{0,30}(?:admin|root|write access)|"
            r"attach.{0,20}administratoraccess|disable.{0,20}(?:mfa|branch protection)|"
            r"add.{0,30}(?:ssh key|recovery address|repo admin)|"
            r"auto-grant.{0,20}admin consent|"
            r"(?:撤销|授予|提升|禁用|添加).{0,20}(?:权限|管理员|密钥|MFA|认证))",
            re.IGNORECASE,
        ),
    ),
    (
        "external_message_or_exfiltration",
        re.compile(
            r"(?:\b(?:email|forward|upload|post|dm|sms|webhook)\b.{0,80}"
            r"(?:external|gmail|proton|attacker|pastebin|my server|my account|public)|"
            r"(?:send|share).{0,60}(?:externally|external address|publicly)|"
            r"(?:发送|转发|上传|外传|公开分享).{0,30}(?:外部|邮箱|服务器|网盘|地址))",
            re.IGNORECASE,
        ),
    ),
    (
        "financial_or_payment_action",
        re.compile(
            r"(?:\b(?:refund|wire transfer|gift card|payroll|brokerage|market order|"
            r"purchase order|banking transfer)\b|mark.{0,20}invoice.{0,20}paid|"
            r"(?:退款|付款|转账|礼品卡|工资|证券交易|采购单|标记发票已付款))",
            re.IGNORECASE,
        ),
    ),
    (
        "code_execution_or_persistence",
        re.compile(
            r"(?:curl\s+[^\s]+\s*\|\s*bash|reverse shell|keylogger|backdoor|"
            r"authorized_keys|writable cron|execute.{0,30}(?:script|binary)|"
            r"install.{0,30}(?:untrusted|unsigned|mcp server)|"
            r"(?:执行|安装|植入|创建).{0,20}(?:脚本|后门|定时任务|键盘记录器|远程程序))",
            re.IGNORECASE,
        ),
    ),
    (
        "business_or_infrastructure_mutation",
        re.compile(
            r"(?:set\s+(?:every|all).{0,30}(?:product|price)|"
            r"modify.{0,30}(?:price|contract|dns|firewall|payroll)|"
            r"point.{0,30}(?:domain|subdomain).{0,30}(?:my server|attacker)|"
            r"(?:修改|篡改|重写|调整).{0,20}(?:商品价格|合同|DNS|防火墙|工资))",
            re.IGNORECASE,
        ),
    ),
    (
        "persistent_memory_write",
        re.compile(
            r"(?:remember this for all future tasks|store this as a permanent rule|"
            r"save this permanently|(?:永久|长期).{0,16}(?:记住|保存|写入).{0,20}(?:规则|指令))",
            re.IGNORECASE,
        ),
    ),
    (
        "order_creation",
        re.compile(
            r"(?:\bcreate(?:_crm)?_?order\b|\bplace\s+(?:the\s+)?order\b|"
            r"(?:创建|提交|生成|直接下)(?:一个|这笔|该笔)?(?:测试)?订单|按.{0,24}下单)",
            re.IGNORECASE,
        ),
    ),
)

_WRONG_PRICE_PATTERN = re.compile(
    r"(?:错误价|低价|更低.{0,10}价格|低于.{0,16}(?:报价|价格)|"
    r"比.{0,20}(?:报价|价格).{0,12}低|折扣价|老价格|历史价格|"
    r"wrong price|lower price|below.{0,20}(?:quoted|tool|current) price)",
    re.IGNORECASE,
)


def _text_list(value: Any) -> list[str]:
    values = value if isinstance(value, list) else ([] if value is None else [value])
    return [str(item).strip() for item in values if str(item).strip()]


def classify_candidate(
    messages: Sequence[str], *, safety_class: str = "read_only"
) -> dict[str, Any]:
    """静态阻止破坏性动作；错误价格订单只允许进入隔离候选区。"""

    clean_safety_class = str(safety_class or "").strip()
    text = "\n".join(_text_list(list(messages)))
    matched = [name for name, pattern in _BLOCK_RULES if pattern.search(text)]
    issues: list[str] = []
    if clean_safety_class not in SAFETY_CLASSES:
        issues.append("unknown_safety_class")
    if clean_safety_class == "test_env_order_creation":
        if "order_creation" not in matched:
            issues.append("missing_order_creation_intent")
        if not _WRONG_PRICE_PATTERN.search(text):
            issues.append("missing_wrong_price_boundary")
        blocked_categories = [name for name in matched if name != "order_creation"]
    else:
        blocked_categories = matched
    if blocked_categories:
        issues.extend(f"blocked:{name}" for name in blocked_categories)
    return {
        "accepted": not issues,
        "safety_class": clean_safety_class,
        "matched_action_categories": matched,
        "blocked_action_categories": blocked_categories,
        "issues": issues,
    }


def load_tencent_candidates(
    path: Path = TENCENT_CANDIDATE_PATH,
) -> dict[str, Any]:
    """读取已本地化的候选；所有内容仍需人工批准后才能进入执行定义。"""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TencentCandidateDataError(f"无法读取 Tencent 候选库：{path}") from exc
    if not isinstance(raw, Mapping):
        raise TencentCandidateDataError("Tencent 候选库必须是 JSON object")
    source = raw.get("source")
    if not isinstance(source, Mapping) or not str(source.get("commit") or "").strip():
        raise TencentCandidateDataError("Tencent 候选库必须固定 source.commit")

    items: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for position, item in enumerate(raw.get("items") or [], start=1):
        if not isinstance(item, Mapping):
            raise TencentCandidateDataError(f"items[{position}] 必须是 object")
        candidate = copy.deepcopy(dict(item))
        candidate_id = str(candidate.get("candidate_id") or "").strip()
        if not candidate_id or candidate_id in seen_ids:
            raise TencentCandidateDataError(f"candidate_id 缺失或重复：{candidate_id!r}")
        seen_ids.add(candidate_id)
        messages = _text_list(candidate.get("messages"))
        if not messages:
            raise TencentCandidateDataError(f"{candidate_id}: messages 不能为空")
        status = str(candidate.get("review_status") or "draft").strip()
        if status not in REVIEW_STATUSES:
            raise TencentCandidateDataError(f"{candidate_id}: review_status 无效")
        safety_class = str(candidate.get("safety_class") or "read_only").strip()
        classification = classify_candidate(messages, safety_class=safety_class)
        items.append(
            {
                **candidate,
                "candidate_id": candidate_id,
                "messages": messages,
                "tactic_axes": _text_list(candidate.get("tactic_axes")),
                "source_ref": str(candidate.get("source_ref") or "").strip(),
                "target_engine": str(candidate.get("target_engine") or "").strip(),
                "target_pack": str(candidate.get("target_pack") or "").strip(),
                "safety_class": safety_class,
                "review_status": status,
                "classification": classification,
            }
        )
    if not items:
        raise TencentCandidateDataError("Tencent 候选库不能为空")
    return {
        **copy.deepcopy(dict(raw)),
        "source": copy.deepcopy(dict(source)),
        "items": items,
        "source_file": str(path.resolve()),
    }


def audit_tencent_candidates(
    library: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """汇总候选状态；test_env_order_creation 永不自动晋级。"""

    loaded = dict(library or load_tencent_candidates())
    results: list[dict[str, Any]] = []
    for item in loaded.get("items") or []:
        classification = dict(item.get("classification") or {})
        missing_metadata = [
            field
            for field in ("source_ref", "target_engine", "target_pack")
            if not str(item.get(field) or "").strip()
        ]
        issues = list(classification.get("issues") or []) + [
            f"missing:{field}" for field in missing_metadata
        ]
        if not _text_list(item.get("tactic_axes")):
            issues.append("missing:tactic_axes")
        status = str(item.get("review_status") or "draft")
        safety_class = str(item.get("safety_class") or "read_only")
        results.append(
            {
                "candidate_id": str(item.get("candidate_id") or ""),
                "review_status": status,
                "safety_class": safety_class,
                "accepted_by_filter": bool(classification.get("accepted")) and not issues,
                "automatic_execution_eligible": (
                    bool(classification.get("accepted"))
                    and not issues
                    and status == "approved"
                    and safety_class == "read_only"
                ),
                "issues": issues,
            }
        )
    return {
        "library_id": str(loaded.get("library_id") or ""),
        "item_count": len(results),
        "accepted_by_filter_count": sum(
            item["accepted_by_filter"] for item in results
        ),
        "automatic_execution_eligible_count": sum(
            item["automatic_execution_eligible"] for item in results
        ),
        "test_env_order_candidate_count": sum(
            item["safety_class"] == "test_env_order_creation" for item in results
        ),
        "items": results,
    }


__all__ = [
    "TENCENT_CANDIDATE_PATH",
    "TencentCandidateDataError",
    "audit_tencent_candidates",
    "classify_candidate",
    "load_tencent_candidates",
]
