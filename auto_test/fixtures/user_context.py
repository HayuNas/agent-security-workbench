"""跨用户上下文隔离测试使用的双用户 Canary 夹具。"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping


PAIRED_USER_CONTEXT_FIXTURE = "paired_user_context_canary"


def is_paired_user_context_pack(pack: Mapping[str, Any]) -> bool:
    fixture = pack.get("fixture") or {}
    return (
        isinstance(fixture, Mapping)
        and str(fixture.get("type") or "") == PAIRED_USER_CONTEXT_FIXTURE
    )


def fixture_query_cost(pack: Mapping[str, Any]) -> int:
    """每次 iteration 在正式攻击前消耗的目标 Agent 调用数。"""

    return 1 if is_paired_user_context_pack(pack) else 0


def build_user_context_fixture(
    pack: Mapping[str, Any], *, run_id: str, scope_id: str
) -> dict[str, str]:
    """为一个受害用户会话生成唯一 Canary 和无业务副作用的预置消息。"""

    if not is_paired_user_context_pack(pack):
        raise ValueError(f"Pack {pack.get('pack_id')!r} 未声明双用户上下文夹具")
    fixture = dict(pack.get("fixture") or {})
    prefix = str(fixture.get("canary_prefix") or "KY_TEST_USER_CONTEXT").strip()
    template = str(fixture.get("victim_seed_message_template") or "")
    if template.count("{canary}") < 1:
        raise ValueError("victim_seed_message_template 必须至少包含一个 {canary}")
    digest = hashlib.sha256(
        f"{run_id}|{pack.get('pack_id')}|{scope_id}|victim".encode("utf-8")
    ).hexdigest()[:16].upper()
    canary = f"{prefix}_{digest}"
    return {
        "type": PAIRED_USER_CONTEXT_FIXTURE,
        "canary": canary,
        "victim_seed_message": template.replace("{canary}", canary),
    }


__all__ = [
    "PAIRED_USER_CONTEXT_FIXTURE",
    "build_user_context_fixture",
    "fixture_query_cost",
    "is_paired_user_context_pack",
]
