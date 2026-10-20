"""Attack Pack 到确定性 Oracle 的分派层。"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .discount import score_discount_boundary
from .commercial_commitment import score_commercial_commitment_boundary
from .pricing_context import score_pricing_context_disclosure
from .protected_assets import (
    DEFAULT_ASSET_PATH,
    load_protected_assets,
    score_protected_asset_turns,
)
from .tool_provenance import score_tool_provenance_boundary
from .user_context import score_user_context_boundary


def prepare_pack_oracle(
    pack: Mapping[str, Any],
    *,
    asset_registry: Path | None = None,
    selected_asset_ids: Iterable[str] | None = None,
    selected_marker_group_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    oracle = copy.deepcopy(dict(pack.get("oracle") or {}))
    oracle_type = str(oracle.get("type") or "")
    runtime: dict[str, Any] = {"type": oracle_type, "config": oracle}
    if oracle_type == "protected_asset_match":
        registry = load_protected_assets(asset_registry or DEFAULT_ASSET_PATH)
        configured = [
            str(item).strip()
            for item in oracle.get("protected_asset_ids") or []
            if str(item).strip()
        ]
        asset_source = (
            selected_asset_ids if selected_asset_ids is not None else configured
        )
        selected = list(
            dict.fromkeys(
                str(item).strip() for item in asset_source if str(item).strip()
            )
        )
        known = {
            str(item.get("asset_id") or "")
            for item in registry.get("assets") or []
            if isinstance(item, Mapping)
        }
        unknown = sorted(set(selected) - known)
        if unknown:
            raise ValueError(f"未知 asset-id：{unknown}")
        configured_marker_groups = [
            str(item).strip()
            for item in oracle.get("protected_marker_group_ids") or []
            if str(item).strip()
        ]
        marker_source = (
            selected_marker_group_ids
            if selected_marker_group_ids is not None
            else configured_marker_groups
        )
        selected_marker_groups = list(
            dict.fromkeys(
                str(item).strip()
                for item in marker_source
                if str(item).strip()
            )
        )
        known_marker_groups = {
            str(item.get("group_id") or "")
            for item in registry.get("marker_groups") or []
            if isinstance(item, Mapping)
        }
        unknown_marker_groups = sorted(
            set(selected_marker_groups) - known_marker_groups
        )
        if unknown_marker_groups:
            raise ValueError(
                f"未知 protected marker group-id：{unknown_marker_groups}"
            )
        runtime.update(
            {
                "registry": registry,
                "selected_asset_ids": selected,
                "selected_marker_group_ids": selected_marker_groups,
                "asset_snapshot_id": registry.get("snapshot_id"),
                "effective_asset_ids": selected or sorted(known),
                "effective_marker_group_ids": selected_marker_groups
                or sorted(known_marker_groups),
            }
        )
    elif oracle_type == "pricing_context_disclosure":
        registry = load_protected_assets(asset_registry or DEFAULT_ASSET_PATH)
        configured = [
            str(item).strip()
            for item in oracle.get("protected_asset_ids") or []
            if str(item).strip()
        ]
        selected = list(
            dict.fromkeys(str(item) for item in selected_asset_ids or configured if str(item))
        )
        known = {
            str(item.get("asset_id") or "")
            for item in registry.get("assets") or []
            if isinstance(item, Mapping)
        }
        unknown = sorted(set(selected) - known)
        if unknown:
            raise ValueError(f"未知 asset-id：{unknown}")
        runtime.update(
            {
                "registry": registry,
                "selected_asset_ids": selected,
                "asset_snapshot_id": registry.get("snapshot_id"),
                "effective_asset_ids": selected or sorted(known),
            }
        )
    elif oracle_type in {
        "discount_boundary",
        "commercial_commitment_boundary",
        "tool_provenance_boundary",
    }:
        runtime.update(
            {
                "asset_snapshot_id": None,
                "effective_asset_ids": [],
            }
        )
    elif oracle_type == "user_context_boundary":
        oracle.pop("victim_canaries", None)
        runtime.update(
            {
                "asset_snapshot_id": None,
                "effective_asset_ids": [],
            }
        )
    else:
        raise ValueError(f"不支持的 Attack Pack Oracle：{oracle_type!r}")
    return runtime


def bind_user_context_canary(
    runtime: Mapping[str, Any], canary: str
) -> dict[str, Any]:
    """给一次配对 iteration 的 Oracle Runtime 绑定唯一受害用户 Canary。"""

    if str(runtime.get("type") or "") != "user_context_boundary":
        raise ValueError("只有 user_context_boundary Runtime 可以绑定用户 Canary")
    clean_canary = str(canary or "").strip()
    if not clean_canary:
        raise ValueError("用户上下文 Canary 不能为空")
    bound = copy.deepcopy(dict(runtime))
    config = copy.deepcopy(dict(bound.get("config") or {}))
    config["victim_canaries"] = [clean_canary]
    bound["config"] = config
    return bound


def score_pack_turns(
    pack: Mapping[str, Any],
    turns: Sequence[Mapping[str, Any]],
    runtime: Mapping[str, Any],
) -> dict[str, Any]:
    _assert_single_scoring_branch(turns)
    oracle_type = str(runtime.get("type") or "")
    expected_type = str((pack.get("oracle") or {}).get("type") or "")
    if oracle_type != expected_type:
        raise ValueError(
            f"Attack Pack {pack.get('pack_id')!r} 要求 Oracle {expected_type!r}，"
            f"但收到 {oracle_type!r}"
        )
    if oracle_type == "protected_asset_match":
        result = score_protected_asset_turns(
            runtime.get("registry") or {},
            turns=turns,
            selected_asset_ids=runtime.get("selected_asset_ids") or [],
            selected_marker_group_ids=(
                runtime.get("selected_marker_group_ids") or []
            ),
        )
        return {"oracle_type": oracle_type, **result}
    if oracle_type == "discount_boundary":
        return score_discount_boundary(turns, runtime.get("config") or {})
    if oracle_type == "commercial_commitment_boundary":
        return score_commercial_commitment_boundary(
            turns, runtime.get("config") or {}
        )
    if oracle_type == "pricing_context_disclosure":
        return score_pricing_context_disclosure(
            turns,
            runtime.get("config") or {},
            registry=runtime.get("registry") or {},
            selected_asset_ids=runtime.get("selected_asset_ids") or [],
        )
    if oracle_type == "tool_provenance_boundary":
        return score_tool_provenance_boundary(
            turns, runtime.get("config") or {}
        )
    if oracle_type == "user_context_boundary":
        return score_user_context_boundary(turns, runtime.get("config") or {})
    raise ValueError(f"不支持的 Attack Pack Oracle：{oracle_type!r}")


def score_attack_turns(pack, turns, runtime):
    """生产执行使用双重判定；score_pack_turns 保留为可独立测试的硬规则层。"""
    registry = runtime.get('registry') or {}
    if str((registry.get('target') or {}).get('target_key') or '').startswith('ai-web:'):
        _assert_single_scoring_branch(turns)
        from ..judges.internal_agent import attack_result
        return attack_result(registry, turns)
    from ..judges.attack_consensus import adjudicate
    hard = score_pack_turns(pack, turns, runtime)
    return adjudicate(pack, turns, runtime, hard)


def _assert_single_scoring_branch(turns: Sequence[Mapping[str, Any]]) -> None:
    """Reject accidental Oracle input spanning restarts or target sessions."""

    branch_keys = {
        (
            str(turn.get("session_restart_index") or "0"),
            str(turn.get("session_id") or ""),
        )
        for turn in turns
        if "session_restart_index" in turn or "session_id" in turn
    }
    if len(branch_keys) > 1:
        raise ValueError("Oracle 只能评分同一 Session、同一有效分支的 turns")


def oracle_success(pack: Mapping[str, Any], result: Mapping[str, Any]) -> bool:
    outcomes = {
        str(item)
        for item in ((pack.get("oracle") or {}).get("success_outcomes") or [])
    }
    return str(result.get("outcome") or "") in outcomes


__all__ = [
    "bind_user_context_canary",
    "oracle_success",
    "prepare_pack_oracle",
    "score_pack_turns",
]
