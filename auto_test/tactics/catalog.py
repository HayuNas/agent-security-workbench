"""Strategy registry; the source snapshot ships only a synthetic example."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


TACTIC_DATA_DIR = Path(__file__).resolve().parent / "data"
TENCENT_STRATEGY_MAP_PATH = TACTIC_DATA_DIR / "strategies.example.json"
TENCENT_ADAPTERS_PATH = TACTIC_DATA_DIR / "generation_adapters.example.json"
SUPPORTED_ENGINES = frozenset({"cr", "epe"})


class TacticDataError(ValueError):
    """The checked-in tactic registry or adapter is missing or invalid."""


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TacticDataError(f"无法读取策略文件：{path}") from exc
    if not isinstance(value, Mapping):
        raise TacticDataError(f"策略文件必须是 JSON object：{path}")
    return dict(value)


def _text_list(value: Any) -> list[str]:
    values = value if isinstance(value, list) else ([] if value is None else [value])
    return [str(item).strip() for item in values if str(item).strip()]


def load_tactic_catalog(
    *,
    registry_path: Path = TENCENT_STRATEGY_MAP_PATH,
    adapters_path: Path = TENCENT_ADAPTERS_PATH,
) -> dict[str, Any]:
    """Load the exact upstream method registry plus locally constrained adapters."""

    registry = _read_object(registry_path)
    adapters = _read_object(adapters_path)
    source = adapters.get("source")
    if not isinstance(source, Mapping) or not str(source.get("commit") or "").strip():
        raise TacticDataError("策略适配缺少固定的 Tencent source commit")

    schema = registry.get("configSchema")
    groups = schema.get("strategies") if isinstance(schema, Mapping) else None
    if not isinstance(groups, list) or not groups:
        raise TacticDataError("Tencent strategy_map 缺少 configSchema.strategies")
    registry_by_id: dict[str, dict[str, str]] = {}
    categories: list[dict[str, Any]] = []
    for raw_group in groups:
        if not isinstance(raw_group, Mapping):
            raise TacticDataError("Tencent strategy group 必须是 object")
        category_id = str(raw_group.get("id") or "").strip()
        methods = raw_group.get("methods")
        if not category_id or not isinstance(methods, list):
            raise TacticDataError("Tencent strategy group 缺少 id/methods")
        method_ids: list[str] = []
        for raw_method in methods:
            if not isinstance(raw_method, Mapping):
                raise TacticDataError(f"{category_id}: method 必须是 object")
            tactic_id = str(raw_method.get("id") or "").strip()
            if not tactic_id or tactic_id in registry_by_id:
                raise TacticDataError(f"Tencent tactic ID 缺失或重复：{tactic_id!r}")
            registry_by_id[tactic_id] = {
                "tactic_id": tactic_id,
                "name": str(raw_method.get("type") or tactic_id).strip(),
                "name_cn": str(raw_method.get("typeCn") or tactic_id).strip(),
                "category_id": category_id,
                "category": str(raw_group.get("type") or category_id).strip(),
                "category_cn": str(raw_group.get("typeCn") or category_id).strip(),
            }
            method_ids.append(tactic_id)
        categories.append(
            {
                "category_id": category_id,
                "name": str(raw_group.get("type") or category_id).strip(),
                "name_cn": str(raw_group.get("typeCn") or category_id).strip(),
                "description": str(raw_group.get("description") or "").strip(),
                "description_cn": str(raw_group.get("descriptionCn") or "").strip(),
                "method_ids": method_ids,
            }
        )

    tactics: list[dict[str, Any]] = []
    seen_adapters: set[str] = set()
    for position, raw_adapter in enumerate(adapters.get("tactics") or [], start=1):
        if not isinstance(raw_adapter, Mapping):
            raise TacticDataError(f"tactics[{position}] 必须是 object")
        tactic_id = str(raw_adapter.get("tactic_id") or "").strip()
        if tactic_id not in registry_by_id or tactic_id in seen_adapters:
            raise TacticDataError(f"策略适配未知或重复：{tactic_id!r}")
        seen_adapters.add(tactic_id)
        engines = _text_list(raw_adapter.get("engines"))
        default_for = _text_list(raw_adapter.get("default_for"))
        unknown_engines = sorted((set(engines) | set(default_for)) - SUPPORTED_ENGINES)
        if not engines or unknown_engines or not set(default_for).issubset(engines):
            raise TacticDataError(f"{tactic_id}: engines/default_for 无效")
        pack_ids = _text_list(raw_adapter.get("pack_ids"))
        guidance = str(raw_adapter.get("guidance") or "").strip()
        source_ref = str(raw_adapter.get("source_ref") or "").strip()
        if not pack_ids or not guidance or not source_ref:
            raise TacticDataError(f"{tactic_id}: 缺少 pack_ids/guidance/source_ref")
        tactics.append(
            {
                **registry_by_id[tactic_id],
                **copy.deepcopy(dict(raw_adapter)),
                "tactic_id": tactic_id,
                "engines": engines,
                "default_for": default_for,
                "pack_ids": pack_ids,
                "guidance": guidance,
                "source_ref": source_ref,
            }
        )
    if not tactics:
        raise TacticDataError("策略适配不能为空")
    return {
        "schema_version": str(adapters.get("schema_version") or ""),
        "registry_version": str((registry.get("metadata") or {}).get("version") or ""),
        "source": copy.deepcopy(dict(source)),
        "categories": categories,
        "registered_method_count": len(registry_by_id),
        "adapted_method_count": len(tactics),
        "tactics": tactics,
        "registry_file": str(registry_path.resolve()),
        "adapters_file": str(adapters_path.resolve()),
    }


def tactic_cards_for(
    *,
    engine: str,
    pack_id: str,
    tactic_ids: Sequence[str] | None = None,
) -> list[dict[str, str]]:
    """Select compatible cards; explicit IDs preserve caller order."""

    clean_engine = str(engine or "").strip()
    clean_pack = str(pack_id or "").strip()
    if clean_engine not in SUPPORTED_ENGINES:
        raise TacticDataError(f"不支持的生成引擎：{clean_engine!r}")
    available = {
        tactic["tactic_id"]: tactic
        for tactic in load_tactic_catalog()["tactics"]
        if clean_engine in tactic["engines"]
        and (clean_pack in tactic["pack_ids"] or "*" in tactic["pack_ids"])
    }
    selected_ids = list(dict.fromkeys(_text_list(tactic_ids)))
    if selected_ids:
        unknown = [item for item in selected_ids if item not in available]
        if unknown:
            raise TacticDataError(
                f"{clean_engine}/{clean_pack} 不支持策略：{unknown}; "
                f"可选：{sorted(available)}"
            )
    else:
        defaults = [
            tactic_id
            for tactic_id, tactic in available.items()
            if clean_engine in tactic["default_for"]
        ]
        selected_ids = defaults[:1]
    cards: list[dict[str, str]] = []
    for tactic_id in selected_ids:
        tactic = available[tactic_id]
        cards.append(
            {
                "tactic_id": tactic_id,
                "name": tactic["name"],
                "name_cn": tactic["name_cn"],
                "category": tactic["category"],
                "category_cn": tactic["category_cn"],
                "guidance": tactic["guidance"],
                "source_ref": tactic["source_ref"],
            }
        )
    if not cards:
        raise TacticDataError(
            f"{clean_engine}/{clean_pack} 没有默认策略；请显式传入 tactic_ids"
        )
    return cards


__all__ = [
    "TENCENT_ADAPTERS_PATH",
    "TENCENT_STRATEGY_MAP_PATH",
    "TacticDataError",
    "load_tactic_catalog",
    "tactic_cards_for",
]
