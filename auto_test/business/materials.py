"""Historical product hints, not a catalogue of current prices or stock."""
from __future__ import annotations

import hashlib
import re
import sqlite3
from pathlib import Path
from typing import Any, Mapping, Sequence


SCENES = {"inquiry", "stock_delivery"}


def _connection(history_path):
    from ..core.paths import BUSINESS_SCENARIO_SOURCES_PATH
    from ..records import resources
    if resources.enabled() and history_path.parent.resolve() == BUSINESS_SCENARIO_SOURCES_PATH.parent.resolve():
        from risk_guard.config_storage import connect
        return connect(history_path, "material_usage", backend="mysql")
    history_path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(history_path, timeout=5)


def extract_materials(source: Mapping[str, Any], turns: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    # Reuse the customer-owned anchor; never promote an Agent recommendation
    # from a later turn into a fact the customer knew at the beginning.
    from .scenario_cards import _source_seed_facts

    name = _source_seed_facts(source)["product"].strip()
    if not name or len(name) > 80 or re.search(r"https?://|@|\*{3}|[\r\n]", name):
        return []
    evidence = []
    tags = set()
    for turn in turns:
        reply = str(turn.get("reference_reply") or "")
        for sentence in re.split(r"[。！？\n;；]", reply):
            # Require the product in the same clause. Ambiguous replies remain
            # unknown; absence of evidence is not proof of unavailability.
            if name not in sentence or re.search(r"未查|没查|无法|不能|待确认|待核实|稍后|可能|预计|例如|假设|不确定", sentence):
                continue
            price = bool(re.search(r"\d[\d,.]*\s*元\s*[/／每]\s*(?:吨|公斤|千克|kg|KG)", sentence))
            stock = bool(re.search(r"(?:库存|现货)\s*(?:为|有|[:：])?\s*\d+(?:\.\d+)?\s*(?:吨|公斤|千克|kg|KG)|有现货|暂无库存|无现货", sentence))
            if price or stock:
                tags.update((["inquiry"] if price else []) + (["stock_delivery"] if stock else []))
                evidence.append({"round": turn.get("round"), "price_mentioned": price, "stock_mentioned": stock})
    return [{
        "material_id": "MAT-" + hashlib.sha256(name.casefold().encode()).hexdigest()[:16],
        "product_name": name,
        "source_id": source.get("source_id"),
        "scene_tags": sorted(tags or SCENES),
        "historical_status": "reply_mentioned" if evidence else "unknown",
        "tool_verified": False,
        "current_availability": "unknown",
        "evidence": evidence,
    }]


def prioritize_material_sources(sources: list[dict[str, Any]], *, scenes: set[str], limit: int, history_path: Path, preserve_families: bool = False) -> list[dict[str, Any]]:
    """Reserve least-recently sampled products; keep each source intact.

    Only explicit small-pilot scenes participate. SQLite serializes concurrent
    tasks. Old libraries and unavailable history storage keep the old order.
    """
    target_scenes = scenes & SCENES
    if not target_scenes or limit < 1:
        return sources
    if preserve_families:
        return _rotate_source_families(sources, limit=limit, history_path=history_path)
    def material(source):
        return next((item for item in source.get("product_materials", [])
                     if isinstance(item, Mapping) and item.get("material_id")
                     and target_scenes <= set(item.get("scene_tags", []))), None)
    eligible = [(source, material(source)) for source in sources]
    eligible = [(source, item) for source, item in eligible if item]
    if not eligible:
        return sources
    connection = None
    try:
        connection = _connection(history_path)
        connection.execute("CREATE TABLE IF NOT EXISTS material_usage (id TEXT PRIMARY KEY, sequence INTEGER NOT NULL)")
        connection.commit()
        connection.execute("BEGIN IMMEDIATE")
        usage = dict(connection.execute("SELECT id, sequence FROM material_usage"))
        sequence = max(usage.values(), default=0)
        ordered = []
        while eligible:
            index = min(range(len(eligible)), key=lambda i: usage.get(eligible[i][1]["material_id"], 0))
            source, item = eligible.pop(index)
            ordered.append(source)
            sequence += 1
            usage[item["material_id"]] = sequence
            if len(ordered) <= limit:
                connection.execute("INSERT OR REPLACE INTO material_usage VALUES (?, ?)", (item["material_id"], sequence))
        connection.commit()
        selected = {str(source.get("source_id")) for source in ordered}
        return ordered + [source for source in sources if str(source.get("source_id")) not in selected]
    except (OSError, sqlite3.Error):
        return sources
    finally:
        if connection is not None:
            connection.close()


def _rotate_source_families(sources, *, limit, history_path):
    """Preserve upstream family slots; least-recently reserve sources per family."""
    connection = None
    try:
        connection = _connection(history_path)
        connection.execute("CREATE TABLE IF NOT EXISTS source_usage (id TEXT PRIMARY KEY, sequence INTEGER NOT NULL)")
        connection.commit()
        connection.execute("BEGIN IMMEDIATE")
        usage = dict(connection.execute("SELECT id, sequence FROM source_usage"))
        sequence = max(usage.values(), default=0)
        buckets = {}
        for source in sources:
            buckets.setdefault(source.get("scenario_type", "unknown"), []).append(source)
        for values in buckets.values():
            values.sort(key=lambda s: usage.get(s["source_id"], 0))
        indexes = dict.fromkeys(buckets, 0)
        ordered = []
        for slot in sources:
            family = slot.get("scenario_type", "unknown")
            item = buckets[family][indexes[family]]
            indexes[family] += 1
            ordered.append(item)
            if len(ordered) <= limit:
                sequence += 1
                connection.execute("INSERT OR REPLACE INTO source_usage VALUES (?, ?)", (item["source_id"], sequence))
        connection.commit()
        return ordered
    except (OSError, sqlite3.Error):
        return sources
    finally:
        if connection is not None:
            connection.close()
