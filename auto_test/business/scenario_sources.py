"""Build a balanced, multi-scenario source library for dynamic business tests."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from ..core.paths import BUSINESS_SCENARIO_SOURCES_PATH
from ..core.redaction import redact_value
from .cases import _json_object, _reference_turns, _utf8


SOURCE_TABLE = "t_a_i_adversarial_json_parsing"
SOURCE_FILTER = "status = 2"
SCHEMA_VERSION = "1.0-business-scenario-source-library"

SCENARIO_TYPES: dict[int, dict[str, Any]] = {
    1: {
        "id": "sales_order",
        "name": "销售询价、议价与下单",
        "capabilities": ["询价", "议价", "库存与交期确认", "下单信息确认"],
    },
    2: {
        "id": "product_recommendation",
        "name": "产品推荐",
        "capabilities": ["需求澄清", "选型推荐", "适用性说明", "商务收尾"],
    },
    3: {
        "id": "market_qa",
        "name": "行情问答",
        "capabilities": ["行情概述", "型号询价", "采购建议", "传闻核验"],
    },
    4: {
        "id": "formulation_optimization",
        "name": "配方优化",
        "capabilities": ["配方诊断", "相容性判断", "方案建议", "验证闭环"],
    },
    5: {
        "id": "technical_qa",
        "name": "技术问答",
        "capabilities": ["技术澄清", "材料选型", "故障诊断", "技术与商务边界"],
    },
}

_SOURCE_COLUMNS = (
    "id,type,business_scenario_summary,scoring_total_score,bad_case_count,"
    "json_content,current_training_round,current_training_version,create_time,"
    "adversarial_agent_name,a_i_apps_id,a_i_apps_name"
).split(",")

_TAX_ID_RE = re.compile(r"(?i)(税号\s*[:：]?\s*)[0-9A-Z]{15,20}")
_ID_CARD_RE = re.compile(r"(身份证(?:号)?\s*[:：]?\s*)\d{17}[0-9Xx]")


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _source_id(record_id: Any, scenario_type: str) -> str:
    value = f"{record_id}:{scenario_type}".encode("utf-8")
    return "BIZSRC-" + hashlib.sha256(value).hexdigest()[:12].upper()


def _redact_business_value(value: Any) -> Any:
    """Redact contact and identity data while preserving business numbers."""

    safe = redact_value(value)
    if isinstance(safe, Mapping):
        return {str(key): _redact_business_value(item) for key, item in safe.items()}
    if isinstance(safe, list):
        return [_redact_business_value(item) for item in safe]
    if isinstance(safe, str):
        safe = _TAX_ID_RE.sub(r"\1<税号已脱敏>", safe)
        return _ID_CARD_RE.sub(r"\1<身份证已脱敏>", safe)
    return safe


def _scenario_type(type_id: int) -> dict[str, Any]:
    if type_id not in SCENARIO_TYPES:
        raise ValueError(f"未登记的业务场景 type：{type_id}")
    return SCENARIO_TYPES[type_id]


def _normalized_scenario(
    row: Mapping[str, Any], report: Mapping[str, Any], type_config: Mapping[str, Any]
) -> dict[str, Any]:
    raw = report.get("business_scenario")
    scenario = dict(raw) if isinstance(raw, Mapping) else {}
    design = report.get("test_design")
    design = dict(design) if isinstance(design, Mapping) else {}
    summary = str(
        scenario.get("summary")
        or design.get("project_context")
        or _utf8(row.get("business_scenario_summary"))
        or type_config["name"]
    ).strip()
    return {
        **scenario,
        "summary": summary,
        "scenario_type": type_config["id"],
        "scenario_name": type_config["name"],
        "industry": str(scenario.get("industry") or design.get("industry") or "").strip(),
        "capabilities": list(type_config["capabilities"]),
        "depth_level": str(design.get("depth_level") or "").strip(),
    }


def _normalized_profile(report: Mapping[str, Any]) -> dict[str, Any]:
    raw = report.get("customer_profile")
    if isinstance(raw, Mapping) and raw:
        return dict(raw)
    design = report.get("test_design")
    design = dict(design) if isinstance(design, Mapping) else {}
    return {
        "persona_id": str(design.get("persona_id") or "").strip(),
        "role": str(design.get("persona_name") or "正常业务客户").strip(),
        "industry": str(design.get("industry") or "").strip(),
        "project_context": str(design.get("project_context") or "").strip(),
        "expertise_level": str(design.get("depth_level") or "").strip(),
    }


def _normalized_style(report: Mapping[str, Any]) -> dict[str, Any]:
    raw = report.get("customer_speech_style")
    if isinstance(raw, Mapping) and raw:
        return dict(raw)
    design = report.get("test_design")
    design = dict(design) if isinstance(design, Mapping) else {}
    return {
        "source": "historical_test_design",
        "techniques": list(design.get("techniques_used") or []),
        "question_types": list(design.get("question_types_covered") or []),
        "archetypes": list(design.get("archetypes_covered") or []),
    }


def _normalized_task(
    report: Mapping[str, Any], scenario: Mapping[str, Any], type_config: Mapping[str, Any]
) -> dict[str, Any]:
    raw = report.get("core_task")
    if isinstance(raw, Mapping) and raw:
        return dict(raw)
    design = report.get("test_design")
    design = dict(design) if isinstance(design, Mapping) else {}
    requirements = list(design.get("question_types_covered") or [])
    return {
        "primary_goal": str(scenario.get("summary") or type_config["name"]),
        "key_deliverables": requirements or list(type_config["capabilities"]),
        "project_context": str(design.get("project_context") or "").strip(),
    }


def build_scenario_source(row: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize one historical report without treating its replies as ground truth."""

    type_id = int(row.get("type") or 0)
    type_config = _scenario_type(type_id)
    report = _json_object(row["json_content"])
    turns = _reference_turns(
        report.get("conversation_log"), customer_roles=("customer", "prober")
    )
    scenario = _normalized_scenario(row, report, type_config)
    source_id = _source_id(row.get("id"), str(type_config["id"]))
    design = report.get("test_design")
    design = dict(design) if isinstance(design, Mapping) else {}
    scoring = report.get("scoring")
    scoring = dict(scoring) if isinstance(scoring, Mapping) else {}
    customer_turns = [
        {
            "round": turn.get("round"),
            "customer_message": turn.get("customer_message"),
        }
        for turn in turns
    ]
    source = {
        "source_id": source_id,
        "source_type": type_id,
        "scenario_type": type_config["id"],
        "status": "active",
        "source": {
            "table": SOURCE_TABLE,
            "record_id": str(row.get("id") or ""),
            "created_at": str(row.get("create_time") or ""),
            "training_round": int(row.get("current_training_round") or 0),
            "training_version": _utf8(row.get("current_training_version")),
            "app_id": str(row.get("a_i_apps_id") or ""),
            "app_name": _utf8(row.get("a_i_apps_name")),
            "agent_name": _utf8(row.get("adversarial_agent_name")),
        },
        "scenario": scenario,
        "customer_profile": _normalized_profile(report),
        "customer_speech_style": _normalized_style(report),
        "core_task": _normalized_task(report, scenario, type_config),
        "dynamic_seed": {
            "initial_message": turns[0]["customer_message"],
            "suggested_max_turns": max(2, min(10, len(turns))),
        },
        # Dynamic CR learns the customer's progression and wording only. Historical
        # Agent replies are intentionally excluded so they cannot become current facts.
        "reference_customer_turns": customer_turns,
        "baseline": {
            "score": float(row.get("scoring_total_score") or 0),
            "grade": str(scoring.get("grade") or "").strip(),
            "bad_case_count": int(row.get("bad_case_count") or 0),
        },
    }
    from .materials import extract_materials

    source = _redact_business_value(source)
    source["product_materials"] = extract_materials(source, turns)
    return source


def load_scenario_sources(
    path: Path = BUSINESS_SCENARIO_SOURCES_PATH,
) -> dict[str, Any]:
    from ..records import resources
    if resources.enabled() and Path(path).resolve() == BUSINESS_SCENARIO_SOURCES_PATH.resolve():
        record = resources.get("business_sources", "default")
        if not record:
            raise ValueError("正向业务场景素材尚未迁移到数据库")
        value = {**record["value"], "_resourceRevision": record["revision"]}
    else:
        if not path.is_file():
            return {"schema_version": SCHEMA_VERSION, "sources": []}
        value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping) or not isinstance(value.get("sources"), list):
        raise ValueError(f"业务场景来源库结构无效：{path}")
    source_ids = [str(item.get("source_id") or "") for item in value["sources"]]
    if not all(source_ids) or len(source_ids) != len(set(source_ids)):
        raise ValueError("业务场景来源 ID 为空或重复")
    return dict(value)


def save_scenario_sources(library, path=BUSINESS_SCENARIO_SOURCES_PATH):
    from ..records import resources
    if resources.enabled() and Path(path).resolve() == BUSINESS_SCENARIO_SOURCES_PATH.resolve():
        value = {key: item for key, item in library.items() if key != "_resourceRevision"}
        with resources.transaction() as cur:
            resources._lock(cur, "business_sources", "default")
            old = resources.get("business_sources", "default", cur=cur)
            expected = library.get("_resourceRevision", old["revision"] if old else 0)
            if old:
                import hashlib
                digest = hashlib.sha256(json.dumps(old["value"], sort_keys=True, ensure_ascii=False).encode()).hexdigest()
                resources.put("business_sources_history", digest, old["value"], cur=cur, only_if_missing=True)
            resources.put("business_sources", "default", value, expected=expected, cur=cur)
        return
    from ..records.library_lock import atomic_library_write
    atomic_library_write(path, json.dumps(library, ensure_ascii=False, indent=2))


def _select_columns() -> str:
    binary = {
        "business_scenario_summary",
        "json_content",
        "current_training_version",
        "adversarial_agent_name",
        "a_i_apps_name",
    }
    return ",".join(
        f"CAST({name} AS BINARY) AS {name}" if name in binary else name
        for name in _SOURCE_COLUMNS
    )


def refresh_product_materials(path: Path = BUSINESS_SCENARIO_SOURCES_PATH) -> dict[str, Any]:
    """Enrich existing source IDs without replacing the user's source library."""
    from ..records.mysql import _connect
    from .materials import extract_materials
    from ..records.library_lock import serialized_library_write

    @serialized_library_write
    def refresh():
        library = load_scenario_sources(path)
        sources = library["sources"]
        connection = _connect()
        updated = 0
        try:
            cursor = connection.cursor()
            try:
                for source in sources:
                    record_id = (source.get("source") or {}).get("record_id")
                    if not record_id:
                        continue
                    cursor.execute(f"SELECT CAST(json_content AS BINARY) FROM {SOURCE_TABLE} WHERE id = %s AND status = 2", (record_id,))
                    row = cursor.fetchone()
                    if not row:
                        continue
                    report = _json_object(row[0])
                    try:
                        turns = _reference_turns(report.get("conversation_log"), customer_roles=("customer", "prober"))
                    except ValueError:
                        continue
                    source["product_materials"] = extract_materials(source, turns)
                    updated += 1
            finally:
                cursor.close()
        finally:
            connection.close()
        library["product_material_pool"] = [item for source in sources for item in source.get("product_materials", [])]
        library["materials_updated_at"] = _now()
        from ..records import resources
        if resources.enabled() and Path(path).resolve() == BUSINESS_SCENARIO_SOURCES_PATH.resolve():
            save_scenario_sources(library, path)
            return {"updated_sources": updated, "material_count": len(library["product_material_pool"]),
                    "historical_reply_evidence_count": sum(item["historical_status"] == "reply_mentioned"
                                                           for item in library["product_material_pool"])}
        # Keep a recovery copy; atomic replacement prevents partial JSON reads.
        import shutil
        import tempfile
        import os
        shutil.copy2(path, path.with_suffix(".before-materials.json"))
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
                temporary = Path(handle.name)
                json.dump(library, handle, ensure_ascii=False, indent=2)
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return {"updated_sources": updated, "material_count": len(library["product_material_pool"]), "historical_reply_evidence_count": sum(item["historical_status"] == "reply_mentioned" for item in library["product_material_pool"])}

    return refresh()


def import_scenario_sources(
    *,
    limit: int = 100,
    scenario_types: Sequence[str] | None = None,
    output_path: Path = BUSINESS_SCENARIO_SOURCES_PATH,
    connection_factory: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Read a balanced latest sample for each selected scenario type."""

    if limit < 1 or limit > 1000:
        raise ValueError("limit 必须在 1 到 1000 之间")
    requested = [str(item).strip() for item in scenario_types or [] if str(item).strip()]
    by_name = {str(item["id"]): type_id for type_id, item in SCENARIO_TYPES.items()}
    unknown = sorted(set(requested) - set(by_name))
    if unknown:
        raise ValueError(f"未知业务场景类型：{unknown}")
    selected_type_ids = [by_name[item] for item in dict.fromkeys(requested)] if requested else list(SCENARIO_TYPES)
    if limit < len(selected_type_ids):
        raise ValueError("limit 不能小于所选场景类型数量")

    if connection_factory is None:
        from ..records.mysql import _connect

        connection_factory = _connect
    connection = connection_factory()
    base, remainder = divmod(limit, len(selected_type_ids))
    quotas = {
        type_id: base + (1 if index < remainder else 0)
        for index, type_id in enumerate(selected_type_ids)
    }
    sources: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []
    fetched_counts: dict[str, int] = {}
    try:
        cursor = connection.cursor()
        try:
            query = (
                f"SELECT {_select_columns()} FROM {SOURCE_TABLE} "
                f"WHERE {SOURCE_FILTER} AND type = %s ORDER BY id DESC LIMIT %s"
            )
            for type_id in selected_type_ids:
                quota = quotas[type_id]
                cursor.execute(query, (type_id, min(1000, quota + 20)))
                rows = cursor.fetchall()
                fetched_counts[str(type_id)] = len(rows)
                accepted = 0
                for values in rows:
                    row = dict(zip(_SOURCE_COLUMNS, values))
                    try:
                        source = build_scenario_source(row)
                    except Exception as exc:
                        issues.append(
                            {
                                "source_record_id": str(row.get("id") or ""),
                                "source_type": str(type_id),
                                "reason": f"{type(exc).__name__}: {exc}",
                            }
                        )
                        continue
                    sources.append(source)
                    accepted += 1
                    if accepted >= quota:
                        break
        finally:
            cursor.close()
    finally:
        connection.close()

    imported_at = _now()
    counts = {
        config["id"]: sum(source["source_type"] == type_id for source in sources)
        for type_id, config in SCENARIO_TYPES.items()
        if type_id in selected_type_ids
    }
    library = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": imported_at,
        "source_snapshot": {
            "database": "dm_data",
            "table": SOURCE_TABLE,
            "filter": SOURCE_FILTER,
            "sampling": "latest_balanced_by_type",
            "requested_limit": limit,
            "selected_type_ids": selected_type_ids,
            "requested_quotas": {str(key): value for key, value in quotas.items()},
            "fetched_counts": fetched_counts,
            "source_count": len(sources),
            "issue_count": len(issues),
            "issues": issues,
        },
        "scenario_types": {
            str(type_id): dict(config) for type_id, config in SCENARIO_TYPES.items()
        },
        "scenario_counts": counts,
        "sources": sources,
        "product_material_pool": [item for source in sources for item in source.get("product_materials", [])],
    }
    save_scenario_sources(library, output_path)
    return {
        "status": "IMPORTED" if sources else "NO_RUNNABLE_SOURCES",
        "source_count": len(sources),
        "material_count": sum(len(source.get("product_materials", [])) for source in sources),
        "scenario_counts": counts,
        "issue_count": len(issues),
        "issues": issues,
        "business_scenario_sources": str(output_path.resolve()),
        "updated_at": imported_at,
    }


__all__ = [
    "SCENARIO_TYPES",
    "SCHEMA_VERSION",
    "SOURCE_FILTER",
    "SOURCE_TABLE",
    "build_scenario_source",
    "import_scenario_sources",
    "load_scenario_sources",
]
