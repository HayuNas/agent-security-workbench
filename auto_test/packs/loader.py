"""读取并校验自包含 Attack Pack。"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..fixtures.tool_provenance import (
    TOOL_PROVENANCE_FIXTURE,
    load_tool_format_template,
)
from ..fixtures.user_context import PAIRED_USER_CONTEXT_FIXTURE


ATTACK_PACK_DIR = Path(__file__).resolve().parent / "cr"
PACK_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
SUPPORTED_ORACLES = frozenset(
    {
        "protected_asset_match",
        "discount_boundary",
        "commercial_commitment_boundary",
        "pricing_context_disclosure",
        "tool_provenance_boundary",
        "user_context_boundary",
    }
)
KNOWN_RISK_FLAGS = frozenset(
    {"stateful_context", "notification", "order", "persistent_memory"}
)


class AttackPackError(ValueError):
    """Attack Pack 缺失、重复或结构不可执行。"""


def _text_list(value: Any) -> list[str]:
    values = value if isinstance(value, list) else ([] if value is None else [value])
    return [str(item).strip() for item in values if str(item).strip()]


def _pack_files(directory: Path = ATTACK_PACK_DIR) -> list[Path]:
    return sorted(
        path
        for path in directory.glob("*.json")
        if path.is_file() and not path.name.startswith("_")
    )


def _read_pack(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AttackPackError(f"无法读取 Attack Pack：{path}") from exc
    if not isinstance(value, Mapping):
        raise AttackPackError(f"Attack Pack 必须是 JSON object：{path}")
    return copy.deepcopy(dict(value))


def _positive_int(value: Any, *, field: str, path: Path) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise AttackPackError(f"{path.name}: {field} 必须是正整数") from exc
    if parsed < 1:
        raise AttackPackError(f"{path.name}: {field} 必须是正整数")
    return parsed


def _validate_pack(pack: dict[str, Any], path: Path) -> dict[str, Any]:
    pack_id = str(pack.get("pack_id") or "").strip()
    if not PACK_ID_RE.fullmatch(pack_id):
        raise AttackPackError(f"{path.name}: pack_id 格式无效：{pack_id!r}")
    if path.stem != pack_id:
        raise AttackPackError(
            f"{path.name}: 文件名必须与 pack_id 一致（{pack_id}.json）"
        )
    for field in ("pack_version", "name", "objective"):
        if not str(pack.get(field) or "").strip():
            raise AttackPackError(f"{path.name}: 缺少 {field}")

    raw_seeds = pack.get("seeds")
    if not isinstance(raw_seeds, list) or not raw_seeds:
        raise AttackPackError(f"{path.name}: seeds 必须是非空数组")
    seeds: list[dict[str, Any]] = []
    seen_seed_ids: set[str] = set()
    for position, raw in enumerate(raw_seeds, start=1):
        if not isinstance(raw, Mapping):
            raise AttackPackError(f"{path.name}: seeds[{position}] 必须是 object")
        seed_id = str(raw.get("seed_id") or "").strip()
        initial_message = str(raw.get("initial_message") or "").strip()
        if not seed_id or seed_id in seen_seed_ids:
            raise AttackPackError(
                f"{path.name}: seed_id 缺失或重复：{seed_id!r}"
            )
        if not initial_message:
            raise AttackPackError(f"{path.name}: {seed_id} 缺少 initial_message")
        seen_seed_ids.add(seed_id)
        seed = copy.deepcopy(dict(raw))
        seed["seed_id"] = seed_id
        seed["initial_message"] = initial_message
        seed["tactic_tags"] = _text_list(seed.get("tactic_tags"))
        seeds.append(seed)

    guidance = pack.get("controller_guidance")
    if not isinstance(guidance, Mapping):
        raise AttackPackError(f"{path.name}: controller_guidance 必须是 object")
    guidance = copy.deepcopy(dict(guidance))
    for field in (
        "progress_signals",
        "allowed_tactics",
        "stop_conditions",
        "hard_constraints",
        "refusal_patterns",
    ):
        guidance[field] = _text_list(guidance.get(field))
    for pattern in guidance["refusal_patterns"]:
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise AttackPackError(
                f"{path.name}: refusal_patterns 含无效正则：{pattern}: {exc}"
            ) from exc

    oracle = pack.get("oracle")
    if not isinstance(oracle, Mapping):
        raise AttackPackError(f"{path.name}: oracle 必须是 object")
    oracle = copy.deepcopy(dict(oracle))
    oracle_type = str(oracle.get("type") or "").strip()
    if oracle_type not in SUPPORTED_ORACLES:
        raise AttackPackError(
            f"{path.name}: oracle.type 不支持：{oracle_type!r}"
        )
    success_outcomes = _text_list(oracle.get("success_outcomes"))
    if not success_outcomes:
        raise AttackPackError(f"{path.name}: oracle.success_outcomes 不能为空")
    oracle["type"] = oracle_type
    oracle["success_outcomes"] = success_outcomes
    fixture: dict[str, Any] = {}
    if oracle_type == "user_context_boundary":
        raw_fixture = pack.get("fixture")
        if not isinstance(raw_fixture, Mapping):
            raise AttackPackError(
                f"{path.name}: user_context_boundary 必须声明 fixture"
            )
        fixture = copy.deepcopy(dict(raw_fixture))
        fixture_type = str(fixture.get("type") or "").strip()
        if fixture_type != PAIRED_USER_CONTEXT_FIXTURE:
            raise AttackPackError(
                f"{path.name}: fixture.type 必须是 {PAIRED_USER_CONTEXT_FIXTURE}"
            )
        canary_prefix = str(fixture.get("canary_prefix") or "").strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{5,47}", canary_prefix):
            raise AttackPackError(
                f"{path.name}: fixture.canary_prefix 格式无效"
            )
        template = str(fixture.get("victim_seed_message_template") or "")
        if template.count("{canary}") < 1:
            raise AttackPackError(
                f"{path.name}: victim_seed_message_template 必须至少包含一个 {{canary}}"
            )
        if _text_list(oracle.get("victim_canaries")):
            raise AttackPackError(
                f"{path.name}: user_context_boundary 必须在运行时生成 Canary"
            )
        if any("{canary}" in seed["initial_message"] for seed in seeds):
            raise AttackPackError(
                f"{path.name}: 攻击 Seed 不得包含 Canary 占位符"
            )
        fixture.update(
            {
                "type": fixture_type,
                "canary_prefix": canary_prefix,
                "victim_seed_message_template": template,
            }
        )
    elif oracle_type == "tool_provenance_boundary":
        raw_fixture = pack.get("fixture")
        if not isinstance(raw_fixture, Mapping):
            raise AttackPackError(
                f"{path.name}: tool_provenance_boundary 必须声明 fixture"
            )
        fixture = copy.deepcopy(dict(raw_fixture))
        fixture_type = str(fixture.get("type") or "").strip()
        if fixture_type != TOOL_PROVENANCE_FIXTURE:
            raise AttackPackError(
                f"{path.name}: fixture.type 必须是 {TOOL_PROVENANCE_FIXTURE}"
            )
        format_source = str(
            fixture.get("format_source") or "versioned_template"
        ).strip()
        if format_source not in {"versioned_template", "visible_agent_reply"}:
            raise AttackPackError(
                f"{path.name}: fixture.format_source 仅支持 "
                "versioned_template 或 visible_agent_reply"
            )
        template_id = str(fixture.get("template_id") or "").strip()
        if format_source == "versioned_template":
            try:
                load_tool_format_template(template_id)
            except ValueError as exc:
                raise AttackPackError(f"{path.name}: {exc}") from exc
        capture_round = int(fixture.get("capture_round") or 2)
        if format_source == "visible_agent_reply" and capture_round < 2:
            raise AttackPackError(
                f"{path.name}: visible_agent_reply 的 capture_round 必须不小于 2"
            )
        marker_prefix = str(fixture.get("marker_prefix") or "").strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{3,47}", marker_prefix):
            raise AttackPackError(
                f"{path.name}: fixture.marker_prefix 格式无效"
            )
        if _text_list(oracle.get("spoof_markers")):
            raise AttackPackError(
                f"{path.name}: tool_provenance_boundary 必须在运行时生成伪装标记"
            )
        for seed in seeds:
            plan_text = json.dumps(
                seed.get("attack_plan") or {}, ensure_ascii=False, sort_keys=True
            )
            if plan_text.count("{spoof_payload}") != 1:
                raise AttackPackError(
                    f"{path.name}: {seed['seed_id']} 的 attack_plan 必须且只能包含一次"
                    " {spoof_payload}"
                )
            if "{marker}" not in plan_text:
                raise AttackPackError(
                    f"{path.name}: {seed['seed_id']} 的 attack_plan 必须包含 {marker}"
                )
        fixture.update(
            {
                "type": fixture_type,
                "format_source": format_source,
                "template_id": template_id,
                "capture_round": capture_round,
                "marker_prefix": marker_prefix,
            }
        )

    risk_policy = pack.get("risk_policy") or {}
    if not isinstance(risk_policy, Mapping):
        raise AttackPackError(f"{path.name}: risk_policy 必须是 object")
    risk_policy = copy.deepcopy(dict(risk_policy))
    risk_flags = _text_list(risk_policy.get("risk_flags"))
    unknown_risks = sorted(set(risk_flags) - KNOWN_RISK_FLAGS)
    if unknown_risks:
        raise AttackPackError(f"{path.name}: 未知 risk_flags：{unknown_risks}")
    risk_policy["risk_flags"] = risk_flags
    risk_policy["forbidden_actions"] = _text_list(
        risk_policy.get("forbidden_actions")
    )

    defaults = pack.get("defaults")
    if not isinstance(defaults, Mapping):
        raise AttackPackError(f"{path.name}: defaults 必须是 object")
    defaults = copy.deepcopy(dict(defaults))
    for field in ("iterations", "max_turns", "query_budget"):
        defaults[field] = _positive_int(defaults.get(field), field=field, path=path)
    if defaults["iterations"] > len(seeds):
        raise AttackPackError(
            f"{path.name}: defaults.iterations 不能超过种子数 {len(seeds)}"
        )

    serialised = json.dumps(pack, ensure_ascii=False, sort_keys=True).encode("utf-8")
    pack.update(
        {
            "schema_version": str(
                pack.get("schema_version") or "1.0-attack-pack"
            ),
            "pack_id": pack_id,
            "pack_version": str(pack["pack_version"]),
            "name": str(pack["name"]),
            "objective": str(pack["objective"]),
            "report_tags": _text_list(pack.get("report_tags")),
            "seeds": seeds,
            "controller_guidance": guidance,
            "oracle": oracle,
            "fixture": fixture,
            "risk_policy": risk_policy,
            "defaults": defaults,
            "source_file": str(path.resolve()),
            "snapshot_sha256": hashlib.sha256(serialised).hexdigest(),
        }
    )
    return pack


def list_attack_packs(directory: Path = ATTACK_PACK_DIR) -> list[dict[str, Any]]:
    """列出所有可执行 Pack 的轻量元数据，并同时完成结构校验。"""

    return [
        {
            "pack_id": pack["pack_id"],
            "pack_version": pack["pack_version"],
            "name": pack["name"],
            "objective": pack["objective"],
            "oracle_type": pack["oracle"]["type"],
            "fixture_type": str((pack.get("fixture") or {}).get("type") or ""),
            "seed_count": len(pack["seeds"]),
            "defaults": copy.deepcopy(pack["defaults"]),
        }
        for pack in (_validate_pack(_read_pack(path), path) for path in _pack_files(directory))
    ]


def load_attack_pack(
    pack_id: str, directory: Path = ATTACK_PACK_DIR
) -> dict[str, Any]:
    clean_id = str(pack_id or "").strip()
    if not PACK_ID_RE.fullmatch(clean_id):
        raise AttackPackError(f"无效 pack_id：{clean_id!r}")
    path = directory / f"{clean_id}.json"
    if not path.is_file():
        available = [item["pack_id"] for item in list_attack_packs(directory)]
        raise AttackPackError(
            f"未知 Attack Pack {clean_id!r}；可选：{available}"
        )
    return _validate_pack(_read_pack(path), path)


def load_attack_packs(
    pack_ids: Iterable[str] | None = None,
    *,
    load_all: bool = False,
    directory: Path = ATTACK_PACK_DIR,
) -> list[dict[str, Any]]:
    if load_all and pack_ids:
        raise AttackPackError("--all 不能与 --pack 同时使用")
    selected = (
        [item["pack_id"] for item in list_attack_packs(directory)]
        if load_all
        else list(dict.fromkeys(str(item).strip() for item in pack_ids or [] if str(item).strip()))
    )
    if not selected:
        selected = ["prompt_leakage"]
    return [load_attack_pack(pack_id, directory) for pack_id in selected]


__all__ = [
    "ATTACK_PACK_DIR",
    "AttackPackError",
    "list_attack_packs",
    "load_attack_pack",
    "load_attack_packs",
]
