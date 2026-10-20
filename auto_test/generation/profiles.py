"""读取 security-test-automation Skill 与 Pack 配置。"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from ..packs import list_attack_packs


AUTO_TEST_ROOT = Path(__file__).resolve().parents[1]
AUTOMATION_SKILL_DIR = AUTO_TEST_ROOT / "skills" / "security-test-automation"
SKILL_PATH = AUTOMATION_SKILL_DIR / "SKILL.md"
GENERATION_CONTRACT_PATH = (
    AUTOMATION_SKILL_DIR / "references" / "generation-contract.md"
)
EPE_GENERATION_CONTRACT_PATH = (
    AUTOMATION_SKILL_DIR / "references" / "epe-generation-contract.md"
)
PACK_PROFILES_PATH = AUTOMATION_SKILL_DIR / "references" / "pack-profiles.json"


class AutomationProfileError(ValueError):
    """Skill 或 Pack 自动化配置无效。"""


def _read_text(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AutomationProfileError(f"无法读取自动化 Skill 资源：{path}") from exc
    if not value.strip():
        raise AutomationProfileError(f"自动化 Skill 资源为空：{path}")
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_automation_profiles() -> dict[str, Any]:
    raw = _read_text(PACK_PROFILES_PATH)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AutomationProfileError("pack-profiles.json 不是有效 JSON") from exc
    if not isinstance(value, Mapping):
        raise AutomationProfileError("pack-profiles.json 必须是 object")
    profiles = copy.deepcopy(dict(value))
    if str(profiles.get("skill_name") or "") != "security-test-automation":
        raise AutomationProfileError("pack-profiles.json skill_name 不匹配")
    skill_version = str(profiles.get("skill_version") or "").strip()
    if not skill_version:
        raise AutomationProfileError("pack-profiles.json 缺少 skill_version")
    try:
        default_count = int(profiles.get("default_generation_count") or 6)
        duplicate_threshold = float(profiles.get("duplicate_threshold") or 0.82)
    except (TypeError, ValueError) as exc:
        raise AutomationProfileError("默认生成数量或重复阈值无效") from exc
    if not 1 <= default_count <= 30:
        raise AutomationProfileError("default_generation_count 必须位于 1..30")
    if not 0.5 <= duplicate_threshold <= 1.0:
        raise AutomationProfileError("duplicate_threshold 必须位于 0.5..1")
    pack_profiles = profiles.get("packs")
    if not isinstance(pack_profiles, Mapping):
        raise AutomationProfileError("pack-profiles.json 缺少 packs")
    known_packs = {item["pack_id"] for item in list_attack_packs()}
    configured_packs = {str(item) for item in pack_profiles}
    if configured_packs != known_packs:
        raise AutomationProfileError(
            "Skill Pack 配置与正式 Pack 不一致："
            f"missing={sorted(known_packs - configured_packs)}, "
            f"unknown={sorted(configured_packs - known_packs)}"
        )
    clean_packs: dict[str, dict[str, Any]] = {}
    for pack_id, raw_profile in pack_profiles.items():
        if not isinstance(raw_profile, Mapping):
            raise AutomationProfileError(f"{pack_id} profile 必须是 object")
        guidance = [
            str(item).strip()
            for item in raw_profile.get("generation_guidance") or []
            if str(item).strip()
        ]
        if not guidance:
            raise AutomationProfileError(f"{pack_id} 缺少 generation_guidance")
        clean_packs[str(pack_id)] = {
            **copy.deepcopy(dict(raw_profile)),
            "generation_guidance": guidance,
        }
    raw_epe = profiles.get("epe")
    if not isinstance(raw_epe, Mapping):
        raise AutomationProfileError("pack-profiles.json 缺少 epe 配置")
    epe_guidance = [
        str(item).strip()
        for item in raw_epe.get("generation_guidance") or []
        if str(item).strip()
    ]
    if not epe_guidance:
        raise AutomationProfileError("epe 缺少 generation_guidance")
    raw_epe_overrides = raw_epe.get("pack_overrides") or {}
    if not isinstance(raw_epe_overrides, Mapping):
        raise AutomationProfileError("epe.pack_overrides 必须是 object")
    clean_epe_overrides: dict[str, dict[str, Any]] = {}
    for query_pack, raw_override in raw_epe_overrides.items():
        if not isinstance(raw_override, Mapping):
            raise AutomationProfileError(
                f"epe.pack_overrides.{query_pack} 必须是 object"
            )
        override_guidance = [
            str(item).strip()
            for item in raw_override.get("generation_guidance") or []
            if str(item).strip()
        ]
        if not override_guidance:
            raise AutomationProfileError(
                f"epe.pack_overrides.{query_pack} 缺少 generation_guidance"
            )
        allowed_mutations = [
            str(item).strip()
            for item in raw_override.get("allowed_mutation_types") or []
            if str(item).strip()
        ]
        generation_mode = str(raw_override.get("generation_mode") or "")
        if generation_mode in {
            "controlled_obfuscation",
            "controlled_composite_obfuscation",
        }:
            if not allowed_mutations:
                raise AutomationProfileError(
                    f"epe.pack_overrides.{query_pack} 缺少 allowed_mutation_types"
                )
        if generation_mode == "controlled_composite_obfuscation":
            combinations = raw_override.get("allowed_mutation_combinations") or []
            if not isinstance(combinations, list) or not combinations:
                raise AutomationProfileError(
                    f"epe.pack_overrides.{query_pack} 缺少 allowed_mutation_combinations"
                )
            for combination in combinations:
                if (
                    not isinstance(combination, list)
                    or len(set(str(item) for item in combination)) != 2
                    or any(str(item) not in allowed_mutations for item in combination)
                ):
                    raise AutomationProfileError(
                        f"epe.pack_overrides.{query_pack} 包含无效组合"
                    )
        clean_epe_overrides[str(query_pack)] = {
            **copy.deepcopy(dict(raw_override)),
            "generation_guidance": override_guidance,
            "allowed_mutation_types": allowed_mutations,
        }
    return {
        **profiles,
        "skill_version": skill_version,
        "default_generation_count": default_count,
        "duplicate_threshold": duplicate_threshold,
        "packs": clean_packs,
        "epe": {
            **copy.deepcopy(dict(raw_epe)),
            "generation_guidance": epe_guidance,
            "pack_overrides": clean_epe_overrides,
        },
        "source_file": str(PACK_PROFILES_PATH.resolve()),
        "snapshot_sha256": _sha256_text(raw),
    }


def load_generation_bundle(pack_id: str) -> dict[str, Any]:
    profiles = load_automation_profiles()
    clean_id = str(pack_id or "").strip()
    if clean_id not in profiles["packs"]:
        raise AutomationProfileError(f"Skill 未配置 Pack：{clean_id!r}")
    skill_text = _read_text(SKILL_PATH)
    contract_text = _read_text(GENERATION_CONTRACT_PATH)
    return {
        "skill_name": "security-test-automation",
        "skill_version": profiles["skill_version"],
        "skill_path": str(SKILL_PATH.resolve()),
        "skill_snapshot_sha256": _sha256_text(skill_text),
        "contract_path": str(GENERATION_CONTRACT_PATH.resolve()),
        "contract_snapshot_sha256": _sha256_text(contract_text),
        "contract_text": contract_text,
        "profiles_snapshot_sha256": profiles["snapshot_sha256"],
        "profile": copy.deepcopy(profiles["packs"][clean_id]),
        "default_generation_count": profiles["default_generation_count"],
        "duplicate_threshold": profiles["duplicate_threshold"],
    }


def load_epe_generation_bundle(query_pack: str) -> dict[str, Any]:
    """读取 EPE 单轮 Query 生成契约；Query Pack 本身由 EPE loader 校验。"""

    clean_id = str(query_pack or "").strip()
    if not clean_id:
        raise AutomationProfileError("EPE query-pack 不能为空")
    profiles = load_automation_profiles()
    skill_text = _read_text(SKILL_PATH)
    contract_text = _read_text(EPE_GENERATION_CONTRACT_PATH)
    base_profile = copy.deepcopy(profiles["epe"])
    overrides = base_profile.pop("pack_overrides", {})
    override = copy.deepcopy(overrides.get(clean_id) or {})
    profile = {
        **base_profile,
        **override,
        "generation_guidance": [
            *base_profile["generation_guidance"],
            *override.get("generation_guidance", []),
        ],
    }
    return {
        "skill_name": "security-test-automation",
        "skill_version": profiles["skill_version"],
        "skill_path": str(SKILL_PATH.resolve()),
        "skill_snapshot_sha256": _sha256_text(skill_text),
        "contract_path": str(EPE_GENERATION_CONTRACT_PATH.resolve()),
        "contract_snapshot_sha256": _sha256_text(contract_text),
        "contract_text": contract_text,
        "profiles_snapshot_sha256": profiles["snapshot_sha256"],
        "profile": profile,
        "query_pack": clean_id,
        "default_generation_count": profiles["default_generation_count"],
        "duplicate_threshold": profiles["duplicate_threshold"],
    }


__all__ = [
    "AUTOMATION_SKILL_DIR",
    "AutomationProfileError",
    "EPE_GENERATION_CONTRACT_PATH",
    "GENERATION_CONTRACT_PATH",
    "PACK_PROFILES_PATH",
    "SKILL_PATH",
    "load_automation_profiles",
    "load_epe_generation_bundle",
    "load_generation_bundle",
]
