"""Sync protected system-prompt assets from ky_agent_config to a private file."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

import pymysql
from pymysql.cursors import DictCursor

from .engine import RiskEngine
from .assets import DEFAULT_K_GRAM, DEFAULT_MIN_MATCH_CHARS, normalize_asset_text
from .settings import DEFAULT_POLICIES_PATH, _LOCAL_ENV_FILES, _unquote


_MYSQL_KEYS = frozenset(
    {
        "DM_DATA_MYSQL_HOST",
        "DM_DATA_MYSQL_PORT",
        "DM_DATA_MYSQL_USER",
        "DM_DATA_MYSQL_PASSWORD",
        "DM_DATA_MYSQL_DB",
    }
)

_PRIVATE_SKILL_MARKERS = (
    "内部记忆，禁止输出给客户",
    "内部记忆,禁止输出给客户",
)

_DEFAULT_AI_WEB_ASSET_INDEX = (
    Path(__file__).resolve().parents[1]
    / "auto_test"
    / ".private"
    / "ai_web_assets"
    / "index.json"
)


def _skill_roots_from_environment() -> tuple[Path, ...]:
    configured = os.getenv("RISK_GUARD_SKILL_ROOTS", "")
    roots = [
        Path(value.strip())
        for value in configured.split(os.pathsep)
        if value.strip()
    ]
    repository = Path(__file__).resolve().parents[1]
    roots.extend(
        (
            repository / "demo" / "skills",
        )
    )
    return tuple(dict.fromkeys(path.resolve() for path in roots if path.is_dir()))


def _parse_skill_paths(raw_value: Any) -> tuple[str, ...]:
    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return ()
        try:
            raw_value = json.loads(text)
        except json.JSONDecodeError:
            raw_value = [text]
    if not isinstance(raw_value, (list, tuple)):
        return ()
    return tuple(
        str(value).strip()
        for value in raw_value
        if str(value).strip()
    )


def _resolve_skill_directory(raw_path: str, roots: Sequence[Path]) -> Path | None:
    direct = Path(raw_path)
    if direct.is_dir():
        return direct.resolve()

    parts = tuple(part for part in raw_path.replace("\\", "/").split("/") if part)
    skill_indexes = [index for index, part in enumerate(parts) if part == "skills"]
    suffix = parts[skill_indexes[-1] + 1 :] if skill_indexes else parts[-1:]
    if not suffix:
        return None
    for root in roots:
        candidate = root.joinpath(*suffix)
        if candidate.is_dir():
            return candidate.resolve()
    return None


def _private_skill_assets(skill_directories: Iterable[Path]) -> list[dict[str, Any]]:
    """Load only Skill files that explicitly declare their whole content private."""
    assets: list[dict[str, Any]] = []
    content_hashes: set[str] = set()
    for skill_directory in skill_directories:
        for path in sorted(skill_directory.rglob("*.md")):
            content = path.read_text(encoding="utf-8-sig")
            header = "\n".join(content.splitlines()[:8])
            if not any(marker in header for marker in _PRIVATE_SKILL_MARKERS):
                continue
            content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if content_hash in content_hashes:
                continue
            content_hashes.add(content_hash)
            relative = path.relative_to(skill_directory).as_posix().lower()
            safe_name = re.sub(r"[^a-z0-9._/-]+", "-", relative).strip("-")
            assets.append(
                {
                    "asset_id": f"private-skill:{safe_name}",
                    "asset_type": "internal_skill",
                    "content": content,
                    "match_modes": ["winnowing", "fuzzy"],
                }
            )
    return assets


def _as_bool(raw_value: str, *, default: bool = False) -> bool:
    value = str(raw_value or "").strip().casefold()
    if not value:
        return default
    return value in {"1", "true", "yes", "on"}


def _configured_ai_web_asset_index() -> Path | None:
    configured = os.getenv("RISK_GUARD_AI_WEB_ASSET_INDEX", "").strip()
    if configured:
        path = Path(configured).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"ai-web asset index does not exist: {path}")
        return path
    try:
        from auto_test.assets import store
        if store.enabled():
            return _DEFAULT_AI_WEB_ASSET_INDEX
    except ImportError:
        pass  # The standalone guard image does not include the test workbench.
    return _DEFAULT_AI_WEB_ASSET_INDEX if _DEFAULT_AI_WEB_ASSET_INDEX.is_file() else None


def ai_web_policy_from_registry(registry, *, include_skill_assets=False):
    """Convert an already loaded snapshot without requiring a local file."""
    raw_assets = registry.get("assets")
    if not isinstance(raw_assets, list):
        raise ValueError("ai-web asset snapshot has no assets")
    grouped = {}
    for asset in raw_assets:
        if not isinstance(asset, dict):
            continue
        kind = str(asset.get("asset_type") or "").strip()
        if kind != "system_prompt_span" and not (include_skill_assets and kind == "skill_text_span"):
            continue
        if asset.get("customer_visibility") != "forbidden":
            continue
        text = str(asset.get("canonical_text") or "").strip()
        if text:
            grouped.setdefault((kind, str(asset.get("source_path") or kind)), []).append(text)
    protected = []
    prompt_parts = []
    for (kind, source), parts in sorted(grouped.items()):
        text = "\n".join(dict.fromkeys(parts)).strip()
        length = len(normalize_asset_text(text))
        if length < DEFAULT_K_GRAM:
            raise ValueError("私有提示词有效字符不足 9 个，无法建立可靠的保护资产匹配")
        digest = hashlib.sha256(f"{kind}\0{source}\0{text}".encode()).hexdigest()[:12]
        value = {"asset_id": f"ai-web:{kind}:{digest}", "asset_type": kind,
                 "content": text, "match_modes": ["winnowing", "fuzzy"]}
        if length < DEFAULT_MIN_MATCH_CHARS:
            value.update(min_match_chars=length, fuzzy_threshold=100.0, match_modes=["fuzzy"])
        protected.append(value)
        if kind == "system_prompt_span":
            prompt_parts.append(text)
    if not prompt_parts:
        raise ValueError("ai-web snapshot has no protected prompt")
    return {"input_profile": "internal",
            "prompt_fingerprints": list(RiskEngine.extract_prompt_fingerprints("\n".join(prompt_parts))),
            "protected_assets": protected}


def _ai_web_policies_from_index(
    index_path: Path,
    *,
    include_skill_assets: bool = False,
    only_app_id: str | None = None,
    snapshot_path: Path | None = None,
) -> tuple[dict[str, dict[str, Any]], int]:
    """Convert private ai-web snapshots into Risk Guard per-app policies.

    The attack harness snapshots all Skill text for evaluation.  Skill text can
    contain customer-visible business procedures, so the guard imports only
    the system prompt by default.  Whole-Skill blocking must be explicitly
    enabled after those files have been reviewed as entirely private.
    """
    resolved_index = Path(index_path).expanduser().resolve()
    database_store = None
    try:
        from auto_test.assets import store
        if store.enabled() and resolved_index == _DEFAULT_AI_WEB_ASSET_INDEX.resolve():
            database_store = store
    except ImportError:
        pass
    payload = database_store.index() if database_store else json.loads(resolved_index.read_text(encoding="utf-8"))
    targets = payload.get("targets") if isinstance(payload, dict) else None
    if not isinstance(targets, dict):
        raise ValueError(f"invalid ai-web asset index: {resolved_index}")

    policies: dict[str, dict[str, Any]] = {}
    total_assets = 0
    for target_key, record in sorted(targets.items()):
        if not isinstance(record, dict):
            raise ValueError(f"invalid ai-web asset record: {target_key}")
        app_id = str(record.get("app_id") or "").strip()
        if only_app_id is not None and app_id != only_app_id:
            continue
        filename = str(record.get("registry_file") or "").strip()
        if not app_id or not filename:
            raise ValueError(f"incomplete ai-web asset record: {target_key}")
        registry_path = snapshot_path if snapshot_path is not None and app_id == only_app_id else resolved_index.parent / app_id / filename
        if not database_store and not registry_path.is_file():
            raise FileNotFoundError(
                f"ai-web asset snapshot does not exist: {registry_path}"
            )
        registry = database_store.read(app_id, record["snapshot_id"]) if database_store else json.loads(registry_path.read_text(encoding="utf-8"))
        registry_target = registry.get("target") if isinstance(registry, dict) else None
        if not isinstance(registry_target, dict) or str(
            registry_target.get("app_id") or ""
        ) != app_id:
            raise ValueError(f"ai-web asset snapshot target mismatch: {registry_path}")
        raw_assets = registry.get("assets")
        if not isinstance(raw_assets, list):
            raise ValueError(f"ai-web asset snapshot has no assets: {registry_path}")

        policies[app_id] = ai_web_policy_from_registry(registry, include_skill_assets=include_skill_assets)
        total_assets += len(policies[app_id]["protected_assets"])
    return policies, total_assets


def _mysql_settings() -> dict[str, str]:
    values: dict[str, str] = {}
    for path in _LOCAL_ENV_FILES:
        if not path.is_file():
            continue
        for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            if key in _MYSQL_KEYS:
                values[key] = _unquote(raw_value)
    for key in _MYSQL_KEYS:
        if os.getenv(key):
            values[key] = os.environ[key].strip()
    missing = sorted(_MYSQL_KEYS - values.keys())
    if missing:
        raise RuntimeError("Missing DM_DATA MySQL settings: " + ", ".join(missing))
    return values


def sync_policies(
    output_path: Path = DEFAULT_POLICIES_PATH,
    *,
    skill_roots: Sequence[Path] | None = None,
    ai_web_asset_index: Path | None = None,
    include_ai_web_skill_assets: bool | None = None,
) -> dict[str, Any]:
    settings = _mysql_settings()
    connection = pymysql.connect(
        host=settings["DM_DATA_MYSQL_HOST"],
        port=int(settings["DM_DATA_MYSQL_PORT"]),
        user=settings["DM_DATA_MYSQL_USER"],
        password=settings["DM_DATA_MYSQL_PASSWORD"],
        database=settings["DM_DATA_MYSQL_DB"],
        charset="utf8mb4",
        cursorclass=DictCursor,
        connect_timeout=10,
        read_timeout=20,
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT type, system_prompt, skill_paths FROM ky_agent_config "
                "WHERE is_active = 1 ORDER BY type"
            )
            rows = list(cursor.fetchall())
    finally:
        connection.close()

    roots = (
        tuple(skill_roots)
        if skill_roots is not None
        else _skill_roots_from_environment()
    )
    agents: dict[str, dict[str, Any]] = {}
    unresolved_skill_paths: list[str] = []
    private_skill_asset_count = 0
    for row in rows:
        agent_id = str(row.get("type") or "").strip()
        prompt = str(row.get("system_prompt") or "")
        if not agent_id or not prompt:
            continue
        fingerprints = list(RiskEngine.extract_prompt_fingerprints(prompt))
        resolved_skills: list[Path] = []
        for raw_skill_path in _parse_skill_paths(row.get("skill_paths")):
            resolved = _resolve_skill_directory(raw_skill_path, roots)
            if resolved is None:
                unresolved_skill_paths.append(f"{agent_id}:{raw_skill_path}")
            else:
                resolved_skills.append(resolved)
        private_skill_assets = _private_skill_assets(resolved_skills)
        private_skill_asset_count += len(private_skill_assets)
        agents[agent_id] = {
            # Keep the original exact-line detector during migration.
            "prompt_fingerprints": fingerprints,
            # Full protected content is stored in the policy file so the service
            # can build Winnowing and fuzzy signatures at startup.
            "protected_assets": [
                {
                    "asset_id": "system-prompt",
                    "asset_type": "system_prompt",
                    "content": prompt,
                    "match_modes": ["winnowing", "fuzzy"],
                }
            ]
            + private_skill_assets,
        }

    selected_ai_web_index = (
        Path(ai_web_asset_index).expanduser().resolve()
        if ai_web_asset_index is not None
        else _configured_ai_web_asset_index()
    )
    include_ai_web_skills = (
        bool(include_ai_web_skill_assets)
        if include_ai_web_skill_assets is not None
        else _as_bool(os.getenv("RISK_GUARD_AI_WEB_INCLUDE_SKILLS", ""))
    )
    ai_web_agents: dict[str, dict[str, Any]] = {}
    ai_web_asset_count = 0
    if selected_ai_web_index is not None:
        ai_web_agents, ai_web_asset_count = _ai_web_policies_from_index(
            selected_ai_web_index,
            include_skill_assets=include_ai_web_skills,
        )
        collisions = sorted(set(agents) & set(ai_web_agents))
        if collisions:
            raise ValueError(
                "duplicate ky-agent/ai-web policy ids: " + ", ".join(collisions)
            )
        agents.update(ai_web_agents)

    canonical = json.dumps(agents, ensure_ascii=False, sort_keys=True)
    version = "mysql-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    payload = {
        "version": version,
        "synced_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source": "dm_data.ky_agent_config",
        "agents": agents,
    }
    if os.getenv("RISK_GUARD_CONFIG_BACKEND", "mysql").lower() == "mysql" and Path(output_path).resolve() == DEFAULT_POLICIES_PATH.resolve():
        from .policy_admin import save_base_policy
        save_base_policy(payload)
        output_reference = "mysql:ky_config_guard_base"
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        output_reference = str(output_path.resolve())
    return {
        "status": "SYNCED",
        "policy_version": version,
        "agent_count": len(agents),
        "agent_ids": sorted(agents),
        "private_skill_asset_count": private_skill_asset_count,
        "ai_web_agent_count": len(ai_web_agents),
        "ai_web_asset_count": ai_web_asset_count,
        "ai_web_skill_assets_included": include_ai_web_skills,
        "ai_web_asset_index": (
            str(selected_ai_web_index) if selected_ai_web_index is not None else ""
        ),
        "unresolved_skill_paths": sorted(unresolved_skill_paths),
        "output": output_reference,
    }


def main() -> None:
    print(json.dumps(sync_policies(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()


__all__ = ["sync_policies"]
