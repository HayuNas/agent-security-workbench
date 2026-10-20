"""Read-only synchronization of ai-web Prompt and Skill protected assets."""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from ..records.library_lock import atomic_library_write, serialized_library_write
from ..clients.ai_web import AIWebClient, AIWebError
from ..clients.factory import build_target_client, resolve_target_profile
from ..core.paths import AI_WEB_PRIVATE_ASSET_INDEX, AI_WEB_PRIVATE_ASSET_ROOT
from ..oracles.protected_assets import load_protected_assets, normalise_text


TEXT_EXTENSIONS = frozenset(
    {".md", ".txt", ".json", ".yaml", ".yml", ".py", ".toml"}
)
MAX_SKILL_TEXT_FILE_BYTES = 2_000_000


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _decode_text(content: bytes, *, source: str) -> str:
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            value = content.decode(encoding)
        except UnicodeDecodeError:
            continue
        if value.strip():
            return value.replace("\r\n", "\n").replace("\r", "\n")
    raise ValueError(f"无法把 Skill 文件解码为文本：{source}")


def _skill_documents(
    skill: Mapping[str, Any], content: bytes
) -> list[dict[str, str]]:
    file_info = skill.get("skillFile")
    file_info = file_info if isinstance(file_info, Mapping) else {}
    display_name = str(file_info.get("name") or f"skill-{skill.get('id')}.md")
    buffer = io.BytesIO(content)
    if not zipfile.is_zipfile(buffer):
        return [
            {
                "source_path": display_name,
                "text": _decode_text(content, source=display_name),
            }
        ]

    documents: list[dict[str, str]] = []
    buffer.seek(0)
    with zipfile.ZipFile(buffer) as archive:
        for info in sorted(archive.infolist(), key=lambda item: item.filename):
            path = PurePosixPath(info.filename)
            if info.is_dir() or path.suffix.casefold() not in TEXT_EXTENSIONS:
                continue
            if info.file_size > MAX_SKILL_TEXT_FILE_BYTES:
                raise ValueError(f"Skill 文本文件过大，拒绝同步：{info.filename}")
            raw = archive.read(info)
            documents.append(
                {
                    "source_path": info.filename,
                    "text": _decode_text(raw, source=info.filename),
                }
            )
    if not documents:
        raise ValueError(f"Skill 压缩包没有可读取的文本文件：{display_name}")
    return documents


def _text_units(value: str) -> list[str]:
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    raw_units = re.split(r"(?<=[。！？!?；;])\s*|\n+", text)
    units: list[str] = []
    for raw in raw_units:
        clean = re.sub(r"^\s{0,3}(?:#{1,6}|[-*+] |\d+[.)、] )", "", raw).strip()
        if len(normalise_text(clean)) >= 8:
            units.append(clean)
    return units


def _chunks(value: str, maximum: int = 600) -> list[list[str]]:
    units = _text_units(value)
    chunks: list[list[str]] = []
    current: list[str] = []
    current_length = 0
    for unit in units:
        if len(unit) > maximum:
            if current:
                chunks.append(current)
                current = []
                current_length = 0
            for start in range(0, len(unit), maximum):
                piece = unit[start : start + maximum].strip()
                if len(normalise_text(piece)) >= 8:
                    chunks.append([piece])
            continue
        projected = current_length + len(unit) + (1 if current else 0)
        if current and projected > maximum:
            chunks.append(current)
            current = []
            current_length = 0
        current.append(unit)
        current_length += len(unit) + (1 if current_length else 0)
    if current:
        chunks.append(current)
    return chunks


def _assets_for_document(
    *,
    prefix: str,
    asset_type: str,
    source_path: str,
    text: str,
) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for index, units in enumerate(_chunks(text), start=1):
        canonical = "\n".join(units).strip()
        span_units = [unit for unit in units if len(normalise_text(unit)) >= 12]
        if not span_units:
            span_units = [canonical]
        stable_spans = [
            {
                "span_id": f"{prefix}-SPAN-{index:03d}-{position:02d}",
                "text": unit,
                "weight": 1.0,
            }
            for position, unit in enumerate(span_units[:12], start=1)
        ]
        assets.append(
            {
                "asset_id": f"{prefix}-{index:03d}",
                "asset_type": asset_type,
                "source_path": source_path,
                "sensitivity": "critical",
                "customer_visibility": "forbidden",
                "canonical_text": canonical,
                "stable_spans": stable_spans,
                "common_phrase_exclusions": [],
            }
        )
    return assets


def build_ai_web_asset_registry(
    *,
    app_id: str,
    target_key: str,
    app_details: Mapping[str, Any],
    prompt: Mapping[str, Any],
    skills: Sequence[Mapping[str, Any]],
    skill_documents: Sequence[Sequence[Mapping[str, str]]],
) -> dict[str, Any]:
    prompt_text = str(prompt.get("prompt") or "").strip()
    if not prompt_text:
        raise ValueError("目标 Agent 的系统提示词为空")
    if len(skills) != len(skill_documents):
        raise ValueError("Skill 详情和文件内容数量不一致")

    source_documents: list[dict[str, str]] = [
        {
            "kind": "system_prompt",
            "source_id": str(prompt.get("id") or ""),
            "source_path": f"prompt/{prompt.get('id')}",
            "text": prompt_text,
        }
    ]
    assets = _assets_for_document(
        prefix="AIWEB-PROMPT",
        asset_type="system_prompt_span",
        source_path=f"prompt/{prompt.get('id')}",
        text=prompt_text,
    )
    skill_sources: list[dict[str, Any]] = []
    for skill_index, (skill, documents) in enumerate(
        zip(skills, skill_documents), start=1
    ):
        skill_id = str(skill.get("id") or "")
        skill_sources.append(
            {
                "id": skill_id,
                "name": str(skill.get("name") or ""),
                "update_time": str(skill.get("updateTime") or ""),
                "file_id": str(
                    ((skill.get("skillFile") or {}).get("id") or "")
                    if isinstance(skill.get("skillFile"), Mapping)
                    else ""
                ),
                "files": [str(item.get("source_path") or "") for item in documents],
            }
        )
        for document_index, document in enumerate(documents, start=1):
            source_path = f"skill/{skill_id}/{document.get('source_path')}"
            text = str(document.get("text") or "").strip()
            source_documents.append(
                {
                    "kind": "skill",
                    "source_id": skill_id,
                    "source_path": source_path,
                    "text": text,
                }
            )
            assets.extend(
                _assets_for_document(
                    prefix=f"AIWEB-SKILL-{skill_index:02d}-{document_index:02d}",
                    asset_type="skill_text_span",
                    source_path=source_path,
                    text=text,
                )
            )
    if not assets:
        raise ValueError("没有从系统提示词和 Skill 中生成受保护资产")

    fingerprint_source = json.dumps(
        source_documents,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    source_sha256 = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()
    return {
        "schema_version": "1.1-protected-assets",
        "snapshot_id": f"ai-web-{app_id}-{source_sha256[:16]}",
        "target": {
            "adapter": "ai-web",
            "target_key": target_key,
            "app_id": app_id,
            "name": str(app_details.get("name") or ""),
        },
        "source_snapshot_sha256": source_sha256,
        "source_synced_at": _now(),
        "documents": source_documents,
        "source": {
            "app_update_time": str(app_details.get("updateTime") or ""),
            "prompt_id": str(prompt.get("id") or ""),
            "prompt_name": str(prompt.get("name") or ""),
            "prompt_update_time": str(prompt.get("updateTime") or ""),
            "skills": skill_sources,
        },
        "report_policy": (
            "完整 Prompt/Skill 保存在受控的数据库资产快照；"
            "测试报告只保存 snapshot_id、哈希和命中 span_id"
        ),
        "assets": assets,
        "marker_groups": [],
    }


def _read_index(path: Path = AI_WEB_PRIVATE_ASSET_INDEX) -> dict[str, Any]:
    from . import store
    if store.enabled() and Path(path).resolve() == AI_WEB_PRIVATE_ASSET_INDEX.resolve():
        return store.index()
    if not path.is_file():
        return {"schema_version": "1.0-ai-web-asset-index", "targets": {}}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping) or not isinstance(value.get("targets"), Mapping):
        raise ValueError(f"ai-web 资产索引格式无效：{path}")
    return {**dict(value), "targets": dict(value["targets"])}


def resolve_ai_web_asset_registry(
    app_id: str,
    *,
    root: Path = AI_WEB_PRIVATE_ASSET_ROOT,
    index_path: Path = AI_WEB_PRIVATE_ASSET_INDEX,
    snapshot_id: str = "",
) -> Path:
    from . import store
    if store.enabled() and Path(root).resolve() == AI_WEB_PRIVATE_ASSET_ROOT.resolve():
        registry = store.read(str(app_id), snapshot_id)
        return store.reference(str(app_id), registry["snapshot_id"])
    target_key = f"ai-web:{app_id}"
    record = _read_index(index_path)["targets"].get(target_key)
    if not isinstance(record, Mapping):
        raise ValueError(
            f"ai-web 目标 {target_key} 尚无资产快照；请先运行 target assets-sync"
        )
    filename = str(record.get("registry_file") or "").strip()
    candidate = Path(root) / str(app_id) / filename
    if not filename or not candidate.is_file():
        raise ValueError(f"ai-web 目标 {target_key} 的最新资产快照不存在")
    load_protected_assets(candidate)
    return candidate


@serialized_library_write
def _save_registry(
    registry: Mapping[str, Any],
    *,
    root: Path = AI_WEB_PRIVATE_ASSET_ROOT,
    index_path: Path = AI_WEB_PRIVATE_ASSET_INDEX,
) -> Path:
    from . import store
    if store.enabled() and Path(root).resolve() == AI_WEB_PRIVATE_ASSET_ROOT.resolve():
        return store.write(dict(registry))["reference"]
    app_id = str((registry.get("target") or {}).get("app_id") or "")
    target_key = str((registry.get("target") or {}).get("target_key") or "")
    snapshot_id = str(registry.get("snapshot_id") or "")
    target_dir = Path(root) / app_id
    target_dir.mkdir(parents=True, exist_ok=True)
    registry_path = target_dir / f"{snapshot_id}.json"
    atomic_library_write(registry_path, json.dumps(registry, ensure_ascii=False, indent=2) + "\n")
    load_protected_assets(registry_path)

    index = _read_index(index_path)
    index["targets"][target_key] = {
        "target_key": target_key,
        "app_id": app_id,
        "name": str((registry.get("target") or {}).get("name") or ""),
        "snapshot_id": snapshot_id,
        "source_snapshot_sha256": str(
            registry.get("source_snapshot_sha256") or ""
        ),
        "synced_at": str(registry.get("source_synced_at") or ""),
        "registry_file": registry_path.name,
    }
    index["updated_at"] = _now()
    index_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_library_write(index_path, json.dumps(index, ensure_ascii=False, indent=2) + "\n")
    return registry_path


def sync_ai_web_assets(args: Any, *, client: AIWebClient | None = None) -> dict[str, Any]:
    from . import store
    profile = resolve_target_profile(args)
    if profile.adapter != "ai-web":
        raise ValueError("target assets-sync 当前只支持 ai-web")
    target_client = client or build_target_client(args, profile)
    if not isinstance(target_client, AIWebClient):
        raise TypeError("ai-web 资产同步需要 AIWebClient")
    health = target_client.health()
    if not bool(health.get("target_visible")):
        raise ValueError(f"授权账号的 Agent 列表中未找到 appId {profile.app_id}")

    app = target_client.get_app_details()
    prompt_id = str(app.get("aiPromptID") or "").strip()
    prompt = next(
        (
            item
            for item in target_client.list_prompts()
            if str(item.get("id") or "") == prompt_id
        ),
        None,
    )
    if not isinstance(prompt, Mapping):
        raise AIWebError(f"未找到 Agent 绑定的系统提示词 aiPromptID={prompt_id}")

    binding_ids: list[str] = []
    for item in app.get("skills") or []:
        if not isinstance(item, Mapping) or item.get("isSelect") is False:
            continue
        skill_id = str(item.get("aiSkillToolManagementId") or "").strip()
        if skill_id and skill_id not in binding_ids:
            binding_ids.append(skill_id)
    # The production GetDetails DTO currently returns selected Skill/Tool IDs
    # here while leaving ``skills`` empty. Resolve every binding and retain only
    # actual Skill files; ordinary HTTP/Python tools have no protected file.
    for value in app.get("aiSkillsToolsBindIds") or []:
        skill_id = str(value or "").strip()
        if skill_id and skill_id not in binding_ids:
            binding_ids.append(skill_id)
    skills: list[dict[str, Any]] = []
    documents: list[list[dict[str, str]]] = []
    for skill_id in binding_ids:
        skill = target_client.get_skill_details(skill_id)
        file_info = skill.get("skillFile")
        file_id = (
            str(file_info.get("id") or "").strip()
            if isinstance(file_info, Mapping)
            else ""
        )
        if not file_id:
            if int(skill.get("skillToolType") or 0) == 2:
                raise AIWebError(f"Skill {skill_id} 没有可下载的 skillFile")
            continue
        skills.append(skill)
        documents.append(_skill_documents(skill, target_client.download_file(file_id)))

    registry = build_ai_web_asset_registry(
        app_id=profile.app_id,
        target_key=profile.target_key,
        app_details=app,
        prompt=prompt,
        skills=skills,
        skill_documents=documents,
    )
    root = Path(getattr(args, "asset_sync_root", None) or AI_WEB_PRIVATE_ASSET_ROOT)
    index_path = Path(
        getattr(args, "asset_sync_index", None) or AI_WEB_PRIVATE_ASSET_INDEX
    )
    path = _save_registry(registry, root=root, index_path=index_path)
    return {
        "status": "SYNCED",
        "target": profile.safe_dict(),
        "agent_name": str(app.get("name") or ""),
        "snapshot_id": registry["snapshot_id"],
        "source_snapshot_sha256": registry["source_snapshot_sha256"],
        "prompt_id": prompt_id,
        "skill_ids": [str(item.get("id") or "") for item in skills],
        "skill_file_count": sum(len(items) for items in documents),
        "asset_count": len(registry["assets"]),
        "registry": str(path.resolve()),
        "index": str(index_path.resolve()),
        "storage": "mysql" if store.enabled()
            and root.resolve() == AI_WEB_PRIVATE_ASSET_ROOT.resolve() else "file",
    }


__all__ = [
    "build_ai_web_asset_registry",
    "resolve_ai_web_asset_registry",
    "sync_ai_web_assets",
]
