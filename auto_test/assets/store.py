"""Protected snapshots and current pointers; no file fallback in MySQL mode."""
import hashlib
from pathlib import Path

from ..core.paths import AI_WEB_PRIVATE_ASSET_ROOT
from ..records import resources


def enabled():
    return resources.enabled()


def target_id(registry):
    target = registry.get("target") or {}
    app_id = str(target.get("app_id") or "")
    if not app_id.isascii() or not app_id.isdigit() or not 18 <= len(app_id) <= 20:
        raise ValueError("保护资产 appId 无效")
    if target.get("target_key") != "ai-web:" + app_id:
        raise ValueError("保护资产目标不一致")
    if not str(registry.get("snapshot_id") or "").startswith("ai-web-" + app_id + "-"):
        raise ValueError("保护资产快照编号与目标不一致")
    return app_id


def reference(app_id, snapshot_id):
    return AI_WEB_PRIVATE_ASSET_ROOT / app_id / (snapshot_id + ".json")


def locator(path):
    try:
        relative = Path(path).resolve().relative_to(AI_WEB_PRIVATE_ASSET_ROOT.resolve())
    except ValueError:
        return None
    if len(relative.parts) != 2 or relative.suffix != ".json":
        return None
    app_id, filename = relative.parts
    if not app_id.isascii() or not app_id.isdigit() or not 18 <= len(app_id) <= 20:
        return None
    return app_id, filename[:-5]


def read(app_id, snapshot_id=""):
    if not snapshot_id:
        current = resources.get("asset_current", app_id)
        if not current:
            raise ValueError(f"ai-web 目标 {app_id} 尚无数据库保护资产，请先同步或迁移")
        snapshot_id = current["value"]["snapshot_id"]
    record = resources.get("protected_asset", app_id + "/" + snapshot_id)
    if not record:
        raise ValueError(f"ai-web 目标 {app_id} 的数据库快照不存在")
    registry = record["value"]
    if target_id(registry) != app_id or registry["snapshot_id"] != snapshot_id:
        raise ValueError("数据库保护资产目标或快照不一致")
    return registry


def write(registry, *, make_current=True, only_if_missing=False):
    app_id = target_id(registry)
    snapshot_id = registry["snapshot_id"]
    key = app_id + "/" + snapshot_id
    with resources.transaction() as cur:
        resources._lock(cur, "protected_asset", key, app_id)
        existing = resources.get("protected_asset", key, cur=cur)
        if existing and existing["value"].get("source_snapshot_sha256") != registry.get("source_snapshot_sha256"):
            raise resources.Conflict("同一资产快照编号存在不同来源内容，未覆盖")
        if existing and any(existing["value"].get(field) != registry.get(field)
                            for field in ("assets", "marker_groups")):
            raise resources.Conflict("已有保护资产快照内容不同，未覆盖")
        if registry.get("documents"):
            from ..records import report_store
            digest = hashlib.sha256(
                report_store.encoded(registry["documents"]).encode()).hexdigest()
            if digest != registry.get("source_snapshot_sha256"):
                raise ValueError("原始资产文档与来源哈希不一致")
        value = registry
        if existing:
            old = existing["value"]
            # A later download can add original documents to an old chunk-only snapshot.
            if not registry.get("documents") and old.get("documents"):
                value = {**registry, "documents": old["documents"]}
        result = resources.put("protected_asset", key, value, owner_id=app_id, cur=cur,
            only_if_missing=only_if_missing,
            metadata={"snapshot_id": snapshot_id, "source_hash": registry.get("source_snapshot_sha256"),
                      "asset_count": len(registry.get("assets") or []),
                      "has_original_documents": bool(value.get("documents"))})
        if make_current:
            resources.put("asset_current", app_id,
                {"snapshot_id": snapshot_id, "synced_at": registry.get("source_synced_at", ""),
                 "name": (registry.get("target") or {}).get("name", "")},
                owner_id=app_id, cur=cur, only_if_missing=only_if_missing)
    return {**result, "reference": reference(app_id, snapshot_id)}


def index():
    targets = {}
    for row in resources.all_metadata("asset_current"):
        app_id = row["key"]
        value = resources.get("asset_current", app_id)["value"]
        registry = read(app_id, value["snapshot_id"])
        targets["ai-web:" + app_id] = {
            "target_key": "ai-web:" + app_id, "app_id": app_id,
            "snapshot_id": value["snapshot_id"], "name": value.get("name", ""),
            "synced_at": value.get("synced_at", ""),
            "source_snapshot_sha256": registry.get("source_snapshot_sha256", ""),
            "registry_file": value["snapshot_id"] + ".json",
        }
    return {"schema_version": "1.0-ai-web-asset-index", "targets": targets, "storage": "mysql"}


def registry_exists(path):
    location = locator(path) if enabled() else None
    if location:
        return resources.get("protected_asset", "/".join(location)) is not None
    from ..oracles.protected_assets import DEFAULT_ASSET_PATH
    if enabled() and Path(path).resolve() == DEFAULT_ASSET_PATH.resolve():
        return resources.get("protected_asset", "ky-agent/default") is not None
    return Path(path).is_file()
