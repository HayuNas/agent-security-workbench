"""Shared browser drafts and preferences; raw runtime objects are not exposed."""
import json
import hashlib
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..records import resources

router = APIRouter(prefix="/api/agent/client-state", tags=["工作台偏好与草稿"])
KEYS = {
    "ky-agent-local-drafts-v1", "ky-live-drafts-v2", "ky-skill-template-v1",
    "ky-workbench-preferences-v1", "ky-workbench-models-v2",
    "ky-agent-migration-backup-v1", "ky-workbench-logs-v1",
}


def valid(key):
    if key not in KEYS:
        raise HTTPException(404, "未知的草稿或偏好设置")


class State(BaseModel):
    revision: int = Field(ge=0)
    value: Any


class LegacyState(BaseModel):
    value: Any


@router.post("/{key}/legacy")
def archive_legacy(key: str, body: LegacyState):
    valid(key)
    encoded = json.dumps(body.value, ensure_ascii=False, sort_keys=True)
    if len(encoded.encode()) > 8 * 1024 * 1024:
        raise HTTPException(413, "旧资料超过迁移限制")
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    resources.put("client_state_archive", key + "/" + digest, body.value, owner_id=key,
                  only_if_missing=True, metadata={"source": "legacy_browser"})
    return {"archived": True}


@router.get("/{key}")
def read(key: str):
    valid(key)
    row = resources.get("client_state", key)
    return {"value": row["value"], "revision": row["revision"]} if row else {"value": None, "revision": 0}


@router.put("/{key}")
def save(key: str, body: State):
    valid(key)
    maximum = 48 if key == "ky-workbench-logs-v1" else 2
    if len(json.dumps(body.value, ensure_ascii=False).encode()) > maximum * 1024 * 1024:
        raise HTTPException(413, "草稿或偏好超过大小限制")
    try:
        result = resources.put("client_state", key, body.value, expected=body.revision)
    except resources.Conflict as exc:
        raise HTTPException(409, "设置已被其他浏览器修改，请刷新后重试") from exc
    return {"revision": result["revision"]}
