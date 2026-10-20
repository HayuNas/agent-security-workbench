"""Read display metadata from the existing scenario table; rules stay in the engine."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, ConfigDict

from ..records import report_store, unified
from ..records.findings import SCENARIO_GUIDANCE
from .contracts import PACKS

router = APIRouter(prefix="/api/agent/settings/scenarios", tags=["场景配置"])


class Update(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=2000)
    enabled: bool = True
    sort_order: int = Field(default=0, ge=0, le=10000)


def catalog(include_disabled=False):
    if not unified.enabled():
        return [{"id": key, "name": row["scenario_name"], "description": row["description"],
                 "enabled": True, "revision": 1, "sort_order": 0} for key, row in SCENARIO_GUIDANCE.items()]
    with report_store.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT scenario_code,scenario_name,description,enabled,revision,sort_order
                FROM agent_security_scenarios WHERE test_kind='attack'""" +
                ("" if include_disabled else " AND enabled=1") + " ORDER BY sort_order,id")
            return [{"id": code.lower(), "name": name, "description": description or "", "enabled": bool(enabled),
                     "revision": revision, "sort_order": order, "supported": code.lower() in PACKS}
                    for code, name, description, enabled, revision, order in cur.fetchall()]


@router.get("")
def list_scenarios():
    try:
        return {"items": catalog(True)}
    except Exception:
        raise HTTPException(503, "场景数据库暂不可用") from None


@router.put("/{scene_id}")
def update(scene_id: str, body: Update):
    if not unified.enabled():
        raise HTTPException(503, "数据库场景配置未启用")
    if scene_id not in PACKS:
        raise HTTPException(422, "该场景尚无执行器配置，不能仅新增目录就执行")
    try:
        with report_store.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""UPDATE agent_security_scenarios
                    SET scenario_name=%s,description=%s,enabled=%s,sort_order=%s,revision=revision+1
                    WHERE scenario_code=%s AND test_kind='attack' AND revision=%s""",
                    (body.name, body.description, body.enabled, body.sort_order, scene_id.upper(), body.revision))
                if cur.rowcount != 1:
                    raise HTTPException(409, "场景不存在或已被修改，请刷新")
            conn.commit()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "场景保存失败，请重试") from None
    return {"id": scene_id, **body.model_dump(), "revision": body.revision + 1}
