"""Normal-question integration verification for the ai-web adapter."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from ..core.paths import AI_WEB_CONTRACTS_PATH, AI_WEB_INTEGRATION_RESULTS_DIR
from ..core.redaction import redact_report_text, redact_value
from .factory import build_target_client, resolve_target_profile


DEFAULT_SMOKE_MESSAGE = "请用一句话介绍你可以提供哪些帮助。"


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_contract_registry(path: Path = AI_WEB_CONTRACTS_PATH) -> dict[str, Any]:
    from ..records import resources
    if resources.enabled() and Path(path).resolve() == AI_WEB_CONTRACTS_PATH.resolve():
        record = resources.get("contract_registry", "ai-web")
        if not record:
            raise ValueError("ai-web 契约尚未迁移到数据库")
        return record["value"]
    if not Path(path).is_file():
        return {"schema_version": "1.0-ai-web-contracts", "targets": {}}
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping) or not isinstance(value.get("targets"), Mapping):
        raise ValueError(f"ai-web 契约登记文件格式无效：{path}")
    return {**dict(value), "targets": dict(value["targets"])}


def require_ai_web_contract(
    target_key: str,
    path: Path = AI_WEB_CONTRACTS_PATH,
) -> dict[str, Any]:
    registry = load_contract_registry(path)
    record = registry["targets"].get(str(target_key))
    if not isinstance(record, Mapping) or not bool(record.get("verified")):
        raise ValueError(
            f"ai-web 目标 {target_key} 尚未通过正常问答契约验证；"
            "请先运行 target smoke"
        )
    return dict(record)


def _save_contract(
    *,
    path: Path,
    target: Mapping[str, Any],
    verified_at: str,
    report_path: Path,
    reply_sha256: str,
) -> None:
    from ..records import resources
    if resources.enabled() and Path(path).resolve() == AI_WEB_CONTRACTS_PATH.resolve():
        from ..workbench.artifacts import reference
        location = reference(report_path)
        def save(current):
            registry = current or {"schema_version": "1.0-ai-web-contracts", "targets": {}}
            registry.setdefault("targets", {})[str(target["target_key"])] = {
                "verified": True, "adapter": "ai-web", "target_key": target["target_key"],
                "app_id": target["app_id"], "verified_at": verified_at,
                "report": location, "reply_sha256": reply_sha256,
                "contract_version": "ai-web-two-call-v1"}
            registry["updated_at"] = verified_at
            return registry
        resources.update("contract_registry", "ai-web", save)
        return
    registry = load_contract_registry(path)
    registry["targets"][str(target["target_key"])] = {
        "verified": True,
        "adapter": "ai-web",
        "target_key": str(target["target_key"]),
        "app_id": str(target["app_id"]),
        "verified_at": verified_at,
        "report": str(report_path.resolve()),
        "reply_sha256": reply_sha256,
        "contract_version": "ai-web-two-call-v1",
    }
    registry["updated_at"] = verified_at
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(registry, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def run_target_smoke(args: Any) -> dict[str, Any]:
    profile = resolve_target_profile(args)
    if profile.adapter != "ai-web":
        raise ValueError("target smoke 当前只用于 ai-web 适配器")
    try:
        client = build_target_client(args, profile)
        health = client.health()
    except Exception as exc:
        raise ValueError(
            f"ai-web 连通性检查失败：{type(exc).__name__}: "
            f"{redact_value(str(exc))}"
        ) from exc
    if not bool(health.get("target_visible")):
        raise ValueError(f"授权账号的 Agent 列表中未找到 appId {profile.app_id}")

    smoke_id = "AWS-" + datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    message = str(getattr(args, "smoke_message", None) or DEFAULT_SMOKE_MESSAGE)
    session = client.init_test(
        wx_account=smoke_id,
        wx_contact=f"{smoke_id}-NORMAL",
    )
    trace = client.chat(session, message, allow_transport_retry=False)
    reply = str(trace.get("reply") or "").strip()
    if not reply:
        raise ValueError("正常问答未取得 Agent 回复，契约验证失败")

    created_at = _now()
    output_dir = Path(
        getattr(args, "smoke_output_dir", None) or AI_WEB_INTEGRATION_RESULTS_DIR
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"{smoke_id}.json"
    safe_reply = str(redact_report_text(reply))
    report = {
        "schema_version": "1.0-ai-web-smoke-report",
        "status": "VERIFIED",
        "smoke_id": smoke_id,
        "created_at": created_at,
        "target": profile.safe_dict(),
        "health": health,
        "request_contract": {
            "session_endpoint": "/api/AIChats/Add",
            "message_endpoint": "/api/AIChatHistorys/Add",
            "history_endpoint": "/api/AIChatHistorys/GetPageData",
            "single_turn": True,
        },
        "session": {
            "agent_type": session.agent_type,
            "agent_id": session.agent_id,
            "session_id": session.session_id,
        },
        "message": message,
        "reply": safe_reply,
        "reply_sha256": hashlib.sha256(reply.encode("utf-8")).hexdigest(),
        "trace": {
            key: trace.get(key)
            for key in (
                "adapter",
                "duration_seconds",
                "stream_end_reason",
                "response_history_id",
                "response_created_at",
                "received_at",
            )
        },
    }
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    contract_path = Path(
        getattr(args, "contract_registry", None) or AI_WEB_CONTRACTS_PATH
    )
    _save_contract(
        path=contract_path,
        target=profile.safe_dict(),
        verified_at=created_at,
        report_path=report_path,
        reply_sha256=report["reply_sha256"],
    )
    return {
        "status": "VERIFIED",
        "smoke_id": smoke_id,
        "target": profile.safe_dict(),
        "session_id": session.session_id,
        "report": str(report_path.resolve()),
        "contract_registry": str(contract_path.resolve()),
    }


__all__ = [
    "DEFAULT_SMOKE_MESSAGE",
    "load_contract_registry",
    "require_ai_web_contract",
    "run_target_smoke",
]
