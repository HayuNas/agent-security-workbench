"""Resolve safe target metadata and construct the selected target adapter."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any

from .ai_web import AIWebClient, DEFAULT_AI_WEB_BASE_URL
from .base import TargetClient
from .target import DEFAULT_BASE_URL, KyAgentClient


@dataclass(frozen=True)
class TargetProfile:
    adapter: str
    target_key: str
    base_url: str
    app_id: str = ""

    def safe_dict(self) -> dict[str, str]:
        return asdict(self)


def parse_target_selector(value: str) -> tuple[str, str]:
    """Parse the stable, one-flag target selector used by scheduled jobs."""

    selector = str(value or "").strip()
    if selector in {"ky-app", "ky-app:sales-agent"}:
        return "ky-app", "sales-agent"
    if selector == "ky-agent":
        return "ky-agent", ""
    if selector.startswith("ai-web:"):
        app_id = selector.partition(":")[2].strip()
        if app_id.isdigit() and 18 <= len(app_id) <= 20:
            return "ai-web", app_id
    raise ValueError(
        "--target 必须是 ky-agent、ky-app:sales-agent 或 ai-web:<18至20位appId>"
    )


def resolve_target_profile(args: Any) -> TargetProfile:
    selector = str(
        getattr(args, "target", None) or os.getenv("KY_TARGET", "")
    ).strip()
    selected_adapter = ""
    selected_app_id = ""
    if selector:
        selected_adapter, selected_app_id = parse_target_selector(selector)
    adapter = selected_adapter or str(
        getattr(args, "target_adapter", None) or "ky-agent"
    ).strip()
    if adapter == "ky-app":
        from .ky_app import DEFAULT_BASE_URL as APP_URL
        return TargetProfile(adapter="ky-app", target_key="ky-app:sales-agent",
            base_url=str(getattr(args, "ky_app_base_url", None) or os.getenv("KY_APP_BASE_URL") or APP_URL).strip().rstrip("/"))
    if adapter == "ky-agent":
        return TargetProfile(
            adapter=adapter,
            target_key="ky-agent:ky-sales",
            base_url=str(getattr(args, "base_url", None) or DEFAULT_BASE_URL),
        )
    if adapter != "ai-web":
        raise ValueError(f"未知目标适配器：{adapter!r}")
    app_id = selected_app_id or str(
        getattr(args, "app_id", None) or os.getenv("KY_AI_WEB_APP_ID", "")
    ).strip()
    if not app_id.isdigit() or not 18 <= len(app_id) <= 20:
        raise ValueError("使用 ai-web 时必须通过 --app-id 或 KY_AI_WEB_APP_ID 提供 18 至 20 位 appId")
    base_url = str(
        getattr(args, "ai_web_base_url", None)
        or os.getenv("KY_AI_WEB_BASE_URL", "")
        or DEFAULT_AI_WEB_BASE_URL
    )
    return TargetProfile(
        adapter=adapter,
        target_key=f"ai-web:{app_id}",
        base_url=base_url,
        app_id=app_id,
    )


def build_target_client(
    args: Any,
    profile: TargetProfile,
    *,
    ky_agent_client_class: type[KyAgentClient] = KyAgentClient,
) -> TargetClient:
    if profile.adapter == "ky-app":
        from .ky_app import KyAppClient
        token = os.getenv("KY_APP_API_TOKEN", "").strip()
        if not token:
            raise ValueError("缺少 KY_APP_API_TOKEN（新销售 Agent 凭据，不能用护栏口令）")
        return KyAppClient(base_url=profile.base_url, api_token=token,
            customer_id=os.getenv("KY_APP_CUSTOMER_ID", "100001"),
            customer_contact_id=os.getenv("KY_APP_CUSTOMER_CONTACT_ID", "200001"),
            request_timeout=float(getattr(args, "request_timeout", 60)),
            chat_timeout=float(getattr(args, "chat_timeout", 300)),
            idle_timeout=float(getattr(args, "idle_timeout", 90)),
            artifact_char_limit=int(getattr(args, "artifact_char_limit", 200000)),
            save_raw_events=bool(getattr(args, "save_raw_events", False)), init_interval=0, chat_retries=1)
    if profile.adapter == "ky-agent":
        api_token = os.getenv("KY_AGENT_API_TOKEN", "").strip()
        if not api_token:
            raise ValueError("缺少 KY_AGENT_API_TOKEN 环境变量")
        return ky_agent_client_class(
            base_url=profile.base_url,
            api_token=api_token,
            request_timeout=float(getattr(args, "request_timeout", 60.0)),
            chat_timeout=float(getattr(args, "chat_timeout", 240.0)),
            idle_timeout=float(getattr(args, "idle_timeout", 90.0)),
            artifact_char_limit=int(
                getattr(args, "artifact_char_limit", 200_000)
            ),
            save_raw_events=bool(getattr(args, "save_raw_events", False)),
            init_interval=float(getattr(args, "init_interval", 2.1)),
            chat_retries=int(getattr(args, "chat_retries", 3)),
        )
    verify_tls = os.getenv("KY_AI_WEB_VERIFY_TLS", "true").strip().casefold()
    tenant_text = os.getenv("KY_AI_WEB_TENANT_ID", "1000").strip() or "1000"
    try:
        tenant_id = int(tenant_text)
    except ValueError as exc:
        raise ValueError("KY_AI_WEB_TENANT_ID 必须是整数") from exc
    return AIWebClient(
        base_url=profile.base_url,
        app_id=profile.app_id,
        target_key=profile.target_key,
        api_token=os.getenv("KY_AI_WEB_TOKEN", "").strip(),
        username=os.getenv("KY_AI_WEB_USERNAME", "").strip(),
        password=os.getenv("KY_AI_WEB_PASSWORD", ""),
        tenant_id=tenant_id,
        request_timeout=float(getattr(args, "request_timeout", 60.0)),
        chat_timeout=float(getattr(args, "chat_timeout", 240.0)),
        poll_interval=float(getattr(args, "ai_web_poll_interval", 1.0)),
        verify_tls=verify_tls not in {"0", "false", "no", "off"},
    )


__all__ = [
    "TargetProfile",
    "build_target_client",
    "parse_target_selector",
    "resolve_target_profile",
]
