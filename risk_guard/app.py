"""FastAPI entrypoint for the standalone Risk Engine."""

from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status

from .api_docs import CHECK_DESCRIPTION, SERVICE_DESCRIPTION
from .schemas import HealthResponse, RiskCheckCompactResponse, RiskCheckRequest, RiskCheckResponse
from .service import RiskGuardService
from .settings import RiskGuardSettings
from .skill_api import create_skill_router
from .skill_service import SkillScanService
from .skill_settings import SkillScanSettings


def create_app(
    settings: RiskGuardSettings | None = None,
    *,
    skill_scan_settings: SkillScanSettings | None = None,
) -> FastAPI:
    resolved = settings or RiskGuardSettings.from_env()
    logging.basicConfig(
        level=getattr(logging, resolved.log_level, logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    service = RiskGuardService(resolved)
    skill_scanner = SkillScanService(skill_scan_settings or SkillScanSettings.from_env(resolved))

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        service.close()

    # 接口文档（/docs、/redoc、/openapi.json）由 RISK_GUARD_DOCS_ENABLED 控制；
    # 关闭时三处都设 None，避免只关 UI 仍能通过 /openapi.json 拿到 schema。
    app = FastAPI(
        title="KY Risk Guard Service",
        version=resolved.engine_version,
        description=SERVICE_DESCRIPTION,
        docs_url="/docs" if resolved.docs_enabled else None,
        redoc_url="/redoc" if resolved.docs_enabled else None,
        openapi_url="/openapi.json" if resolved.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.risk_guard = service
    app.state.skill_scanner = skill_scanner

    async def authenticate(
        authorization: str = Header(default="", description="可选：Bearer <接口口令>。与 x-risk-guard-token 二选一，不是模型 API Key。"),
        x_risk_guard_token: str = Header(default="", description="推荐填写：服务端配置的接口口令原文，不加引号、不加 Bearer；不是模型 API Key。"),
    ) -> None:
        if not resolved.api_tokens:
            return
        bearer = ""
        if authorization.lower().startswith("bearer "):
            bearer = authorization[7:].strip()
        supplied = x_risk_guard_token or bearer
        if not any(
            secrets.compare_digest(supplied, expected)
            for expected in resolved.api_tokens
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid risk guard token",
            )

    @app.get("/health", response_model=HealthResponse, tags=["服务状态"],
             summary="查看服务状态（免鉴权）",
             description="只检查本地配置和加载状态，不主动探测模型、阿里云或数据库连通性。policy_agents=0 表示没有加载 Agent 资产策略。")
    async def health() -> HealthResponse:
        service.refresh_policies()
        return HealthResponse(
            engine_version=resolved.engine_version,
            source_revision=resolved.source_revision,
            policy_version=service.policies.version,
            policy_agents=service.policies.agent_count,
            qwen_guard_enabled=resolved.guard_llm_enable,
            aliyun_guardrail_enabled=resolved.aliyun_guardrail_enable,
            mongo_audit_enabled=(
                bool(resolved.mongo_uri) and resolved.audit_mode != "off"
            ),
            audit_mode=resolved.audit_mode,
            skill_scan_enabled=skill_scanner.settings.enabled,
            skill_scan_ready=skill_scanner.ready,
        )

    @app.post(
        "/v1/check",
        response_model=RiskCheckCompactResponse | RiskCheckResponse,
        response_model_exclude_none=True,
        dependencies=[Depends(authenticate)],
        tags=["安全护栏"], summary="检查 Agent 输入或输出", description=CHECK_DESCRIPTION,
    )
    async def check(
        payload: RiskCheckRequest,
        compact: bool = Query(default=True, description="默认 true，返回 action、safe、decision、degraded、reason、block_message、request_id、latency_ms；false 获取完整返回。只影响返回字段，不改变检测和审计。"),
        include_trace: bool = Query(
            default=False,
            description="默认 false。设为 true 时在返回体追加逐模块 trace，包含实际调用、耗时、拦截、跳过和脱敏异常信息。",
        ),
    ) -> RiskCheckResponse | RiskCheckCompactResponse:
        try:
            result = await service.check(
                content=payload.content,
                direction=payload.direction,
                stage=payload.stage,
                agent_id=payload.agent_id,
                request_id=payload.request_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        data = asdict(result)
        data["checked_by"] = list(result.checked_by)
        data["action"] = "BLOCK" if not result.safe else ("REVIEW" if result.degraded else "ALLOW")
        if include_trace:
            data["trace"] = [dict(item) for item in result.trace]
        else:
            # 保持旧客户端的返回字段集合不变；trace 只在调用方明确要求时出现。
            data.pop("trace", None)
        full_response = RiskCheckResponse(**data)
        if compact:
            return RiskCheckCompactResponse(**full_response.model_dump(
                include=set(RiskCheckCompactResponse.model_fields),
            ))
        return full_response

    app.include_router(create_skill_router(skill_scanner, authenticate))
    from .policy_admin import create_policy_router
    app.include_router(create_policy_router(service))
    return app


app = create_app()
