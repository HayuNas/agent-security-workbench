"""Application service that exposes structured Risk Engine decisions."""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Literal

from .audit import AuditSink, build_audit_sink
from .engine import RiskEngine
from .policies import PolicyRegistry
from .settings import RiskGuardSettings


Direction = Literal["input", "output"]
Stage = Literal["full", "stream"]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GuardResult:
    request_id: str
    agent_id: str
    direction: Direction
    stage: Stage
    safe: bool
    decision: Literal["ALLOW", "BLOCK"]
    rule_id: str
    detector: str
    reason: str
    block_message: str
    checked_by: tuple[str, ...]
    degraded: bool
    latency_ms: float
    engine_version: str
    source_revision: str
    policy_version: str
    input_profile: str = "sales"
    # 逐模块 trace 仅在 HTTP 请求明确要求时返回；审计记录始终保留脱敏摘要。
    trace: tuple[dict[str, object], ...] = ()


class RiskGuardService:
    def __init__(
        self,
        settings: RiskGuardSettings,
        policies: PolicyRegistry | None = None,
        engine: RiskEngine | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self.settings = settings
        from .policy_admin import PolicyStore
        self.policy_store = PolicyStore(settings.policy_store_path) if settings.policy_store_path else None
        self._database_base = policies is None and self.policy_store is not None and self.policy_store.mysql
        if self._database_base:
            self.policies = PolicyRegistry.from_payload(self.policy_store.base_policy())
        else:
            self.policies = policies or PolicyRegistry.from_file(settings.policies_path)
        self.base_policies = self.policies
        self._policy_revision = -1
        self._policy_lock = threading.RLock()
        self.refresh_policies()
        self.engine = engine or RiskEngine(
            guard_llm_enable=settings.guard_llm_enable,
            api_key=settings.dashscope_api_key,
            model_name=settings.guard_model,
            api_base_url=settings.dashscope_base_url,
            aliyun_guardrail_enable=settings.aliyun_guardrail_enable,
            aliyun_access_key_id=settings.aliyun_access_key_id,
            aliyun_access_key_secret=settings.aliyun_access_key_secret,
            aliyun_region=settings.aliyun_region,
        )
        self.audit_sink = audit_sink or build_audit_sink(
            uri=settings.mongo_uri if settings.audit_mode != "off" else "",
            database=settings.mongo_database,
            collection=settings.mongo_collection,
        )

    async def check(
        self,
        *,
        content: str,
        direction: Direction,
        stage: Stage = "full",
        agent_id: str = "default",
        request_id: str = "",
    ) -> GuardResult:
        if direction not in {"input", "output"}:
            raise ValueError("direction must be 'input' or 'output'")
        if stage not in {"full", "stream"}:
            raise ValueError("stage must be 'full' or 'stream'")
        if direction == "input" and stage == "stream":
            raise ValueError("stream stage is only valid for output checks")
        if not content or not content.strip():
            raise ValueError("content must not be empty")
        if len(content) > self.settings.max_content_length:
            raise ValueError(
                f"content exceeds {self.settings.max_content_length} characters"
            )

        started = time.perf_counter()
        policies = self.refresh_policies()
        policy = policies.get(agent_id)
        if direction == "input":
            if policy.input_profile == "internal":
                from .internal_context import internal_role_context
                context = internal_role_context(agent_id)
                result = await self.engine.evaluate_input(content, input_profile="internal",
                    **({"business_context": context} if context else {}))
                if not result.safe:
                    result = replace(result, block_message="抱歉，该请求涉及受限内容或操作，无法执行。请确认请求及访问权限。")
            else:
                result = await self.engine.evaluate_input(content)
        else:
            if stage == "stream":
                result = self.engine.evaluate_stream_output(
                    content,
                    prompt_fingerprints=policy.prompt_fingerprints,
                    protected_assets=policy.protected_assets,
                )
            else:
                result = await self.engine.evaluate_output(
                    content,
                    prompt_fingerprints=policy.prompt_fingerprints,
                    protected_assets=policy.protected_assets,
                )

        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        guard_result = GuardResult(
            request_id=request_id or uuid.uuid4().hex,
            agent_id=agent_id,
            direction=direction,
            stage=stage,
            safe=result.safe,
            decision="ALLOW" if result.safe else "BLOCK",
            rule_id=result.rule_id,
            detector=result.detector,
            reason=result.reason,
            block_message=result.block_message,
            checked_by=result.checked_by,
            degraded=result.degraded,
            latency_ms=latency_ms,
            engine_version=self.settings.engine_version,
            source_revision=self.settings.source_revision,
            policy_version=policies.version,
            input_profile=policy.input_profile,
            trace=tuple(getattr(result, "trace", ()) or ()),
        )
        self._audit(content, guard_result)
        return guard_result

    def refresh_policies(self):
        if self.policy_store is not None:
            with self._policy_lock:
                revision, payload = self.policy_store.snapshot(self._policy_revision)
                if revision != self._policy_revision:
                    if self._database_base:
                        self.base_policies = PolicyRegistry.from_payload(self.policy_store.base_policy())
                    self.policies = self.base_policies.overlay(payload, f'{self.base_policies.version}:managed:{revision}')
                    self._policy_revision = revision
        return self.policies

    def _audit(self, content: str, result: GuardResult) -> None:
        if self.settings.audit_mode == "off":
            return
        if (
            result.stage == "stream"
            and result.decision == "ALLOW"
            and not result.degraded
            and not result.rule_id
        ):
            return
        if (
            self.settings.audit_mode == "blocked"
            and result.decision != "BLOCK"
            and not result.degraded
            and not result.rule_id
        ):
            return
        limit = max(0, int(self.settings.audit_content_limit))
        record = {
            "request_id": result.request_id,
            "agent_id": result.agent_id,
            "direction": result.direction,
            "stage": result.stage,
            "decision": result.decision,
            "safe": result.safe,
            "rule_id": result.rule_id,
            "detector": result.detector,
            "reason": result.reason,
            "checked_by": list(result.checked_by),
            "degraded": result.degraded,
            "latency_ms": result.latency_ms,
            "engine_version": result.engine_version,
            "source_revision": result.source_revision,
            "policy_version": result.policy_version,
            "input_profile": result.input_profile,
            "trace": [dict(item) for item in result.trace],
            "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "content_excerpt": content[:limit] if limit else "",
            "content_length": len(content),
            "created_at": datetime.now(timezone.utc),
        }
        try:
            self.audit_sink.submit(record)
        except Exception as exc:
            logger.warning("Risk Guard audit submission failed: %s", exc)

    def close(self) -> None:
        self.audit_sink.close()
