"""HTTP request and response schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class RiskCheckRequest(BaseModel):
    content: str = Field(min_length=1, description="本次要检查的输入或输出文本；不是需要登记的保护资产。", examples=["你好，我想咨询产品规格。"])
    direction: Literal["input", "output"] = Field(description="必填：input 检查输入，output 检查 Agent 输出。")
    stage: Literal["full", "stream"] = Field(default="full", description="默认 full 全文检查；stream 仅支持输出片段检查，窗口由客户端维护。")
    agent_id: str = Field(default="default", min_length=1, max_length=128, description="与资产配置中的 Agent ID 一致；KY Agent 为 type，ai-web 为 appId。未匹配时仅有通用检测。", examples=["ky-sales"])
    request_id: str = Field(default="", max_length=128, description="请求追踪编号；不传或留空时自动生成，响应中返回。")


class RiskTraceEntry(BaseModel):
    """一次护栏子模块调用的脱敏观测结果。"""

    module: str = Field(description="模块名称，例如 regex、qwen_guard、protected_assets。")
    enabled: bool = Field(description="该模块是否启用。")
    status: Literal["passed", "blocked", "error", "skipped"] = Field(
        description="模块状态：通过、拦截、异常或跳过。"
    )
    duration_ms: float = Field(description="该模块实际耗时，单位毫秒；跳过模块为 0。")
    calls: int = Field(description="该模块实际调用次数；跳过模块为 0。")
    blocked: bool = Field(description="该模块是否产生了拦截结果。")
    rule_id: str = Field(description="该模块命中的规则编号；未命中时为空。")
    detector: str = Field(description="实际检测器名称；未执行时为空。")
    skip_reason: str = Field(description="跳过原因；执行过的模块为空。")
    error: str = Field(description="脱敏异常类别；没有异常时为空。")
    degraded: bool = Field(description="该模块是否发生降级。")


class RiskCheckResponse(BaseModel):
    input_profile: Literal["sales", "internal"] = Field(default="sales", description="服务端为该 agent_id 配置的输入策略组；未配置默认 sales。仅影响输入检测，不是数据访问授权。")
    action: Literal["ALLOW", "BLOCK", "REVIEW"] = Field(description="建议处理方式：safe=false 时 BLOCK（拦截优先）；否则 degraded=true 时 REVIEW（异常待复核），其余 ALLOW。不自动执行拦截或创建复核任务。")
    request_id: str = Field(description="本次请求编号，用于关联日志。")
    agent_id: str = Field(description="本次请求指定的 Agent ID，不代表一定匹配到了资产配置。")
    direction: Literal["input", "output"] = Field(description="本次检测方向。")
    stage: Literal["full", "stream"] = Field(description="本次全文或流式片段检测阶段。")
    safe: bool = Field(description="与 decision 对应：true 为 ALLOW，false 为 BLOCK；还应查看 degraded。")
    decision: Literal["ALLOW", "BLOCK"] = Field(description="ALLOW 放行，BLOCK 拦截；实际停止执行或输出由调用方实现。")
    rule_id: str = Field(description="命中的规则编号，未命中时通常为空；非阻断提示也可能有编号。")
    detector: str = Field(description="给出命中结果的检测器，例如 regex、qwen_guard、protected_asset_winnowing；无命中时通常为 none。")
    reason: str = Field(description="命中原因或提示，正常放行时可能为空。")
    block_message: str = Field(description="拦截时供调用方展示的提示语，非拦截时通常为空。")
    checked_by: list[str] = Field(description="本次记录的检测层或资产匹配模式；不代表每层都成功完成，需结合 degraded。")
    degraded: bool = Field(description="true 表示检测发生异常降级，例如模型超时或无效 JSON；仍可能 ALLOW，需查服务端日志。")
    latency_ms: float = Field(description="服务端引擎检测耗时，单位毫秒；不含网络往返、客户端缓冲和后续审计写入。")
    engine_version: str = Field(description="护栏引擎版本标识。")
    source_revision: str = Field(description="配置的原始引擎来源版本标识，不等于当前部署的 Git 提交。")
    policy_version: str = Field(description="当前加载的资产策略版本，未设置版本时为 unversioned。")
    trace: list[RiskTraceEntry] | None = Field(
        default=None,
        description="可选的逐模块 trace；仅 include_trace=true 时返回，不含原始文本、资产内容或密钥。",
    )


class RiskCheckCompactResponse(BaseModel):
    block_message: str = Field(description="拦截时供调用方展示给用户的提示语，非拦截时通常为空；调用方需自行停止执行并展示提示。")
    action: Literal["ALLOW", "BLOCK", "REVIEW"] = Field(description="建议处理方式：safe=false 时 BLOCK（拦截优先）；否则 degraded=true 时 REVIEW（异常待复核），其余 ALLOW。不自动执行拦截或创建复核任务。")
    safe: bool = Field(description="true 表示本次允许通过，false 表示拦截；不是绝对安全保证，还需查看 degraded。")
    decision: Literal["ALLOW", "BLOCK"] = Field(description="与 safe 对应：ALLOW 放行，BLOCK 拦截；实际停止执行或输出由调用方实现。")
    degraded: bool = Field(description="true 表示检测异常降级；即使 safe=true，也不能当成正常检查通过。")
    reason: str = Field(description="命中原因或诊断提示，正常放行时可能为空；不是直接展示给终端用户的拦截文案。")
    request_id: str = Field(description="本次请求编号，用于关联日志。")
    latency_ms: float = Field(description="服务端引擎检测耗时，单位毫秒，不含网络往返及后续审计写入。")
    trace: list[RiskTraceEntry] | None = Field(
        default=None,
        description="可选的逐模块 trace；仅 include_trace=true 时返回，不含原始文本、资产内容或密钥。",
    )


class HealthResponse(BaseModel):
    status: Literal["ok"] = Field(default="ok", description="服务可以响应健康检查，不代表外部依赖均可用。")
    engine_version: str = Field(description="护栏引擎版本标识。")
    source_revision: str = Field(description="配置的原始引擎来源标识，不是当前部署提交号。")
    policy_version: str = Field(description="已加载的资产策略版本；无版本时为 unversioned。")
    policy_agents: int = Field(description="已加载的 Agent 策略数量；0 表示没有配置各 Agent 的私有资产保护。")
    qwen_guard_enabled: bool = Field(description="输入模型检测是否启用；不代表模型连通性检测成功。")
    aliyun_guardrail_enabled: bool = Field(description="阿里云检测是否启用；不代表云接口连通性检测成功。")
    mongo_audit_enabled: bool = Field(description="Mongo 审计是否配置启用；不代表已验证数据库连通性。")
    audit_mode: Literal["off", "blocked", "all"] = Field(description="审计模式：off 关闭，blocked 记录拦截及降级/规则提示，all 按记录规则审计；普通流式通过记录跳过。")
    skill_scan_enabled: bool = Field(default=False, description="Skill 扫描开关是否启用。")
    skill_scan_ready: bool = Field(default=False, description="扫描开关、模型密钥和包可发现性是否满足本地就绪条件；未实际调用模型探测。")
