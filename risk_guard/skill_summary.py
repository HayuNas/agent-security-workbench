"""Public scan summary; preserve upstream scoring and never execute report text."""

import re
from typing import Literal

from pydantic import BaseModel, Field

from .skill_service import ScanFailure, SkillScanResponse, output_warnings


class SafetyLocation(BaseModel):
    FileName: str | None = Field(description="已核对的 ZIP 内相对路径：保留包中实际存在的 Skill 根目录，去掉服务器临时目录；ZIP 没有根目录时不造名字。缺失、不存在或无法唯一定位时为 null。")
    LineStart: int | None = Field(description="起始行号；缺失或无效为 null。")
    LineEnd: int | None = Field(description="结束行号；缺失或无效为 null。")


class SafetyDetail(BaseModel):
    Title: str = Field(description="问题标题，来自上游发现项。")
    Locations: list[SafetyLocation] = Field(description="该问题的文件及行号；仅合并标题、说明、类型、等级和建议完全一致的发现项。")
    Suggestion: str | None = Field(description="修复建议；上游未提供时为 null。")


class ScanDiagnostics(BaseModel):
    """精简返回中的安全诊断日志；只包含定位和阶段信息。"""

    request_id: str = Field(description="本次扫描请求编号，用于关联服务器日志。")
    status: Literal["completed", "review_required", "failed"] = Field(
        description="本次扫描状态；failed 表示没有形成可用安全结论。",
    )
    stage: str = Field(description="发生信息的阶段，例如 scan、summary、response。")
    code: str = Field(description="稳定的诊断码，例如 ok、model_http_error、invalid_output。")
    message: str | None = Field(
        description="脱敏后的诊断说明；不包含提示词、源码、密钥或模型原始响应。",
    )
    latency_ms: float | None = Field(
        description="截至该诊断点的服务端耗时，单位毫秒。",
    )


class SkillSafetyResponse(BaseModel):
    IsSafe: bool = Field(description="是否达到公司准入标准：有效扫描分数 >=70 为 true，低于 70 为 false；不是无漏洞保证。")
    Score: int = Field(ge=0, le=100, description="上游安全分，不重算；70 分及以上通过。有问题也可能达到通过分数。")
    SafetyDetails: list[SafetyDetail] = Field(description="所有解析出的风险明细；通过时仍展示发现项，无发现时为空列表。")
    Diagnostics: ScanDiagnostics = Field(
        description="精简诊断日志：用于知道请求在哪个阶段结束以及如何关联服务器日志。",
    )


def _line(value) -> int | None:
    if type(value) is int:
        return value if value > 0 else None
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,10}", value.strip()):
        number = int(value.strip())
        return number if number > 0 else None
    return None


def summarize_scan(
    response: SkillScanResponse,
    *,
    diagnostics: ScanDiagnostics | None = None,
) -> SkillSafetyResponse:
    """Only build a pass/fail summary from a structurally usable final report."""
    invalid = "扫描结果不完整或无法解析，未作通过判定；请重试或联系维护人员。"
    try:
        if response.status != "completed" or response.warnings or output_warnings({
            "result": response.result, "stage_reports": response.stage_reports,
        }):
            raise ValueError("incomplete output")
        score = response.result["score"]
        if type(score) is not int or not 0 <= score <= 100:
            raise ValueError("invalid score")
        findings = response.result["results"]
        if not isinstance(findings, list):
            raise ValueError("invalid findings")
        groups: dict[tuple, SafetyDetail] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("invalid finding")
            title = finding.get("title")
            if not isinstance(title, str) or not title.strip():
                raise ValueError("missing title")
            # A repeated title alone does not prove that two findings are the same issue.
            values = [finding.get(key) for key in ("description", "risk_type", "level", "suggestion")]
            if any(value is not None and not isinstance(value, str) for value in values):
                raise ValueError("invalid finding fields")
            key = (title, *values)
            detail = groups.setdefault(key, SafetyDetail(
                Title=title, Locations=[], Suggestion=finding.get("suggestion") or None,
            ))
            file_name = finding.get("file")
            if isinstance(file_name, str):
                file_name = response._public_file_names.get(file_name, file_name)
            start, end = _line(finding.get("line_start")), _line(finding.get("line_end"))
            if start is not None and end is not None and end < start:
                start = end = None
            location = SafetyLocation(
                FileName=file_name if isinstance(file_name, str) and file_name.strip() else None,
                LineStart=start, LineEnd=end,
            )
            if location not in detail.Locations:
                detail.Locations.append(location)
        return SkillSafetyResponse(
            IsSafe=score >= 70,
            Score=score,
            SafetyDetails=list(groups.values()),
            Diagnostics=diagnostics or ScanDiagnostics(
                request_id=response.request_id,
                status="completed",
                stage="response",
                code="ok",
                message="扫描完成，已生成精简结果。",
                latency_ms=response.latency_ms,
            ),
        )
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ScanFailure(
            502,
            invalid,
            code="invalid_output",
            stage="summary",
        ) from exc
