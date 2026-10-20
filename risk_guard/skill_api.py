"""Authenticated multipart endpoint for the original Tencent scanner."""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from functools import partial
from typing import Literal

import anyio
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.datastructures import UploadFile

from .api_docs import SCAN_DESCRIPTION, SCAN_SUMMARY_EXAMPLES
from .skill_archive import InvalidArchive
from .skill_download import DownloadFailure, validate_url
from .skill_service import ScanFailure, SkillScanResponse, SkillScanService
from .skill_summary import ScanDiagnostics, SkillSafetyResponse, summarize_scan

LOGGER = logging.getLogger(__name__)
_REQUEST_ID_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")


class SkillScanWithSummary(SkillScanResponse):
    safety_summary: SkillSafetyResponse | None = Field(default=None, description="同一次扫描的公司摘要；输出不完整时为空，不生成安全定论。")
    summary_error: str | None = Field(default=None, description="摘要不可用的原因；保留完整报告供复核。")


class ScanOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["full", "single"] = "single"
    language: Literal["zh", "en"] = "zh"
    prompt: str = Field(default="", max_length=8000)
    request_id: str = Field(default="", max_length=128)
    include_sarif: bool = False
    url: str = Field(default="", max_length=8192)


REQUEST_BODY = {
    "requestBody": {"required": True, "content": {"multipart/form-data": {
        "schema": {"type": "object", "description": "archive 文件和 url 下载链接必须二选一。", "properties": {
            # Explicit empty example/default prevents Swagger versions from
            # synthesizing the literal "string" for an unselected binary field.
            "archive": {"type": "string", "format": "binary", "default": "", "example": "", "description": "与 url 二选一：选择包含 SKILL.md 和相关文件的 ZIP。填写 url 时不选文件。大小、数量和解压限制由服务端配置。"},
            "url": {"type": "string", "maxLength": 8192, "default": "", "description": "与 archive 二选一：填写公网 HTTPS ZIP 下载直链；上传文件时留空。"},
            "mode": {"type": "string", "enum": ["single", "full"], "default": "single", "description": "可省略，默认 single：只做代码审计；full 包含信息收集、代码审计、漏洞复审。"},
            "language": {"type": "string", "enum": ["zh", "en"], "default": "zh", "description": "可省略，默认 zh 中文报告；en 为英文报告。"},
            "prompt": {"type": "string", "maxLength": 8000, "default": "", "description": "可选的检查重点，例如：重点检查越权读取和数据外传。"},
            "request_id": {"type": "string", "maxLength": 128, "default": "", "description": "可选的请求追踪编号；省略或留空由服务端自动生成。"},
            "include_sarif": {"type": "boolean", "default": False, "description": "默认 false。需要 SARIF 标准报告时，先在上方 query 参数选择 compact=false，再将此项设为 true；不影响扫描和评分。"},
        }},
    }}}
}


def _diagnostic_error(
    *,
    status_code: int,
    detail: str,
    request_id: str,
    stage: str,
    code: str,
    started: float,
    headers: dict[str, str] | None = None,
    provider_code: str | None = None,
) -> JSONResponse:
    """返回保留 HTTP 错误语义的脱敏诊断体，不把异常原文回显给调用方。"""
    latency_ms = round((time.monotonic() - started) * 1000, 2)
    diagnostics = {
        "request_id": request_id,
        "status": "failed",
        "stage": stage,
        "code": code,
        "message": detail,
        "latency_ms": latency_ms,
    }
    if provider_code:
        diagnostics["provider_code"] = provider_code
    LOGGER.warning(
        "Skill scan failed | request_id=%s | status=%s | stage=%s | code=%s | latency_ms=%s",
        request_id, status_code, stage, code, latency_ms,
    )
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail, "diagnostics": diagnostics},
        headers=headers,
    )


def _safe_request_id(value: str, fallback: str) -> str:
    """保留可读追踪 ID，同时阻止控制字符污染响应和服务日志。"""
    candidate = value.strip()
    return candidate if _REQUEST_ID_RE.fullmatch(candidate) else fallback


def create_skill_router(scanner: SkillScanService, authenticate) -> APIRouter:
    router = APIRouter()

    @router.post(
        "/v1/skill-scan", response_model=SkillSafetyResponse | SkillScanResponse | SkillScanWithSummary,
        dependencies=[Depends(authenticate)], openapi_extra=REQUEST_BODY,
        summary="扫描 Skill ZIP（上传文件或填写 URL）", tags=["Skill 扫描"], description=SCAN_DESCRIPTION,
        responses={
            200: {"description": "默认返回准入判断、分数、问题明细和脱敏 Diagnostics；IsSafe=true 不代表没有漏洞。",
                  "content": {"application/json": {"examples": SCAN_SUMMARY_EXAMPLES}}},
            **{code: {"description": description} for code, description in {
                401: "接口口令无效：检查 x-risk-guard-token。",
                408: "上传超时：检查网络及 ZIP 大小。", 413: "上传或下载体积超过服务端限制。",
                415: "请求格式错误：请使用 multipart/form-data，archive 与 url 二选一。",
                422: "参数、下载地址或 ZIP 无效：archive 与 url 必须二选一；下载不允许内网地址。",
                429: "扫描器繁忙：按 Retry-After 响应头等待后重试。",
                502: "远程下载、扫描或模型调用失败，或返回数据无效。",
                503: "扫描器未就绪或无法启动：检查开关、依赖和模型配置。",
                504: "下载或扫描超过服务端时限；网关也可能返回 504，需要结合服务端日志判断。",
            }.items()},
        },
    )
    async def scan_skill(request: Request, compact: bool = Query(
        default=True, description="默认 true：返回 IsSafe、Score、SafetyDetails 和脱敏 Diagnostics，不返回长报告。false 为排查用原始完整结果；include_sarif=true 需同时选择 false。",
    ), include_summary: bool = Query(
        default=False, description="仅 compact=false 时可用：在完整结果中附加 safety_summary，不重复扫描。摘要校验失败时保留原报告并返回 summary_error。",
    )):
        req_started = time.monotonic()
        # 先生成服务端请求编号，保证解析表单前失败也能关联服务器日志。
        request_id = uuid.uuid4().hex

        def fail(
            status_code: int,
            detail: str,
            *,
            stage: str,
            code: str,
            headers: dict[str, str] | None = None,
            provider_code: str | None = None,
        ) -> JSONResponse:
            return _diagnostic_error(
                status_code=status_code,
                detail=detail,
                request_id=request_id,
                stage=stage,
                code=code,
                started=req_started,
                headers=headers,
                provider_code=provider_code,
            )

        if compact and include_summary:
            return fail(
                422,
                "include_summary=true requires compact=false",
                stage="admission",
                code="invalid_options",
            )
        client_host = request.client.host if request.client else "unknown"
        try:
            scanner.ensure_available()
        except ScanFailure as exc:
            return fail(
                exc.status_code,
                exc.detail,
                stage=exc.stage,
                code=exc.code,
                provider_code=exc.provider_code,
            )
        if not scanner.slots.acquire(blocking=False):
            return fail(
                429,
                "Skill scanner is busy; retry later",
                stage="admission",
                code="scanner_busy",
                headers={"Retry-After": "30"},
            )
        try:
            if request.headers.get("content-type", "").split(";", 1)[0].lower() != "multipart/form-data":
                return fail(
                    415,
                    "Use multipart/form-data with archive or url",
                    stage="admission",
                    code="invalid_content_type",
                )
            # Bound the entire multipart body BEFORE the parser can spool arbitrary
            # uploads to disk. Admission/auth checks have already run at this point.
            limit = scanner.settings.max_archive_bytes + 64 * 1024
            declared = request.headers.get("content-length")
            if declared is not None:
                try:
                    length = int(declared)
                except ValueError as exc:
                    return fail(
                        422,
                        "Invalid Content-Length",
                        stage="upload",
                        code="invalid_content_length",
                    )
                if length < 0 or length > limit:
                    return fail(
                        413,
                        "Multipart body exceeds the upload limit",
                        stage="upload",
                        code="archive_too_large",
                    )
            body = bytearray()
            try:
                async with asyncio.timeout(scanner.settings.upload_timeout_seconds):
                    async for chunk in request.stream():
                        if len(body) + len(chunk) > limit:
                            return fail(
                                413,
                                "Multipart body exceeds the upload limit",
                                stage="upload",
                                code="archive_too_large",
                            )
                        body.extend(chunk)
            except TimeoutError as exc:
                return fail(
                    408,
                    "Skill upload timed out",
                    stage="upload",
                    code="upload_timeout",
                )

            async def receive():
                return {"type": "http.request", "body": bytes(body), "more_body": False}

            bounded = Request(request.scope, receive=receive)
            async with bounded.form(max_files=1, max_fields=7, max_part_size=32768) as form:
                items = list(form.multi_items())
                if len(items) != len({key for key, _ in items}):
                    return fail(
                        422,
                        "Duplicate form fields are not allowed",
                        stage="admission",
                        code="invalid_options",
                    )
                archive = form.get("archive")
                # Swagger may submit an empty optional file field as text.
                if archive == "" or (
                    isinstance(archive, UploadFile) and archive.filename == "" and archive.size == 0
                ):
                    archive = None
                if archive is not None and not isinstance(archive, UploadFile):
                    return fail(
                        422,
                        "archive must be an uploaded ZIP file",
                        stage="upload",
                        code="invalid_archive",
                    )
                try:
                    options = ScanOptions.model_validate({k: v for k, v in items if k != "archive"})
                except ValidationError as exc:
                    return fail(
                        422,
                        "Invalid scan options",
                        stage="admission",
                        code="invalid_options",
                    )
                if compact and options.include_sarif:
                    return fail(
                        422,
                        "include_sarif=true requires compact=false",
                        stage="admission",
                        code="invalid_options",
                    )
                url = options.url.strip()
                if (archive is not None) == bool(url):
                    return fail(
                        422,
                        "Provide exactly one of archive or url",
                        stage="admission",
                        code="invalid_source",
                    )
                if url:
                    try:
                        validate_url(url, scanner.settings.download_allowed_hosts)
                    except DownloadFailure as exc:
                        return fail(
                            exc.status,
                            exc.detail,
                            stage="download",
                            code="invalid_download_url",
                        )
                source_type = "url" if url else "archive"
                effective_request_id = _safe_request_id(options.request_id, request_id)
                request_id = effective_request_id
                LOGGER.info(
                    "Skill scan request received | request_id=%s | mode=%s | source=%s | compact=%s | client=%s",
                    effective_request_id, options.mode, source_type, compact, client_host,
                )
                scan_options = options.model_dump(exclude={"include_sarif", "url"})
                # 让扫描器和外层 HTTP 诊断使用同一个请求编号。
                scan_options["request_id"] = effective_request_id
                task = partial(scanner.run_url, url, **scan_options) if url else partial(
                    scanner.run, archive.file, **scan_options,
                )
                try:
                    # Keep slot and uploaded file alive even if the client cancels.
                    # The bounded child process is reaped before cleanup/release.
                    with anyio.CancelScope(shield=True):
                        result = await anyio.to_thread.run_sync(task)
                    req_latency = round((time.monotonic() - req_started) * 1000, 2)
                    LOGGER.info(
                        "Skill scan response | request_id=%s | status=%s | latency_ms=%s | client=%s",
                        result.request_id, result.status, req_latency, client_host,
                    )
                    if compact:
                        diagnostics = ScanDiagnostics(
                            request_id=effective_request_id,
                            status="completed",
                            stage="response",
                            code="ok",
                            message="扫描完成，已生成精简结果。",
                            latency_ms=req_latency,
                        )
                        return JSONResponse(
                            content=summarize_scan(
                                result,
                                diagnostics=diagnostics,
                            ).model_dump(),
                        )
                    # Remove only the top-level SARIF field. Do not use recursive
                    # exclude_none/exclude_unset: upstream nulls and fields must survive.
                    payload = result.model_dump(
                        mode="json", exclude=set() if options.include_sarif else {"sarif"},
                    )
                    if include_summary:
                        # 复用已完成的结果，不重新执行扫描；摘要无效也保留诊断报告。
                        payload["safety_summary"] = None
                        payload["summary_error"] = None
                        try:
                            payload["safety_summary"] = summarize_scan(
                                result,
                                diagnostics=ScanDiagnostics(
                                    request_id=effective_request_id,
                                    status="completed",
                                    stage="response",
                                    code="ok",
                                    message="扫描完成，已生成精简结果。",
                                    latency_ms=req_latency,
                                ),
                            ).model_dump()
                        except ScanFailure as exc:
                            payload["summary_error"] = exc.detail
                    return JSONResponse(content=payload)
                except InvalidArchive as exc:
                    return fail(
                        422,
                        str(exc),
                        stage="upload",
                        code="invalid_archive",
                    )
                except ScanFailure as exc:
                    return fail(
                        exc.status_code,
                        exc.detail,
                        stage=exc.stage,
                        code=exc.code,
                        provider_code=exc.provider_code,
                    )
        except HTTPException as exc:
            # Starlette 的 multipart 解析器会把格式错误转换成 HTTPException；
            # 也统一包装诊断信息，避免前端只看到没有上下文的 400。
            detail = exc.detail if isinstance(exc.detail, str) else "请求格式无效"
            return fail(
                exc.status_code,
                detail,
                stage="upload",
                code="invalid_multipart",
            )
        finally:
            scanner.slots.release()

    return router
