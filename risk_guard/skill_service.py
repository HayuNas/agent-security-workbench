"""Process and HTTP result adaptation around the unmodified Tencent scanner."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, PrivateAttr

from .api_docs import RESULT_SCHEMA, SCAN_EXAMPLES
from .skill_archive import extract_archive, scan_root
from .skill_settings import SkillScanSettings
from .skill_paths import public_file_name

LOGGER = logging.getLogger(__name__)


class ScanFailure(Exception):
    def __init__(
        self,
        status_code: int,
        detail: str,
        *,
        code: str = "scan_failed",
        stage: str = "scan",
        provider_code: str | None = None,
    ):
        self.status_code = status_code
        self.detail = detail
        # 这些字段只用于返回脱敏诊断信息，不携带异常原文或模型响应内容。
        self.code = code
        self.stage = stage
        self.provider_code = provider_code
        super().__init__(detail)


class SkillScanResponse(BaseModel):
    _public_file_names: dict[str, str | None] = PrivateAttr(default_factory=dict)
    request_id: str = Field(description="请求追踪编号；调用方未填写时由服务端生成。")
    mode: Literal["full", "single"] = Field(description="本次模式：full 三阶段，single 单阶段代码审计。")
    status: Literal["completed", "review_required"] = Field(description="completed 表示通过基本输出检查，不代表安全；review_required 表示需要人工复核。")
    warnings: list[str] = Field(description="输出完整性警告；先处理这些提醒，再解释分数。空列表不保证无风险。")
    archive_sha256: str = Field(description="上传 ZIP 的 SHA-256 摘要，用于核对是否为同一份文件，不是安全判定。")
    file_count: int = Field(description="解压后的文件数量，不代表模型逐份完成了审计。")
    latency_ms: float = Field(description="服务端扫描处理耗时，单位毫秒；包含哈希、解压及子进程扫描，URL 入口还包含下载耗时；不含客户端上传和网络往返。")
    scanner_version: str = Field(description="部署环境中 aig-skill-scan 包的实际版本。")
    upstream_commit: str = Field(
        default="", description="旧版兼容字段；PyPI 安装时为空，不宣称对应某个已验证的 Git 提交。",
    )
    package_name: Literal["aig-skill-scan"] = Field(default="aig-skill-scan", description="使用的上游 Python 包名称。")
    result: dict[str, Any] = Field(
        description="上游 Agent.scan 原始结果。内部结构仅用于文档说明，不过滤扩展字段，也不重算上游分数。",
        json_schema_extra=RESULT_SCHEMA, examples=[SCAN_EXAMPLES["findings"]["value"]["result"]],
    )
    stage_reports: dict[str, str] = Field(
        description="阶段名到原始报告文本的映射，名称随模式和语言变化。full 的详细结论看代码审计和漏洞复审；不要只看 result.readme。",
        examples=[SCAN_EXAMPLES["findings"]["value"]["stage_reports"]],
    )
    sarif: dict[str, Any] | None = Field(
        default=None,
        description="仅 include_sarif=true 时返回的 SARIF 2.1.0 标准报告。默认省略此字段，不影响扫描、分数和详细审计文本。",
        examples=[SCAN_EXAMPLES["findings"]["value"]["sarif"]],
    )


def output_warnings(data: dict) -> list[str]:
    """Flag unusable upstream output without inventing a new security verdict."""
    stages = data["stage_reports"]
    if not stages:
        return ["Upstream skipped LLM auditing because no auditable content was found."]
    report = list(stages.values())[-1]
    findings = data["result"]["results"]
    blocks = len(re.findall(r"<vuln>.*?</vuln>", report, re.DOTALL))
    openings = report.count("<vuln>")
    if openings != blocks or blocks != len(findings):
        return ["Upstream vulnerability output was incomplete or could not be fully parsed."]
    if findings and "<empty>" in report:
        return ["Upstream output contains both findings and an empty-result marker."]
    if not findings and "<empty>" not in report:
        return ["Upstream returned no findings without a valid empty-result marker; review the report."]
    return []


def child_environment() -> dict[str, str]:
    allowed = {
        "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "PATH", "LANG", "LC_ALL",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE",
        "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    # httpx 会在创建客户端时初始化代理传输，即使目标地址最终命中 NO_PROXY。
    # 本机常见的 socks5 ALL_PROXY 在未安装 socksio 时会让扫描还没发请求就失败，
    # 因此只把 http/https 代理交给扫描子进程；不支持的代理会按直连处理。
    for key in list(environment):
        if key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}:
            continue
        value = environment.get(key)
        if not value:
            continue
        try:
            scheme = urlsplit(value).scheme.lower()
        except ValueError:
            scheme = ""
        if scheme not in {"http", "https"}:
            environment.pop(key, None)
    # 本地模型服务（测试夹具或本机调试端口）不能被系统代理接管。
    # Windows 环境中可能没有 NO_PROXY，或者已有值没有覆盖 localhost；补齐这两个地址，
    # 同时保留用户已有的代理例外配置。
    no_proxy = environment.get("NO_PROXY", "")
    entries = [item.strip() for item in no_proxy.split(",") if item.strip()]
    for host in ("127.0.0.1", "localhost"):
        if host not in entries:
            entries.append(host)
    environment["NO_PROXY"] = ",".join(entries)
    return environment


class SkillScanService:
    def __init__(self, settings: SkillScanSettings):
        self.settings = settings
        self.slots = threading.BoundedSemaphore(settings.max_concurrency)

    @property
    def ready(self) -> bool:
        return bool(self.settings.enabled and self.settings.api_key
                    and importlib.util.find_spec("skill_scan") is not None)

    def ensure_available(self):
        if not self.ready:
            raise ScanFailure(
                503,
                "Skill scanner is disabled, missing dependencies or not configured",
                code="scanner_unavailable",
                stage="admission",
            )

    def run_url(self, url: str, **options) -> SkillScanResponse:
        started = time.monotonic()
        # The outer HTTP endpoint holds the same admission slot throughout
        # download, scanning and cleanup. A subprocess bounds DNS and slow reads.
        with tempfile.TemporaryDirectory(prefix="ky-skill-download-") as scratch:
            root = Path(scratch)
            self._download(url, root)
            with (root / "archive.zip").open("rb") as source:
                result = self.run(source, **options)
        result.latency_ms = round((time.monotonic() - started) * 1000, 2)
        return result

    def _download(self, url: str, root: Path) -> None:
        worker = Path(__file__).with_name("skill_download.py").resolve()
        config = {"url": url, "max_bytes": self.settings.max_archive_bytes,
                  "timeout": self.settings.download_timeout_seconds,
                  "allowed_hosts": self.settings.download_allowed_hosts}
        try:
            completed = subprocess.run(
                [sys.executable, "-I", "-X", "utf8", str(worker)],
                input=json.dumps(config).encode("utf-8"), cwd=root,
                env=child_environment(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=self.settings.download_timeout_seconds, check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if completed.returncode:
                raise ValueError("download process failed")
            result = json.loads(completed.stdout)
            if result["status"] != 200:
                detail = result["detail"]
                status = result["status"]
                if status == 504:
                    code = "download_timeout"
                elif status == 413:
                    code = "archive_too_large"
                elif status == 422:
                    code = "download_invalid"
                else:
                    code = "download_failed"
                raise ScanFailure(status, detail, code=code, stage="download")
        except subprocess.TimeoutExpired as exc:
            raise ScanFailure(
                504,
                "ZIP download exceeded its time limit",
                code="download_timeout",
                stage="download",
            ) from exc
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ScanFailure(
                502,
                "Could not complete the ZIP download",
                code="download_failed",
                stage="download",
            ) from exc

    def run(self, source: BinaryIO, *, mode: str, language: str,
            prompt: str, request_id: str) -> SkillScanResponse:
        started = time.monotonic()
        source.seek(0)
        digest = hashlib.sha256()
        size = 0
        while chunk := source.read(65536):
            size += len(chunk)
            if size > self.settings.max_archive_bytes:
                raise ScanFailure(
                    413,
                    "Skill ZIP exceeds the upload size limit",
                    code="archive_too_large",
                    stage="upload",
                )
            digest.update(chunk)
        with tempfile.TemporaryDirectory(prefix="ky-skill-scan-") as scratch:
            root = Path(scratch)
            repo = root / "repo"
            repo.mkdir()
            extracted_root = repo
            count = extract_archive(source, repo, self.settings)
            repo = scan_root(repo)
            config = {
                "repo": str(repo), "mode": mode, "language": language, "prompt": prompt,
                "model": self.settings.model, "api_key": self.settings.api_key,
                "base_url": self.settings.base_url, "context_window": self.settings.context_window,
                "max_result_bytes": self.settings.max_result_bytes,
            }
            data = self._execute(root, config)
            # Validate paths while the files still exist. Keep raw reports intact.
            public_names = {}
            raw_result = data.get("result") if isinstance(data, dict) else None
            findings = raw_result.get("results", []) if isinstance(raw_result, dict) else []
            if isinstance(findings, list):
                for finding in findings:
                    name = finding.get("file") if isinstance(finding, dict) else None
                    if isinstance(name, str):
                        public_names[name] = public_file_name(name, extracted_root, repo)
        try:
            if not isinstance(data["result"]["results"], list):
                raise ValueError("invalid results")
            if not isinstance(data["stage_reports"], dict):
                raise ValueError("invalid stages")
            warnings = output_warnings(data)
            response = SkillScanResponse(
                **data, request_id=request_id or str(uuid.uuid4()), mode=mode,
                status="review_required" if warnings else "completed", warnings=warnings,
                archive_sha256=digest.hexdigest(), file_count=count,
                latency_ms=round((time.monotonic() - started) * 1000, 2),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ScanFailure(
                502,
                "Skill scanner returned invalid result data",
                code="invalid_output",
                stage="scan",
            ) from exc
        # No uploaded names, custom prompts, code, credentials or reports in shared logs.
        response._public_file_names = public_names
        LOGGER.info("Skill scan finished | status=%s | files=%d | latency_ms=%s",
                    response.status, count, response.latency_ms)
        return response

    def _execute(self, root: Path, config: dict) -> dict:
        worker = Path(__file__).with_name("skill_worker.py").resolve()
        try:
            completed = subprocess.run(
                [sys.executable, "-I", "-X", "utf8", str(worker)],
                input=json.dumps(config).encode("utf-8"), cwd=root,
                env=child_environment(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=self.settings.timeout_seconds, check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except subprocess.TimeoutExpired as exc:
            # subprocess.run kills and reaps the child before raising.
            raise ScanFailure(
                504,
                "Skill scan exceeded its time limit",
                code="scanner_timeout",
                stage="scan",
            ) from exc
        except OSError as exc:
            raise ScanFailure(
                503,
                "Unable to start Skill scanner process",
                code="scanner_start_failed",
                stage="scan",
            ) from exc
        if completed.returncode:
            diagnostic = self._read_worker_diagnostic(root)
            if diagnostic.get("kind") == "model_http_error":
                provider_code = diagnostic.get("provider_code")
                status = diagnostic.get("status_code")
                suffix = f"（{provider_code}）" if provider_code else ""
                detail = f"模型服务返回 HTTP {status}{suffix}，请检查扫描模型配置、额度或内容审核限制。"
                raise ScanFailure(
                    502,
                    detail,
                    code="model_http_error",
                    stage="scan",
                    provider_code=provider_code,
                )
            if diagnostic.get("kind") == "model_timeout":
                raise ScanFailure(
                    502,
                    "扫描模型调用超时，未生成可用结果。",
                    code="model_timeout",
                    stage="scan",
                )
            if diagnostic.get("kind") == "model_connection_error":
                raise ScanFailure(
                    502,
                    "无法连接扫描模型服务，未生成可用结果。",
                    code="model_connection_error",
                    stage="scan",
                )
            raise ScanFailure(
                502,
                "Skill scanner or its LLM failed; check model configuration and limits",
                code="scanner_failed",
                stage="scan",
            )
        try:
            result_path = root / "result.json"
            if result_path.stat().st_size > self.settings.max_result_bytes:
                raise ValueError("oversized output")
            return json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ScanFailure(
                502,
                "Skill scanner produced invalid or oversized output",
                code="invalid_output",
                stage="scan",
            ) from exc

    @staticmethod
    def _read_worker_diagnostic(root: Path) -> dict[str, Any]:
        """读取子进程写入的安全错误分类，不读取 stderr 或异常原文。"""
        path = root / "worker-diagnostic.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}
        return data if isinstance(data, dict) else {}
