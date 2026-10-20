"""Service-only configuration; does not modify Tencent's scanner defaults/code."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .settings import RiskGuardSettings


@dataclass(frozen=True)
class SkillScanSettings:
    enabled: bool = False
    api_key: str = field(default="", repr=False)
    model: str = "qwen-flash"
    base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    context_window: int = 128_000
    timeout_seconds: float = 900
    upload_timeout_seconds: float = 60
    download_timeout_seconds: float = 60
    download_allowed_hosts: tuple[str, ...] = ()
    max_concurrency: int = 1
    max_archive_bytes: int = 10 * 1024 * 1024
    max_extracted_bytes: int = 50 * 1024 * 1024
    max_entries: int = 2000
    max_result_bytes: int = 16 * 1024 * 1024

    def __post_init__(self):
        for name in (
            "context_window", "timeout_seconds", "upload_timeout_seconds", "download_timeout_seconds",
            "max_concurrency", "max_archive_bytes", "max_extracted_bytes",
            "max_entries", "max_result_bytes",
        ):
            value = getattr(self, name)
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"Skill scan {name} must be finite and positive")
        url = urlsplit(self.base_url)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
            raise ValueError("Skill scan base_url must be an HTTP(S) URL without credentials")
        if not self.model.strip():
            raise ValueError("Skill scan model must not be empty")

    @classmethod
    def from_env(cls, guard: RiskGuardSettings) -> "SkillScanSettings":
        def value(name, fallback):
            return os.getenv("RISK_GUARD_SKILL_SCAN_" + name, "").strip() or fallback

        return cls(
            enabled=value("ENABLE", "false").lower() in {"1", "true", "yes", "on"},
            api_key=value("API_KEY", guard.dashscope_api_key),
            model=value("MODEL", guard.guard_model),
            base_url=value("BASE_URL", guard.dashscope_base_url),
            context_window=int(value("CONTEXT_WINDOW", "128000")),
            timeout_seconds=float(value("TIMEOUT_SECONDS", "900")),
            upload_timeout_seconds=float(value("UPLOAD_TIMEOUT_SECONDS", "60")),
            download_timeout_seconds=float(value("DOWNLOAD_TIMEOUT_SECONDS", "60")),
            download_allowed_hosts=tuple(host.strip().encode("idna").decode("ascii").lower()
                                         for host in value("DOWNLOAD_ALLOWED_HOSTS", "").split(",") if host.strip()),
            max_concurrency=int(value("MAX_CONCURRENCY", "1")),
            max_archive_bytes=int(value("MAX_ARCHIVE_BYTES", str(10 * 1024 * 1024))),
            max_extracted_bytes=int(value("MAX_EXTRACTED_BYTES", str(50 * 1024 * 1024))),
            max_entries=int(value("MAX_ENTRIES", "2000")),
            max_result_bytes=int(value("MAX_RESULT_BYTES", str(16 * 1024 * 1024))),
        )
