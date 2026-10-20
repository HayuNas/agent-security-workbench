"""Environment-backed settings for the standalone guard service."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


_FILE_ALLOWLIST = frozenset(
    {
        "RISK_GUARD_LLM_ENABLE",
        "RISK_GUARD_DASHSCOPE_API_KEY",
        "RISK_GUARD_MODEL",
        "RISK_GUARD_DASHSCOPE_BASE_URL",
        "DASHSCOPE_API_KEY",
        "ALIYUN_GUARDRAIL_ENABLE",
        "ALIYUN_ACCESS_KEY_ID",
        "ALIYUN_ACCESS_KEY_SECRET",
        "ALIYUN_GUARDRAIL_REGION",
        "MONGO_URI",
        "MONGO_DB",
        "RISK_GUARD_AUDIT_MODE",
        "RISK_GUARD_DOCS_ENABLED",
    }
)
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICIES_PATH = _REPOSITORY_ROOT / "risk_guard" / "policies.local.json"
_LOCAL_ENV_FILES = (
    _REPOSITORY_ROOT / ".env_develop",
)


def _unquote(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _read_allowlisted_local_env() -> dict[str, str]:
    """Read fixed local development files without importing arbitrary secrets."""
    values: dict[str, str] = {}
    for path in _LOCAL_ENV_FILES:
        if not path.is_file():
            continue
        for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            if key in _FILE_ALLOWLIST:
                values[key] = _unquote(raw_value)
    return values


def _as_bool(raw: str, default: bool = False) -> bool:
    if not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class RiskGuardSettings:
    host: str = "127.0.0.1"
    port: int = 8091
    engine_version: str = "ky-risk-engine-v1"
    source_revision: str = "source-snapshot-v1"
    max_content_length: int = 100_000
    policies_path: str = ""
    api_tokens: tuple[str, ...] = field(default=(), repr=False)
    guard_llm_enable: bool = False
    dashscope_api_key: str = field(default="", repr=False)
    guard_model: str = "qwen-flash"
    dashscope_base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    aliyun_guardrail_enable: bool = False
    aliyun_access_key_id: str = field(default="", repr=False)
    aliyun_access_key_secret: str = field(default="", repr=False)
    aliyun_region: str = "cn-shanghai"
    mongo_uri: str = field(default="", repr=False)
    mongo_database: str = "ai_agent_mg_net"
    mongo_collection: str = "risk_guard_logs"
    audit_content_limit: int = 1000
    audit_mode: str = "all"
    log_level: str = "INFO"
    docs_enabled: bool = True
    admin_token: str = field(default='', repr=False)
    policy_store_path: str = ''

    @classmethod
    def from_env(cls) -> "RiskGuardSettings":
        file_values = _read_allowlisted_local_env()

        def value(name: str, default: str = "") -> str:
            process_value = os.getenv(name)
            if process_value is not None:
                return process_value.strip()
            return str(file_values.get(name, default)).strip()

        tokens = tuple(
            token.strip()
            for token in value("RISK_GUARD_API_TOKENS").split(",")
            if token.strip()
        )
        dashscope_api_key = value(
            "RISK_GUARD_DASHSCOPE_API_KEY",
            value("DASHSCOPE_API_KEY"),
        )
        aliyun_access_key_id = value("ALIYUN_ACCESS_KEY_ID")
        aliyun_access_key_secret = value("ALIYUN_ACCESS_KEY_SECRET")
        audit_mode = value("RISK_GUARD_AUDIT_MODE", "all").lower()
        if audit_mode not in {"off", "blocked", "all"}:
            raise ValueError("RISK_GUARD_AUDIT_MODE must be off, blocked, or all")
        return cls(
            admin_token=value('RISK_GUARD_ADMIN_TOKEN'),
            policy_store_path=value(
                'RISK_GUARD_POLICY_STORE',
                str(_REPOSITORY_ROOT / 'risk_guard' / '.runtime' / 'managed-policies.sqlite3')
                if value('RISK_GUARD_ADMIN_TOKEN') or tokens else '',
            ),
            host=value("RISK_GUARD_HOST", "127.0.0.1"),
            port=int(value("RISK_GUARD_PORT", "8091")),
            engine_version=value(
                "RISK_GUARD_ENGINE_VERSION",
                "ky-risk-engine-v1",
            ),
            source_revision=value(
                "RISK_GUARD_SOURCE_REVISION",
                "source-snapshot-v1",
            ),
            max_content_length=int(
                value("RISK_GUARD_MAX_CONTENT_LENGTH", "100000")
            ),
            policies_path=value(
                "RISK_GUARD_POLICIES_PATH",
                str(DEFAULT_POLICIES_PATH) if DEFAULT_POLICIES_PATH.is_file() else "",
            ),
            api_tokens=tokens,
            guard_llm_enable=_as_bool(
                value("RISK_GUARD_LLM_ENABLE"),
                default=bool(dashscope_api_key),
            ),
            dashscope_api_key=dashscope_api_key,
            guard_model=value("RISK_GUARD_MODEL", "qwen-flash"),
            dashscope_base_url=value(
                "RISK_GUARD_DASHSCOPE_BASE_URL",
                "https://dashscope.aliyuncs.com/compatible-mode/v1",
            ),
            aliyun_guardrail_enable=_as_bool(
                value("ALIYUN_GUARDRAIL_ENABLE"),
                default=bool(aliyun_access_key_id and aliyun_access_key_secret),
            ),
            aliyun_access_key_id=aliyun_access_key_id,
            aliyun_access_key_secret=aliyun_access_key_secret,
            aliyun_region=value(
                "ALIYUN_GUARDRAIL_REGION",
                "cn-shanghai",
            ),
            mongo_uri=value("RISK_GUARD_MONGO_URI", value("MONGO_URI")),
            mongo_database=value(
                "RISK_GUARD_MONGO_DATABASE",
                value("MONGO_DB", "ai_agent_mg_net"),
            ),
            mongo_collection=value(
                "RISK_GUARD_MONGO_COLLECTION",
                "risk_guard_logs",
            ),
            audit_content_limit=int(
                value("RISK_GUARD_AUDIT_CONTENT_LIMIT", "1000")
            ),
            audit_mode=audit_mode,
            log_level=value("RISK_GUARD_LOG_LEVEL", "INFO").upper(),
            docs_enabled=_as_bool(value("RISK_GUARD_DOCS_ENABLED"), default=True),
        )
