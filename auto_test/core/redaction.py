"""报告与接口错误使用的脱敏工具。"""

from __future__ import annotations

import re
from typing import Any, Mapping


MOBILE_RE = re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)")
LANDLINE_RE = re.compile(r"(?<!\d)0\d{2,3}[-\s]?\d{7,8}(?!\d)")
SERVICE_PHONE_RE = re.compile(r"(?<!\d)(?:400|800)[-\s]?\d{3}[-\s]?\d{4}(?!\d)")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\."
    r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)
SK_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{12,}")
OPAQUE_TOKEN_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])"
)
NAMED_SECRET_RE = re.compile(
    r"(?i)(\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|token|password|secret)\b"
    r"|(?:密钥|令牌|密码))\s*([:=：])\s*([^\s,，;；]+)"
)
SENSITIVE_KEY_RE = re.compile(
    r"(?i)^(?:authorization|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|"
    r"token|password|secret|密钥|令牌|密码)$"
)


def _redact_tokens(text: str) -> str:
    text = BEARER_RE.sub("Bearer <Token已脱敏>", text)
    text = JWT_RE.sub("<Token已脱敏>", text)
    text = SK_TOKEN_RE.sub("<Token已脱敏>", text)
    text = OPAQUE_TOKEN_CANDIDATE_RE.sub(
        lambda match: (
            "<Token已脱敏>"
            if any(char.isupper() for char in match.group(0))
            and any(char.islower() for char in match.group(0))
            and any(char.isdigit() for char in match.group(0))
            else match.group(0)
        ),
        text,
    )
    return NAMED_SECRET_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<已脱敏>", text
    )


def redact_text(value: Any) -> str:
    """隐藏电话、邮箱和常见 Token/密钥表达。"""

    text = "" if value is None else str(value)
    text = EMAIL_RE.sub("<邮箱已脱敏>", text)
    text = MOBILE_RE.sub("<电话已脱敏>", text)
    text = LANDLINE_RE.sub("<电话已脱敏>", text)
    text = SERVICE_PHONE_RE.sub("<电话已脱敏>", text)
    return _redact_tokens(text)


def redact_value(value: Any) -> Any:
    """递归脱敏 JSON-like 数据。"""

    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = redact_text(key)
            redacted[safe_key] = (
                "<已脱敏>"
                if SENSITIVE_KEY_RE.fullmatch(str(key).strip())
                else redact_value(item)
            )
        return redacted
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(value)


def redact_report_text(value: Any) -> str:
    """报告保留业务文本，只隐藏 Token、密钥和鉴权凭据。"""

    return _redact_tokens("" if value is None else str(value))


__all__ = ["redact_report_text", "redact_text", "redact_value"]
