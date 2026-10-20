"""Small, auditable transforms applied to messages at send time."""

from __future__ import annotations

from typing import Any


def normalize_message_prefix(value: Any) -> str:
    prefix = str(value or "")
    if len(prefix) > 100:
        raise ValueError("--message-prefix 不能超过 100 个字符")
    if "\r" in prefix or "\n" in prefix:
        raise ValueError("--message-prefix 不能包含换行")
    return prefix


def apply_message_prefix(message: Any, prefix: Any) -> str:
    """Prepend a target wake phrase once while preserving the source query."""

    text = str(message or "")
    normalized_prefix = normalize_message_prefix(prefix)
    if not normalized_prefix:
        return text
    if text.lstrip().casefold().startswith(normalized_prefix.strip().casefold()):
        return text
    return normalized_prefix + text


__all__ = ["apply_message_prefix", "normalize_message_prefix"]
