#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Crescendo 攻击 Controller 与进展评估器共用的模型客户端。

安全约束：

* 只读取本模块声明的环境变量，以及 ``ky_agent/.env_develop`` 中的
  ``DASHSCOPE_API_KEY``、``DASHSCOPE_API_BASE_URL``、``MODEL_NAME``；
* API Key 不进入 ``repr``、错误信息或可序列化的安全配置；
* 供应商错误正文不向上透传，避免意外泄漏请求或鉴权信息。

本模块只负责模型通信与 JSON 解码，不会在导入时发起网络请求。
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import socket
import time
from http.client import IncompleteRead, RemoteDisconnected
from email.utils import parsedate_to_datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from .model_limits import provider_slot, ModelQueueTimeout, ModelLimitError

logger = logging.getLogger(__name__)


# 本模块位于 auto_test/clients/；项目级 .env_develop 在 ky_agent 根目录。
KY_AGENT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ENV_FILE = KY_AGENT_ROOT / ".env_develop"

# 这里只允许模型相关配置。即便 .env_develop 中还包含数据库等配置，也不会读取。
FILE_ENV_ALLOWLIST = frozenset(
    {
        "DASHSCOPE_API_KEY",
        "DASHSCOPE_API_BASE_URL",
        "MODEL_NAME",
    }
)
PROCESS_ENV_ALLOWLIST = frozenset(
    {
        "KY_AUTO_TEST_API_KEY",
        "KY_AUTO_TEST_API_BASE_URL",
        "KY_AUTO_TEST_MODEL",
        "KY_AUTO_TEST_ATTACK_MODEL",
        "KY_AUTO_TEST_JUDGE_MODEL",
        "KY_AUTO_TEST_FINDING_MODEL",
        "DASHSCOPE_API_KEY",
        "DASHSCOPE_API_BASE_URL",
        "MODEL_NAME",
    }
)


class ModelClientError(RuntimeError):
    """模型配置、通信或响应解析错误（错误文本中不包含 API Key）。"""
    def __init__(self, message, *, retryable=False, http_status=None, code='', attempts=0):
        super().__init__(message)
        self.retryable = retryable
        self.http_status = http_status
        self.code = code
        self.attempts = attempts


@dataclass(frozen=True)
class ModelSettings:
    """OpenAI-compatible 模型配置。

    ``api_key`` 被排除在 dataclass 的 ``repr`` 外；调用方若需要记录配置，应只
    使用 :meth:`safe_dict`。
    """

    api_key: str = field(repr=False)
    base_url: str
    model: str
    source: str

    def safe_dict(self) -> dict[str, Any]:
        """返回可安全写入报告的配置摘要。"""

        return {
            "provider": "openai-compatible",
            "model": self.model,
            "source": self.source,
            "api_key_present": bool(self.api_key),
        }


@dataclass(frozen=True)
class ModelResponse:
    """一次非流式 Chat Completions 响应。"""

    content: str
    model: str
    usage: dict[str, Any]
    request_id: str
    finish_reason: str = ""
    transport_attempts: int = 1
    queue_wait_seconds: float = 0.0
    retry_wait_seconds: float = 0.0

    def diagnostic(self) -> str:
        return _response_diagnostic({'choices': [{'finish_reason': self.finish_reason}],
                                     'usage': self.usage}, None)


def _response_diagnostic(data: Mapping[str, Any], limit: int | None) -> str:
    """Only allowlisted scalar metadata; never include response text or secrets."""
    choices = data.get('choices') or [{}]
    finish = choices[0].get('finish_reason')
    usage = data.get('usage') or {}
    safe = {'finish_reason': finish if finish in
            {'stop', 'length', 'content_filter', 'tool_calls', 'function_call'} else 'unknown'}
    if limit is not None:
        safe['max_tokens'] = limit
    for key in ('prompt_tokens', 'completion_tokens', 'total_tokens'):
        if isinstance(usage.get(key), int):
            safe[key] = usage[key]
    detail = usage.get('completion_tokens_details') or {}
    if isinstance(detail, Mapping) and isinstance(detail.get('reasoning_tokens'), int):
        safe['reasoning_tokens'] = detail['reasoning_tokens']
    return json.dumps(safe, ensure_ascii=False)


def _unquote_env_value(raw_value: str) -> str:
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def read_allowlisted_env(path: Path = DEFAULT_ENV_FILE) -> dict[str, str]:
    """只解析根目录 ``.env_develop`` 中的模型白名单字段。

    不支持从调用参数切换到其他 env 文件，防止测试脚本无意读取额外凭据。
    ``path`` 参数仅用于测试；真实路径必须解析为项目根目录的
    ``.env_develop``。
    """

    expected = DEFAULT_ENV_FILE.resolve()
    try:
        resolved = path.resolve()
    except OSError as exc:  # pragma: no cover - 极少见的文件系统错误
        raise ModelClientError("无法解析模型配置文件路径") from exc
    if resolved != expected:
        raise ModelClientError("只允许读取 ky_agent 根目录的 .env_develop")
    if not resolved.is_file():
        return {}

    values: dict[str, str] = {}
    try:
        lines = resolved.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise ModelClientError("无法读取 ky_agent/.env_develop") from exc
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if key in FILE_ENV_ALLOWLIST:
            values[key] = _unquote_env_value(raw_value)
    return values


def _read_process_env(key: str) -> str:
    if key not in PROCESS_ENV_ALLOWLIST:  # 防止未来调用方绕过白名单动态取值
        return ""
    return os.environ.get(key, "").strip()


def _first_nonempty(*values: str | None) -> str:
    return next((str(value).strip() for value in values if str(value or "").strip()), "")


def _validate_base_url(base_url: str) -> str:
    value = base_url.strip().rstrip("/")
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ModelClientError("模型 API Base URL 必须是有效的 http/https 地址")
    # 鉴权只能走 Authorization header，禁止把秘密放入 URL。
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ModelClientError("模型 API Base URL 不允许包含用户信息、查询参数或片段")
    return value


def load_model_settings(
    *,
    role: str = "generic",
    model_override: str | None = None,
) -> ModelSettings:
    """从白名单环境变量和根目录 ``.env_develop`` 加载模型配置。

    Args:
        role: ``attack``、``judge``、``finding`` 或 ``generic``。不同角色可通过各自的
           白名单环境变量覆盖模型名。
        model_override: 仅覆盖模型名，不允许覆盖密钥或配置文件路径。
    """

    if role not in {"generic", "attack", "judge", "finding"}:
        raise ModelClientError(f"未知模型角色：{role}")
    # 工作台在创建任务时冻结配置，仅注入该任务子进程，不修改 8092 的全局环境。
    snapshot = os.getenv("KY_WORKBENCH_MODEL_SNAPSHOT")
    if snapshot:
        try:
            value = json.loads(snapshot)[role]
            return ModelSettings(api_key=value["api_key"], base_url=_validate_base_url(value["base_url"]),
                                 model=value["model"], source=value["source"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ModelClientError("工作台模型快照无效，请重新创建任务") from None
    file_values = read_allowlisted_env()

    api_key = _first_nonempty(
        _read_process_env("KY_AUTO_TEST_API_KEY"),
        _read_process_env("DASHSCOPE_API_KEY"),
        file_values.get("DASHSCOPE_API_KEY"),
    )
    base_url = _first_nonempty(
        _read_process_env("KY_AUTO_TEST_API_BASE_URL"),
        _read_process_env("DASHSCOPE_API_BASE_URL"),
        file_values.get("DASHSCOPE_API_BASE_URL"),
    )
    role_env_key = {
        "attack": "KY_AUTO_TEST_ATTACK_MODEL",
        "judge": "KY_AUTO_TEST_JUDGE_MODEL",
        "finding": "KY_AUTO_TEST_FINDING_MODEL",
        "generic": "KY_AUTO_TEST_MODEL",
    }[role]
    model = _first_nonempty(
        model_override,
        _read_process_env(role_env_key),
        _read_process_env("KY_AUTO_TEST_MODEL"),
        _read_process_env("MODEL_NAME"),
        file_values.get("MODEL_NAME"),
    )

    missing = [
        label
        for label, value in (
            ("API Key", api_key),
            ("API Base URL", base_url),
            ("模型名", model),
        )
        if not value
    ]
    if missing:
        raise ModelClientError("模型配置缺少：" + "、".join(missing))

    uses_process_env = any(
        _read_process_env(key)
        for key in (
            "KY_AUTO_TEST_API_KEY",
            "KY_AUTO_TEST_API_BASE_URL",
            role_env_key,
            "KY_AUTO_TEST_MODEL",
            "DASHSCOPE_API_KEY",
            "DASHSCOPE_API_BASE_URL",
            "MODEL_NAME",
        )
    )
    return ModelSettings(
        api_key=api_key,
        base_url=_validate_base_url(base_url),
        model=model,
        source="process_environment+root_env" if uses_process_env else "root_env",
    )


def extract_json(text: str) -> Any:
    """从模型文本中提取第一个完整 JSON object/array。

    支持纯 JSON、Markdown fenced JSON，以及 JSON 前后夹有少量说明文字的响应。
    使用 ``JSONDecoder.raw_decode``，因此字符串内部的花括号不会破坏提取。
    """

    if not isinstance(text, str) or not text.strip():
        raise ModelClientError("模型响应为空，无法提取 JSON")
    value = text.lstrip("\ufeff").strip()

    candidates = [value]
    candidates.extend(
        match.group(1).strip()
        for match in re.finditer(
            r"```(?:json)?\s*(.*?)\s*```",
            value,
            flags=re.IGNORECASE | re.DOTALL,
        )
    )
    decoder = json.JSONDecoder()
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            return parsed

        for index, char in enumerate(candidate):
            if char not in "[{":
                continue
            try:
                parsed, _end = decoder.raw_decode(candidate[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, (dict, list)):
                return parsed
    raise ModelClientError("模型响应中没有可解析的 JSON object/array")


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, Mapping):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)
    if isinstance(content, Mapping):
        return json.dumps(content, ensure_ascii=False)
    return ""


class OpenAICompatibleClient:
    """最小化、无第三方依赖的 Chat Completions 客户端。"""

    def __init__(
        self,
        settings: ModelSettings,
        *,
        timeout: float = 120.0,
        retries: int = 2,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout 必须大于 0")
        self.settings = settings
        self.timeout = float(timeout)
        self.retries = max(1, int(retries))

    @property
    def endpoint(self) -> str:
        base_url = self.settings.base_url
        if base_url.endswith("/chat/completions"):
            return base_url
        return base_url + "/chat/completions"

    def chat(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        temperature: float = 0.0,
        max_tokens: int = 2500,
        seed: int | None = 42,
        json_mode: bool = False,
    ) -> ModelResponse:
        """调用一次非流式 Chat Completions。

        重试仅覆盖网络错误、限流与服务端错误；确定性的 4xx 请求错误不重试。
        """

        if not messages:
            raise ValueError("messages 不能为空")
        request_messages = [
            {"role": str(item.get("role") or ""), "content": str(item.get("content") or "")}
            for item in messages
        ]
        if any(not item["role"] for item in request_messages):
            raise ValueError("每条 message 都必须包含 role")

        body: dict[str, Any] = {
            "model": self.settings.model,
            "messages": request_messages,
            "temperature": float(temperature),
            "max_tokens": int(max_tokens),
            "stream": False,
        }
        if seed is not None:
            # Providers may reject unsigned 32-bit seeds as invalid integers.
            body["seed"] = int(seed) % (2 ** 31)
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")

        last_error: ModelClientError | None = None
        queue_wait = 0.0
        retry_wait = 0.0
        call_started = time.monotonic()
        def remaining_timeout(slot):
            remaining = self.timeout - (time.monotonic() - call_started - queue_wait - slot['queue_wait_seconds'])
            if remaining <= 0:
                raise ModelClientError('模型请求及退避总等待预算已耗尽，停止重试',
                                       code='request_budget_exhausted', attempts=attempt-1)
            return min(self.timeout, remaining)
        for attempt in range(1, self.retries + 1):
            request = Request(
                self.endpoint,
                data=encoded,
                headers={
                    "Authorization": f"Bearer {self.settings.api_key}",
                    "Content-Type": "application/json; charset=utf-8",
                    "Accept": "application/json",
                    "User-Agent": "ky-agent-auto-test",
                },
                method="POST",
            )
            retryable = False
            retry_after = 0.0
            slot = None
            queue_counted = False
            try:
                with provider_slot(self.settings.base_url, self.settings.api_key) as slot, urlopen(request, timeout=remaining_timeout(slot)) as response:
                    queue_wait += slot['queue_wait_seconds']
                    queue_counted = True
                    raw = response.read().decode("utf-8", errors="replace")
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError as exc:
                        raise ModelClientError("模型 API 返回了无效 JSON") from exc
                    if not isinstance(data, Mapping):
                        raise ModelClientError("模型 API 响应结构不是 JSON object")
                    choices = data.get("choices")
                    if not isinstance(choices, list) or not choices:
                        raise ModelClientError("模型 API 响应缺少 choices")
                    first_choice = choices[0]
                    if not isinstance(first_choice, Mapping):
                        raise ModelClientError("模型 API choices[0] 结构无效")
                    message = first_choice.get("message")
                    content = _content_to_text(
                        message.get("content") if isinstance(message, Mapping) else first_choice.get("text")
                    ).strip()
                    diagnostic = _response_diagnostic(data, int(max_tokens))
                    if first_choice.get('finish_reason') == 'length':
                        raise ModelClientError("模型输出额度耗尽，响应不完整；" + diagnostic)
                    if not content:
                        raise ModelClientError("模型 API 返回了空内容；" + diagnostic)
                    usage = data.get("usage")
                    return ModelResponse(
                        content=content,
                        model=str(data.get("model") or self.settings.model),
                        usage=dict(usage) if isinstance(usage, Mapping) else {},
                        request_id=str(
                            response.headers.get("x-request-id")
                            or data.get("request_id")
                            or data.get("id")
                            or ""
                        ),
                        finish_reason=str(first_choice.get('finish_reason') or ''),
                        transport_attempts=attempt, queue_wait_seconds=queue_wait,
                        retry_wait_seconds=retry_wait,
                    )
            except ModelQueueTimeout as exc:
                last_error = ModelClientError(str(exc), code='local_queue_timeout', attempts=attempt-1)
            except ModelLimitError as exc:
                last_error = ModelClientError(str(exc), code='local_limit_error', attempts=attempt-1)
            except HTTPError as exc:
                # 只识别白名单错误码，绝不透传供应商可能回显请求的 message。
                error_code = ''
                try:
                    error_body = json.loads(exc.read(16384))
                    error = error_body.get('error', {})
                    if isinstance(error, Mapping):
                        error_code = error.get('code') or error.get('type') or ''
                except Exception:
                    pass
                finally:
                    exc.close()
                if not isinstance(error_code, str):
                    error_code = ''
                retryable = exc.code in {408, 429} or exc.code >= 500
                if error_code in {'insufficient_quota', 'quota_exhausted', 'Arrearage'}:
                    retryable = False
                value = exc.headers.get('Retry-After') if exc.headers else None
                if value:
                    try:
                        retry_after = max(0.0, float(value))
                    except (TypeError, ValueError):
                        try: retry_after = max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
                        except (TypeError, ValueError, OverflowError): retry_after = 0.0
                if error_code == 'data_inspection_failed':
                    retryable = False
                    last_error = ModelClientError(
                        '模型供应商内容审核拒绝了生成请求（data_inspection_failed，HTTP 400）。'
                        '这不是被测 Agent 的检测结果。请使用允许该评测用途的模型配置，或选择已有用例测试；系统不会自动重试。',
                        http_status=exc.code, code='data_inspection_failed',
                    )
                else:
                    safe_code = error_code if error_code in {'invalid_value', 'invalid_request_error', 'rate_limit_exceeded', 'context_length_exceeded', 'insufficient_quota', 'quota_exhausted', 'Arrearage', 'Throttling', 'Throttling.RateQuota', 'Throttling.AllocationQuota'} else 'unknown'
                    last_error = ModelClientError(f"模型 API HTTP 错误：{exc.code}；code={safe_code}；max_tokens={max_tokens}；seed={body.get('seed')}",
                                                  retryable=retryable, http_status=exc.code, code=safe_code)
            except (IncompleteRead, RemoteDisconnected) as exc:
                retryable = True
                last_error = ModelClientError(f"模型 API 连接中断：{type(exc).__name__}", retryable=True, code='connection_interrupted')
            except (URLError, TimeoutError, socket.timeout) as exc:
                retryable = True
                last_error = ModelClientError(f"模型 API 网络错误：{type(exc).__name__}", retryable=True, code='network_error')
            except OSError as exc:
                retryable = True
                last_error = ModelClientError(f"模型 API IO 错误：{type(exc).__name__}", retryable=True, code='io_error')
            except ModelClientError as exc:
                last_error = exc

            if slot and not queue_counted:
                queue_wait += slot['queue_wait_seconds']
            if not retryable or attempt >= self.retries:
                break
            # Retry the same pure model request, never the surrounding Agent session.
            # A long Retry-After is not shortened into another premature request.
            if retry_after > 30:
                break
            delay = max(retry_after, min(2 ** attempt, 16) + random.uniform(0, .5))
            if time.monotonic() - call_started - queue_wait + delay >= self.timeout:
                break
            logger.warning('模型请求暂时失败，%.1f 秒后进行第 %s/%s 次尝试；原因=%s',
                           delay, attempt+1, self.retries, last_error.code or type(last_error).__name__)
            time.sleep(delay)
            retry_wait += delay
        if last_error and last_error.code not in {'local_queue_timeout','local_limit_error','request_budget_exhausted'}:
            last_error.attempts = attempt
        raise last_error or ModelClientError("模型 API 调用失败")

    def chat_json(
        self,
        messages: Sequence[Mapping[str, str]],
        **kwargs: Any,
    ) -> tuple[Any, ModelResponse]:
        """调用模型并将返回文本健壮地提取为 JSON。"""

        kwargs.setdefault("json_mode", True)
        response = self.chat(messages, **kwargs)
        try:
            return extract_json(response.content), response
        except ModelClientError as exc:
            diagnostic = _response_diagnostic({'choices': [{'finish_reason': response.finish_reason}],
                                               'usage': response.usage}, int(kwargs.get('max_tokens', 2500)))
            raise ModelClientError(str(exc) + '；' + diagnostic, code='invalid_json',
                                   attempts=getattr(response,'transport_attempts',1)) from exc


__all__ = [
    "DEFAULT_ENV_FILE",
    "FILE_ENV_ALLOWLIST",
    "PROCESS_ENV_ALLOWLIST",
    "ModelClientError",
    "ModelResponse",
    "ModelSettings",
    "OpenAICompatibleClient",
    "extract_json",
    "load_model_settings",
    "read_allowlisted_env",
]
