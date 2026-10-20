"""ky-agent 黑盒测试目标客户端。

只负责初始化测试 Session、读取 Chat SSE 与生成隔离身份；不包含 Suite、Clean、
业务评测或报告逻辑。
"""

from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen as _system_urlopen, build_opener, ProxyHandler
from urllib.parse import urlsplit

from .trace import SSETraceBuilder
from ..core.redaction import redact_value
from ..oracles.price_evidence import short_tool_name


DEFAULT_BASE_URL = "https://service.example"

# 默认公司 Agent 直连，避免桌面代理退出后遗留的 HTTP_PROXY 使请求落到错误网关。
# 仅处理这个已知服务域名；自定义目标仍遵循原来的系统网络配置，模型请求不受影响。
_direct_target_opener = build_opener(ProxyHandler({}))


def urlopen(request, timeout=None):
    address = request.full_url if isinstance(request, Request) else str(request)
    if urlsplit(address).hostname == urlsplit(DEFAULT_BASE_URL).hostname:
        return _direct_target_opener.open(request, timeout=timeout)
    return _system_urlopen(request, timeout=timeout)
FIXED_CUSTOMER_ID = 100001
FIXED_CUSTOMER_CONTACT_ID = 200001
FIXED_SOURCE = "wechat"
SIDE_EFFECT_TOOLS = frozenset(
    {"create_crm_order", "ky_set_todo_task", "ky_inform_human", "product_sample"}
)


class KyAgentError(RuntimeError):
    """测试接口通信或协议错误。"""


@dataclass(frozen=True)
class SessionInfo:
    agent_type: str
    user_id: str
    agent_id: str
    session_id: str
    wx_account: str
    wx_contact: str


def _compact_id(value: str, maximum: int = 60) -> str:
    safe = "".join(
        ch if ((ch.isascii() and ch.isalnum()) or ch in "-_") else "_"
        for ch in str(value)
    )
    return (safe.strip("-_") or "TEST")[:maximum]


def _observed_side_effect(trace: Mapping[str, Any]) -> str:
    for entry in list(trace.get("tool_calls") or []) + list(
        trace.get("tool_results") or []
    ):
        name = short_tool_name(str(entry.get("name") or ""))
        if name in SIDE_EFFECT_TOOLS:
            return name
    return ""


class KyAgentClient:
    """无第三方依赖的 ky-agent 测试接口客户端。"""

    def __init__(
        self,
        *,
        base_url: str,
        api_token: str,
        request_timeout: float,
        chat_timeout: float,
        idle_timeout: float,
        artifact_char_limit: int,
        save_raw_events: bool,
        init_interval: float,
        chat_retries: int = 1,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.request_timeout = float(request_timeout)
        self.chat_timeout = float(chat_timeout)
        self.idle_timeout = float(idle_timeout)
        self.artifact_char_limit = int(artifact_char_limit)
        self.save_raw_events = bool(save_raw_events)
        self.init_interval = max(0.0, float(init_interval))
        self.chat_retries = max(1, int(chat_retries))
        self._last_init_started = 0.0
        self._init_throttle_lock = threading.Lock()

    def _headers(self, user_id: str | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "ky-agent-security-test",
        }
        if self.api_token:
            headers["token"] = self.api_token
        if user_id:
            headers["X-User-ID"] = user_id
        return headers

    def _throttle_init(self) -> None:
        with self._init_throttle_lock:
            remaining = self.init_interval - (
                time.monotonic() - self._last_init_started
            )
            if remaining > 0:
                time.sleep(remaining)
            self._last_init_started = time.monotonic()

    def _json_request(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        *,
        timeout: float | None = None,
        retries: int = 1,
        throttle_init: bool = False,
    ) -> dict[str, Any]:
        encoded = (
            None
            if body is None
            else json.dumps(dict(body), ensure_ascii=False).encode("utf-8")
        )
        last_error: Exception | None = None
        for attempt in range(1, max(1, retries) + 1):
            if throttle_init:
                self._throttle_init()
            request = Request(
                f"{self.base_url}{path}",
                data=encoded,
                headers=self._headers(),
                method=method,
            )
            retryable = False
            retry_after = 0.0
            try:
                with urlopen(
                    request, timeout=timeout or self.request_timeout
                ) as response:
                    raw = response.read().decode("utf-8", errors="replace")
                    if not raw.strip():
                        return {}
                    data = json.loads(raw)
                    if not isinstance(data, dict):
                        raise KyAgentError(f"{path} 未返回 JSON object")
                    return data
            except HTTPError as exc:
                detail = str(
                    redact_value(
                        exc.read().decode("utf-8", errors="replace")[:1000]
                    )
                )
                retryable = exc.code == 429 or exc.code >= 500
                if exc.code == 429:
                    try:
                        retry_after = float(exc.headers.get("Retry-After") or 0)
                    except (TypeError, ValueError):
                        retry_after = 0.0
                last_error = KyAgentError(f"{path} HTTP {exc.code}: {detail}")
            except (
                URLError,
                TimeoutError,
                socket.timeout,
                json.JSONDecodeError,
            ) as exc:
                retryable = True
                last_error = KyAgentError(
                    f"{path} 请求或解析失败：{type(exc).__name__}"
                )
            if not retryable or attempt >= max(1, retries):
                break
            time.sleep(max(retry_after, min(2 ** (attempt - 1), 8)))
        raise last_error or KyAgentError(f"{path} 请求失败")

    def health(self) -> dict[str, Any]:
        return self._json_request("GET", "/api/health", timeout=15, retries=1)

    def init_test(self, *, wx_account: str, wx_contact: str) -> SessionInfo:
        body = {
            "wx_account": wx_account,
            "wx_contact": wx_contact,
            "source": FIXED_SOURCE,
            "agent_types": ["ky-sales"],
        }
        data = self._json_request(
            "POST", "/api/init_test", body, retries=3, throttle_init=True
        )
        results = data.get("results") or []
        if not data.get("ok") or not results or not isinstance(results[0], Mapping):
            diagnostic = redact_value(
                {
                    "ok": data.get("ok"),
                    "code": data.get("code"),
                    "status": data.get("status"),
                    "message": str(data.get("message") or data.get("error") or "")[:500],
                    "result_count": len(results) if isinstance(results, list) else 0,
                    "response_keys": sorted(str(key) for key in data)[:30],
                }
            )
            raise KyAgentError(
                "init_test 未返回可用的 ky-sales 会话；诊断="
                + json.dumps(diagnostic, ensure_ascii=False, separators=(",", ":"))
            )
        result = results[0]
        missing = [
            key
            for key in ("user_id", "agent_id", "session_id")
            if not result.get(key)
        ]
        if missing:
            raise KyAgentError(f"init_test 缺少字段：{missing}")
        session = SessionInfo(
            agent_type=str(result.get("agent_type") or "ky-sales"),
            user_id=str(result["user_id"]),
            agent_id=str(result["agent_id"]),
            session_id=str(result["session_id"]),
            wx_account=wx_account,
            wx_contact=wx_contact,
        )
        expected = f"+{FIXED_CUSTOMER_ID}+{FIXED_CUSTOMER_CONTACT_ID}+"
        if expected not in session.user_id:
            raise KyAgentError(
                f"init_test 返回了意外客户映射；user_id 应包含 {expected!r}"
            )
        if wx_account not in session.user_id or wx_contact not in session.user_id:
            raise KyAgentError("init_test 返回的 user_id 未包含本次 wx 身份")
        return session

    def _set_stream_idle_timeout(self, response: Any) -> None:
        candidates = [
            getattr(getattr(response, "fp", None), "raw", None),
            getattr(response, "fp", None),
        ]
        for candidate in candidates:
            sock = getattr(candidate, "_sock", None)
            if sock is not None and hasattr(sock, "settimeout"):
                sock.settimeout(self.idle_timeout)
                return

    def _chat_once(self, session: SessionInfo, message: str) -> dict[str, Any]:
        body = {
            "agent_id": session.agent_id,
            "session_id": session.session_id,
            "input": {
                "name": "user",
                "content": [{"type": "text", "text": message}],
                "role": "user",
            },
        }
        request = Request(
            f"{self.base_url}/chat/",
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers=self._headers(user_id=session.user_id),
            method="POST",
        )
        started = time.monotonic()
        trace_builder = SSETraceBuilder(
            artifact_char_limit=self.artifact_char_limit,
            save_raw_events=self.save_raw_events,
        )
        stream_end_reason = "eof"
        request_id = ""
        try:
            with urlopen(request, timeout=self.chat_timeout) as response:
                request_id = str(response.headers.get("x-request-id") or "")
                self._set_stream_idle_timeout(response)
                while True:
                    if time.monotonic() - started > self.chat_timeout:
                        stream_end_reason = "total_timeout"
                        break
                    try:
                        raw_line = response.readline()
                    except socket.timeout:
                        stream_end_reason = "idle_timeout"
                        break
                    if not raw_line:
                        break
                    if trace_builder.feed_line(raw_line):
                        stream_end_reason = "done_event"
                        break
        except HTTPError as exc:
            detail = str(
                redact_value(
                    exc.read().decode("utf-8", errors="replace")[:1000]
                )
            )
            raise KyAgentError(f"chat HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError, socket.timeout) as exc:
            raise KyAgentError(f"chat 请求失败：{type(exc).__name__}") from exc
        return trace_builder.build(
            request_id=request_id,
            duration_seconds=time.monotonic() - started,
            stream_end_reason=stream_end_reason,
        )

    def chat(
        self,
        session: SessionInfo,
        message: str,
        *,
        allow_transport_retry: bool = False,
    ) -> dict[str, Any]:
        attempts: list[dict[str, Any]] = []
        overall_started = time.monotonic()
        for attempt in range(1, self.chat_retries + 1):
            is_last = attempt >= self.chat_retries
            attempt_started = time.monotonic()
            try:
                trace = self._chat_once(session, message)
            except KyAgentError as exc:
                if is_last or not allow_transport_retry:
                    raise
                attempts.append(
                    {
                        "attempt": attempt,
                        "reason": f"传输失败：{type(exc).__name__}",
                        "duration_seconds": round(
                            time.monotonic() - attempt_started, 3
                        ),
                        "tool_call_count": 0,
                        "tool_result_count": 0,
                        "tool_names": [],
                    }
                )
                time.sleep(min(2 ** (attempt - 1), 8))
                continue
            if str(trace.get("reply") or "").strip() or is_last:
                trace["attempt_count"] = attempt
                trace["retry_count"] = len(attempts)
                trace["total_duration_seconds"] = round(
                    time.monotonic() - overall_started, 3
                )
                if attempts:
                    trace["retry_attempts"] = attempts
                return trace
            side_effect = _observed_side_effect(trace)
            if side_effect:
                trace["attempt_count"] = attempt
                trace["retry_count"] = len(attempts)
                trace["total_duration_seconds"] = round(
                    time.monotonic() - overall_started, 3
                )
                trace["retry_blocked_by_side_effect"] = side_effect
                trace["retry_attempts"] = attempts
                trace.setdefault("errors", []).append(
                    f"空回复但已触发副作用工具 {side_effect}，不重试"
                )
                return trace
            attempts.append(
                {
                    "attempt": attempt,
                    "reason": "空回复",
                    "duration_seconds": trace.get("duration_seconds"),
                    "stream_end_reason": trace.get("stream_end_reason"),
                    "event_type_counts": trace.get("event_type_counts"),
                    "tool_call_count": len(trace.get("tool_calls") or []),
                    "tool_result_count": len(trace.get("tool_results") or []),
                    "tool_names": list(
                        dict.fromkeys(
                            short_tool_name(str(item.get("name") or ""))
                            for item in trace.get("tool_calls") or []
                            if str(item.get("name") or "")
                        )
                    ),
                }
            )
            time.sleep(min(2 ** (attempt - 1), 8))
        raise KyAgentError("chat 重试后仍未获得回复")


def build_test_identity(
    *,
    run_id: str,
    scenario_group_id: str,
    case: Mapping[str, Any],
    repeat_index: int,
) -> tuple[str, str]:
    role = str(case.get("variant") or "attack").upper()
    case_id = str(case.get("case_id") or "")
    digest = hashlib.sha256(
        f"{role}|{run_id}|{scenario_group_id}|{case_id}|R{repeat_index}".encode(
            "utf-8"
        )
    ).hexdigest()[:10]
    readable = _compact_id(
        f"AUTOTEST_{role}_{run_id}_{case_id}_R{repeat_index}", 60
    )
    base = f"{readable}_{digest}"
    return f"{base}_ACCOUNT", f"{base}_CONTACT"


__all__ = [
    "DEFAULT_BASE_URL",
    "FIXED_CUSTOMER_CONTACT_ID",
    "FIXED_CUSTOMER_ID",
    "KyAgentClient",
    "KyAgentError",
    "SessionInfo",
    "build_test_identity",
]
