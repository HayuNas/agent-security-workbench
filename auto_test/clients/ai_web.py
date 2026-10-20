"""Authenticated ai-web single-turn Agent client.

The adapter deliberately exposes the same small surface as ``KyAgentClient``
so the EPE runner and the fixed-message regression runner can share their
execution and Oracle code.  Credentials are accepted only at runtime and are
never included in the returned session or trace dictionaries.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from datetime import datetime
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ..core.redaction import redact_value
from .target import SessionInfo


DEFAULT_AI_WEB_BASE_URL = "https://service.example"


class AIWebError(RuntimeError):
    """ai-web authentication, transport, or response-contract error."""


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _response_data(payload: Any, *, path: str) -> Any:
    """Unwrap the platform's common ``code/isSuccess/data`` envelope."""

    value = _mapping(payload)
    if value is None:
        return payload
    def failure_message(default: str) -> str:
        message = str(value.get("msg") or value.get("errmsg") or default)
        details: list[str] = []
        for key in ("error", "errors", "data"):
            detail = value.get(key)
            if detail in (None, "", [], {}):
                continue
            safe = redact_value(detail)
            rendered = (
                json.dumps(safe, ensure_ascii=False, separators=(",", ":"))
                if isinstance(safe, (Mapping, list))
                else str(safe)
            )
            if rendered and rendered != message:
                details.append(f"{key}={rendered[:1000]}")
        suffix = " | " + " | ".join(details) if details else ""
        return str(redact_value(message)) + suffix

    if "isSuccess" in value and not bool(value.get("isSuccess")):
        raise AIWebError(f"{path} 返回失败：{failure_message('request failed')}")
    code = value.get("code")
    if code is not None:
        try:
            numeric_code = int(code)
        except (TypeError, ValueError):
            numeric_code = 0
        if numeric_code and not 200 <= numeric_code < 300:
            raise AIWebError(
                f"{path} 返回失败：{failure_message(f'code={code}') }"
            )
    return value.get("data") if "data" in value else value


def _rows(value: Any) -> list[dict[str, Any]]:
    """Extract DTO rows from raw arrays and common nested page envelopes."""

    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, Mapping)]
    current = _mapping(value)
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        for key in ("data", "rows", "items", "list"):
            nested = current.get(key)
            if isinstance(nested, list):
                return [
                    dict(item) for item in nested if isinstance(item, Mapping)
                ]
            if isinstance(nested, Mapping):
                current = nested
                break
        else:
            return [dict(current)] if current else []
    return []


def _chat_id(value: Any) -> str:
    """Find the conversation identifier declared by ``AIChatHistorysDto``."""

    if isinstance(value, Mapping):
        direct = str(value.get("aiChatsId") or "").strip()
        if direct:
            return direct
        for nested in value.values():
            found = _chat_id(nested)
            if found:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = _chat_id(nested)
            if found:
                return found
    return ""


def _history_id(row: Mapping[str, Any]) -> str:
    return str(row.get("id") or "").strip()


def _is_agent_message(row: Mapping[str, Any]) -> bool:
    """Swagger defines ``isSend=true`` as sender/user, false as receiver/AI."""

    return row.get("isSend") is False and bool(str(row.get("content") or "").strip())


def _sort_key(row: Mapping[str, Any]) -> tuple[str, str]:
    return (str(row.get("createTime") or ""), _history_id(row))


class AIWebClient:
    """Single-turn ai-web adapter used by authorized EPE runs."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_AI_WEB_BASE_URL,
        app_id: str,
        target_key: str,
        api_token: str = "",
        username: str = "",
        password: str = "",
        tenant_id: int = 1000,
        request_timeout: float = 60.0,
        chat_timeout: float = 240.0,
        poll_interval: float = 1.0,
        verify_tls: bool = True,
    ) -> None:
        if not str(app_id).isdigit() or not 18 <= len(str(app_id)) <= 20:
            raise ValueError("ai-web appId 必须是 18 至 20 位数字字符串")
        self.base_url = str(base_url).rstrip("/")
        self.app_id = str(app_id)
        self.target_key = str(target_key)
        self._api_token = str(api_token).strip()
        self._username = str(username).strip()
        self._password = str(password)
        self._tenant_id = int(tenant_id)
        self.request_timeout = float(request_timeout)
        self.chat_timeout = float(chat_timeout)
        self.poll_interval = max(0.1, float(poll_interval))
        self.verify_tls = bool(verify_tls)
        self._auth_lock = threading.Lock()
        self._session_state_lock = threading.Lock()
        self._session_locks: dict[str, Any] = {}
        self._failed_sessions: set[str] = set()

    def _ssl_context(self) -> ssl.SSLContext | None:
        return None if self.verify_tls else ssl._create_unverified_context()

    def _request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        *,
        authenticated: bool = True,
        timeout: float | None = None,
    ) -> Any:
        token = self._ensure_token() if authenticated else ""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "ky-agent-security-test/ai-web",
        }
        if token:
            headers["Authorization"] = (
                token if token.casefold().startswith("bearer ") else f"Bearer {token}"
            )
        encoded = (
            None
            if body is None
            else json.dumps(dict(body), ensure_ascii=False).encode("utf-8")
        )
        request = Request(
            f"{self.base_url}{path}",
            data=encoded,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(
                request,
                timeout=timeout or self.request_timeout,
                context=self._ssl_context(),
            ) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            detail = str(
                redact_value(exc.read().decode("utf-8", errors="replace")[:1000])
            )
            raise AIWebError(f"{path} HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError, socket.timeout) as exc:
            raise AIWebError(f"{path} 请求失败：{type(exc).__name__}") from exc
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AIWebError(f"{path} 未返回有效 JSON") from exc

    def _ensure_token(self) -> str:
        if self._api_token:
            return self._api_token
        with self._auth_lock:
            if self._api_token:
                return self._api_token
            if not self._username or not self._password:
                raise AIWebError(
                    "缺少 ai-web 凭证；设置 KY_AI_WEB_TOKEN，或同时设置 "
                    "KY_AI_WEB_USERNAME、KY_AI_WEB_PASSWORD、KY_AI_WEB_TENANT_ID"
                )
            payload = self._request_json(
                "POST",
                "/api/Authorize/GetToken",
                {
                    "name": self._username,
                    "passWord": self._password,
                    "tenantId": self._tenant_id,
                },
                authenticated=False,
            )
            token = str(_response_data(payload, path="/api/Authorize/GetToken") or "").strip()
            if not token:
                raise AIWebError("/api/Authorize/GetToken 未返回 Token")
            self._api_token = token
            return token

    def health(self) -> dict[str, Any]:
        payload = self._request_json("GET", "/api/AIApps/GetMyALLList")
        data = _response_data(payload, path="/api/AIApps/GetMyALLList")
        apps = _rows(data)
        visible_ids = {str(item.get("id") or "") for item in apps}
        return {
            "ok": self.app_id in visible_ids,
            "adapter": "ai-web",
            "target_key": self.target_key,
            "app_id": self.app_id,
            "visible_app_count": len(apps),
            "target_visible": self.app_id in visible_ids,
        }

    def get_app_details(self) -> dict[str, Any]:
        path = "/api/AIApps/GetDetails?" + urlencode({"Id": self.app_id})
        payload = self._request_json("GET", path)
        data = _response_data(payload, path="/api/AIApps/GetDetails")
        if not isinstance(data, Mapping):
            raise AIWebError("/api/AIApps/GetDetails 未返回 Agent 详情")
        details = dict(data)
        if str(details.get("id") or "") != self.app_id:
            raise AIWebError("/api/AIApps/GetDetails 返回了错误的 appId")
        return details

    def list_prompts(self) -> list[dict[str, Any]]:
        payload = self._request_json("GET", "/api/AIPrompts/GetALLList")
        data = _response_data(payload, path="/api/AIPrompts/GetALLList")
        return _rows(data)

    def get_skill_details(self, skill_id: str) -> dict[str, Any]:
        clean_id = str(skill_id).strip()
        if not clean_id:
            raise ValueError("skill_id 不能为空")
        path = "/api/AISkillToolManagement/GetById?" + urlencode({"Id": clean_id})
        payload = self._request_json("GET", path)
        data = _response_data(payload, path="/api/AISkillToolManagement/GetById")
        if not isinstance(data, Mapping):
            raise AIWebError("/api/AISkillToolManagement/GetById 未返回 Skill 详情")
        return dict(data)

    def download_file(self, file_id: str) -> bytes:
        clean_id = str(file_id).strip()
        if not clean_id:
            raise ValueError("file_id 不能为空")
        token = self._ensure_token()
        authorization = (
            token if token.casefold().startswith("bearer ") else f"Bearer {token}"
        )
        path = "/api/File/GetFile?" + urlencode({"fileid": clean_id})
        request = Request(
            f"{self.base_url}{path}",
            headers={
                "Accept": "application/octet-stream, application/zip, text/plain",
                "Authorization": authorization,
                "User-Agent": "ky-agent-security-test/ai-web",
            },
            method="GET",
        )
        try:
            with urlopen(
                request,
                timeout=self.request_timeout,
                context=self._ssl_context(),
            ) as response:
                content = response.read()
        except HTTPError as exc:
            detail = str(
                redact_value(exc.read().decode("utf-8", errors="replace")[:1000])
            )
            raise AIWebError(f"/api/File/GetFile HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError, socket.timeout) as exc:
            raise AIWebError(
                f"/api/File/GetFile 请求失败：{type(exc).__name__}"
            ) from exc
        if not content:
            raise AIWebError("/api/File/GetFile 返回空文件")
        return content

    def _history_rows(self, ai_chats_id: str) -> list[dict[str, Any]]:
        payload = self._request_json(
            "POST",
            "/api/AIChatHistorys/GetPageData",
            {"whereId": str(ai_chats_id), "pageNum": 1, "pageSize": 100},
        )
        data = _response_data(payload, path="/api/AIChatHistorys/GetPageData")
        return sorted(_rows(data), key=_sort_key)

    def _find_chat_by_name(self, name: str) -> str:
        payload = self._request_json(
            "POST",
            "/api/AIChats/GetMyPageData",
            {"searchKey": name, "pageNum": 1, "pageSize": 20},
        )
        data = _response_data(payload, path="/api/AIChats/GetMyPageData")
        matches = [
            item
            for item in _rows(data)
            if str(item.get("name") or "") == name
            and str(item.get("appId") or "") == self.app_id
        ]
        if len(matches) != 1:
            return ""
        return str(matches[0].get("id") or "").strip()

    def init_test(self, *, wx_account: str, wx_contact: str) -> SessionInfo:
        suffix = str(wx_account or wx_contact or int(time.time()))[:180]
        name = f"提示词泄露测试-{suffix}"
        payload = self._request_json(
            "POST",
            "/api/AIChats/Add",
            {
                "appId": self.app_id,
                "name": name,
                # Match the platform's own MyAIChat.vue request exactly. The
                # Swagger DTO marks this nullable, but the backend currently
                # fails with a generic errmsg when the property is omitted.
                "lastMessage": "",
            },
        )
        data = _response_data(payload, path="/api/AIChats/Add")
        ai_chats_id = _chat_id(data) or self._find_chat_by_name(name)
        if not ai_chats_id:
            raise AIWebError("/api/AIChats/Add 未返回且无法定位 aiChatsId")
        return SessionInfo(
            agent_type=self.target_key,
            user_id="ai-web-authenticated-user",
            agent_id=self.app_id,
            session_id=ai_chats_id,
            wx_account=wx_account,
            wx_contact=wx_contact,
        )

    def _direct_agent_reply(self, value: Any) -> dict[str, Any] | None:
        candidates = _rows(value)
        replies = [item for item in candidates if _is_agent_message(item)]
        return max(replies, key=_sort_key) if replies else None

    def chat(
        self,
        session: SessionInfo,
        message: str,
        *,
        allow_transport_retry: bool = False,
    ) -> dict[str, Any]:
        with self._session_state_lock:
            lock = self._session_locks.setdefault(session.session_id, threading.Lock())
        with lock:
            if session.session_id in self._failed_sessions:
                raise AIWebError('该会话此前请求失败或超时，禁止续发以免迟到回复串轮；请新建会话')
            try:
                return self._chat_once(session, message, allow_transport_retry=allow_transport_retry)
            except Exception:
                self._failed_sessions.add(session.session_id)
                raise

    def _chat_once(
        self,
        session: SessionInfo,
        message: str,
        *,
        allow_transport_retry: bool = False,
    ) -> dict[str, Any]:
        """Send once and poll history; mutating requests are never retried."""

        del allow_transport_retry
        started = time.monotonic()
        baseline = self._history_rows(session.session_id)
        baseline_ids = {_history_id(item) for item in baseline if _history_id(item)}
        payload = self._request_json(
            "POST",
            "/api/AIChatHistorys/Add",
            {
                "aiChatsId": session.session_id,
                "content": str(message),
                "isSend": True,
                "msgType": 1,
                "isOnlineSearch": False,
            },
            timeout=self.chat_timeout,
        )
        data = _response_data(payload, path="/api/AIChatHistorys/Add")
        reply_row = self._direct_agent_reply(data)
        if reply_row is not None and (
            _history_id(reply_row) in baseline_ids
            or str(reply_row.get('aiChatsId') or session.session_id) != session.session_id
        ):
            reply_row = None
        deadline = started + self.chat_timeout
        while reply_row is None and time.monotonic() < deadline:
            time.sleep(self.poll_interval)
            current = self._history_rows(session.session_id)
            new_agent_rows = [
                item
                for item in current
                if _is_agent_message(item)
                and _history_id(item)
                and _history_id(item) not in baseline_ids
                and str(item.get('aiChatsId') or session.session_id) == session.session_id
            ]
            if new_agent_rows:
                reply_row = max(new_agent_rows, key=_sort_key)
        if reply_row is None:
            raise AIWebError("发送消息后未在时限内取得目标 Agent 回复")
        return {
            "reply": str(reply_row.get("content") or ""),
            "adapter": "ai-web",
            "trace_capabilities": {"tool_calls": False, "tool_results": False, "thinking": False},
            "request_id": "",
            "duration_seconds": round(time.monotonic() - started, 3),
            "stream_end_reason": "history_response",
            "retry_count": 0,
            "errors": [],
            "tool_calls": [],
            "tool_results": [],
            "response_history_id": _history_id(reply_row),
            "response_created_at": str(reply_row.get("createTime") or ""),
            "received_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        }


__all__ = ["AIWebClient", "AIWebError", "DEFAULT_AI_WEB_BASE_URL"]
