"""Reusable client and streaming output middleware for Risk Guard callers."""

from __future__ import annotations

import http.client
import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit


FailMode = Literal["open", "closed"]


class RiskGuardClientError(RuntimeError):
    """The guard API could not return a usable decision."""


@dataclass(frozen=True)
class GuardCheck:
    decision: Literal["ALLOW", "BLOCK"]
    safe: bool
    direction: Literal["input", "output"]
    stage: Literal["full", "stream"]
    request_id: str = ""
    agent_id: str = ""
    rule_id: str = ""
    detector: str = "none"
    reason: str = ""
    block_message: str = ""
    checked_by: tuple[str, ...] = ()
    degraded: bool = False
    latency_ms: float = 0.0
    engine_version: str = ""
    source_revision: str = ""
    policy_version: str = ""
    trace: tuple[Mapping[str, Any], ...] = ()

    @property
    def blocked(self) -> bool:
        return self.decision == "BLOCK"

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "GuardCheck":
        decision = str(payload.get("decision") or "").upper()
        direction = str(payload.get("direction") or "").lower()
        stage = str(payload.get("stage") or "").lower()
        if decision not in {"ALLOW", "BLOCK"}:
            raise RiskGuardClientError("Risk Guard response has an invalid decision")
        if direction not in {"input", "output"}:
            raise RiskGuardClientError("Risk Guard response has an invalid direction")
        if stage not in {"full", "stream"}:
            raise RiskGuardClientError("Risk Guard response has an invalid stage")
        return cls(
            decision=decision,
            safe=bool(payload.get("safe", decision == "ALLOW")),
            direction=direction,
            stage=stage,
            request_id=str(payload.get("request_id") or ""),
            agent_id=str(payload.get("agent_id") or ""),
            rule_id=str(payload.get("rule_id") or ""),
            detector=str(payload.get("detector") or "none"),
            reason=str(payload.get("reason") or ""),
            block_message=str(payload.get("block_message") or ""),
            checked_by=tuple(str(item) for item in payload.get("checked_by") or []),
            degraded=bool(payload.get("degraded")),
            latency_ms=float(payload.get("latency_ms") or 0),
            engine_version=str(payload.get("engine_version") or ""),
            source_revision=str(payload.get("source_revision") or ""),
            policy_version=str(payload.get("policy_version") or ""),
            trace=tuple(
                dict(item)
                for item in (payload.get("trace") or [])
                if isinstance(item, Mapping)
            ),
        )


@dataclass(frozen=True)
class BufferedGuardCheck:
    """A guard decision plus text that is now safe to release downstream."""

    check: GuardCheck
    released_content: str = ""

    @property
    def blocked(self) -> bool:
        return self.check.blocked


class RiskGuardClient:
    """Model-agnostic HTTP client with one persistent connection per thread."""

    def __init__(
        self,
        *,
        agent_id: str,
        base_url: str = "http://127.0.0.1:8091",
        token: str = "",
        timeout: float = 10.0,
        fail_mode: FailMode = "open",
    ) -> None:
        clean_agent_id = str(agent_id).strip()
        if not clean_agent_id:
            raise ValueError("agent_id must not be empty")
        if fail_mode not in {"open", "closed"}:
            raise ValueError("fail_mode must be 'open' or 'closed'")
        parts = urlsplit(str(base_url).rstrip("/"))
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("base_url must be a valid HTTP(S) URL")
        self.agent_id = clean_agent_id
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port
        self.base_path = parts.path.rstrip("/")
        self.token = str(token).strip()
        self.timeout = float(timeout)
        self.fail_mode = fail_mode
        self._connections: dict[int, http.client.HTTPConnection] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls, *, agent_id: str) -> "RiskGuardClient":
        fail_mode = os.getenv("RISK_GUARD_FAIL_MODE", "open").strip().lower()
        if fail_mode not in {"open", "closed"}:
            raise ValueError("RISK_GUARD_FAIL_MODE must be open or closed")
        return cls(
            agent_id=agent_id,
            base_url=os.getenv("RISK_GUARD_BASE_URL", "http://127.0.0.1:8091"),
            token=os.getenv("RISK_GUARD_API_TOKEN", ""),
            timeout=float(os.getenv("RISK_GUARD_TIMEOUT", "10")),
            fail_mode=fail_mode,
        )

    def _connection(self) -> http.client.HTTPConnection:
        thread_id = threading.get_ident()
        with self._lock:
            connection = self._connections.get(thread_id)
            if connection is None:
                connection_type = (
                    http.client.HTTPSConnection
                    if self.scheme == "https"
                    else http.client.HTTPConnection
                )
                connection = connection_type(
                    self.host,
                    self.port,
                    timeout=self.timeout,
                )
                self._connections[thread_id] = connection
            return connection

    def _discard_current_connection(self) -> None:
        thread_id = threading.get_ident()
        with self._lock:
            connection = self._connections.pop(thread_id, None)
        if connection is not None:
            connection.close()

    def close(self) -> None:
        with self._lock:
            connections = list(self._connections.values())
            self._connections.clear()
        for connection in connections:
            connection.close()

    def __enter__(self) -> "RiskGuardClient":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def _request_json(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(dict(payload), ensure_ascii=False).encode("utf-8")
        if self.token:
            headers["X-Risk-Guard-Token"] = self.token
        for attempt in range(2):
            try:
                connection = self._connection()
                connection.request(
                    method,
                    self.base_path + path,
                    body=body,
                    headers=headers,
                )
                response = connection.getresponse()
                raw = response.read().decode("utf-8", errors="replace")
                if response.will_close:
                    self._discard_current_connection()
                break
            except (OSError, http.client.HTTPException) as exc:
                # HTTP checks are idempotent.  Windows can discover a stale
                # keep-alive socket only when the next request is written;
                # rebuild it once before applying the configured fail mode.
                self._discard_current_connection()
                if attempt == 0:
                    continue
                raise RiskGuardClientError(
                    f"Risk Guard unavailable: {exc}"
                ) from exc
        if not 200 <= response.status < 300:
            raise RiskGuardClientError(
                f"Risk Guard HTTP {response.status}: {raw[:500]}"
            )
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RiskGuardClientError("Risk Guard returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise RiskGuardClientError("Risk Guard response must be a JSON object")
        return value

    def health(self) -> dict[str, Any]:
        return self._request_json("GET", "/health")

    def check(
        self,
        content: str,
        *,
        direction: Literal["input", "output"],
        stage: Literal["full", "stream"] = "full",
        request_id: str = "",
        include_trace: bool = False,
    ) -> GuardCheck:
        try:
            path = "/v1/check?compact=false"
            if include_trace:
                path += "&include_trace=true"
            payload = self._request_json(
                "POST",
                path,
                {
                    "content": str(content),
                    "direction": direction,
                    "stage": stage,
                    "agent_id": self.agent_id,
                    "request_id": str(request_id),
                },
            )
            return GuardCheck.from_payload(payload)
        except RiskGuardClientError as exc:
            if self.fail_mode == "closed":
                raise
            return GuardCheck(
                decision="ALLOW",
                safe=True,
                direction=direction,
                stage=stage,
                request_id=str(request_id),
                agent_id=self.agent_id,
                detector="client_transport",
                reason=str(exc),
                checked_by=("client_transport",),
                degraded=True,
            )

    def check_input(
        self,
        content: str,
        *,
        request_id: str = "",
        include_trace: bool = False,
    ) -> GuardCheck:
        return self.check(
            content,
            direction="input",
            stage="full",
            request_id=request_id,
            include_trace=include_trace,
        )

    def check_output(
        self,
        content: str,
        *,
        request_id: str = "",
        include_trace: bool = False,
    ) -> GuardCheck:
        return self.check(
            content,
            direction="output",
            stage="full",
            request_id=request_id,
            include_trace=include_trace,
        )

    def output_stream(
        self,
        *,
        request_id: str = "",
        window_size: int = 500,
        holdback_size: int = 96,
    ) -> "OutputStreamGuard":
        return OutputStreamGuard(
            self,
            request_id=request_id,
            window_size=window_size,
            holdback_size=holdback_size,
        )


class OutputStreamGuard:
    """Caller-facing rolling-window middleware for streamed model output."""

    def __init__(
        self,
        client: RiskGuardClient,
        *,
        request_id: str = "",
        window_size: int = 500,
        holdback_size: int = 96,
    ) -> None:
        if window_size < 1:
            raise ValueError("window_size must be greater than 0")
        if holdback_size < 1:
            raise ValueError("holdback_size must be greater than 0")
        self.client = client
        self.request_id = str(request_id)
        self.window_size = int(window_size)
        self.holdback_size = int(holdback_size)
        self._buffer = ""
        self._parts: list[str] = []
        self._pending_release = ""
        self._chunk_index = 0
        self._blocked: GuardCheck | None = None
        self._final_audit: GuardCheck | None = None
        self._delivery_mode = ""

    @property
    def blocked(self) -> bool:
        return self.block_decision is not None

    @property
    def full_output(self) -> str:
        return "".join(self._parts)

    @property
    def final_audit(self) -> GuardCheck | None:
        return self._final_audit

    @property
    def block_decision(self) -> GuardCheck | None:
        if self._blocked is not None:
            return self._blocked
        if self._final_audit is not None and self._final_audit.blocked:
            return self._final_audit
        return None

    def _select_delivery_mode(self, mode: str) -> None:
        if self._delivery_mode and self._delivery_mode != mode:
            raise RuntimeError("cannot mix immediate and buffered stream delivery")
        self._delivery_mode = mode

    def _check_chunk(self, chunk: str) -> GuardCheck:
        if self._final_audit is not None:
            raise RuntimeError("output stream has already been finalized")
        if self._blocked is not None:
            return self._blocked
        text = str(chunk)
        if not text:
            return GuardCheck(
                decision="ALLOW",
                safe=True,
                direction="output",
                stage="stream",
                request_id=f"{self.request_id}:stream:{self._chunk_index}",
                agent_id=self.client.agent_id,
                reason="empty chunk skipped by client middleware",
                checked_by=("client_middleware",),
            )
        self._parts.append(text)
        self._chunk_index += 1
        degraded_decision = None
        # Check every new character before trimming the lookbehind. A provider
        # may emit an arbitrarily large chunk, not just a few tokens. Each check
        # includes the previous window, so splitting cannot hide a boundary hit.
        # push_buffered releases nothing from this chunk until all segments pass.
        for offset in range(0, len(text), self.window_size):
            candidate = self._buffer + text[offset : offset + self.window_size]
            request_id = f"{self.request_id}:stream:{self._chunk_index}"
            if len(text) > self.window_size:
                request_id += f":part:{offset // self.window_size + 1}"
            decision = self.client.check(
                candidate,
                direction="output",
                stage="stream",
                request_id=request_id,
            )
            self._buffer = candidate[-self.window_size :]
            if decision.blocked:
                self._blocked = decision
                return decision
            if decision.degraded:
                degraded_decision = decision
        return degraded_decision or decision

    def push(self, chunk: str) -> GuardCheck:
        """Check one chunk without managing when the caller sends it."""
        self._select_delivery_mode("immediate")
        return self._check_chunk(chunk)

    def push_buffered(self, chunk: str) -> BufferedGuardCheck:
        """Check one chunk and release only text outside the safety holdback."""
        self._select_delivery_mode("buffered")
        text = str(chunk)
        decision = self._check_chunk(text)
        if decision.blocked:
            self._pending_release = ""
            return BufferedGuardCheck(check=decision)

        self._pending_release += text
        release_length = max(0, len(self._pending_release) - self.holdback_size)
        released = self._pending_release[:release_length]
        self._pending_release = self._pending_release[release_length:]
        return BufferedGuardCheck(check=decision, released_content=released)

    def finish(self) -> GuardCheck:
        if self._final_audit is not None:
            return self._final_audit
        if self._blocked is not None:
            self._final_audit = self._blocked
            return self._blocked
        if not self._parts:
            raise ValueError("cannot finalize an empty output stream")
        self._final_audit = self.client.check_output(
            self.full_output,
            request_id=f"{self.request_id}:full-audit",
        )
        return self._final_audit

    def finish_buffered(self) -> BufferedGuardCheck:
        """Finalize the stream and release the remaining safe tail."""
        self._select_delivery_mode("buffered")
        decision = self.finish()
        if decision.blocked:
            self._pending_release = ""
            return BufferedGuardCheck(check=decision)
        released = self._pending_release
        self._pending_release = ""
        return BufferedGuardCheck(check=decision, released_content=released)


__all__ = [
    "BufferedGuardCheck",
    "FailMode",
    "GuardCheck",
    "OutputStreamGuard",
    "RiskGuardClient",
    "RiskGuardClientError",
]
