"""把 ky-agent SSE 事件解析为稳定 Trace 证据。

网络客户端负责收取字节和处理超时；本模块只处理协议事件。只有 SSE 中成对出现
的 TOOL_CALL / TOOL_RESULT 才属于可信工具通道证据。普通文本即使长得像 MCP
返回，也不会被解析成工具证据。
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any, Mapping


def _limited_text(value: Any, limit: int) -> tuple[str, bool]:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]", True


class SSETraceBuilder:
    """逐行接收 SSE，并构造与旧客户端兼容的 Trace 字典。"""

    def __init__(self, *, artifact_char_limit: int, save_raw_events: bool) -> None:
        self.artifact_char_limit = int(artifact_char_limit)
        self.save_raw_events = bool(save_raw_events)
        self.event_counts: Counter[str] = Counter()
        self.raw_events: list[dict[str, Any]] = []
        self.text_blocks: list[str] = []
        self.thinking_blocks: list[str] = []
        self.current_text = -1
        self.current_thinking = -1
        self.current_tool_id = ""
        self.tool_calls: dict[str, dict[str, Any]] = {}
        self.tool_call_order: list[str] = []
        self.tool_results: dict[str, dict[str, Any]] = {}
        self.model_usage = {"calls": 0, "input_tokens": 0, "output_tokens": 0}
        self.invalid_json_events = 0
        self.errors: list[str] = []

    def feed_line(self, raw_line: bytes | str) -> bool:
        """处理一行 SSE；收到 `[DONE]` 时返回 True。"""

        line = (
            raw_line.decode("utf-8", errors="replace")
            if isinstance(raw_line, bytes)
            else str(raw_line)
        ).strip()
        if not line.startswith("data:"):
            return False
        payload_text = line[5:].strip()
        if not payload_text:
            return False
        if payload_text == "[DONE]":
            return True
        try:
            event = json.loads(payload_text)
        except json.JSONDecodeError:
            self.invalid_json_events += 1
            self.event_counts["INVALID_JSON"] += 1
            return False
        if not isinstance(event, dict):
            return False
        self.feed_event(event)
        return False

    def feed_event(self, event: Mapping[str, Any]) -> None:
        """处理一个已经解码的 SSE 事件对象。"""

        event = dict(event)
        event_type = str(event.get("type") or "UNKNOWN")
        self.event_counts[event_type] += 1
        if self.save_raw_events:
            self.raw_events.append(event)

        if event_type == "TEXT_BLOCK_START":
            self.text_blocks.append("")
            self.current_text = len(self.text_blocks) - 1
        elif event_type == "TEXT_BLOCK_DELTA":
            if self.current_text < 0:
                self.text_blocks.append("")
                self.current_text = len(self.text_blocks) - 1
            self.text_blocks[self.current_text] += str(event.get("delta") or "")
        elif event_type == "THINKING_BLOCK_START":
            self.thinking_blocks.append("")
            self.current_thinking = len(self.thinking_blocks) - 1
        elif event_type == "THINKING_BLOCK_DELTA":
            if self.current_thinking < 0:
                self.thinking_blocks.append("")
                self.current_thinking = len(self.thinking_blocks) - 1
            self.thinking_blocks[self.current_thinking] += str(
                event.get("delta") or ""
            )
        elif event_type == "TOOL_CALL_START":
            self.current_tool_id = str(
                event.get("tool_call_id")
                or f"anonymous-{len(self.tool_call_order) + 1}"
            )
            if self.current_tool_id not in self.tool_calls:
                self.tool_call_order.append(self.current_tool_id)
            self.tool_calls[self.current_tool_id] = {
                "tool_call_id": self.current_tool_id,
                "name": str(event.get("tool_call_name") or ""),
                "arguments_text": "",
                "arguments": None,
            }
        elif event_type == "TOOL_CALL_DELTA":
            tool_id = str(event.get("tool_call_id") or self.current_tool_id)
            if tool_id in self.tool_calls:
                self.tool_calls[tool_id]["arguments_text"] += str(
                    event.get("delta") or ""
                )
        elif event_type == "TOOL_CALL_END":
            tool_id = str(event.get("tool_call_id") or self.current_tool_id)
            if tool_id in self.tool_calls:
                args_text = self.tool_calls[tool_id]["arguments_text"]
                try:
                    self.tool_calls[tool_id]["arguments"] = (
                        json.loads(args_text) if args_text else None
                    )
                except json.JSONDecodeError:
                    self.tool_calls[tool_id]["arguments_parse_error"] = True
        elif event_type == "TOOL_RESULT_START":
            tool_id = str(
                event.get("tool_call_id")
                or self.current_tool_id
                or f"result-{len(self.tool_results) + 1}"
            )
            self.tool_results[tool_id] = {
                "tool_call_id": tool_id,
                "name": str(
                    event.get("tool_call_name")
                    or self.tool_calls.get(tool_id, {}).get("name")
                    or ""
                ),
                "result": "",
                "state": "",
                "truncated": False,
            }
        elif event_type == "TOOL_RESULT_TEXT_DELTA":
            tool_id = str(event.get("tool_call_id") or self.current_tool_id)
            if tool_id in self.tool_results:
                combined = self.tool_results[tool_id]["result"] + str(
                    event.get("delta") or ""
                )
                clipped, truncated = _limited_text(combined, self.artifact_char_limit)
                self.tool_results[tool_id]["result"] = clipped
                self.tool_results[tool_id]["truncated"] |= truncated
        elif event_type == "TOOL_RESULT_END":
            tool_id = str(event.get("tool_call_id") or self.current_tool_id)
            if tool_id in self.tool_results:
                self.tool_results[tool_id]["state"] = str(
                    event.get("state") or ""
                )
        elif event_type == "MODEL_CALL_END":
            self.model_usage["calls"] += 1
            self.model_usage["input_tokens"] += int(event.get("input_tokens") or 0)
            self.model_usage["output_tokens"] += int(event.get("output_tokens") or 0)
        elif event_type in {"EXCEED_MAX_ITERS", "REQUIRE_USER_CONFIRM"}:
            self.errors.append(f"SSE event: {event_type}")
        elif any(token in event_type.upper() for token in ("ERROR", "EXCEPTION")):
            self.errors.append(f"SSE event: {event_type}")
        elif event_type not in {
            "TEXT_BLOCK_END", "THINKING_BLOCK_END", "REPLY_START", "REPLY_END",
            "MODEL_CALL_START",
        }:
            fallback = event.get("delta") or event.get("content")
            if isinstance(fallback, str) and fallback:
                if self.current_text < 0:
                    self.text_blocks.append("")
                    self.current_text = len(self.text_blocks) - 1
                self.text_blocks[self.current_text] += fallback

    def build(
        self, *, request_id: str, duration_seconds: float, stream_end_reason: str
    ) -> dict[str, Any]:
        errors = list(self.errors)
        if self.invalid_json_events:
            errors.append(f"SSE invalid JSON event count: {self.invalid_json_events}")
        return {
            "request_id": str(request_id or ""),
            "duration_seconds": round(float(duration_seconds), 3),
            "stream_end_reason": str(stream_end_reason or ""),
            "reply": "".join(part for part in self.text_blocks if part),
            "text_blocks": list(self.text_blocks),
            "thinking": "\n".join(part for part in self.thinking_blocks if part),
            "thinking_blocks": list(self.thinking_blocks),
            "tool_calls": [dict(self.tool_calls[key]) for key in self.tool_call_order],
            "tool_results": [dict(item) for item in self.tool_results.values()],
            "model_usage": dict(self.model_usage),
            "event_type_counts": dict(sorted(self.event_counts.items())),
            "invalid_json_event_count": self.invalid_json_events,
            "raw_events": list(self.raw_events) if self.save_raw_events else None,
            "errors": errors,
        }


def trusted_tool_exchanges(trace: Mapping[str, Any]) -> list[dict[str, Any]]:
    """返回 SSE 工具通道中按 tool_call_id 成对出现的调用和结果。"""

    calls = {
        str(item.get("tool_call_id") or ""): dict(item)
        for item in trace.get("tool_calls") or []
        if isinstance(item, Mapping) and str(item.get("tool_call_id") or "")
    }
    exchanges: list[dict[str, Any]] = []
    for result in trace.get("tool_results") or []:
        if not isinstance(result, Mapping):
            continue
        tool_id = str(result.get("tool_call_id") or "")
        call = calls.get(tool_id)
        if call is None:
            continue
        exchanges.append({
            "tool_call_id": tool_id,
            "name": str(result.get("name") or call.get("name") or ""),
            "call": call,
            "result": dict(result),
            "provenance": "sse_tool_channel",
        })
    return exchanges


__all__ = ["SSETraceBuilder", "trusted_tool_exchanges"]
