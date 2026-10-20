"""Private subprocess entrypoint. Execute with Python -I -X utf8.

No KY package imports: importing risk_guard initializes unrelated guard modules.
All scanner imports and logs stay in this child process and its scratch directory.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path

from skill_scan.utils.llm import LLM


class UsageTrackingLLM(LLM):
    """LLM wrapper used only by the local scan worker to collect token usage."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "api_calls": 0,
            "usage_reports": 0,
        }
        self._usage_fields = {
            "prompt_tokens": False,
            "completion_tokens": False,
            "total_tokens": False,
        }

    def chat_stream(self, message: list[dict]):
        self._usage["api_calls"] += 1
        result = super().chat_stream(message)
        usage = result[1] if isinstance(result, tuple) and len(result) == 2 else None
        if not isinstance(usage, dict):
            return result

        self._usage["usage_reports"] += 1
        for name in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = usage.get(name)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                self._usage[name] += value
                self._usage_fields[name] = True
        return result

    def token_usage(self) -> dict:
        """Return numeric usage only; never expose prompts, skill contents or keys."""
        usage = dict(self._usage)
        for name, present in self._usage_fields.items():
            if not present:
                usage[name] = None
        usage["usage_complete"] = (
            usage["api_calls"] > 0
            and usage["usage_reports"] == usage["api_calls"]
            and all(self._usage_fields.values())
        )
        return usage


async def scan(config: dict) -> dict:
    import skill_scan.tools  # noqa: F401 -- register original tools
    from skill_scan import __version__
    from skill_scan.agent.agent import Agent
    from skill_scan.utils.sarif_formatter import to_sarif

    llm = UsageTrackingLLM(
        model=config["model"], api_key=config["api_key"],
        base_url=config["base_url"], context_window=config["context_window"],
    )
    agent = Agent(llm=llm, debug=False, language=config["language"],
                  aig_mode=config["mode"] == "full")
    # Import config/prompts/loggers from the installed package BEFORE entering
    # untrusted content, so an uploaded .env is never auto-loaded. Original tools
    # resolve relative paths against cwd; only this isolated child changes cwd.
    original_cwd = Path.cwd()
    try:
        os.chdir(config["repo"])
        result = await agent.scan(config["repo"], config["prompt"], config["language"])
        # Preserve all upstream output, including the intermediate full-mode reports.
        result["token_usage"] = llm.token_usage()
        return {
            "result": result,
            "stage_reports": dict(agent.pipeline.results),
            "sarif": to_sarif(result, tool_version=__version__, language=config["language"]),
            "scanner_version": __version__,
        }
    finally:
        os.chdir(original_cwd)
        try:
            await agent.dispatcher.close()
        finally:
            llm.client.close()


def _safe_worker_diagnostic(exc: BaseException) -> dict[str, object]:
    """只提取可公开的错误分类，不把异常文本、请求体或响应体写回父进程。"""
    name = type(exc).__name__
    lowered = name.lower()
    status = getattr(exc, "status_code", None)
    if type(status) is int and 400 <= status <= 599:
        raw_code = getattr(exc, "code", None) or getattr(exc, "type", None)
        # OpenAI 兼容服务有时把 code 放在 {"error": {"code": ...}}；
        # 只读取并校验短的机器码，绝不把 body 或异常文本写回父进程。
        body = getattr(exc, "body", None)
        if not raw_code and isinstance(body, dict):
            nested = body.get("error")
            if isinstance(nested, dict):
                raw_code = nested.get("code") or nested.get("type")
        provider_code = (
            raw_code.strip()
            if isinstance(raw_code, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", raw_code.strip())
            else None
        )
        result: dict[str, object] = {
            "kind": "model_http_error",
            "status_code": status,
        }
        if provider_code:
            result["provider_code"] = provider_code
        return result
    if "timeout" in lowered:
        return {"kind": "model_timeout"}
    if any(token in lowered for token in ("connection", "connect", "network", "ssl")):
        return {"kind": "model_connection_error"}
    return {"kind": "scanner_error"}


def main() -> int:
    try:
        config = json.load(sys.stdin)
        data = asyncio.run(scan(config))
        serialized = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(serialized) > config["max_result_bytes"]:
            return 3
        Path("result.json").write_bytes(serialized)
        return 0
    except Exception as exc:
        # Upstream exceptions may contain credentials or scanned code. Never return
        # their text through the shared service's HTTP error/log channel.
        try:
            Path("worker-diagnostic.json").write_text(
                json.dumps(_safe_worker_diagnostic(exc), ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
