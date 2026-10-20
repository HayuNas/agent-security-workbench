"""线程安全的终端进度输出。"""

from __future__ import annotations

import sys
import threading
from typing import TextIO


class TerminalProgress:
    """以完整行输出进度，避免并行 Worker 的日志互相穿插。"""

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream or sys.stderr
        self._lock = threading.Lock()

    def emit(self, scope: str, message: str) -> None:
        label = str(scope or "AUTO_TEST").strip()
        text = " ".join(str(message or "").splitlines()).strip()
        with self._lock:
            print(f"[{label}] {text}", file=self.stream, flush=True)


__all__ = ["TerminalProgress"]
