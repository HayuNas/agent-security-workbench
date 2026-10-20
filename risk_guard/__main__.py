"""Run with: python -m risk_guard"""

from __future__ import annotations

import os

import uvicorn

from .settings import RiskGuardSettings


def main() -> None:
    settings = RiskGuardSettings.from_env()
    # 多 worker 开关：默认 1 = 单进程单事件循环（与之前行为一致）。
    # workers > 1 会以多进程方式横向扩展 /v1/check 的 CPU 密集匹配，
    # 每个 worker 独立加载 engine/policies/审计队列，内存近似 ×N。
    # 注意 RISK_GUARD_SKILL_SCAN_MAX_CONCURRENCY 是「每进程」名额，
    # 总 skill-scan 并发 = workers × MAX_CONCURRENCY。
    workers = int(os.getenv("RISK_GUARD_WORKERS", "1"))
    uvicorn.run(
        "risk_guard.app:app",
        host=settings.host,
        port=settings.port,
        workers=workers,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
