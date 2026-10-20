"""Shared target-client contract used by EPE and regression runners."""

from __future__ import annotations

from typing import Any, Protocol

from .target import SessionInfo


class TargetClient(Protocol):
    """Small black-box surface required by the current runners."""

    def health(self) -> dict[str, Any]: ...

    def init_test(self, *, wx_account: str, wx_contact: str) -> SessionInfo: ...

    def chat(
        self,
        session: SessionInfo,
        message: str,
        *,
        allow_transport_retry: bool = False,
    ) -> dict[str, Any]: ...


__all__ = ["TargetClient"]
