"""Non-blocking audit sinks for production guard decisions."""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Mapping, Protocol


logger = logging.getLogger(__name__)


class AuditSink(Protocol):
    def submit(self, record: Mapping[str, Any]) -> None: ...

    def close(self) -> None: ...


class NullAuditSink:
    def submit(self, record: Mapping[str, Any]) -> None:
        return None

    def close(self) -> None:
        return None


class MongoAuditSink:
    """Write audit records on one daemon worker so checks never wait for MongoDB."""

    def __init__(self, uri: str, database: str, collection: str) -> None:
        try:
            from pymongo import MongoClient
        except ImportError as exc:
            raise RuntimeError(
                "Mongo audit requires pymongo; install risk_guard/requirements.txt"
            ) from exc

        self._client = MongoClient(
            uri,
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000,
        )
        self._collection = self._client[database][collection]
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=10_000)
        self._closed = False
        self._worker = threading.Thread(
            target=self._run,
            name="risk-guard-mongo-audit",
            daemon=True,
        )
        self._worker.start()

    def submit(self, record: Mapping[str, Any]) -> None:
        if self._closed:
            return
        try:
            self._queue.put_nowait(dict(record))
        except queue.Full:
            logger.error("Risk Guard audit queue is full; dropping one record")

    def _run(self) -> None:
        while True:
            record = self._queue.get()
            try:
                if record is None:
                    return
                self._collection.insert_one(record)
            except Exception as exc:
                logger.warning("Risk Guard Mongo audit write failed: %s", exc)
            finally:
                self._queue.task_done()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            logger.warning("Risk Guard audit queue did not drain during shutdown")
        self._worker.join(timeout=3.0)
        self._client.close()


def build_audit_sink(*, uri: str, database: str, collection: str) -> AuditSink:
    if not uri.strip():
        return NullAuditSink()
    return MongoAuditSink(uri.strip(), database, collection)


__all__ = [
    "AuditSink",
    "MongoAuditSink",
    "NullAuditSink",
    "build_audit_sink",
]
