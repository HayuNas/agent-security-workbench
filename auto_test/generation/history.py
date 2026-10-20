"""Read prior generated variants from normal reports without a second corpus store."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


def _read_report(path: Path) -> Mapping[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, Mapping) else None


def _epe_records(report: Mapping[str, Any], pack_id: str, path: Path) -> list[dict[str, str]]:
    manifest = report.get("automation_generation")
    if not isinstance(manifest, Mapping):
        return []
    if str(report.get("query_pack") or manifest.get("query_pack") or "") != pack_id:
        return []
    meta_by_id = {
        str(item.get("generated_query_id") or ""): item
        for item in manifest.get("accepted") or []
        if isinstance(item, Mapping)
    }
    records: list[dict[str, str]] = []
    for item in report.get("results") or []:
        if not isinstance(item, Mapping):
            continue
        generated_id = str(item.get("query_id") or "")
        meta = meta_by_id.get(generated_id)
        messages = item.get("customer_messages")
        message = str(messages[0] if isinstance(messages, list) and messages else "").strip()
        if not message or not isinstance(meta, Mapping):
            continue
        records.append(
            {
                "generated_id": generated_id,
                "source_id": str(meta.get("source_query_id") or item.get("generation_source_query_id") or ""),
                "tactic_id": str(meta.get("tactic_id") or ""),
                "message": message,
                "outcome": str(item.get("outcome") or ""),
                "report": str(path.resolve()),
            }
        )
    return records


def _cr_records(report: Mapping[str, Any], pack_id: str, path: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for pack in report.get("packs") or []:
        if not isinstance(pack, Mapping) or str(pack.get("pack_id") or "") != pack_id:
            continue
        manifest = pack.get("automation_generation")
        if not isinstance(manifest, Mapping):
            continue
        meta_by_id = {
            str(item.get("generated_seed_id") or ""): item
            for item in manifest.get("accepted") or []
            if isinstance(item, Mapping)
        }
        for item in pack.get("iterations") or []:
            if not isinstance(item, Mapping):
                continue
            generated_id = str(item.get("seed_id") or "")
            meta = meta_by_id.get(generated_id)
            message = str(item.get("initial_message") or "").strip()
            if not message or not isinstance(meta, Mapping):
                continue
            records.append(
                {
                    "generated_id": generated_id,
                    "source_id": str(meta.get("source_seed_id") or ""),
                    "tactic_id": str(meta.get("tactic_id") or ""),
                    "message": message,
                    "outcome": str(item.get("outcome") or ""),
                    "report": str(path.resolve()),
                }
            )
    return records


def load_generation_history(
    *,
    engine: str,
    pack_id: str,
    output_dir: Path,
    max_reports: int = 500,
    max_records: int = 5000,
) -> list[dict[str, str]]:
    """Return attempted variants (success and failure) from newest saved reports."""

    clean_engine = str(engine or "").strip()
    clean_pack = str(pack_id or "").strip()
    from ..records import resources, report_store
    if resources.enabled() and clean_engine in {"cr", "epe"} and clean_pack:
        suffix = "%security-attack-pack-report" if clean_engine == "cr" else "%epe-report"
        with report_store.connection() as conn, conn.cursor() as cur:
            cur.execute("""SELECT report_id,payload FROM agent_test_reports
                WHERE report_type='result' AND schema_version LIKE %s
                ORDER BY created_at DESC,report_id DESC LIMIT %s""", (suffix, max(1, min(500, int(max_reports)))))
            saved = cur.fetchall()
        records, seen = [], set()
        for report_id, packed in saved:
            header = report_store.unpacked(packed)
            if clean_engine == "epe" and str(header.get("query_pack") or "") != clean_pack:
                continue
            if clean_engine == "cr" and not any(p.get("pack_id") == clean_pack for p in header.get("packs") or []):
                continue
            report = report_store.detail("report", report_id)
            path = Path("database") / report_id
            extracted = _cr_records(report, clean_pack, path) if clean_engine == "cr" else _epe_records(report, clean_pack, path)
            for record in extracted:
                key = (record["message"], record["tactic_id"], record["source_id"])
                if key not in seen:
                    seen.add(key)
                    records.append({**record, "report": "mysql:report:" + report_id})
                if len(records) >= max(1, int(max_records)):
                    return records
        return records
    root = Path(output_dir)
    if clean_engine not in {"cr", "epe"} or not clean_pack or not root.exists():
        return []
    paths = sorted(
        root.rglob("*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )[: max(1, int(max_reports))]
    records: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for path in paths:
        report = _read_report(path)
        if report is None:
            continue
        extracted = (
            _cr_records(report, clean_pack, path)
            if clean_engine == "cr"
            else _epe_records(report, clean_pack, path)
        )
        for record in extracted:
            key = (record["message"], record["tactic_id"], record["source_id"])
            if key in seen:
                continue
            seen.add(key)
            records.append(record)
            if len(records) >= max(1, int(max_records)):
                return records
    return records


__all__ = ["load_generation_history"]
