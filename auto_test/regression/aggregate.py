"""Aggregate repeated security-regression reports into one Case status."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..records.cases import DEFAULT_CASES_PATH, LEAK_OUTCOMES, load_security_cases, save_security_cases
from ..records.mysql import update_case_aggregate_statuses
from ..records.library_lock import serialized_library_write


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


@serialized_library_write
def aggregate_regression_reports(
    report_paths: Sequence[Path],
    *,
    cases_path: Path = DEFAULT_CASES_PATH,
    sync_mysql: bool = True,
) -> dict[str, Any]:
    paths = [Path(item).resolve() for item in report_paths]
    if len(paths) < 2:
        raise ValueError("回归聚合至少需要两份报告")
    reports = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    if any(
        not str(report.get("schema_version") or "").endswith(
            "security-regression-report"
        )
        for report in reports
    ):
        raise ValueError("回归聚合只支持 security-regression-report")
    targets = {
        str((report.get("target") or {}).get("target_key") or "")
        for report in reports
    }
    if len(targets) != 1 or not next(iter(targets)):
        raise ValueError("待聚合报告必须属于同一 Target")

    result_maps = [
        {
            str(item.get("case_id") or ""): item
            for item in report.get("results") or []
            if isinstance(item, Mapping) and str(item.get("case_id") or "")
        }
        for report in reports
    ]
    case_sets = [set(items) for items in result_maps]
    if not case_sets or any(items != case_sets[0] for items in case_sets[1:]):
        raise ValueError("待聚合报告的 Case 集合不一致")

    aggregate_at = _now()
    aggregate: dict[str, dict[str, Any]] = {}
    counts: Counter[str] = Counter()
    for case_id in sorted(case_sets[0]):
        outcomes = [
            str(items[case_id].get("outcome") or "INVALID")
            for items in result_maps
        ]
        successes = sum(outcome in LEAK_OUTCOMES for outcome in outcomes)
        reviews = sum(outcome == "REVIEW" for outcome in outcomes)
        if successes == len(outcomes):
            status = "STABLE_REPRODUCED"
            label = "稳定可复现"
            mysql_status = 0
        elif successes:
            status = "INTERMITTENT_REPRODUCED"
            label = "间歇性可复现"
            mysql_status = 0
        elif reviews:
            status = "JUDGE_REVIEW_PENDING"
            label = "辅助审查待确认"
            mysql_status = 0
        else:
            status = "NOT_REPRODUCED"
            label = "两轮未复现"
            mysql_status = 1
        counts[status] += 1
        aggregate[case_id] = {
            "status": status,
            "label": label,
            "attempts": len(outcomes),
            "successes": successes,
            "reviews": reviews,
            "outcomes": outcomes,
            "report_paths": [str(path) for path in paths],
            "aggregated_at": aggregate_at,
            "mysql_status": mysql_status,
        }

    library = load_security_cases(cases_path)
    known = {
        str(item.get("case_id") or ""): item
        for item in library["cases"]
        if isinstance(item, dict)
    }
    missing = sorted(set(aggregate) - set(known))
    if missing:
        raise ValueError(f"本地 Case 库缺少待聚合 Case：{missing}")
    for case_id, summary in aggregate.items():
        case = known[case_id]
        case.update(
            {
                "result": summary["label"],
                "aggregate_retest_status": summary["status"],
                "aggregate_retest_attempts": summary["attempts"],
                "aggregate_retest_successes": summary["successes"],
                "aggregate_retest_reviews": summary["reviews"],
                "aggregate_retest_outcomes": summary["outcomes"],
                "aggregate_retest_reports": summary["report_paths"],
                "last_action_at": aggregate_at,
            }
        )
        history = list(case.get("status_history") or [])
        history.append(
            {
                "status": summary["label"],
                "at": aggregate_at,
                "source": "regression_aggregate",
                "outcomes": summary["outcomes"],
                "source_json": summary["report_paths"],
            }
        )
        case["status_history"] = history
    save_security_cases(library, cases_path)

    mysql_sync = (
        update_case_aggregate_statuses(
            {case_id: value["mysql_status"] for case_id, value in aggregate.items()}
        )
        if sync_mysql
        else {"enabled": False, "synced": False, "case_count": 0}
    )
    return {
        "status": "AGGREGATED",
        "target_key": next(iter(targets)),
        "report_count": len(paths),
        "case_count": len(aggregate),
        "counts": dict(sorted(counts.items())),
        "confirmed_real_count": counts["STABLE_REPRODUCED"]
        + counts["INTERMITTENT_REPRODUCED"],
        "mysql_sync": mysql_sync,
    }


__all__ = ["aggregate_regression_reports"]
