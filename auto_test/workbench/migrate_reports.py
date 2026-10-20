"""Import historical task reports without models or replaying Agent calls."""
import argparse
import json
import os
from pathlib import Path

from ..core.paths import RESULTS_ROOT
from ..records import report_store


def migrate(root, apply=False, progress=None):
    root = Path(root).resolve()
    tasks, skipped = [], []
    for task_path in sorted([*root.glob("*/task.json"), *root.glob("guard/*/task.json")]):
        if not task_path.resolve().is_relative_to(root):
            raise ValueError("Task path outside results root")
        task = json.loads(task_path.read_text(encoding="utf-8"))
        if task.get("status") in {"queued", "running", "draft"} or task.get("kind") == "skill":
            skipped.append({"task_id": task.get("id"), "reason": "active_or_skill"})
            continue
        counts = {"reports": 0, "results": 0, "findings": 0}
        for _, report, _ in report_store.task_reports(task_path.parent):
            counts["reports"] += 1
            counts["results"] += sum(1 for _ in report_store.result_entries(report))
            counts["findings"] += len(report.get("findings") or [])
        tasks.append({"task_id": task["id"], "directory": task_path.parent, **counts})
    result = {"mode": "apply" if apply else "preview", "tasks": len(tasks),
              **{key: sum(t[key] for t in tasks) for key in ("reports", "results", "findings")},
              "skipped": skipped}
    if apply:
        report_store.initialize()
        # Each task is atomic. Successful tasks survive interruption; retry is idempotent.
        result["inserted_reports"] = 0
        for index, task in enumerate(tasks, 1):
            if progress:
                progress({"task": index, "total": len(tasks), "task_id": task["task_id"]})
            original = json.loads((task["directory"] / "task.json").read_text(encoding="utf-8"))
            imported = report_store.import_task(task["directory"], task=original)
            result["inserted_reports"] += imported["inserted"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(os.getenv("WORKBENCH_RESULTS_DIR", RESULTS_ROOT / "workbench")))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--status", action="store_true", help="Read database counts and packet limit")
    args = parser.parse_args()
    if args.status:
        result = report_store.status()
    else:
        result = migrate(args.root, args.apply, lambda row: print(json.dumps(row), flush=True))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
