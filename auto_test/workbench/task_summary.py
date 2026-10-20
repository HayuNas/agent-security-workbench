"""On-demand overview of saved primary batch reports; never rescores results."""
import json
from pathlib import Path

from ..report_digest import concise_report, _text


def task_summary(directory: Path, *, positive: bool = False) -> str:
    from . import artifacts
    if artifacts.enabled():
        from ..records import report_store
        reports = list(report_store.task_reports(directory))
        rows = []
        internal = False
        for _, data, _ in reports:
            if "finding" in str(data.get("schema_version")):
                continue
            internal |= data.get("evaluation_scope") == "visible_reply_only"
            rows.extend(data.get("results") or [])
            rows.extend(item for pack in data.get("packs") or [] for item in pack.get("iterations") or [])
        content = concise_report({"results": rows}, "# 全任务汇总")
        scope = "> 本任务仅验证内部可见回复，不代表后台工具或权限已验证。\n\n" if internal else ""
        return scope + content
    rows, batches, skipped = [], [], []
    internal_visible = False
    for folder in sorted(directory.glob("batch-*"), key=lambda p: int(p.name[6:]) if p.name[6:].isdigit() else 999999):
        for path in sorted(folder.glob("WEB-*.json")):
            if "finding" in path.name.lower():
                continue
            if not path.resolve().is_relative_to(directory.resolve()) or path.stat().st_size > 20_000_000:
                skipped.append(path.name)
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                internal_visible |= data.get('evaluation_scope') == 'visible_reply_only'
                items = data.get("results", [])
                if "packs" in data:
                    items = [r for p in data["packs"] for r in p.get("iterations", [])]
                items = [r for r in items if isinstance(r, dict) and r.get("outcome")]
            except (ValueError, OSError, TypeError, AttributeError):
                skipped.append(path.name)
                continue
            if not items:
                continue
            batches.append(f"- {_text(folder.name)}：{len(items)} 条")
            for item in items:
                identity = item.get("iteration_id") or item.get("query_id") or item.get("source_id") or ""
                rows.append({**item, "iteration_id": f"{folder.name} / {identity}"})
    original = "# " + ("ky-sales 动态正向业务回归" if positive else "信息泄露论文攻击报告")
    original += "\n\n## 子批次来源\n\n" + "\n".join(batches)
    if skipped:
        original += "\n\n未读取的报告：" + "、".join(_text(name) for name in skipped)
    content = concise_report({"results": rows}, original)
    scope_note = '> 本任务是内部可见流程检查。通过仅表示回复与澄清表现通过，不代表工具执行、权限校验或报告保存已验证。\n\n' if internal_visible else ''
    return "全任务汇总（已落盘结果）\n\n> 运行中或失败任务可能尚未产生全部结果；未生成的用例不计为通过。单批完整证据请切换对应报告。\n\n" + scope_note + content
