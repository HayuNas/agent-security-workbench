"""One transaction for a human decision, regression membership and Finding links."""
import copy
import json
from datetime import datetime, timezone
from pathlib import Path

from ..records import case_store, report_store, unified


def blocked(item):
    judge = item.get("judge") or {}
    return judge.get("issue_owner") in {"test_data", "test_controller"} or str(item.get("stop_reason") or "") in {
        "controller_contract_unrecoverable", "controller_evaluation_unrecoverable", "controller_evaluation_error",
        "customer_generation_unrecoverable"}


def make_case(candidate, decision, source):
    report = copy.deepcopy(source)
    parts = candidate["pointer"].split("/")
    if parts[0] == "packs":
        pack = report["packs"][int(parts[1])]
        item = pack["iterations"][int(parts[3])]
        pack["iterations"] = [item]
        report["packs"] = [pack]
    else:
        item = report["results"][int(parts[1])]
        report["results"] = [item]
    if item.get("outcome") != "REVIEW":
        raise ValueError("原始判定已变化")
    if candidate["kind"] == "positive" and blocked(item):
        raise ValueError("测试数据或控制器问题不能登记为 Agent 缺陷")
    item["outcome"] = decision.outcome
    target = report.get("target") or {"adapter": "ky-agent", "target_key": "ky-agent:ky-sales"}
    if candidate["kind"] == "attack":
        from ..records.cases import _report_successes, security_case_id
        source_ref = "db-report-" + candidate["_reportId"]
        incoming = _report_successes(report, json_path=Path(source_ref), markdown_path=Path(source_ref))
        if len(incoming) != 1:
            raise ValueError("报告缺少可复测的完整攻击消息")
        case = incoming[0]
        target_id = target.get("target_key") or "ky-agent:ky-sales"
        case["case_id"] = security_case_id(case["pack_id"], case["messages"],
            target_key=target_id if target.get("adapter") in {"ai-web", "ky-app"} else "")
        case.update(prompt="\n\n".join(case["messages"]), status="active", result="攻击成功（待修复）",
                    latest_outcome=decision.outcome, last_tested_at=report.get("created_at"),
                    source_json="db:" + candidate["_reportId"], source_markdown="")
    else:
        if target.get("adapter") not in {"ky-agent", "ky-app", None}:
            raise ValueError("内部正向用例暂未接入回归执行器，不能登记成可执行的销售用例")
        from ..business.bad_cases import _build_case
        case = _build_case(report, {**item, "source_id": item.get("source_id") or item.get("case_id")}, item)
        if not case.get("core_task"):
            raise ValueError("报告缺少业务目标，不能构造不完整的回归用例")
    case["target"] = target
    case["manual_review"] = {"id": candidate["id"], "source_result_id":
        report_store.identity(candidate["_reportId"], candidate["pointer"]), "original_outcome": "REVIEW"}
    return case


def decide(root, key, decision):
    from . import reviews
    decision = decision.model_copy(update={"reason": decision.reason.strip()})
    candidate = reviews._candidate(root, key)
    if "_reportId" not in candidate:
        raise ValueError("请先将来源测试报告迁移到数据库")
    source = reviews._candidate_report(candidate)
    rid = report_store.identity(candidate["_reportId"], candidate["pointer"])
    with case_store.transaction() as conn, conn.cursor() as cur:
        cur.execute("SELECT payload FROM agent_manual_reviews WHERE review_id=%s FOR UPDATE", (key,))
        row = cur.fetchone()
        if row:
            previous = json.loads(row[0])["review"]
            if any(previous.get(k) != getattr(decision, k) for k in ("action", "reason", "outcome")):
                raise case_store.Conflict("该用例已经复核，不能重复覆盖结论")
            return previous
        cur.execute("""SELECT outcome FROM agent_security_case_runs
            WHERE result_id=%s FOR UPDATE""", (rid,))
        execution = cur.fetchone()
        if not execution or execution[0] != "REVIEW":
            raise ValueError("来源执行不存在或已不是待复核状态")
        receipt = {"id": key, "taskId": candidate["taskId"], "kind": candidate["kind"], "caseId": candidate["caseId"],
                   **decision.model_dump(), "reviewedAt": datetime.now(timezone.utc).isoformat(),
                   "sourceReport": candidate["report"], "sourcePointer": candidate["pointer"],
                   "sourceResultId": rid, "reviewedBy": "共享工作台（尚未接入登录身份）",
                   "originalOutcome": "REVIEW", "libraryCaseIds": [], "findingIds": [],
                   "database": {"synced": True, "status": "synced"}, "findingStatus": "not_required"}
        if decision.action == "include":
            if decision.outcome not in candidate["outcomes"]:
                raise ValueError("请选择该场景支持的问题类型")
            case = make_case(candidate, decision, source)
            kind = "security" if candidate["kind"] == "attack" else "business_bad"
            case_id = case["case_id"]
            old = case_store.detail(kind, case_id)
            if old:
                # Preserve edited input and explicit disabled state; attach evidence only.
                case = {**old["case"], "manual_review": case["manual_review"]}
            case_store.put(cur, kind, case, expected=old["revision"] if old else 0)
            receipt.update(libraryCaseIds=[case_id], findingStatus="pending_analysis")
        unified.save_receipt(receipt, cur=cur)
        from . import review_analysis
        review_analysis.register(cur, receipt, candidate, source)
        return receipt
