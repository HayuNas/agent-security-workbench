"""Review list projections never deserialize execution or audit payloads."""
import hashlib
from fastapi import APIRouter, HTTPException, Query
from typing import Annotated, Literal
from ..records import report_store, unified

router = APIRouter(prefix="/api/agent", tags=["人工复核"])
FROM = """FROM agent_security_case_runs x
 JOIN agent_test_reports r ON r.report_id=x.report_id
 JOIN agent_test_tasks t ON t.task_id=r.task_id
 LEFT JOIN agent_manual_reviews m ON m.source_result_id=x.result_id
 WHERE x.outcome='REVIEW' AND x.test_kind IN ('attack','positive')
 AND t.runtime_deleted=0 AND t.status NOT IN ('running','queued','draft')"""


def pending_counts(cur, task_ids=None):
    if task_ids is not None and not task_ids:
        return {}
    where, args = FROM + " AND m.review_id IS NULL", []
    if task_ids is not None:
        args = list(dict.fromkeys(task_ids))
        where += " AND r.task_id IN (" + ",".join(["%s"] * len(args)) + ")"
    cur.execute("SELECT r.task_id,COUNT(*) " + where + " GROUP BY r.task_id", args)
    return dict(cur.fetchall())


@router.get("/review-summary")
def summary():
    if not unified.enabled():
        from . import api, reviews
        result = reviews.list_reviews(api.ROOT)
        counts = {}
        for row in result["items"]:
            if not row["decision"]:
                counts[row["taskId"]] = counts.get(row["taskId"], 0) + 1
        return {"pending": result["pending"], "byTask": counts}
    try:
        with report_store.connection() as conn:
            with conn.cursor() as cur:
                counts = pending_counts(cur)
        return {"pending": sum(counts.values()), "byTask": counts}
    except Exception:
        raise HTTPException(503, "复核摘要暂不可用") from None


@router.get("/review-items")
def listing(task_id: str = Query("", max_length=64), kind: Literal["", "attack", "positive"] = "",
            pending: bool = True, page: int = Query(1, ge=1, le=1000000),
            page_size: int = Query(30, ge=1, le=100),
            focus_id: Annotated[str, Query(max_length=32)] = ""):
    if not unified.enabled():
        from . import api, reviews
        rows = [row for row in reviews.list_reviews(api.ROOT)["items"]
                if (not task_id or row["taskId"] == task_id) and (not kind or row["kind"] == kind)
                and (not pending or not row["decision"])]
        if focus_id:
            index = next((i for i, row in enumerate(rows) if row["id"] == focus_id), None)
            if index is not None:
                page = index // page_size + 1
        return {"items": rows[(page-1)*page_size:page*page_size], "total": len(rows), "page": page}
    where, args = FROM, []
    if task_id:
        where += " AND r.task_id=%s"
        args.append(task_id)
    if kind:
        where += " AND x.test_kind=%s"
        args.append(kind)
    if pending:
        where += " AND m.review_id IS NULL"
    try:
        with report_store.connection() as conn:
            with conn.cursor() as cur:
                if focus_id:
                    cur.execute("SELECT x.result_id,t.created_at " + where +
                                " AND LEFT(SHA2(CONCAT(r.task_id,'/',r.source_name,'/',x.pointer),256),32)=%s LIMIT 1",
                                (*args, focus_id))
                    focused = cur.fetchone()
                    if focused:
                        result_id, created = focused
                        cur.execute("SELECT COUNT(*) " + where +
                                    " AND (t.created_at>%s OR (t.created_at=%s AND x.result_id<%s))",
                                    (*args, created, created, result_id))
                        page = cur.fetchone()[0] // page_size + 1
                cur.execute("SELECT COUNT(*) " + where, args)
                total = cur.fetchone()[0]
                cur.execute("""SELECT r.task_id,t.name,t.created_at,x.test_kind,r.source_name,
                    r.schema_version,x.pointer,x.source_case_id,m.review_id,x.title,x.description """ + where +
                    " ORDER BY t.created_at DESC,x.result_id LIMIT %s OFFSET %s",
                    (*args, page_size, (page-1)*page_size))
                items = []
                for tid, name, created, module, source, schema, pointer, case, reviewed, title, description in cur.fetchall():
                    key = hashlib.sha256(f"{tid}/{source}/{pointer}".encode()).hexdigest()[:32]
                    items.append({"id": key, "taskId": tid, "taskName": name, "createdAt": created, "kind": module,
                                  "engine": "epe" if schema.endswith("epe-report") else "cr",
                                  "caseId": case, "decision": bool(reviewed),
                                  "title": title, "preview": report_store.evidence(str(description or "")[:160])})
        return {"items": items, "total": total, "page": page}
    except Exception:
        raise HTTPException(503, "复核列表暂不可用") from None
