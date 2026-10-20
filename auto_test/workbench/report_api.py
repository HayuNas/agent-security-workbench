"""Database-only report browsing; no filesystem fallback or model calls."""
import logging
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from ..records import report_store

router = APIRouter(prefix="/api/agent/report-records", tags=["数据库报告"])
logger = logging.getLogger(__name__)
Page = Annotated[int, Query(ge=1, le=1000000)]
Size = Annotated[int, Query(ge=1, le=100)]
Key = Annotated[str, Query(max_length=64)]


def call(function, *args, **kwargs):
    if not report_store.enabled():
        raise HTTPException(503, "数据库报告存储未启用")
    try:
        return function(*args, **kwargs)
    except Exception:
        # SQL exceptions may contain private data; never expose them to clients.
        logger.error("Database report operation failed: %s", function.__name__)
        raise HTTPException(503, "数据库报告暂不可用，请确认迁移完成及数据库连接") from None


def required(value):
    if value is None:
        raise HTTPException(404, "记录不存在")
    return value


@router.get("")
def reports(page: Page = 1, page_size: Size = 30, task_id: Key = "",
            module: Literal["", "attack", "positive", "guard"] = "",
            report_type: Literal["", "result", "finding"] = ""):
    return call(report_store.list_reports, page=page, page_size=page_size,
                task_id=task_id, module=module, report_type=report_type)


@router.get("/results/{result_id}")
def result_detail(result_id: str):
    from ..records import unified
    result = required(call(report_store.detail, "result", result_id))
    if unified.enabled():
        result["_review_id"] = call(unified.review_reference, result_id)
    return result


@router.get("/tasks/{task_id}/results")
def task_results(task_id: str, page: Page = 1, page_size: Size = 30):
    return call(report_store.list_task_results, task_id, page=page, page_size=page_size)


@router.get("/tasks/{task_id}/findings")
def task_findings(task_id: str, page: Page = 1, page_size: Size = 5,
                  analysis_source: Literal["", "human_review", "automatic"] = ""):
    return call(report_store.list_task_findings, task_id, page=page, page_size=page_size, analysis_source=analysis_source)


@router.get("/tasks/{task_id}/findings/download")
def task_finding_download(task_id: str, analysis_source: Literal["", "human_review", "automatic"] = ""):
    content = required(call(report_store.task_finding_download, task_id, analysis_source=analysis_source))
    return Response(content, media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="findings.md"'})


@router.get("/finding-items/{finding_id}")
def canonical_finding(finding_id: str):
    from ..records import unified
    return required(call(unified.finding_by_id, finding_id))


@router.get("/findings/{entry_id}")
def finding_detail(entry_id: str):
    return required(call(report_store.detail, "finding", entry_id))


@router.get("/{report_id}")
def report_detail(report_id: str):
    return required(call(report_store.detail, "report", report_id))


@router.get("/{report_id}/results")
def results(report_id: str, page: Page = 1, page_size: Size = 30,
            outcome: Annotated[str, Query(max_length=64)] = "",
            direction: Literal["", "input", "output"] = "",
            search: Annotated[str, Query(max_length=200)] = ""):
    return call(report_store.list_results, report_id, page=page, page_size=page_size,
                outcome=outcome, direction=direction, search=search)


@router.get("/{report_id}/summary")
def report_summary(report_id: str):
    return required(call(report_store.summary, report_id))


@router.get("/{report_id}/findings")
def findings(report_id: str, page: Page = 1, page_size: Size = 30):
    return call(report_store.list_findings, report_id, page=page, page_size=page_size)


@router.get("/{report_id}/download")
def download(report_id: str):
    content = required(call(report_store.finding_download, report_id))
    return Response(content, media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="findings.md"'})
