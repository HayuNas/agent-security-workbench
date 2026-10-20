"""Explicit generation/retry and read-only progress for review Findings."""
from fastapi import APIRouter, HTTPException

from ..records import case_store
from . import review_analysis
from .report_api import call

router = APIRouter(prefix="/api/agent/tasks", tags=["人工复核"])


@router.get("/{task_id}/review-findings")
def status(task_id: str):
    return call(review_analysis.status, task_id)


@router.post("/{task_id}/review-findings", status_code=202)
def generate(task_id: str):
    if not case_store.enabled():
        raise HTTPException(503, "请先迁移数据库回归库")
    try:
        return review_analysis.request(task_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except Exception:
        raise HTTPException(503, "分析任务暂未提交，请确认数据库迁移已完成") from None
