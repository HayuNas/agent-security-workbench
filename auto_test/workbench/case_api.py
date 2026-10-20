"""Regression CRUD uses the canonical Case table with optimistic revisions."""
from typing import Annotated, Literal
from uuid import uuid4
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from ..records import case_store as store, report_store
from .contracts import PACKS

router = APIRouter(prefix="/api/agent/case-libraries", tags=["回归库管理"])
Kind = Literal["security", "business_bad", "business", "guard_internal"]
ReadKind = Literal["security", "business_bad", "business", "guard_internal", "attack_fixed"]


class SelectionPage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(max_length=5000)
    page: int = Field(default=1, ge=1)
    pageSize: int = Field(default=5, ge=1, le=10)


class Edit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=0)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    enabled: bool = True
    messages: list[str] = Field(min_length=1, max_length=50)
    target: str = Field(default="ky-agent:ky-sales", max_length=150)
    pack: str = Field(default="prompt_leakage", max_length=128)
    engine: Literal["cr", "epe"] = "cr"


class FixedEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=0)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    enabled: bool = True


class ReferenceTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    round: int = Field(ge=1)
    customerMessage: str = Field(min_length=1, max_length=100000)
    referenceReply: str = Field(min_length=1, max_length=100000)


class BusinessEdit(FixedEdit):
    target: str = Field(default="ky-agent:ky-sales", max_length=150)
    referenceTurns: list[ReferenceTurn] = Field(min_length=1, max_length=100)
    scenario: dict | None = None
    coreTask: dict | None = None
    customerProfile: dict | None = None
    customerSpeechStyle: dict | None = None
    baseline: dict | None = None


class GuardEdit(FixedEdit):
    agentId: str = Field(min_length=1, max_length=128)
    datasetGroup: str | None = Field(default=None, max_length=64)
    content: str = Field(min_length=1, max_length=100000)
    direction: Literal["input", "output"] = "input"
    stage: Literal["full", "stream"] = "full"
    expectedDecision: Literal["ALLOW", "BLOCK", "OBSERVE"] = "ALLOW"
    conversationContext: list[str] | None = Field(default=None, max_length=100)
    labels: dict | None = None
    expectedRationale: str | None = Field(default=None, max_length=10000)
    expectedBehavior: str | None = Field(default=None, max_length=10000)
    grounding: dict | None = None


def guarded(function, *args, **kwargs):
    if not store.enabled():
        raise HTTPException(503, "数据库回归库未启用")
    try:
        return function(*args, **kwargs)
    except store.Conflict as exc:
        raise HTTPException(409, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "回归库数据库暂不可用，未回退本地文件") from None


@router.get("")
def library_catalog():
    return {"libraries": [
        {"kind": "security", "name": "攻击成功回归库"},
        {"kind": "business_bad", "name": "业务问题回归库"},
        {"kind": "business", "name": "正常业务数据集"},
        {"kind": "guard_internal", "name": "内部护栏样本", "groups": [
            {"id": group, "name": name} for group, name in zip(store.INTERNAL_GROUPS, (
                "通用正常输入", "边界正常输入", "业务流程", "业务流程扩展"))]},
    ]}


@router.get("/{kind}")
def listing(kind: ReadKind, page: int = Query(1, ge=1), page_size: int = Query(30, ge=1, le=100),
            search: str = Query("", max_length=200), target: str = Query("", max_length=150),
            engine: Literal["", "all", "cr", "epe", "business", "guard"] = "",
            state: Literal["", "enabled", "disabled"] = "",
            repair: Literal["", "unknown", "0", "1", "2"] = "",
            group: str = Query("", max_length=64)):
    return guarded(store.listing, kind, page=page, page_size=page_size, search=search, target=target,
                   engine=engine, state=state, repair=repair, group=group, include_activity=True)


@router.post("/{kind}/selection-page")
def selection_page(kind: ReadKind, body: SelectionPage):
    return guarded(store.listing, kind, ids=body.ids, page=body.page, page_size=body.pageSize,
                   include_activity=True)


@router.get("/{kind}/{case_id}/activity")
def activity(kind: Kind, case_id: str, section: Literal["runs", "findings", "reviews"],
             page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100)):
    from ..records.case_view import activity as read_activity
    return guarded(read_activity, kind, case_id, section, page, page_size)


@router.get("/{kind}/{case_id}/runs/{run_id}")
def run_detail(kind: Kind, case_id: str, run_id: str):
    from ..records.case_view import run_detail as read_run
    return guarded(read_run, kind, case_id, run_id)


@router.get("/{kind}/{case_id}/discovery")
def discovery(kind: Kind, case_id: str):
    from ..records.case_view import discovery as read_discovery
    return guarded(read_discovery, kind, case_id)


@router.get("/{kind}/{case_id}")
def detail(kind: ReadKind, case_id: str):
    value = guarded(store.detail, kind, case_id)
    if value is None:
        raise HTTPException(404, "回归用例不存在")
    # Field-based edit responses must retain exact executable input, not a redacted replacement.
    # This shares the existing trusted-workbench access boundary; do not expose publicly.
    return value


def update(kind, case_id, body, create=False):
    if kind in {"business", "guard_internal"}:
        return update_fixed(kind, case_id, body, create)
    if not isinstance(body, Edit):
        raise ValueError("此用例库需要 messages 编辑结构")
    if any(not text.strip() or len(text) > 100000 for text in body.messages):
        raise ValueError("消息不能为空，单条最多 100000 字符")
    if sum(map(len, body.messages)) > 500000:
        raise ValueError("用例内容过大")
    if kind == "security" and body.pack not in PACKS:
        raise ValueError("攻击场景尚未适配")
    if kind == "security" and body.engine == "epe" and body.pack != "prompt_leakage":
        raise ValueError("EPE 仅支持提示词泄露场景")
    from .agent_config import read_directory
    targets = {f"{a['adapter']}:{a['agentId']}" for a in read_directory()["agents"]}
    if body.target not in targets:
        raise ValueError("请选择已接入的 Agent")
    if kind == "security" and body.target.startswith("ai-web:") and body.pack != "prompt_leakage":
        raise ValueError("内部 Agent 当前仅适配提示词泄露回归")
    if kind == "business_bad" and body.target not in {"ky-agent:ky-sales", "ky-app:sales-agent"}:
        raise ValueError("当前正向回归执行器仅支持销售 Agent；不改变内部 Agent 适配边界")
    with store.transaction() as conn, conn.cursor() as cur:
        old = store.detail(kind, case_id)
        if create and old:
            raise store.Conflict("用例已存在")
        if not create and not old:
            raise store.Conflict("用例已不存在")
        case = dict(old["case"]) if old else {"case_id": case_id}
        adapter, agent_id = body.target.split(":", 1)
        case.update(title=body.title, description=body.description, status="active" if body.enabled else "disabled",
                    target={"adapter": adapter, "target_key": body.target, "app_id": agent_id if adapter == "ai-web" else ""},
                    engine=body.engine)
        if kind == "security":
            case.update(pack_id=body.pack, messages=body.messages, prompt="\n\n".join(body.messages))
        else:
            case.update(case_type="positive_business_bad_case",
                        reference_turns=[{"round": i+1, "customer_message": text, "reference_reply": ""}
                                         for i, text in enumerate(body.messages)])
            case.setdefault("scenario", {"name": body.title})
            case.setdefault("core_task", {"goal": body.description or body.title})
            case.setdefault("baseline", {"expected_outcome": "PASS"})
        revision = store.put(cur, kind, case, expected=body.revision, allow_create=create)
    return {"id": case_id, "revision": revision}


def update_fixed(kind, case_id, body, create=False):
    expected_type = BusinessEdit if kind == "business" else GuardEdit
    if not isinstance(body, expected_type):
        raise ValueError("正常业务库需要 referenceTurns，内部护栏库需要 content")
    if len(report_store.encoded(body.model_dump()).encode("utf-8")) > 2000000:
        raise ValueError("用例内容过大")
    from .agent_config import read_directory
    targets = {f"{a['adapter']}:{a['agentId']}" for a in read_directory()["agents"]}
    target = body.target if kind == "business" else f"ai-web:{body.agentId}"
    if target not in targets:
        raise ValueError("请选择已接入的 Agent")
    if kind == "business":
        if target not in {"ky-agent:ky-sales", "ky-app:sales-agent"}:
            raise ValueError("固定正常业务执行器当前仅支持销售 Agent")
        rounds = [turn.round for turn in body.referenceTurns]
        if rounds != sorted(set(rounds)) or any(not turn.customerMessage.strip() or not turn.referenceReply.strip()
                                               for turn in body.referenceTurns):
            raise ValueError("对话轮次须递增且不重复，客户消息和参考回复不能为空")
    elif not body.content.strip() or body.datasetGroup and body.datasetGroup not in store.INTERNAL_GROUPS:
        raise ValueError("护栏内容不能为空且分组须有效")
    if isinstance(body, GuardEdit) and any(len(text) > 100000 for text in body.conversationContext or []):
        raise ValueError("上下文过长")
    with store.transaction() as conn, conn.cursor() as cur:
        old = store.detail(kind, case_id)
        if create and old:
            raise store.Conflict("用例已存在")
        if not create and not old:
            raise store.Conflict("用例已不存在")
        case = dict(old["case"]) if old else {"case_id": case_id}
        adapter, agent_id = target.split(":", 1)
        case.update(title=body.title, description=body.description, status="active" if body.enabled else "disabled",
                    target={"adapter": adapter, "target_key": target, "app_id": agent_id if adapter == "ai-web" else ""})
        group = None
        if kind == "business":
            case.update(case_type="positive_business", agent_type="ky-sales", engine="business",
                        reference_turns=[{"round": turn.round, "customer_message": turn.customerMessage,
                                          "reference_reply": turn.referenceReply} for turn in body.referenceTurns])
            for field, key in (("scenario", "scenario"), ("coreTask", "core_task"), ("baseline", "baseline"),
                               ("customerProfile", "customer_profile"), ("customerSpeechStyle", "customer_speech_style")):
                if getattr(body, field) is not None:
                    case[key] = getattr(body, field)
            case.setdefault("scenario", {"name": body.title})
            case.setdefault("core_task", {"goal": body.description or body.title})
            case.setdefault("baseline", {"expected_outcome": "PASS"})
        else:
            case["target"] = {"adapter": "guard", "target_key": f"guard:{body.agentId}", "app_id": body.agentId}
            case.update(case_type=case.get("case_type") or "guard_internal_positive", engine="guard",
                        agent_id=body.agentId, content=body.content, direction=body.direction, stage=body.stage,
                        expected_decision=body.expectedDecision)
            if body.conversationContext is not None:
                case["conversation_context"] = body.conversationContext
            if body.labels is not None:
                case["labels"] = body.labels
            case.setdefault("conversation_context", [])
            case.setdefault("labels", {})
            case.setdefault("source_case_id", case_id)
            case.setdefault("turn_index", 1)
            for field, key in (("expectedRationale", "expected_rationale"), ("expectedBehavior", "expected_behavior"),
                               ("grounding", "grounding")):
                if getattr(body, field) is not None:
                    case[key] = getattr(body, field)
            group = body.datasetGroup if body.datasetGroup is not None else old["datasetGroup"] if old else ""
        revision = store.put(cur, kind, case, expected=body.revision, allow_create=create, group=group)
    return {"id": case_id, "revision": revision}


@router.post("/{kind}", status_code=201)
def create(kind: Kind, body: Edit | BusinessEdit | GuardEdit):
    if body.revision != 0:
        raise HTTPException(422, "新增用例的 revision 必须为 0")
    prefix = {"security": "SEC-USER-", "business_bad": "BIZBAD-USER-",
              "business": "BIZ-USER-", "guard_internal": "GRD-USER-"}[kind]
    return guarded(update, kind, prefix + uuid4().hex.upper(), body, True)


@router.put("/{kind}/{case_id}")
def edit(kind: Kind, case_id: str, body: Edit | BusinessEdit | GuardEdit):
    return guarded(update, kind, case_id, body)


def soft_delete(kind, case_id, revision):
    with store.transaction() as conn, conn.cursor() as cur:
        store.metadata(cur, kind)
        cur.execute("""UPDATE agent_security_cases SET case_deleted=1,case_enabled=0,case_revision=case_revision+1
            WHERE case_id=%s AND library_kind=%s AND case_revision=%s AND case_deleted=0""", (case_id, kind, revision))
        if cur.rowcount != 1:
            raise store.Conflict("用例不存在或版本已变化")
        cur.execute("UPDATE agent_case_libraries SET revision=revision+1 WHERE kind=%s", (kind,))
    return {"id": case_id, "deleted": True}


@router.delete("/{kind}/{case_id}")
def remove(kind: Kind, case_id: str, revision: int = Query(..., ge=1)):
    return guarded(soft_delete, kind, case_id, revision)
