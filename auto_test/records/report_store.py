"""MySQL-backed report evidence and bounded, indexed list queries."""
from __future__ import annotations

import hashlib
import json
import os
import base64
import zlib
from contextlib import contextmanager
from pathlib import Path

from risk_guard.config_storage import mysql_connection
from ..core.redaction import SENSITIVE_KEY_RE, redact_text, redact_value


class ReportConflict(ValueError):
    pass


def enabled():
    backend = os.getenv("WORKBENCH_DATA_BACKEND", "mysql").strip().lower()
    if backend not in {"mysql", "legacy"}:
        raise ValueError("WORKBENCH_DATA_BACKEND must be mysql or legacy")
    return backend == "mysql"


@contextmanager
def connection():
    conn = mysql_connection()
    try:
        yield conn
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass  # A dead connection cannot roll back; preserve the original error.
        raise
    finally:
        conn.close()


def initialize():
    path = Path(__file__).parents[1] / "db/migrations/010_workbench_reports.sql"
    # This owned migration contains only DDL, with no semicolons in literals.
    with connection() as conn:
        with conn.cursor() as cur:
            for statement in path.read_text(encoding="utf-8").split(";"):
                if statement.strip():
                    cur.execute(statement)
        conn.commit()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def packed(text):
    raw = text.encode("utf-8")
    if len(raw) < 128000:
        return text
    return "zlib:" + base64.b64encode(zlib.compress(raw)).decode("ascii")


def unpacked(text):
    if text.startswith("zlib:"):
        text = zlib.decompress(base64.b64decode(text[5:])).decode("utf-8")
    return json.loads(text)


def evidence(value):
    """Keep relational identifiers intact while redacting free text and secrets."""
    if isinstance(value, dict):
        safe = {}
        for key, item in value.items():
            if SENSITIVE_KEY_RE.fullmatch(str(key).strip()):
                safe[redact_text(key)] = redact_value({key: item})[redact_text(key)]
                continue
            if key in {"id", "task_id", "case_id", "finding_id", "run_id", "experiment_id",
                       "source_run_id", "query_id", "iteration_id", "seed_id", "asset_snapshot_id",
                       "case_ids", "source_case_ids", "guard_case_ids", "finding_ids",
                       "taskId", "caseId", "findingIds", "libraryCaseIds", "runId", "resultId", "source_result_id"}:
                safe[key] = item
            else:
                safe[redact_text(key)] = evidence(item)
        return safe
    if isinstance(value, list):
        return [evidence(item) for item in value]
    return redact_value(value)


def identity(*values):
    return hashlib.sha256(encoded(values).encode()).hexdigest()


def report_module(report):
    schema = str(report.get("schema_version") or "")
    if "guard" in schema:
        return "guard"
    if "business" in schema:
        return "positive"
    return "attack"


def supported(report):
    schema = str(report.get("schema_version") or "")
    return bool(schema) and (
        schema.endswith(("security-attack-pack-report", "epe-report",
                         "business-regression-report", "guard-regression-report",
                         "security-regression-report"))
        or ("finding" in schema and isinstance(report.get("findings"), list))
    )


def result_entries(report):
    if str(report.get("schema_version", "")).endswith("security-attack-pack-report"):
        for pi, pack in enumerate(report.get("packs") or []):
            for ri, item in enumerate(pack.get("iterations") or []):
                yield f"packs/{pi}/iterations/{ri}", item, pack
    else:
        for ri, item in enumerate(report.get("results") or []):
            yield f"results/{ri}", item, {}


def project_result(report_id, ordinal, pointer, item, pack):
    case_id = str(item.get("case_id") or item.get("query_id") or item.get("iteration_id") or item.get("seed_id") or "")
    scenario = item.get("scenario") or {}
    if not isinstance(scenario, dict):
        scenario = {}
    title = str(item.get("title") or item.get("scenario_name") or scenario.get("name")
                or pack.get("name") or pack.get("pack_id") or case_id or "Test result")
    turns = item.get("turns") or []
    first = turns[0] if turns and isinstance(turns[0], dict) else {}
    description = str(item.get("description") or item.get("message") or item.get("content") or item.get("prompt")
                      or item.get("input") or first.get("customer_message") or first.get("message") or title)
    return (
        identity(report_id, pointer), report_id, ordinal, pointer, case_id[:191],
        title[:255], description[:2000], str(item.get("outcome") or item.get("result") or "")[:64],
        str(item.get("direction") or "")[:32],
        encoded((pack.get("oracle") or {}).get("success_outcomes") or []), packed(encoded(item)),
    )


def upsert_task(cur, task, module):
    task = evidence(task)
    cur.execute(
        """INSERT INTO agent_test_tasks (task_id,module,name,status,created_at,payload)
        VALUES (%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE
        name=VALUES(name),status=VALUES(status),payload=VALUES(payload)""",
        (task["id"], module, str(task.get("name") or task["id"])[:255],
         str(task.get("status") or "")[:32], str(task.get("createdAt") or "")[:50], encoded(task)),
    )


def write_cli_task(cur, task, module):
    upsert_task(cur, task, module)
    cur.execute("UPDATE agent_test_tasks SET runtime_payload=%s,runtime_summary=NULL WHERE task_id=%s",
                (packed(encoded(task)), task["id"]))


def write_report(cur, task_id, source_name, report, markdown=""):
    from . import unified
    report = evidence(report)
    if not supported(report):
        raise ValueError("Unsupported report schema")
    report_id = identity(task_id, source_name)
    content = encoded(report)
    digest = hashlib.sha256(content.encode()).hexdigest()
    cur.execute("SELECT content_hash FROM agent_test_reports WHERE report_id=%s FOR UPDATE", (report_id,))
    old = cur.fetchone()
    if old:
        if old[0] != digest:
            raise ReportConflict(f"Report content differs; not overwritten: {source_name}")
        return False
    rows = [project_result(report_id, n, pointer, item, pack)
            for n, (pointer, item, pack) in enumerate(result_entries(report), 1)]
    findings = report.get("findings") or []
    report_type = "finding" if "finding" in str(report["schema_version"]) else "result"
    stored = report
    if unified.enabled():
        # New reports retain only their header; rows and Finding versions are relational.
        stored = {**report, "_workbench_storage": "normalized-v1"}
        if "results" in stored:
            stored["results"] = []
        if "findings" in stored:
            stored["findings"] = []
        if "packs" in stored:
            stored["packs"] = [{**pack, "iterations": []} for pack in stored["packs"]]
    cur.execute(
        """INSERT INTO agent_test_reports
        (report_id,task_id,module,report_type,source_name,run_id,schema_version,created_at,
         content_hash,result_count,finding_count,summary,payload,finding_markdown)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (report_id, task_id, report_module(report), report_type, source_name,
         str(report.get("run_id") or report.get("experiment_id") or report.get("source_run_id") or "")[:191],
         report["schema_version"], str(report.get("created_at") or report.get("generated_at") or "")[:50],
         digest, len(rows), len(findings), encoded(report.get("summary") or {}), packed(encoded(stored)),
         str(redact_value(markdown)) if report_type == "finding" else ""),
    )
    if rows:
        from . import unified
        if unified.enabled():
            unified.write_results(cur, report_id, report, rows)
        else:
            cur.executemany(
                """INSERT INTO agent_test_results
                (result_id,report_id,ordinal,pointer,case_id,title,description,outcome,direction,review_outcomes,payload)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", rows,
            )
    if findings:
        from . import unified
        if unified.enabled():
            unified.write_findings(cur, report_id, report)
        ordinal_column = ",ordinal" if unified.enabled() else ""
        ordinal_value = ",%s" if unified.enabled() else ""
        cur.executemany(
            f"""INSERT INTO agent_test_report_findings
            (entry_id,report_id,finding_id,title,severity,status,payload{ordinal_column})
            VALUES (%s,%s,%s,%s,%s,%s,%s{ordinal_value})""",
            [(identity(report_id, str(n)), report_id, str(f.get("finding_id") or "")[:191],
              str(f.get("title") or "")[:255], str(f.get("severity") or "")[:32],
              str(f.get("status") or report.get("analysis_status") or report.get("review_status") or "")[:64],
              packed(encoded(f))) + ((n,) if unified.enabled() else ()) for n, f in enumerate(findings)],
        )
    return True


def task_reports(directory):
    directory = Path(directory).resolve()
    from ..workbench import artifacts
    if artifacts.enabled():
        try:
            artifacts.owner(directory)
        except ValueError:
            pass
        else:
            names = artifacts.listing(directory)
            for name in names:
                if not name.endswith(".json"):
                    continue
                value = artifacts.get(directory, name)
                report = json.loads(value)
                if isinstance(report, dict) and supported(report):
                    markdown = artifacts.get(directory, name[:-5] + ".md") or ""
                    yield name, report, markdown if "finding" in str(report["schema_version"]) else ""
            return
    # Only report locations owned by the workbench. Never scan private assets.
    paths = set()
    for child in directory.iterdir():
        if child.is_dir() and (child.name.startswith("batch-") or child.name in {"findings", "reports"}):
            paths.update(child.rglob("*.json"))
    for path in sorted(paths):
        if not path.resolve().is_relative_to(directory):
            raise ValueError("Report path outside task directory")
        report = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(report, dict) and supported(report):
            md = path.with_suffix(".md")
            markdown = md.read_text(encoding="utf-8") if "finding" in str(report["schema_version"]) and md.is_file() else ""
            yield path.relative_to(directory).as_posix(), report, markdown


def import_task(directory, *, task=None):
    directory = Path(directory)
    from ..workbench import task_store
    path = directory / "task.json"
    if task is None:
        task = task_store.read(path) if task_store.enabled() and task_store.locate(path) else json.loads(path.read_text(encoding="utf-8"))
    if not task:
        raise ValueError("Task runtime record is missing")
    if str(task.get("id")) != directory.name:
        raise ValueError("Task ID does not match directory")
    reports = list(task_reports(directory))
    module = "guard" if directory.parent.name == "guard" else str((task.get("config") or {}).get("kind") or "attack")
    with connection() as conn:
        with conn.cursor() as cur:
            upsert_task(cur, task, module)
            inserted = sum(write_report(cur, task["id"], name, report, md) for name, report, md in reports)
            cur.execute("SELECT COUNT(*) FROM agent_test_reports WHERE task_id=%s", (task["id"],))
            count = cur.fetchone()[0]
            if count < len(reports):
                raise RuntimeError("Report count verification failed")
        conn.commit()
    return {"task_id": task["id"], "reports": len(reports), "inserted": inserted}


def _page(page, page_size):
    if isinstance(page, bool) or isinstance(page_size, bool) or not 1 <= page_size <= 100 or not 1 <= page <= 1000000:
        raise ValueError("Invalid pagination")
    return page_size, (page - 1) * page_size


def _list(table, columns, where, params, order, page, page_size):
    limit, offset = _page(page, page_size)
    clause = " AND ".join(where) or "1=1"
    with connection() as conn:
        with conn.cursor() as cur:
            # Count and page share one InnoDB consistent-read transaction.
            cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {clause}", tuple(params))
            total = cur.fetchone()[0]
            cur.execute(f"SELECT {','.join(columns)} FROM {table} WHERE {clause} ORDER BY {order} LIMIT %s OFFSET %s",
                        (*params, limit, offset))
            items = [dict(zip([column.split(" AS ")[-1] for column in columns], row)) for row in cur.fetchall()]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


def list_reports(*, page=1, page_size=30, task_id="", module="", report_type=""):
    where, params = [], []
    for key, value in (("task_id", task_id), ("module", module), ("report_type", report_type)):
        if value:
            where.append(f"{key}=%s")
            params.append(value)
    return _list("agent_test_reports",
                 ("report_id", "task_id", "module", "report_type", "source_name", "run_id",
                  "created_at", "result_count", "finding_count"),
                 where, params, "created_at DESC,report_id DESC", page, page_size)


def list_results(report_id, *, page=1, page_size=30, outcome="", direction="", search=""):
    from . import unified
    canonical = unified.enabled()
    case_column = "source_case_id" if canonical else "case_id"
    where, params = ["report_id=%s"], [report_id]
    for key, value in (("outcome", outcome), ("direction", direction)):
        if value:
            where.append(f"{key}=%s")
            params.append(value)
    if search:
        where.append(f"(title LIKE %s ESCAPE '!' OR description LIKE %s ESCAPE '!' OR {case_column} LIKE %s ESCAPE '!')")
        query = "%" + search.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
        params.extend([query] * 3)
    return _list("agent_security_case_runs" if canonical else "agent_test_results",
                 ("result_id", "ordinal", case_column + " AS case_id", "title", "description", "outcome", "direction"),
                 where, params, "ordinal ASC", page, page_size)


def list_findings(report_id, *, page=1, page_size=30):
    from . import unified
    if unified.enabled():
        return _list("agent_test_report_findings n JOIN agent_security_findings f ON f.finding_id=n.finding_id",
                     ("n.entry_id AS entry_id", "f.finding_id AS finding_id", "f.title AS title",
                      "f.severity AS severity", "f.status AS status", "n.status AS analysis_status"),
                     ["n.report_id=%s"], [report_id], "n.entry_id ASC", page, page_size)
    return _list("agent_test_report_findings",
                 ("entry_id", "finding_id", "title", "severity", "status"),
                 ["report_id=%s"], [report_id], "entry_id ASC", page, page_size)


def list_task_results(task_id, *, page=1, page_size=30):
    """Read a task's persisted executions across batches, without report bodies."""
    from . import unified
    limit, offset = _page(page, page_size)
    canonical = unified.enabled()
    table = "agent_security_case_runs" if canonical else "agent_test_results"
    case_column = "source_case_id" if canonical else "case_id"
    source = f"{table} x JOIN agent_test_reports r ON r.report_id=x.report_id"
    clause = "r.task_id=%s AND r.report_type='result'"
    with connection() as conn:
        with conn.cursor() as cur:
            # Counts and the bounded page describe the same committed snapshot.
            cur.execute(f"SELECT x.outcome,COUNT(*) FROM {source} WHERE {clause} GROUP BY x.outcome", (task_id,))
            outcomes = dict(cur.fetchall())
            cur.execute(f"""SELECT x.result_id,x.ordinal,x.{case_column},x.title,
                        x.description,x.outcome,x.direction,r.module
                        FROM {source} WHERE {clause}
                        ORDER BY r.created_at,r.source_name,r.report_id,x.ordinal,x.result_id
                        LIMIT %s OFFSET %s""", (task_id, limit, offset))
            columns = ("result_id", "ordinal", "case_id", "title", "description", "outcome", "direction", "kind")
            items = [dict(zip(columns, row)) for row in cur.fetchall()]
    return {"items": items, "total": sum(outcomes.values()), "outcomes": outcomes,
            "page": page, "page_size": page_size}


TASK_FINDINGS = """agent_test_report_findings n JOIN agent_test_reports r ON r.report_id=n.report_id
    JOIN agent_security_findings f ON f.finding_id=n.finding_id"""
LATEST_FINDING = """r.task_id=%s AND r.report_type='finding' AND n.finding_id NOT LIKE 'RF-%%'
    AND NOT EXISTS (SELECT 1 FROM agent_test_report_findings newer
        JOIN agent_test_reports newer_report ON newer_report.report_id=newer.report_id
        WHERE newer_report.task_id=r.task_id AND newer.finding_id=n.finding_id
        AND (newer_report.created_at>r.created_at OR
             (newer_report.created_at=r.created_at AND newer_report.report_id>r.report_id)))"""


def _task_finding_filter(analysis_source):
    if analysis_source not in {"", "human_review", "automatic"}:
        raise ValueError("Invalid Finding analysis source")
    if not analysis_source:
        return LATEST_FINDING
    operator = "LIKE" if analysis_source == "human_review" else "NOT LIKE"
    return LATEST_FINDING + " AND r.source_name " + operator + " 'review-findings/%%'"


def list_task_findings(task_id, *, page=1, page_size=5, analysis_source=""):
    limit, offset = _page(page, page_size)
    clause = _task_finding_filter(analysis_source)
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM " + TASK_FINDINGS + " WHERE " + clause, (task_id,))
        total = cur.fetchone()[0]
        cur.execute("""SELECT n.entry_id,n.finding_id,n.title,f.status,n.severity,
            IF(r.source_name LIKE 'review-findings/%%','human_review','automatic'),r.created_at,
            (SELECT COUNT(*) FROM agent_security_finding_cases linked WHERE linked.finding_id=n.finding_id)
            FROM """ + TASK_FINDINGS + " WHERE " + clause +
            " ORDER BY r.created_at DESC,n.entry_id LIMIT %s OFFSET %s", (task_id, limit, offset))
        items = [dict(zip(("entry_id", "finding_id", "title", "status", "severity", "analysis_source", "created_at", "case_count"), row)) for row in cur.fetchall()]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


def task_finding_download(task_id, *, analysis_source=""):
    # Full bodies are fetched only for an explicit export, never for list views.
    clause = _task_finding_filter(analysis_source)
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT n.payload FROM " + TASK_FINDINGS + " WHERE " + clause +
                    " ORDER BY r.created_at DESC,n.entry_id", (task_id,))
        findings = [unpacked(row[0]) for row in cur.fetchall()]
    if not findings:
        return None
    lines = ["# Finding 报告", "", "测试任务：" + task_id, ""]
    for finding in findings:
        lines.extend(["## " + str(finding.get("title") or finding["finding_id"]), "",
                      "Finding：" + finding["finding_id"], "",
                      "来源：" + ("人工确认后归并分析" if finding.get("analysis_source") == "human_review" else "自动分析"), "",
                      "关联用例：" + ", ".join(finding.get("case_ids") or finding.get("source_ids") or []), ""])
        for title, value in (
            ("根因假设", finding.get("root_cause") or finding.get("root_cause_hypothesis") or finding.get("root_cause_hypotheses")),
            ("证据", finding.get("evidence")),
            ("修复建议", finding.get("remediation") or finding.get("remediation_requirements") or finding.get("fix_contract")),
            ("验收", finding.get("acceptance") or finding.get("acceptance_criteria")),
            ("对话证据", finding.get("case_evidence")),
        ):
            if value:
                text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
                lines.extend(["### " + title, "", "```text", text.replace("```", "` ` `"), "```", ""])
    return "\n".join(lines)


def detail(kind, key):
    from . import unified
    if kind == "finding" and unified.enabled():
        with connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT finding_id FROM agent_test_report_findings WHERE entry_id=%s", (key,))
                row = cur.fetchone()
                return unified.finding_detail(cur, row[0]) if row else None
    table, column = {
        "report": ("agent_test_reports", "report_id"),
        "result": ("agent_test_results", "result_id"),
        "finding": ("agent_test_report_findings", "entry_id"),
    }[kind]
    if kind == "result" and unified.enabled():
        table = "agent_security_case_runs"
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT payload FROM {table} WHERE {column}=%s", (key,))
            row = cur.fetchone()
            data = unpacked(row[0]) if row else None
            if kind == "report" and data and data.pop("_workbench_storage", None) == "normalized-v1":
                cur.execute("""SELECT pointer,payload FROM agent_security_case_runs
                            WHERE report_id=%s ORDER BY ordinal""", (key,))
                for pointer, payload in cur.fetchall():
                    parts = pointer.split("/")
                    if parts[0] == "packs":
                        data["packs"][int(parts[1])]["iterations"].append(unpacked(payload))
                    else:
                        data["results"].append(unpacked(payload))
                if "findings" in data:
                    cur.execute("SELECT payload FROM agent_test_report_findings WHERE report_id=%s ORDER BY ordinal,entry_id", (key,))
                    data["findings"] = [unpacked(item[0]) for item in cur.fetchall()]
    return data


def finding_download(report_id):
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT finding_markdown FROM agent_test_reports
                        WHERE report_id=%s AND report_type='finding'""", (report_id,))
            row = cur.fetchone()
    return row[0] if row else None


def review_candidates(review_id=None):
    from . import unified
    table = "agent_security_case_runs" if unified.enabled() else "agent_test_results"
    case_column = "source_case_id" if unified.enabled() else "case_id"
    selected = " AND LEFT(SHA2(CONCAT(r.task_id,'/',r.source_name,'/',x.pointer),256),32)=%s" if review_id is not None else ""
    limit = " LIMIT 1" if review_id is not None else ""
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""SELECT r.task_id,t.name,t.created_at,r.module,r.source_name,
                        r.schema_version,r.report_id,x.pointer,x.{case_column},x.payload,x.review_outcomes
                        FROM {table} x
                        JOIN agent_test_reports r ON r.report_id=x.report_id
                        JOIN agent_test_tasks t ON t.task_id=r.task_id
                        WHERE x.outcome='REVIEW' AND r.module IN ('attack','positive')
                        AND t.status NOT IN ('running','queued','draft')
                        {selected} ORDER BY t.created_at DESC,x.result_id{limit}""",
                        (review_id,) if review_id is not None else ())
            return cur.fetchall()


def summary(report_id):
    from . import unified
    table = "agent_security_case_runs" if unified.enabled() else "agent_test_results"
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT summary FROM agent_test_reports WHERE report_id=%s", (report_id,))
            row = cur.fetchone()
            if not row:
                return None
            cur.execute(f"SELECT outcome,COUNT(*) FROM {table} WHERE report_id=%s GROUP BY outcome", (report_id,))
            return {"metrics": json.loads(row[0]), "outcomes": dict(cur.fetchall())}


def status():
    counts = {}
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT @@max_allowed_packet")
            counts["max_allowed_packet"] = cur.fetchone()[0]
            for table in ("agent_test_tasks", "agent_test_reports", "agent_test_results", "agent_test_report_findings"):
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                counts[table] = cur.fetchone()[0]
    return counts
