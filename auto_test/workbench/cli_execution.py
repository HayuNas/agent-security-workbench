"""Capture default CLI outputs in the database; explicit exports stay explicit."""
from contextlib import contextmanager, ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4

from ..core.paths import RESULTS_ROOT
from ..records import resources


def reference_text(value):
    from ..records import report_store
    from . import api, artifacts
    text = str(value).replace("\\", "/")
    if text.startswith("mysql:report:"):
        report_id = text.removeprefix("mysql:report:")
        if len(report_id) != 64 or any(c not in "0123456789abcdef" for c in report_id):
            raise ValueError("数据库报告引用无效")
        report = report_store.detail("report", report_id)
        if report is None:
            raise ValueError("数据库报告不存在")
        return report_store.encoded(report)
    if text.startswith("mysql:artifact:"):
        task_id, separator, relative = text.removeprefix("mysql:artifact:").partition("/")
        task_id = str(UUID(task_id))
        if not separator:
            raise ValueError("数据库执行资料引用无效")
        with report_store.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT module FROM agent_test_tasks WHERE task_id=%s", (task_id,))
            row = cur.fetchone()
        if not row:
            raise ValueError("数据库任务不存在")
        directory = (api.GUARD_ROOT if row[0] == "guard" else api.ROOT) / task_id
        result = artifacts.get(directory, relative)
        if result is None:
            raise ValueError("数据库执行资料不存在")
        return result
    if text.startswith("mysql:"):
        raise ValueError("未知数据库资料引用")
    return None


@contextmanager
def database_inputs(args):
    saved = {}
    with ExitStack() as stack:
        directory = None
        references = {}
        def materialize(value):
            nonlocal directory
            if isinstance(value, list):
                return [materialize(item) for item in value]
            if not isinstance(value, (str, Path)) or not str(value).startswith("mysql:"):
                return value
            text = str(value)
            if text not in references:
                content = reference_text(value)
                if directory is None:
                    directory = Path(stack.enter_context(TemporaryDirectory(prefix="ky-cli-input-")))
                path = directory / (str(len(references)) + ".json")
                path.write_text(content, encoding="utf-8")
                references[text] = path
            return references[text]
        try:
            for key, value in list(vars(args).items()):
                changed = materialize(value)
                if changed != value:
                    saved[key] = value
                    setattr(args, key, changed)
            yield
        finally:
            for key, value in saved.items():
                setattr(args, key, value)


@contextmanager
def database_execution(args):
    command = getattr(args, "command", "")
    action = getattr(args, ("finding" if command == "findings" else command) + "_action", "")
    produces_report = (
        command in {"automation", "paper"} or
        command == "security" and getattr(args, "security_strategy", "") not in {"aggregate", "cases"} or
        command == "business" and action in {"regression", "dynamic", "findings"} or
        command == "guard" and action in {"regression", "ai-web-acceptance", "ai-web-security", "findings"} or
        command == "target" and action == "smoke" or
        command == "findings" and action == "generate"
    )
    if not resources.enabled() or getattr(args, "dry_run", False) or not produces_report:
        yield lambda result: result
        return
    output_names = [key for key in vars(args) if key.endswith("output_dir")]
    explicit = [Path(getattr(args, key)) for key in output_names if getattr(args, key)]
    if any(not path.resolve().is_relative_to(RESULTS_ROOT.resolve()) for path in explicit):
        yield lambda result: result
        return
    from . import api, artifacts
    from ..records import report_store
    task_id = str(uuid4())
    kind = "guard" if command == "guard" else "positive" if command == "business" else "attack"
    directory = (api.GUARD_ROOT if kind == "guard" else api.ROOT) / task_id
    directory.mkdir(parents=True)
    saved = {key: getattr(args, key) for key in output_names}
    for key in output_names:
        setattr(args, key, directory / "findings" if "finding" in key else directory / "batch-1")
    record = {"id": task_id, "name": f"CLI {command}", "kind": kind, "status": "running",
              "createdAt": api.now(), "startedAt": api.now(),
              "config": {"kind": kind, "source": "cli"},
              "settingsSnapshot": {"execution": "cli", "models": "process_environment"}}
    def save():
        with report_store.connection() as conn, conn.cursor() as cur:
            report_store.write_cli_task(cur, record, kind)
            conn.commit()
    save()
    status = "failed"
    def replace(value):
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, str) and value.startswith(str(directory)):
            relative = Path(value).relative_to(directory).as_posix()
            return "mysql:artifact:" + task_id + "/" + relative
        return value
    def finish(result):
        nonlocal status
        status = "completed"
        return {**replace(result), "storage": "mysql", "task_id": task_id}
    def persist():
        record.update(status=status, finishedAt=api.now())
        save()
        artifacts.capture(directory)
        report_store.import_task(directory, task=record)
        artifacts.link_reports(directory)
        artifacts.cleanup(directory)
    try:
        try:
            yield finish
        except BaseException as exc:
            from ..core.redaction import redact_value
            record["error"] = str(redact_value(str(exc)))[:2000]
            try:
                persist()
            except Exception as storage_error:
                exc.add_note("执行证据未完整入库，临时目录已保留：" + str(directory) +
                             "；" + type(storage_error).__name__)
            raise
        else:
            persist()
    finally:
        for key, value in saved.items():
            setattr(args, key, value)
