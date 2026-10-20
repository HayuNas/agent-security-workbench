"""Load project-owned settings before importing execution modules."""
import os
from collections.abc import MutableMapping
from pathlib import Path

from dotenv import dotenv_values

PROJECT_ENV = Path(__file__).resolve().parents[1] / ".env_develop"
PROJECT_KEYS = frozenset({
    "DM_DATA_MYSQL_HOST", "DM_DATA_MYSQL_PORT", "DM_DATA_MYSQL_USER",
    "DM_DATA_MYSQL_PASSWORD", "DM_DATA_MYSQL_DB",
    "DASHSCOPE_API_KEY", "DASHSCOPE_API_BASE_URL", "MODEL_NAME",
    "KY_AUTO_TEST_API_KEY", "KY_AUTO_TEST_API_BASE_URL", "KY_AUTO_TEST_MODEL",
    "KY_AUTO_TEST_ATTACK_MODEL", "KY_AUTO_TEST_JUDGE_MODEL", "KY_AUTO_TEST_FINDING_MODEL",
    "KY_AGENT_API_TOKEN", "KY_APP_API_TOKEN", "KY_APP_BASE_URL",
    "KY_APP_CUSTOMER_ID", "KY_APP_CUSTOMER_CONTACT_ID",
    "KY_AI_WEB_TOKEN", "KY_AI_WEB_USERNAME", "KY_AI_WEB_PASSWORD",
    "KY_AI_WEB_TENANT_ID", "KY_AI_WEB_BASE_URL", "KY_AI_WEB_VERIFY_TLS",
    "KY_AI_WEB_ASSET_ROOT", "KY_SECURITY_MYSQL_ENABLED",
    "WORKBENCH_CONFIG_KEY", "WORKBENCH_CONFIG_DIR", "WORKBENCH_RESULTS_DIR",
    "WORKBENCH_CONFIG_BACKEND", "WORKBENCH_DATA_BACKEND", "WORKBENCH_RECORDS_BACKEND",
    "WORKBENCH_CASE_BACKEND", "WORKBENCH_RUNTIME_BACKEND",
    "WORKBENCH_AGENT_TASK_WORKERS", "WORKBENCH_GUARD_TASK_WORKERS",
    "RISK_GUARD_BASE_URL", "RISK_GUARD_TOKEN", "RISK_GUARD_API_TOKEN",
    "GUARD_API_URL", "GUARD_API_TOKEN", "SKILL_SCAN_BASE_URL", "SKILL_SCAN_TOKEN",
    "WORKBENCH_GUARD_ADMIN_URL", "WORKBENCH_GUARD_ADMIN_TOKEN",
    "KY_MODEL_MAX_CONCURRENCY", "KY_MODEL_QUEUE_TIMEOUT",
})


def load_project_environment(
    path: Path | None = None, environ: MutableMapping[str, str] | None = None,
) -> tuple[str, ...]:
    target = os.environ if environ is None else environ
    source = path or Path(target.get("WORKBENCH_ENV_FILE") or PROJECT_ENV)
    if not source.is_file():
        return ()
    # Do not expand ${...} inside credentials, or override deployment variables.
    values = dotenv_values(source, encoding="utf-8-sig", interpolate=False)
    loaded = []
    for key, value in values.items():
        if key in PROJECT_KEYS and value and key not in target:
            target[key] = value
            loaded.append(key)
    return tuple(loaded)
