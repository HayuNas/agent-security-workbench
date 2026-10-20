"""工作台服务默认地址；凭据仍由部署环境提供。"""
import os
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_GUARD_URL = "https://service.example"


def guard_base_url():
    return (os.getenv("RISK_GUARD_BASE_URL") or DEFAULT_GUARD_URL).strip().rstrip("/")


def guard_admin_url():
    return (os.getenv("WORKBENCH_GUARD_ADMIN_URL") or guard_base_url()).strip().rstrip("/")


def guard_token(base_url):
    token = (os.getenv("GUARD_API_TOKEN") or os.getenv("RISK_GUARD_TOKEN") or
             os.getenv("RISK_GUARD_API_TOKEN"))
    if token:
        return token
    # Match the frontend proxy's existing company-only credential source.
    if urlsplit(base_url).netloc != urlsplit(DEFAULT_GUARD_URL).netloc:
        return ""
    if urlsplit(base_url).scheme != "https":
        return ""
    path = Path(__file__).resolve().parents[2] / "risk_guard.env"
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() == "RISK_GUARD_API_TOKENS":
                return value.strip().strip("\"'").split(",")[0].strip()
    return ""
