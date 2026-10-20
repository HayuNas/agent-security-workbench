# -*- coding: utf-8 -*-

"""ky-sales 安全漏洞对抗测试与回归工具。"""

from .environment import load_project_environment

LOADED_ENV_KEYS = load_project_environment()

__version__ = "5.0.0"
