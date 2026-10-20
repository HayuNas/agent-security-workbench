"""auto_test 命令行接口。"""

from .main import (
    _parse_args,
    build_parser,
    main,
    run_automation_workflow,
    run_corpus_workflow,
    run_finding_command,
    run_paper_reproduction,
    run_security_strategy,
)

__all__ = [
    "_parse_args",
    "build_parser",
    "main",
    "run_automation_workflow",
    "run_corpus_workflow",
    "run_finding_command",
    "run_paper_reproduction",
    "run_security_strategy",
]
