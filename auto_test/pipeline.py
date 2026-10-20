"""auto_test 的稳定公共命令入口：``python -m auto_test.pipeline``。"""

from .cli.main import (
    _parse_args,
    build_parser,
    main,
    run_automation_workflow,
    run_business_command,
    run_corpus_workflow,
    run_finding_command,
    run_guard_command,
    run_paper_reproduction,
    run_security_strategy,
    run_target_command,
)

__all__ = [
    "_parse_args",
    "build_parser",
    "main",
    "run_automation_workflow",
    "run_business_command",
    "run_corpus_workflow",
    "run_finding_command",
    "run_guard_command",
    "run_paper_reproduction",
    "run_security_strategy",
    "run_target_command",
]


if __name__ == "__main__":
    raise SystemExit(main())
