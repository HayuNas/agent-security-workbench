"""Read bounded, line-numbered source evidence from a Git ref without checkout."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .redaction import redact_report_text


DEFAULT_SOURCE_REPO = Path(__file__).resolve().parents[2] / "local" / "target-source"
SOURCE_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
SOURCE_PATTERNS = {
    "PROMPT_LEAKAGE": r"risk|guardrail|middleware|prompt|output|stream|leak|system_prompt",
    "TOOL_PROVENANCE_CONFUSION": r"mcp|tool|result|provenance|middleware|risk|guardrail",
    "CROSS_USER_CONTEXT_LEAKAGE": r"context|memory|session|customer_id|contact_id|mongo|history",
    "PRICING_CONTEXT_DISCLOSURE": r"price|pricing|quote|risk|guardrail|output|tool",
    "UNAUTHORIZED_DISCOUNT": r"price|pricing|quote|discount|approval|authorize|risk|sales",
    "UNAUTHORIZED_COMMERCIAL_COMMITMENT": (
        r"commitment|approval|authorize|discount|payment|freight|gift|sales|risk"
    ),
}
BASELINE_PATHS = (
    "middlewares/risk_control.py",
    "risk_engine.py",
    "agent/base.py",
)


class SourceSnapshotError(RuntimeError):
    """Raised when the requested repository or Git ref cannot be inspected."""


def _run_git(repo: Path, arguments: Iterable[str], *, check: bool = True) -> str:
    try:
        completed = subprocess.run(
            ["git", "-c", f"safe.directory={repo}", *arguments],
            cwd=repo,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SourceSnapshotError(f"无法读取源码仓库：{type(exc).__name__}") from exc
    if check and completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "Git 命令失败").strip()
        raise SourceSnapshotError(message[:500])
    return completed.stdout


def _validate_repo_and_branch(repo: Path, branch: str) -> tuple[Path, str]:
    resolved = repo.expanduser().resolve()
    if not (resolved / ".git").exists():
        raise SourceSnapshotError(f"不是 Git 仓库：{resolved}")
    value = str(branch or "").strip()
    if not SOURCE_BRANCH_RE.fullmatch(value) or ".." in value:
        raise SourceSnapshotError("源码分支名称不合法")
    return resolved, value


def resolve_source_snapshot(
    repo: Path = DEFAULT_SOURCE_REPO,
    *,
    branch: str = "develop",
    fetch: bool = False,
) -> dict[str, str]:
    """Resolve ``origin/<branch>`` to a commit without changing the worktree."""

    resolved, branch = _validate_repo_and_branch(repo, branch)
    if fetch:
        _run_git(resolved, ["fetch", "origin", branch])
    ref = f"origin/{branch}"
    commit = _run_git(resolved, ["rev-parse", "--verify", ref]).strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise SourceSnapshotError(f"无法解析源码版本：{ref}")
    return {
        "repo": str(resolved),
        "branch": branch,
        "ref": ref,
        "commit": commit.lower(),
    }


def _parse_grep_line(line: str, ref: str) -> tuple[str, int, str] | None:
    prefix = ref + ":"
    if not line.startswith(prefix):
        return None
    remainder = line[len(prefix) :]
    match = re.match(r"^(.*?):(\d+):(.*)$", remainder)
    if not match:
        return None
    return match.group(1), int(match.group(2)), match.group(3)


def _merge_windows(
    lines: Iterable[int],
    *,
    radius: int = 7,
    max_gap: int = 12,
) -> list[tuple[int, int]]:
    """Build bounded excerpts and bridge small gaps in the same code region.

    A model commonly cites one function-level range spanning two nearby grep
    hits. Keeping the short gap makes that citation fully grounded instead of
    presenting two artificial fragments with missing lines in between.
    """

    windows: list[tuple[int, int]] = []
    for line in sorted(set(int(value) for value in lines if int(value) > 0))[:6]:
        start, end = max(1, line - radius), line + radius
        if windows and start <= windows[-1][1] + max(1, int(max_gap)) + 1:
            windows[-1] = (windows[-1][0], max(windows[-1][1], end))
        else:
            windows.append((start, end))
    return windows


def collect_source_evidence(
    snapshot: dict[str, str],
    *,
    scenario_code: str,
    max_files: int = 8,
    char_limit: int = 32_000,
) -> list[dict[str, Any]]:
    """Collect small source excerpts relevant to one security scenario."""

    repo = Path(snapshot["repo"])
    ref = snapshot["ref"]
    pattern = SOURCE_PATTERNS.get(
        str(scenario_code or ""), r"risk|guardrail|middleware|security|agent"
    )
    grep = _run_git(
        repo,
        ["grep", "-n", "-I", "-E", pattern, ref, "--", "*.py"],
        check=False,
    )
    matches: dict[str, list[int]] = {}
    for raw_line in grep.splitlines():
        parsed = _parse_grep_line(raw_line, ref)
        if parsed is None:
            continue
        path, line_number, _text = parsed
        matches.setdefault(path, []).append(line_number)

    ranked_matches = sorted(matches, key=lambda path: (-len(matches[path]), path))
    ranked = list(BASELINE_PATHS)
    ranked.extend(path for path in ranked_matches if path not in ranked)

    excerpts: list[dict[str, Any]] = []
    used_chars = 0
    for path in ranked[: max(1, int(max_files))]:
        source = _run_git(repo, ["show", f"{ref}:{path}"], check=False)
        if not source:
            continue
        source_lines = source.splitlines()
        line_numbers = matches.get(path) or [1]
        for start, requested_end in _merge_windows(line_numbers):
            end = min(requested_end, len(source_lines))
            numbered = "\n".join(
                f"{index}: {source_lines[index - 1]}"
                for index in range(start, end + 1)
            )
            numbered = redact_report_text(numbered)
            if used_chars + len(numbered) > char_limit:
                remaining = char_limit - used_chars
                if remaining < 300:
                    return excerpts
                numbered = numbered[:remaining]
            excerpts.append(
                {
                    "path": path,
                    "line_start": start,
                    "line_end": end,
                    "content": numbered,
                }
            )
            used_chars += len(numbered)
            if used_chars >= char_limit:
                return excerpts
    return excerpts


__all__ = [
    "DEFAULT_SOURCE_REPO",
    "SourceSnapshotError",
    "collect_source_evidence",
    "resolve_source_snapshot",
]
