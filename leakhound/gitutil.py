"""Thin wrappers around git plumbing used by the scanner.

Everything here shells out to `git`; we keep the parsing (unified diff, blob
listing) in one place so the scanner can stay about *what* is a secret rather
than *how* git hands us bytes.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


class GitError(RuntimeError):
    pass


def _run(args: list[str], cwd: str = ".") -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        errors="replace",
    )
    if proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def is_git_repo(cwd: str = ".") -> bool:
    try:
        return _run(["rev-parse", "--is-inside-work-tree"], cwd).strip() == "true"
    except GitError:
        return False


def tracked_files(cwd: str = ".") -> list[str]:
    out = _run(["ls-files", "-z"], cwd)
    return [p for p in out.split("\0") if p]


@dataclass
class AddedLine:
    path: str
    lineno: int  # line number in the new file
    text: str


def _parse_unified_diff(diff_text: str) -> list[AddedLine]:
    added: list[AddedLine] = []
    current_path: str | None = None
    new_lineno = 0
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            # "+++ b/path/to/file" or "+++ /dev/null"
            target = line[4:].strip()
            if target == "/dev/null":
                current_path = None
            else:
                current_path = target[2:] if target.startswith(("a/", "b/")) else target
            continue
        if line.startswith("@@"):
            # @@ -old,n +new,m @@
            try:
                plus = line.split("+", 1)[1]
                new_start = plus.split(" ", 1)[0].split(",")[0]
                new_lineno = int(new_start)
            except (IndexError, ValueError):
                new_lineno = 0
            continue
        if current_path is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added.append(AddedLine(current_path, new_lineno, line[1:]))
            new_lineno += 1
        elif line.startswith("-") and not line.startswith("---"):
            # Removed line: does not advance the new-file counter.
            continue
        elif line.startswith("\\"):
            # "\ No newline at end of file"
            continue
        else:
            # Context line.
            new_lineno += 1
    return added


def diff_added_lines(base: str, head: str, cwd: str = ".") -> list[AddedLine]:
    """Added lines between two refs. Uses the merge-base (two-dot via `...`)
    so we only see what `head` introduces relative to `base`."""
    diff = _run(["diff", "--unified=0", f"{base}...{head}"], cwd)
    return _parse_unified_diff(diff)


def working_tree_diff(cwd: str = ".") -> list[AddedLine]:
    """Added lines staged + unstaged against HEAD. Handy for a pre-commit hook."""
    diff = _run(["diff", "--unified=0", "HEAD"], cwd)
    return _parse_unified_diff(diff)


@dataclass
class HistoryLine:
    commit: str
    path: str
    lineno: int
    text: str


def history_added_lines(cwd: str = ".", max_commits: int | None = None) -> list[HistoryLine]:
    """Scan added lines across all history. For each commit we read the patch
    it introduced and collect the added lines, tagging them with the commit.

    This is intentionally a simple per-commit walk: it is thorough enough to
    surface a secret that was committed and later deleted (the classic case
    history-rewrite is meant to address) without the memory cost of diffing
    every blob pair."""
    args = ["log", "--all", "--no-merges", "-p", "--unified=0",
            "--pretty=format:%x00COMMIT%x00%H"]
    if max_commits:
        args.insert(1, f"-n{max_commits}")
    out = _run(args, cwd)

    results: list[HistoryLine] = []
    commit = ""
    current_path: str | None = None
    new_lineno = 0
    for line in out.splitlines():
        if line.startswith("\0COMMIT\0"):
            commit = line.split("\0")[-1]
            current_path = None
            continue
        if line.startswith("+++ "):
            target = line[4:].strip()
            current_path = None if target == "/dev/null" else (
                target[2:] if target.startswith(("a/", "b/")) else target
            )
            continue
        if line.startswith("@@"):
            try:
                plus = line.split("+", 1)[1]
                new_lineno = int(plus.split(" ", 1)[0].split(",")[0])
            except (IndexError, ValueError):
                new_lineno = 0
            continue
        if current_path is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            results.append(HistoryLine(commit, current_path, new_lineno, line[1:]))
            new_lineno += 1
        elif line.startswith("-") and not line.startswith("---"):
            continue
        elif not line.startswith("\\"):
            new_lineno += 1
    return results
