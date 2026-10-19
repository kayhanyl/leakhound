"""Core scanning engine: turn text/files/diffs/history into Findings."""

from __future__ import annotations

import os

from . import gitutil
from .config import Config
from .detectors import default_detectors, looks_like_placeholder
from .report import Finding, redact


class Scanner:
    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self.detectors = [
            d
            for d in default_detectors(self.config.entropy_threshold)
            if self.config.is_detector_enabled(getattr(d, "id"))
        ]

    # --- primitives ---------------------------------------------------------

    def scan_line(self, path: str, lineno: int, text: str, commit: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self.detectors:
            for _match, secret in detector.iter_matches(text):
                if not secret:
                    continue
                if looks_like_placeholder(secret):
                    continue
                if self.config.is_allowed_secret(secret):
                    continue
                validator = getattr(detector, "validator", None)
                if validator and not validator(secret):
                    continue
                findings.append(
                    Finding(
                        detector_id=detector.id,
                        description=detector.description,
                        severity=detector.severity,
                        path=path,
                        line=lineno,
                        secret_redacted=redact(secret),
                        provider=getattr(detector, "provider", None),
                        rotate_url=getattr(detector, "rotate_url", None),
                        commit=commit,
                    )
                )
        return findings

    def scan_text(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(text.splitlines(), start=1):
            findings.extend(self.scan_line(path, i, line))
        return findings

    # --- modes --------------------------------------------------------------

    def scan_file(self, path: str) -> list[Finding]:
        if self.config.is_path_excluded(path):
            return []
        try:
            if os.path.getsize(path) > self.config.max_file_bytes:
                return []
            with open(path, "rb") as fh:
                raw = fh.read()
            if b"\0" in raw:  # binary: skip
                return []
            text = raw.decode("utf-8", errors="replace")
        except OSError:
            return []
        return self.scan_text(path, text)

    def scan_tree(self, root: str = ".") -> list[Finding]:
        findings: list[Finding] = []
        if gitutil.is_git_repo(root):
            files = gitutil.tracked_files(root)
            paths = [os.path.join(root, f) if root != "." else f for f in files]
        else:
            paths = []
            for dirpath, _dirs, names in os.walk(root):
                for name in names:
                    paths.append(os.path.join(dirpath, name))
        for p in paths:
            rel = os.path.relpath(p, root) if root != "." else p
            if self.config.is_path_excluded(rel):
                continue
            for f in self.scan_file(p):
                f.path = rel
                findings.append(f)
        return findings

    def scan_diff(self, base: str, head: str, root: str = ".") -> list[Finding]:
        findings: list[Finding] = []
        for added in gitutil.diff_added_lines(base, head, root):
            if self.config.is_path_excluded(added.path):
                continue
            findings.extend(self.scan_line(added.path, added.lineno, added.text))
        return findings

    def scan_working_tree_diff(self, root: str = ".") -> list[Finding]:
        findings: list[Finding] = []
        for added in gitutil.working_tree_diff(root):
            if self.config.is_path_excluded(added.path):
                continue
            findings.extend(self.scan_line(added.path, added.lineno, added.text))
        return findings

    def scan_history(self, root: str = ".", max_commits: int | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for hl in gitutil.history_added_lines(root, max_commits=max_commits):
            if self.config.is_path_excluded(hl.path):
                continue
            findings.extend(self.scan_line(hl.path, hl.lineno, hl.text, commit=hl.commit))
        return findings
