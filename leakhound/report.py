"""Findings model, redaction and output formatting.

Redaction is central to leakhound's safety story: we must be able to tell a
developer *what* leaked and *where* without re-printing the raw secret into CI
logs, PR comments or issues (which would leak it a second time, to a wider
audience). Every value that leaves this module is masked.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Iterable

from .detectors import SEVERITIES


def redact(secret: str) -> str:
    """Mask a secret for safe display: keep a short prefix/suffix for
    recognisability, hide the rest, never reveal enough to use it."""
    if secret is None:
        return ""
    n = len(secret)
    if n <= 8:
        return "*" * n
    keep = 3 if n < 20 else 4
    return f"{secret[:keep]}{'*' * 8}{secret[-keep:]} (len={n})"


@dataclass
class Finding:
    detector_id: str
    description: str
    severity: str
    path: str
    line: int
    secret_redacted: str
    provider: str | None = None
    rotate_url: str | None = None
    # Optional git context (populated in history mode).
    commit: str | None = None

    def severity_rank(self) -> int:
        try:
            return SEVERITIES.index(self.severity)
        except ValueError:
            return 0


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-f.severity_rank(), f.path, f.line),
    )


def to_json(findings: Iterable[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False)


_SEV_ICON = {
    "critical": "\U0001f534",  # red circle
    "high": "\U0001f7e0",      # orange circle
    "medium": "\U0001f7e1",    # yellow circle
    "low": "⚪",           # white circle
}


def to_text(findings: list[Finding]) -> str:
    if not findings:
        return "leakhound: no secrets detected."
    lines = [f"leakhound: {len(findings)} potential secret(s) detected\n"]
    for f in sort_findings(findings):
        loc = f"{f.path}:{f.line}"
        if f.commit:
            loc = f"{loc} @ {f.commit[:10]}"
        lines.append(
            f"  [{f.severity.upper()}] {f.description} ({f.detector_id})\n"
            f"    location: {loc}\n"
            f"    value:    {f.secret_redacted}"
        )
    return "\n".join(lines)


def to_markdown(findings: list[Finding], *, title: str = "leakhound findings") -> str:
    if not findings:
        return f"### {title}\n\n✅ No secrets detected."
    rows = [
        f"### \U0001f6a8 {title}",
        "",
        f"**{len(findings)} potential secret(s) detected.** Values below are redacted.",
        "",
        "| Severity | Type | Location | Value (redacted) |",
        "| --- | --- | --- | --- |",
    ]
    for f in sort_findings(findings):
        loc = f"`{f.path}:{f.line}`"
        if f.commit:
            loc = f"`{f.path}` @ `{f.commit[:10]}`"
        icon = _SEV_ICON.get(f.severity, "")
        rows.append(
            f"| {icon} {f.severity} | {f.description} | {loc} | `{f.secret_redacted}` |"
        )
    return "\n".join(rows)
