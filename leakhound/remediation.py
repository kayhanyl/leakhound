"""Remediation guidance.

The single most important message leakhound delivers: **a leaked secret is
compromised the moment it is pushed.** Rewriting git history does NOT undo the
leak — forks, clones, caches and automated scrapers may already hold a copy.
Rotation at the provider is the only real fix. History rewriting is optional,
secondary clean-up, never a substitute for rotation.
"""

from __future__ import annotations

from .report import Finding, sort_findings


ROTATION_FIRST = (
    "**Step 1 — Rotate the secret NOW (this is the only real fix).**\n"
    "Any secret that reached a remote must be treated as compromised. Forks, "
    "clones, CI caches and scrapers may already have it. Revoke it at the "
    "provider and issue a new one before anything else."
)


def _provider_lines(findings: list[Finding]) -> list[str]:
    seen: dict[str, str] = {}
    for f in findings:
        if f.rotate_url:
            key = f.provider or f.description
            seen.setdefault(key, f.rotate_url)
    if not seen:
        return []
    out = ["", "Where to rotate the detected secrets:"]
    for provider, url in seen.items():
        out.append(f"- **{provider}**: {url}")
    return out


def history_cleanup_commands(paths: list[str]) -> str:
    """Return copy-pasteable history-purge commands. This is step 2, and only
    after rotation. We prefer git-filter-repo (the tool the Git project itself
    recommends) and show BFG as an alternative."""
    uniq = sorted(set(paths))
    filter_targets = " ".join(f"--path {p}" for p in uniq) or "--path <file>"
    return (
        "**Step 2 (optional) — Purge the value from history AFTER rotating.**\n"
        "This rewrites history and requires a force-push; it will break every "
        "existing clone, fork and open PR. Coordinate with collaborators first.\n\n"
        "```bash\n"
        "# Using git-filter-repo (recommended: https://github.com/newren/git-filter-repo)\n"
        "pip install git-filter-repo\n"
        f"git filter-repo --invert-paths {filter_targets}\n"
        "# ...or redact just the string, keeping the files:\n"
        "#   git filter-repo --replace-text <(echo 'THE_SECRET==>REDACTED')\n\n"
        "git push --force-with-lease origin --all\n"
        "git push --force-with-lease origin --tags\n"
        "```\n\n"
        "Alternative (BFG Repo-Cleaner):\n"
        "```bash\n"
        "bfg --delete-files <file>   # or: bfg --replace-text secrets.txt\n"
        "git reflog expire --expire=now --all && git gc --prune=now --aggressive\n"
        "git push --force-with-lease origin --all\n"
        "```"
    )


def build_remediation(findings: list[Finding], *, include_cleanup: bool = True) -> str:
    findings = sort_findings(findings)
    sections = [ROTATION_FIRST]
    sections.extend(_provider_lines(findings))
    if include_cleanup:
        paths = [f.path for f in findings]
        sections.append("")
        sections.append(history_cleanup_commands(paths))
    sections.append("")
    sections.append(
        "_leakhound intentionally does not auto-rotate or auto-rewrite history: "
        "rotation needs provider credentials it should never hold, and automatic "
        "force-pushes are destructive. See THREAT_MODEL.md._"
    )
    return "\n".join(sections)
