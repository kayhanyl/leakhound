"""GitHub reporting: comment on the offending PR, or open an issue.

Uses only the standard library (urllib) so the action needs no extra deps and
no network trust beyond api.github.com. Authentication is the workflow's
built-in GITHUB_TOKEN, passed through the environment by the Action.

Design choices that matter for safety:
  * Only redacted values ever reach the API (see report.redact).
  * Issue creation is deduplicated by a hidden marker so repeated pushes do not
    spam the tracker.
  * We never attempt to rotate secrets or rewrite history from here.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .remediation import build_remediation
from .report import Finding, to_markdown

_MARKER = "<!-- leakhound:finding -->"
_API = "https://api.github.com"


class GitHubContext:
    def __init__(self) -> None:
        self.token = os.environ.get("GITHUB_TOKEN", "")
        self.repo = os.environ.get("GITHUB_REPOSITORY", "")  # "owner/name"
        self.event_name = os.environ.get("GITHUB_EVENT_NAME", "")
        self.event_path = os.environ.get("GITHUB_EVENT_PATH", "")
        self.sha = os.environ.get("GITHUB_SHA", "")

    @property
    def available(self) -> bool:
        return bool(self.token and self.repo)

    def pr_number(self) -> int | None:
        if not self.event_path or not os.path.exists(self.event_path):
            return None
        try:
            with open(self.event_path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, ValueError):
            return None
        pr = payload.get("pull_request") or {}
        num = pr.get("number") or payload.get("number")
        return int(num) if num else None


def _request(method: str, url: str, token: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "leakhound")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 (fixed host)
        return json.loads(resp.read().decode() or "{}")


def _body(findings: list[Finding], *, title: str) -> str:
    return "\n\n".join(
        [
            _MARKER,
            to_markdown(findings, title=title),
            "---",
            build_remediation(findings),
        ]
    )


def comment_on_pr(ctx: GitHubContext, findings: list[Finding]) -> bool:
    pr = ctx.pr_number()
    if pr is None:
        return False
    url = f"{_API}/repos/{ctx.repo}/issues/{pr}/comments"
    _request("POST", url, ctx.token, {"body": _body(findings, title="Secret(s) detected in this PR")})
    return True


def _find_existing_issue(ctx: GitHubContext) -> int | None:
    # Reuse an open leakhound issue instead of opening a new one each push.
    url = f"{_API}/repos/{ctx.repo}/issues?state=open&labels=leakhound&per_page=1"
    try:
        items = _request("GET", url, ctx.token)
    except (urllib.error.URLError, ValueError):
        return None
    if isinstance(items, list) and items:
        return int(items[0]["number"])
    return None


def open_or_update_issue(ctx: GitHubContext, findings: list[Finding]) -> bool:
    existing = _find_existing_issue(ctx)
    body = _body(findings, title="Secret(s) detected on the default branch")
    if existing is not None:
        url = f"{_API}/repos/{ctx.repo}/issues/{existing}/comments"
        _request("POST", url, ctx.token, {"body": body})
        return True
    url = f"{_API}/repos/{ctx.repo}/issues"
    _request(
        "POST",
        url,
        ctx.token,
        {
            "title": "\U0001f6a8 leakhound: potential secret leak detected",
            "body": body,
            "labels": ["leakhound", "security"],
        },
    )
    return True


def report(findings: list[Finding], *, comment_pr: bool, open_issue: bool) -> None:
    """Best-effort reporting from inside a GitHub Action. Network/permission
    errors are reported but never crash the scan — the non-zero exit code from
    the CLI is what actually blocks the merge."""
    if not findings:
        return
    ctx = GitHubContext()
    if not ctx.available:
        print("leakhound: no GitHub context (GITHUB_TOKEN/REPOSITORY); skipping API report.")
        return
    try:
        if comment_pr and ctx.event_name == "pull_request":
            if comment_on_pr(ctx, findings):
                print("leakhound: posted redacted findings as a PR comment.")
        if open_issue and ctx.event_name != "pull_request":
            if open_or_update_issue(ctx, findings):
                print("leakhound: opened/updated a tracking issue with remediation steps.")
    except urllib.error.HTTPError as exc:
        print(f"leakhound: GitHub API error ({exc.code}); check the workflow's permissions.")
    except urllib.error.URLError as exc:
        print(f"leakhound: could not reach GitHub API: {exc.reason}")
