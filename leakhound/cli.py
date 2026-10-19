"""Command-line interface for leakhound."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import load_config
from .ghreport import report as github_report
from .remediation import build_remediation
from .report import sort_findings, to_json, to_markdown, to_text
from .scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="leakhound",
        description="Detect leaked secrets in a repo, its diffs, or its history.",
    )
    p.add_argument("--version", action="version", version=f"leakhound {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan for secrets")
    scan.add_argument(
        "--mode",
        choices=["tree", "diff", "working", "history"],
        default="tree",
        help="tree: all tracked files; diff: changes between --base and --head; "
        "working: uncommitted changes; history: all commits.",
    )
    scan.add_argument("--base", help="base ref for diff mode")
    scan.add_argument("--head", help="head ref for diff mode", default="HEAD")
    scan.add_argument("--root", default=".", help="repo root to scan")
    scan.add_argument("--config", help="path to .leakhound.yml/.json")
    scan.add_argument(
        "--format", choices=["text", "json", "markdown"], default="text"
    )
    scan.add_argument("--max-commits", type=int, default=None, help="limit history mode")
    scan.add_argument(
        "--no-fail",
        action="store_true",
        help="always exit 0 (report only; do not block CI)",
    )
    scan.add_argument(
        "--report-github",
        action="store_true",
        help="when run inside GitHub Actions, comment on the PR / open an issue",
    )
    scan.add_argument(
        "--comment-pr", action="store_true", default=True, help="(with --report-github)"
    )
    scan.add_argument(
        "--open-issue", action="store_true", default=True, help="(with --report-github)"
    )
    return p


def _run_scan(args) -> int:
    config = load_config(args.config)
    scanner = Scanner(config)

    if args.mode == "diff":
        if not args.base:
            print("leakhound: --base is required for --mode diff", file=sys.stderr)
            return 2
        findings = scanner.scan_diff(args.base, args.head, args.root)
    elif args.mode == "working":
        findings = scanner.scan_working_tree_diff(args.root)
    elif args.mode == "history":
        findings = scanner.scan_history(args.root, max_commits=args.max_commits)
    else:
        findings = scanner.scan_tree(args.root)

    findings = sort_findings(findings)

    if args.format == "json":
        print(to_json(findings))
    elif args.format == "markdown":
        print(to_markdown(findings))
        if findings:
            print("\n" + build_remediation(findings))
    else:
        print(to_text(findings))
        if findings:
            print("\n" + build_remediation(findings))

    if args.report_github and findings:
        github_report(findings, comment_pr=args.comment_pr, open_issue=args.open_issue)

    if findings and not args.no_fail:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        try:
            return _run_scan(args)
        except Exception as exc:  # pragma: no cover - top-level guard
            print(f"leakhound: error: {exc}", file=sys.stderr)
            return 2
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
