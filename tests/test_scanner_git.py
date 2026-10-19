"""End-to-end scanner tests over a real throwaway git repo built in tmp_path."""

import subprocess

import pytest

from leakhound.config import Config
from leakhound.scanner import Scanner
from leakhound.report import redact, to_markdown

GHP = "ghp_" + ("aB3dE5" * 6)[:36]
AWS = "AKIAJZ4Q7XW9PL2KR5TY"


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@t.dev")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "clean.py").write_text("x = 1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "init")
    return tmp_path


def test_scan_tree_flags_committed_secret(repo):
    (repo / "config.py").write_text(f"GITHUB_TOKEN = '{GHP}'\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "add config")

    findings = Scanner(Config()).scan_tree(str(repo))
    assert any(f.detector_id == "github-pat-classic" for f in findings)
    # Raw secret never appears in the redacted output.
    assert all(GHP not in f.secret_redacted for f in findings)


def test_scan_diff_only_sees_new_lines(repo):
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True
    ).stdout.strip()
    (repo / "new.py").write_text(f"AWS_KEY = '{AWS}'\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "leak")

    findings = Scanner(Config()).scan_diff(base, "HEAD", str(repo))
    assert any(f.detector_id == "aws-access-key-id" for f in findings)


def test_history_catches_deleted_secret(repo):
    # Commit a secret, then delete it: tree is clean but history is not.
    leak = repo / "secret.py"
    leak.write_text(f"TOKEN = '{GHP}'\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "oops leak")
    leak.unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "remove file")

    tree_findings = Scanner(Config()).scan_tree(str(repo))
    assert not any(f.detector_id == "github-pat-classic" for f in tree_findings)

    hist_findings = Scanner(Config()).scan_history(str(repo))
    assert any(f.detector_id == "github-pat-classic" for f in hist_findings)
    assert any(f.commit for f in hist_findings)


def test_excluded_path_is_skipped(repo):
    (repo / "fixtures").mkdir()
    (repo / "fixtures" / "leak.py").write_text(f"KEY='{GHP}'\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "fixture")

    cfg = Config(exclude_paths=["fixtures/**"])
    findings = Scanner(cfg).scan_tree(str(repo))
    assert findings == []


def test_redaction_is_safe():
    r = redact(GHP)
    assert GHP not in r
    assert r.startswith("ghp")
    assert "len=40" in r


def test_markdown_never_contains_raw_secret(repo):
    (repo / "config.py").write_text(f"GITHUB_TOKEN = '{GHP}'\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "c")
    findings = Scanner(Config()).scan_tree(str(repo))
    md = to_markdown(findings)
    assert GHP not in md
