import json

from leakhound.config import Config, load_config
from leakhound.scanner import Scanner

GHP = "ghp_" + ("aB3dE5" * 6)[:36]


def test_defaults_when_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = load_config(None)
    assert cfg.entropy_threshold == 3.5
    assert cfg.is_detector_enabled("jwt")


def test_path_exclusion():
    cfg = Config(exclude_paths=["tests/fixtures/**", "**/*.min.js"])
    assert cfg.is_path_excluded("tests/fixtures/leak.py")
    assert cfg.is_path_excluded("web/app.min.js")
    assert not cfg.is_path_excluded("src/app.py")


def test_allow_strings_and_patterns():
    cfg = Config(allow_strings={GHP}, allow_patterns=[])
    assert cfg.is_allowed_secret(GHP)
    assert not cfg.is_allowed_secret("ghp_somethingelse")


def test_json_config_allowlists_a_secret(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".leakhound.json").write_text(
        json.dumps({"allow": {"strings": [GHP]}, "disable_detectors": ["jwt"]})
    )
    cfg = load_config(".leakhound.json")
    assert cfg.is_allowed_secret(GHP)
    assert not cfg.is_detector_enabled("jwt")

    scanner = Scanner(cfg)
    # Allowlisted secret must not be reported.
    assert scanner.scan_text("app.py", f"KEY = '{GHP}'") == []


def test_disabled_detector_not_loaded():
    cfg = Config(disable_detectors={"jwt"})
    scanner = Scanner(cfg)
    assert all(getattr(d, "id", None) != "jwt" for d in scanner.detectors)
