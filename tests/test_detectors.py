"""Detector precision/recall tests.

Secrets here are synthetic and built at runtime from repeated nonsense so that
(a) they are obviously not real credentials and (b) they are never stored on
disk as literal token-shaped strings that leakhound's own self-scan would flag.
"""

import pytest

from leakhound.detectors import (
    GenericEntropyDetector,
    default_detectors,
    looks_like_placeholder,
    shannon_entropy,
)
from leakhound.scanner import Scanner
from leakhound.config import Config


def _detector(detector_id):
    for d in default_detectors():
        if getattr(d, "id", None) == detector_id:
            return d
    raise AssertionError(f"no detector {detector_id}")


# Synthetic, correctly-shaped-but-fake secrets.
DISCORD = "M" + ("a1B2c3" * 4)[:24] + ".a1B2c3." + ("d4E5f6" * 5)[:28]
GHP = "ghp_" + ("aB3dE5" * 6)[:36]
GH_PAT = "github_pat_" + ("aB3dE5" * 14)[:82]
AWS = "AKIAJZ4Q7XW9PL2KR5TY"
STRIPE = "sk_live_" + ("9zX2qW" * 4)[:24]
GOOGLE = "AIza" + ("A1b2C3d4E5" * 4)[:35]
SLACK = "xoxb-123456789012-aB3dE5fG7hJ9"
OPENAI = "sk-" + ("aB3dE5" * 4)[:24]
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.aB3dE5fG7hJ9kL1mN2pQ"
PEM = "-----BEGIN RSA PRIVATE KEY-----"


@pytest.mark.parametrize(
    "detector_id,sample",
    [
        ("discord-bot-token", DISCORD),
        ("github-pat-classic", GHP),
        ("github-pat-fine-grained", GH_PAT),
        ("aws-access-key-id", AWS),
        ("stripe-secret-key", STRIPE),
        ("google-api-key", GOOGLE),
        ("slack-token", SLACK),
        ("openai-key", OPENAI),
        ("jwt", JWT),
        ("private-key-block", PEM),
    ],
)
def test_detector_matches_its_secret(detector_id, sample):
    det = _detector(detector_id)
    matches = list(det.iter_matches(f"const key = '{sample}'"))
    assert matches, f"{detector_id} failed to match {sample!r}"


def test_scanner_finds_each_provider_secret():
    scanner = Scanner(Config())
    text = "\n".join([GHP, AWS, STRIPE, GOOGLE, SLACK, OPENAI, DISCORD, PEM])
    findings = scanner.scan_text("app.py", text)
    ids = {f.detector_id for f in findings}
    for expected in {
        "github-pat-classic",
        "aws-access-key-id",
        "stripe-secret-key",
        "google-api-key",
        "slack-token",
        "openai-key",
        "discord-bot-token",
        "private-key-block",
    }:
        assert expected in ids, f"missing {expected}: got {ids}"


def test_placeholders_are_ignored():
    assert looks_like_placeholder("ghp_your_token_here")
    assert looks_like_placeholder("AKIAIOSFODNN7EXAMPLE")
    assert looks_like_placeholder("xxxxxxxxxxxxxxxx")
    assert looks_like_placeholder("aaaaaaaaaaaa")
    assert not looks_like_placeholder(GHP)


def test_scanner_skips_placeholder_tokens():
    scanner = Scanner(Config())
    # Correctly shaped but clearly an example -> should be dropped.
    findings = scanner.scan_text("README.md", "token = 'ghp_your_token_here_aaaaaaaaaaaaaaaaaa'")
    assert findings == []


def test_entropy_ordering():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("Zx9Q2wE7rT5y")
    assert shannon_entropy("") == 0.0


def test_generic_entropy_detector():
    det = GenericEntropyDetector(entropy_threshold=3.0)
    high = list(det.iter_matches("api_key = 'Zx9Q2wE7rT5yU3iO1pA6sD'"))
    assert high
    # Low-entropy value under a secret-like name is not flagged.
    low = list(det.iter_matches("password = 'aaaaaaaaaaaa'"))
    assert not low


def test_no_false_positive_on_prose():
    scanner = Scanner(Config())
    text = "This function returns the user's api key from the database securely."
    assert scanner.scan_text("notes.md", text) == []
