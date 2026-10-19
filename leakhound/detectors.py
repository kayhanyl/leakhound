"""Secret detectors for leakhound.

Each detector is a high-signal rule: a named, compiled regex plus metadata used
for reporting and remediation. We deliberately favour precision over recall for
the provider-specific rules (a false positive in CI is expensive and erodes
trust), and keep a single lower-confidence entropy rule for the long tail.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

# Severity levels, ordered.
SEVERITIES = ("low", "medium", "high", "critical")

# Obvious non-secret placeholders. If the captured value matches any of these we
# drop the finding — these show up constantly in docs, examples and tests.
_PLACEHOLDER_SUBSTRINGS = (
    "example",
    "placeholder",
    "changeme",
    "your_",
    "your-",
    "yourtoken",
    "dummy",
    "sample",
    "redacted",
    "xxxxxxxx",
    "<token>",
    "<secret>",
    "test_",
    "sk_test_",
    "pk_test_",
    "notarealkey",
    "insert_",
    "fake",
)


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character. ~0 for repetitive strings,
    high (>3.5) for random tokens."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    if any(sub in low for sub in _PLACEHOLDER_SUBSTRINGS):
        return True
    # All one repeated character (e.g. "xxxxxxxxxxxx", "000000000000").
    if len(set(value)) <= 2:
        return True
    return False


@dataclass(frozen=True)
class Detector:
    id: str
    description: str
    severity: str
    regex: re.Pattern
    # Which regex group holds the secret itself (for redaction/entropy checks).
    secret_group: int = 0
    provider: Optional[str] = None
    rotate_url: Optional[str] = None
    # Optional extra validation on the captured secret; return False to drop.
    validator: Optional[Callable[[str], bool]] = field(default=None, compare=False)

    def iter_matches(self, line: str):
        for m in self.regex.finditer(line):
            secret = m.group(self.secret_group) if self.secret_group else m.group(0)
            yield m, secret


def _aws_secret_validator(value: str) -> bool:
    # AWS access key ids are a fixed shape; just ensure entropy is non-trivial.
    return shannon_entropy(value) > 3.0


# --- Provider-specific, high-confidence rules -------------------------------

_RULES: list[Detector] = [
    Detector(
        id="discord-bot-token",
        description="Discord bot token",
        severity="critical",
        regex=re.compile(
            r"\b((?:mfa\.[\w-]{80,})|(?:[MNOP][\w-]{23,27}\.[\w-]{6}\.[\w-]{27,40}))\b"
        ),
        secret_group=1,
        provider="Discord",
        rotate_url="https://discord.com/developers/applications -> Bot -> Reset Token",
    ),
    Detector(
        id="github-pat-classic",
        description="GitHub personal access token (classic)",
        severity="critical",
        regex=re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b"),
        secret_group=1,
        provider="GitHub",
        rotate_url="https://github.com/settings/tokens",
    ),
    Detector(
        id="github-pat-fine-grained",
        description="GitHub fine-grained personal access token",
        severity="critical",
        regex=re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
        secret_group=1,
        provider="GitHub",
        rotate_url="https://github.com/settings/tokens?type=beta",
    ),
    Detector(
        id="aws-access-key-id",
        description="AWS access key ID",
        severity="high",
        regex=re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16})\b"),
        secret_group=1,
        provider="AWS",
        rotate_url="https://console.aws.amazon.com/iam/ -> Users -> Security credentials",
        validator=_aws_secret_validator,
    ),
    Detector(
        id="stripe-secret-key",
        description="Stripe live secret key",
        severity="critical",
        regex=re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"),
        secret_group=1,
        provider="Stripe",
        rotate_url="https://dashboard.stripe.com/apikeys",
    ),
    Detector(
        id="google-api-key",
        description="Google API key",
        severity="high",
        regex=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        secret_group=1,
        provider="Google Cloud",
        rotate_url="https://console.cloud.google.com/apis/credentials",
    ),
    Detector(
        id="slack-token",
        description="Slack token",
        severity="high",
        regex=re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"),
        secret_group=1,
        provider="Slack",
        rotate_url="https://api.slack.com/apps -> OAuth & Permissions",
    ),
    Detector(
        id="openai-key",
        description="OpenAI API key",
        severity="high",
        regex=re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b"),
        secret_group=1,
        provider="OpenAI",
        rotate_url="https://platform.openai.com/api-keys",
    ),
    Detector(
        id="private-key-block",
        description="Private key (PEM/OpenSSH) material",
        severity="critical",
        regex=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
        secret_group=0,
        provider=None,
        rotate_url="Revoke the key pair and regenerate it at its origin.",
    ),
    Detector(
        id="jwt",
        description="JSON Web Token",
        severity="medium",
        regex=re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        secret_group=1,
        provider=None,
        rotate_url="Invalidate the session/secret used to sign this token.",
    ),
]


# --- Generic high-entropy assignment rule (lower confidence) ----------------

_GENERIC_ASSIGN = re.compile(
    r"""(?ix)
    \b(
        api[_-]?key | apikey | secret | token | passwd | password | pwd |
        access[_-]?key | client[_-]?secret | auth[_-]?token | private[_-]?key
    )
    \b \s* [:=] \s*
    ['"]([^'"\n]{12,120})['"]
    """
)


@dataclass
class GenericEntropyDetector:
    id: str = "generic-high-entropy"
    description: str = "High-entropy value assigned to a secret-like name"
    severity: str = "medium"
    provider: Optional[str] = None
    rotate_url: Optional[str] = "Rotate this credential at its provider."
    secret_group: int = 2
    entropy_threshold: float = 3.5

    def iter_matches(self, line: str):
        for m in _GENERIC_ASSIGN.finditer(line):
            secret = m.group(2)
            if shannon_entropy(secret) < self.entropy_threshold:
                continue
            yield m, secret


def default_detectors(entropy_threshold: float = 3.5) -> list:
    """Return the full detector set. Provider rules first, entropy rule last."""
    return list(_RULES) + [GenericEntropyDetector(entropy_threshold=entropy_threshold)]
