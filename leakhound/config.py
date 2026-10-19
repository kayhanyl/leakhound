"""Configuration loading and allowlisting.

A `.leakhound.yml` (or `.leakhound.json`) at the repo root can tune behaviour
without touching code:

    entropy_threshold: 3.5
    exclude_paths:
      - "tests/fixtures/**"
      - "**/*.min.js"
    allow:
      strings:                 # exact values to ignore
        - "AKIAEXAMPLEEXAMPLE1"
      patterns:                # regexes; a match anywhere in the value ignores it
        - "^sk_live_0+$"
    disable_detectors:
      - "jwt"
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

_DEFAULT_EXCLUDES = [
    ".git/**",
    "**/node_modules/**",
    "**/*.lock",
    "**/*.min.js",
    "**/*.map",
    "**/vendor/**",
    "**/dist/**",
    "**/build/**",
]


@dataclass
class Config:
    entropy_threshold: float = 3.5
    exclude_paths: list[str] = field(default_factory=lambda: list(_DEFAULT_EXCLUDES))
    allow_strings: set[str] = field(default_factory=set)
    allow_patterns: list[re.Pattern] = field(default_factory=list)
    disable_detectors: set[str] = field(default_factory=set)
    max_file_bytes: int = 2_000_000

    # --- allowlisting -------------------------------------------------------

    def is_path_excluded(self, path: str) -> bool:
        norm = path.replace(os.sep, "/")
        for pattern in self.exclude_paths:
            if fnmatch.fnmatch(norm, pattern) or fnmatch.fnmatch(norm, pattern.lstrip("/")):
                return True
            # Allow a bare dir pattern like "tests/fixtures" to match its contents.
            if norm.startswith(pattern.rstrip("/*") + "/"):
                return True
        return False

    def is_allowed_secret(self, value: str) -> bool:
        if value in self.allow_strings:
            return True
        return any(p.search(value) for p in self.allow_patterns)

    def is_detector_enabled(self, detector_id: str) -> bool:
        return detector_id not in self.disable_detectors


def _coerce(raw: dict) -> Config:
    allow = raw.get("allow") or {}
    patterns = []
    for p in allow.get("patterns", []) or []:
        try:
            patterns.append(re.compile(p))
        except re.error:
            # A broken user pattern should not crash the scan; skip it loudly.
            print(f"leakhound: ignoring invalid allow pattern: {p!r}")
    excludes = list(_DEFAULT_EXCLUDES)
    excludes.extend(raw.get("exclude_paths", []) or [])
    return Config(
        entropy_threshold=float(raw.get("entropy_threshold", 3.5)),
        exclude_paths=excludes,
        allow_strings=set(allow.get("strings", []) or []),
        allow_patterns=patterns,
        disable_detectors=set(raw.get("disable_detectors", []) or []),
        max_file_bytes=int(raw.get("max_file_bytes", 2_000_000)),
    )


def load_config(path: Optional[str]) -> Config:
    """Load config from an explicit path, or autodiscover a default one.
    Missing config is fine — defaults are sensible."""
    if path is None:
        for candidate in (".leakhound.yml", ".leakhound.yaml", ".leakhound.json"):
            if os.path.exists(candidate):
                path = candidate
                break
    if path is None or not os.path.exists(path):
        return Config()

    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    raw: dict
    if path.endswith(".json"):
        raw = json.loads(text) or {}
    else:
        try:
            import yaml  # type: ignore
        except ImportError:
            print(
                "leakhound: PyYAML not installed; cannot read "
                f"{path}. Install pyyaml or use .leakhound.json. Using defaults."
            )
            return Config()
        raw = yaml.safe_load(text) or {}

    if not isinstance(raw, dict):
        print(f"leakhound: {path} is not a mapping; using defaults.")
        return Config()
    return _coerce(raw)
