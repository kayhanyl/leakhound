# 🐾 leakhound

A precise, **safety-first** secret scanner for CI pull requests and git history.

leakhound blocks a leaked credential **before it merges**, and when one has
already landed, it tells you the one thing that actually makes you safe —
**rotate it** — instead of giving you a false sense of security by quietly
rewriting history.

> **Design principle:** a secret that reached a remote is compromised the moment
> it is pushed. Forks, clones, CI caches and automated scrapers may already hold
> a copy. **Rotation at the provider is the only real fix.** History rewriting is
> optional, secondary cleanup — never a substitute. leakhound is built around
> that truth. See [THREAT_MODEL.md](THREAT_MODEL.md).

## What it does

- **Prevents** — runs on `pull_request`, scans only the added lines, and **fails
  the check to block the merge** if a secret is introduced.
- **Alerts** — if a secret is already on the default branch, opens/updates a
  tracking issue with redacted findings and **rotation-first** remediation.
- **Audits history** — `history` mode finds secrets that were committed and
  later deleted (the classic "the file is gone but it's still in git" case).
- **Redacts everything** — raw secrets never appear in logs, PR comments or
  issues. Only masked previews (`ghp_****…****abcd (len=40)`) leave the tool.

### What it deliberately does *not* do

- It does **not** auto-rotate secrets (it should never hold provider credentials).
- It does **not** auto-rewrite history or force-push (destructive, and it hides
  the real risk). It hands you the exact `git filter-repo` / BFG commands to run
  yourself, *after* rotating.

## Usage as a GitHub Action

```yaml
# .github/workflows/leakhound.yml
name: leakhound
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  pull-requests: write
  issues: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: kayhanyl/leakhound@v1
        with:
          mode: diff            # 'tree' on push, 'diff' on PRs
          fail-on-findings: "true"
```

On a pull request this adds a required-style check that turns red (and posts a
redacted comment) the moment a secret appears in the diff.

## Usage as a CLI

```bash
pip install leakhound

leakhound scan --mode tree                 # scan all tracked files
leakhound scan --mode diff --base main     # scan changes vs. main
leakhound scan --mode working              # scan uncommitted changes (pre-commit)
leakhound scan --mode history              # scan the full git history
leakhound scan --format json               # machine-readable output
```

Exit code is `1` when secrets are found (so it fails CI), `0` when clean, and
`2` on error. Use `--no-fail` for report-only runs.

### Pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
exec leakhound scan --mode working
```

## Detectors

High-confidence, provider-specific rules (tuned for precision):

| Detector | Severity |
| --- | --- |
| Discord bot token | critical |
| GitHub PAT (classic + fine-grained) | critical |
| Stripe live secret key | critical |
| Private key (PEM / OpenSSH) | critical |
| AWS access key ID | high |
| Google API key | high |
| Slack token | high |
| OpenAI API key | high |
| JSON Web Token | medium |
| Generic high-entropy assignment | medium |

Shaped-but-obviously-fake values (`…EXAMPLE`, `your_token_here`, repeated
characters) are filtered out automatically.

## Configuration

Drop a `.leakhound.yml` at your repo root (see [`examples/`](examples/)):

```yaml
entropy_threshold: 3.5
exclude_paths:
  - "tests/fixtures/**"
allow:
  strings: ["AKIAIOSFODNN7EXAMPLE"]
  patterns: ["^sk_live_0+$"]
disable_detectors: ["jwt"]
```

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

leakhound scans itself in CI (`.github/workflows/scan.yml`) — it eats its own dog food.

## License

MIT © Kayhan
