# leakhound — Threat Model & Design Rationale

This document explains *why* leakhound behaves the way it does. The behaviour is
deliberate; several "obvious" features were rejected because they are unsafe.

## 1. What problem are we solving?

Secrets (API keys, tokens, private keys) get committed by accident. Once pushed
to a remote, they are **exposed**. The goal is to:

1. **Stop** new secrets from reaching the default branch, and
2. **Correctly remediate** secrets that are already there.

## 2. Core assumption: a pushed secret is compromised

The moment a secret reaches a remote — especially a public one — assume it is in
an adversary's hands:

- GitHub serves commit data via API and caches it.
- Forks and existing clones retain the object even after you delete it.
- Public-repo pushes are indexed by automated secret-harvesting bots within
  **seconds**. Several documented AWS-key abuse cases happened in under 5 minutes.

**Consequence:** the correct first action is always to **rotate/revoke the
secret at its provider.** Removing it from the working tree or from git history
does *not* make the leaked value safe — it only limits further casual discovery.

## 3. Why leakhound does NOT auto-delete / auto-rewrite history

A tempting feature request is: "detect the key, delete it, and scrub it from git
history automatically." leakhound refuses this, for concrete reasons:

1. **It hides the real risk.** Auto-scrubbing creates the impression the problem
   is solved while the compromised key is still live. This is worse than doing
   nothing, because it discourages rotation.
2. **It is destructive.** Rewriting history requires a force-push that breaks
   every clone, fork and open pull request, and can corrupt the repo if it races
   with other writers.
3. **It needs dangerous privileges.** Automatic force-push from CI requires a
   token with write access to all refs — a high-value target that, ironically,
   expands the attack surface a secret scanner is supposed to reduce.

Instead, leakhound **blocks the merge** (prevention) and, for an existing leak,
emits **rotation-first guidance** plus the exact `git filter-repo` / BFG commands
for a human to run *after* rotating, with collaborators informed.

## 4. Redaction is mandatory

A secret scanner that prints the secret into CI logs, a PR comment, or an issue
has just leaked it again — to a wider, often public audience. leakhound masks
every value before it leaves the process (`report.redact`), keeping only a short
prefix/suffix and the length for recognisability. Tests assert that the raw
secret never appears in any rendered output.

## 5. Least privilege in CI

The provided workflow requests only:

- `contents: read` — to read the code.
- `pull-requests: write` — to comment on the offending PR.
- `issues: write` — to open a tracking issue for an already-landed leak.

No write access to code refs. The scan's **exit code** — not any privileged
action — is what blocks a merge, so the security outcome does not depend on the
token being powerful.

## 6. Precision over recall (false positives are a cost)

An alert that is usually wrong trains developers to ignore alerts — the "boy who
cried wolf" failure mode that makes a scanner net-negative. leakhound therefore:

- uses tight, provider-specific patterns for its high-severity rules;
- filters obvious placeholders (`…EXAMPLE`, `your_token`, repeated chars);
- gates the one broad rule (generic high-entropy) behind an entropy threshold;
- supports per-repo allowlists for known-safe values.

Recall is still meaningful (history mode, generic rule), but when precision and
recall conflict in the high-severity path, precision wins.

## 7. Known limitations

- Regex/entropy detection cannot catch a secret with no recognisable shape and
  low entropy (e.g. a short custom token). Pair leakhound with provider-side
  push protection where available.
- `history` mode walks commits and can be slow on very large repos; scope it
  with `--max-commits` for routine runs.
- leakhound detects and advises; it never proves a value is live. Treat every
  finding as compromised until you have rotated and confirmed.

## 8. Out of scope

- Secret *storage* / vaulting (use a dedicated secrets manager).
- Runtime exfiltration detection.
- Rotating or revoking secrets on your behalf (by design — see §3).
