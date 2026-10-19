# Security Policy

## Reporting a vulnerability

If you find a security issue in leakhound itself (for example a way to make it
leak a detected secret into logs, or a detector bypass), please report it
privately:

- Open a GitHub **security advisory** on this repository (Security → Advisories →
  Report a vulnerability), or
- Email the maintainer at the address on the GitHub profile.

Please do **not** open a public issue for an undisclosed vulnerability.

Include: a description, affected version/commit, and a minimal reproduction.
Synthetic (fake) secrets only — never send a real credential in a report.

## Scope

In scope:
- Detector bypasses that let a real-shaped secret pass undetected.
- Any path where a raw (unredacted) secret could reach logs, a PR comment, or an
  issue.
- Privilege or injection issues in the GitHub Action.

Out of scope:
- False positives (please file a normal issue).
- Secrets that are genuinely undetectable by shape/entropy (documented limitation).

## Disclosure

We aim to acknowledge reports within a few days and to coordinate a fix and
disclosure timeline with the reporter.
