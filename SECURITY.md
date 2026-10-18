# Security Policy

## Scope & Intended Use

**Vibe Aegis is a defensive, pre-deployment security and UI/UX quality assurance framework.** It is built for developers to audit applications they own before publishing them.

It is **not** an offensive or exploitation toolkit. It does not weaponise findings, attempt authentication bypass, inject payloads, brute-force credentials, or perform any state-changing request against a target.

### What the static scanner does

`scripts/aegis_scan.py` reads files from a local directory you point it at. It performs regular-expression and heuristic pattern matching over source files. It never transmits your source code anywhere, has zero third-party dependencies, and makes no network calls in static mode.

### What the live `--url` check does (passive, read-only)

When you pass `--url`, the scanner performs a small number of strictly **passive, read-only HTTP `GET` requests** against the URL you supply:

1. One request to the supplied URL to read response headers only (CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, CORS).
2. One request each to `/.env` and `/.git/config` to detect accidental public exposure of configuration files.

It sends the identifying User-Agent `VibeAegis-PreLaunch-Audit/1.0 (Passive-Read-Only)`. It sends no credentials, no payloads, no `POST`/`PUT`/`DELETE`, and reads at most 512 bytes of any probe response. It does not crawl, spider, or enumerate.

### Authorization requirement

**Only scan applications and deployments that you own or have explicit written authorization to test.** Pointing `--url` at third-party infrastructure without permission may violate that provider's terms of service and your local law. You are responsible for the targets you choose.

## Supported Versions

| Version | Supported |
| :--- | :--- |
| 1.0.x | ✅ |

## Reporting a Vulnerability

If you find a security flaw **in Vibe Aegis itself** — for example a path traversal in the installer, a command injection in the CLI wrapper, or a scanner crash on hostile input — please report it privately rather than opening a public issue.

1. Open a [GitHub Security Advisory](../../security/advisories/new) on this repository (preferred), **or**
2. Open a public issue **only** for low-severity, non-exploitable bugs.

Please include: affected file and version, reproduction steps, expected vs actual behaviour, and impact. We aim to acknowledge reports within 7 days.

### Out of scope

- Vulnerabilities in the applications *you scan* (that is the tool working as intended — report those to their owners).
- False positives or false negatives in detection rules. Please file those as normal issues using the rule-accuracy template in `CONTRIBUTING.md`.
