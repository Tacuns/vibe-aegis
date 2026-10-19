#!/usr/bin/env python3
"""Regenerate llms-full.txt by concatenating the real file contents.

Run from the repository root after changing README.md, AGENTS.md, any SKILL.md,
the CLI surface, or the JSON schema:

    python3 scripts/build_llms_full.py .

Keeping this generated means llms-full.txt can never drift from the files it
claims to reproduce. Zero dependencies, like everything else here.
"""
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8").rstrip() + "\n"


HEADER = """# Vibe Aegis - Complete Framework (Single-Fetch Document)

> This is the self-contained edition of the Vibe Aegis repository. Everything an AI agent
> needs to understand and execute the framework is below: the full README, the always-on
> engineering rules, all three skill definitions, the scanner CLI reference, and the JSON
> report schema. Reading this one document is equivalent to reading the whole repository.
>
> Canonical repository: https://github.com/Tacuns/vibe-aegis
> Structured index: https://raw.githubusercontent.com/Tacuns/vibe-aegis/main/llms.txt
> License: MIT
> Scope: Defensive pre-deployment auditing of applications you own. Live `--url` checks are
> passive, read-only HTTP GET requests.

## How An Agent Should Use This Document

1. Read the **6-Stage Adversarial Analysis Loop** to learn the protocol.
2. Run the deterministic scanner (`scripts/aegis_scan.py`) first - it is free of LLM cost and
   fingerprints the stack for you.
3. Execute Stage 2 using the `security-redteam-loop` skill and Stage 3 using the
   `ui-ux-bug-finder` skill, both reproduced in full below.
4. Apply the Skeptic stage to disprove your own findings before reporting any of them.
5. Write `.aegis/AUDIT_REPORT.md` with the Release Readiness Score.
6. Never modify source files without the user's explicit approval.

---

# TABLE OF CONTENTS

- PART 1: README - Full Documentation
- PART 2: AGENTS.md - Always-On Engineering Rules
- PART 3: SKILL - vibe-aegis (Master 6-Stage Orchestrator)
- PART 4: SKILL - security-redteam-loop (Low-to-Critical Security Auditor)
- PART 5: SKILL - ui-ux-bug-finder (UI/UX, Layout & Accessibility Auditor)
- PART 6: SKILL - artifact-leak-hunter (Shipped-Artifact Verification)
- PART 7: Scanner CLI Reference (scripts/aegis_scan.py)
- PART 8: JSON Report Schema (.aegis/scan-report.json)

---
"""

CLI = """
# =============================================================================
# PART 7: SCANNER CLI REFERENCE - `scripts/aegis_scan.py`
# =============================================================================

Zero-dependency Python 3.8+ static and passive-live scanner. No pip install required.

## Usage

```text
python3 scripts/aegis_scan.py [target] [--profile quick|code|full|release] [--url URL] [--json] [--output PATH] [--fail-on-high]
```

## Arguments

**Output**

| Argument | Default | Description |
| :--- | :--- | :--- |
| `target` | `.` | Path to the repository to scan. Exits `2` if it does not exist. |
| `--json` | off | Print the full JSON report to stdout. |
| `--output <PATH>` | none | Write the JSON report to a file. Parent directories are created. |
| `--sarif <PATH>` | none | Write SARIF 2.1.0 so findings appear in GitHub's Security tab. |
| `--sbom <PATH>` | none | Write a CycloneDX 1.5 SBOM of detected dependencies. |
| `--quiet` | off | Print only the one-line summary. |

**Release gate**

| Argument | Description |
| :--- | :--- |
| `--profile <name>` | `quick` / `code` (default) / `full` / `release`. Which stages run by default; see Profiles. |
| `--fail-on-high` | Exit `1` if any `CRITICAL` or `HIGH` finding exists. |
| `--fail-on <level>` | Exit `1` at or above `critical`/`high`/`medium`/`low`. |
| `--fail-on-incomplete` | Exit `1` if any check did not run or did not read what it should have, or if zero source files were scanned. |
| `--min-confidence <level>` | `high` / `medium` / `low` (default `low`). Only findings at or above this confidence affect the exit code. |

**Scope - how a team adopts this on an existing codebase**

| Argument | Description |
| :--- | :--- |
| `--diff [REF]` | Scan only files changed vs `REF` (default `origin/main`). Use for pull requests. |
| `--baseline <PATH>` | Suppress findings recorded in a baseline file. Coverage gaps are never suppressed. |
| `--write-baseline <PATH>` | Accept all current findings as pre-existing; future scans show only new issues. Gaps are never recorded. |
| `--include-tests` | Also audit test and fixture files, excluded by default. |
| `--max-file-size <BYTES>` | Skip source files larger than this (default `1500000`); each is a `COV-00` gap. |

Also honoured: a `.aegis-ignore` file in the repo root, one entry per line, either a rule id
(`SEC-03`) or a path glob (`src/legacy/**`).

**Deep analysis**

| Argument | Description |
| :--- | :--- |
| `--artifact [PATH]` | Verify a build directory or an `.apk`/`.aab`/`.ipa`. With no value, auto-detects `dist/`, `build/`, `out/`, `.next/`, `.output/`, `.svelte-kit/`, `www/`, `public/`, `release/`. Finding none is an `ART-00` gap. |
| `--git-history [N]` | Hunt credentials committed in the last `N` commits (default 300). |
| `--deps` | Check dependencies against the OSV vulnerability database. |
| `--url <URL>` | Passive, read-only live header and exposure checks. |
| `--all` | Enable artifacts + git history + dependencies. |
| `--offline` | Disable this scanner's own network requests. Does not apply to external engines. |

**External engines (optional, never auto-installed)**

| Argument | Description |
| :--- | :--- |
| `--engine <name>` | Also run an installed `semgrep`, `gitleaks`, `trivy`, `osv-scanner` or `scorecard` and import its findings as `EXT-<ENGINE>:<id>`. Repeatable. Missing, crashing or unparseable is an `ENG-00` gap. `codeql` and `zap` are listed but have no adapter. |
| `--list-engines` | Show which engines are installed, with role and licence, and exit. |
| `--authorize-network-scan` | Required with `--url` before any engine that sends live traffic. |

## Profiles

| Profile | Stages run by default | Can return `RELEASE_AUDIT_PASSED` |
| :--- | :--- | :--- |
| `quick` | Source analysis only - currently identical to `code` | No |
| `code` (default) | Source analysis: patterns, data-flow, secret detection | No |
| `full` | `code` + dependencies + git history + build artifacts | No |
| `release` | Everything in `full`, and forces `--fail-on-incomplete` | Yes - the only one |

An explicit flag always adds its stage to any profile. `--profile release` exits `1` on an
incomplete stage but not on findings - add `--fail-on-high` for a merge gate.

## Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | No gate flag tripped. The verdict alone never sets the exit code: `BLOCKED` exits `0` without `--fail-on-high` / `--fail-on`. |
| `1` | A severity gate met a finding at or above `--min-confidence`, or `--fail-on-incomplete` met a gap or a scan of zero files. |
| `2` | The target path does not exist. |

## Common Invocations

```bash
# Release gate: every stage must run, and nothing high may be open
python3 scripts/aegis_scan.py . --profile release --fail-on-high --output .aegis/scan-report.json

# Verify what actually ships before deploying or uploading
python3 scripts/aegis_scan.py . --artifact dist/
python3 scripts/aegis_scan.py . --artifact app/build/outputs/apk/release/app-release.apk

# Pull-request review: only what changed, minus pre-existing noise
python3 scripts/aegis_scan.py . --diff origin/main --baseline .aegis/baseline.json --quiet

# First adoption on a large existing repo
python3 scripts/aegis_scan.py . --write-baseline .aegis/baseline.json

# GitHub code scanning + SBOM
python3 scripts/aegis_scan.py . --all --sarif .aegis/results.sarif --sbom .aegis/sbom.json

# CI merge gate on source only
python3 scripts/aegis_scan.py . --fail-on-high
```

## What Leaves The Machine

A default scan makes no network request, and there is no telemetry. `--deps` (and `--all`,
`--profile full`, `--profile release`) sends dependency names and versions to
`https://api.osv.dev/v1/querybatch`. `--url` sends one `GET` to the supplied URL and one
each to `/.env` and `/.git/config` on the same host. `--offline` disables both. External
engines are separate programs with their own network behaviour, and `--offline` does not
apply to them.

## What `--url` Actually Does

Strictly passive and read-only. It issues:

1. One `GET` to the supplied URL, reading response headers only. It checks for
   `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
   `Strict-Transport-Security` (HTTPS targets only), and a wildcard
   `Access-Control-Allow-Origin: *`.
2. One `GET` each to `/.env` and `/.git/config` to detect accidental public exposure,
   reading at most 512 bytes of the response.

It sends the User-Agent `VibeAegis-PreLaunch-Audit/1.0 (Passive-Read-Only)`, no credentials,
no payloads, and no `POST`/`PUT`/`DELETE`. It does not crawl or spider. If the URL is
unreachable the scanner records a `LIVE-00` coverage gap, so the verdict is
`INCOMPLETE_SCAN` rather than a pass.

**Only use `--url` against deployments you own or are authorized to test.**

## Verdicts And Score

The score starts at `100` and subtracts `25` per `CRITICAL`, `10` per `HIGH`, `4` per
`MEDIUM` and `1` per `LOW`, floored at `0`. Coverage gaps are not scored.

`release_verdict` starts with one of these words, checked in this order; match the leading
word, never the whole string:

| # | `release_verdict` starts with | When |
| :--- | :--- | :--- |
| 1 | `INCOMPLETE_SCAN` | Zero source files were scanned (score forced to `0`). |
| 2 | `BLOCKED` | Any open `CRITICAL` or `HIGH`. |
| 3 | `INCOMPLETE_SCAN` | Any check did not run or did not read what it should have. |
| 4 | `REVIEW_REQUIRED` | Any `MEDIUM`, or a score below 90. |
| 5 | `RELEASE_AUDIT_PASSED` | `--profile release`, every release stage complete, nothing found. |
| 6 | `STATIC_CHECKS_PASSED` | Anything else that is clean. NOT a release-readiness claim. |

With `--diff`, a changeset with no scannable source returns
`NO CODE CHANGES TO REVIEW (diff contained no scannable source files)`.

## Rule Identifier Reference

- `SEC-01` .. `SEC-17` (and `B`/`C` variants) - security rules, `domain` is `SECURITY`.
- `SEC-17B` - live server exposure of `/.env` or `/.git/config`, `CRITICAL`.
- `UX-01` .. `UX-12` - UI/UX rules, `domain` is `UI_UX`.
- `PAY-01` .. `PAY-03` - payments, `domain` is `PAYMENTS`. `REL-01` .. `REL-04` - reliability, `domain` is `RELIABILITY`.
- `FLOW-01` .. `FLOW-05` - data-flow (taint) findings, `domain` is `DATAFLOW`, confidence `MEDIUM` by design.
- `DEP-01` - dependency vulnerabilities, `domain` is `SUPPLY_CHAIN`.
- `ART-01` .. `ART-15` - build artifact and mobile package findings, `domain` is `ARTIFACT`.
  `ART-01` is confirmed by construction (same credential present in both source and bundle) and must not be dismissed.
- `HIST-01` - credentials found in git history, `domain` is `HISTORY`.
- `EXT-<ENGINE>:<id>` - imported from an external engine, `domain` is `EXTERNAL`.
- Any id ending `-00` (`DEP-00`, `LIVE-00`, `GIT-00`, `ART-00`, `ART-10`, `COV-00`, `ENG-00`) is a
  coverage gap, reported under `skipped_checks`, never a defect and never suppressible.

## Reports Are Safe To Share

Every credential in every output format is redacted to its public provider prefix and its
length - no character of the secret itself. `.aegis/scan-report.json` can be committed, attached to an issue, or handed to an agent
without leaking the value it is warning about.

---
"""


def schema_part(text):
    return (
        "\n# =============================================================================\n"
        "# PART 8: JSON REPORT SCHEMA - `.aegis/scan-report.json`\n"
        "# =============================================================================\n\n"
        "Produced by `--output`. Validate with `schemas/scan-report.schema.json`\n"
        "(JSON Schema Draft 2020-12). Top-level keys include `scanner`, `version`, `timestamp`,\n"
        "`target_path`, `live_url`, `stages`, `scanned_files`, `tech_stack`, `readiness_score`,\n"
        "`release_verdict`, `summary_counts`, `coverage`, `skipped_checks`, `findings`.\n\n"
        "Each entry in `findings` and `skipped_checks` has: `rule_id`, `domain` (see the schema enum),\n"
        "`severity` (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`), `title`, `file`, `line`, `snippet`,\n"
        "`cwe_or_standard`, `remediation`, `confidence`.\n\n"
        "Findings arrive pre-sorted: severity first (CRITICAL to LOW), then domain, file, line.\n\n"
        "## Full Schema\n\n"
        "```json\n" + text.rstrip() + "\n```\n"
    )



EXTRA_SKILLS = [
    ("architecture-threat-model", "ARCHITECTURE, TENANCY & STRIDE THREAT MODEL"),
    ("payments-logic-auditor", "PAYMENTS, WEBHOOKS & RACE CONDITIONS"),
    ("ai-llm-security-shield", "AI / LLM SECURITY & DENIAL-OF-WALLET"),
    ("backend-reliability-scale", "BACKEND RELIABILITY, SCALE & PRIVACY"),
    ("production-preflight-gate", "PRODUCTION PRE-FLIGHT GATE"),
]

parts = [
    HEADER,
    "\n# =============================================================================\n"
    "# PART 1: README - FULL DOCUMENTATION\n"
    "# =============================================================================\n\n",
    read("README.md"),
    "\n---\n\n# =============================================================================\n"
    "# PART 2: AGENTS.md - ALWAYS-ON ENGINEERING RULES\n"
    "# =============================================================================\n\n"
    "These rules apply while code is being written, not only during an audit. The installer\n"
    "places this file as `AGENTS.md`, `.cursorrules`, `.clinerules`, `GEMINI.md` and\n"
    "`.windsurf/rules/vibe-aegis.md`.\n\n",
    read("AGENTS.md"),
    "\n---\n\n# =============================================================================\n"
    "# PART 3: SKILL - `vibe-aegis` (MASTER 6-STAGE ORCHESTRATOR)\n"
    "# =============================================================================\n\n"
    "Source file: `skills/vibe-aegis/SKILL.md`\n\n",
    read("skills/vibe-aegis/SKILL.md"),
    "\n---\n\n# =============================================================================\n"
    "# PART 4: SKILL - `security-redteam-loop` (LOW-TO-CRITICAL SECURITY AUDITOR)\n"
    "# =============================================================================\n\n"
    "Source file: `skills/security-redteam-loop/SKILL.md`\n\n",
    read("skills/security-redteam-loop/SKILL.md"),
    "\n---\n\n# =============================================================================\n"
    "# PART 5: SKILL - `ui-ux-bug-finder` (UI/UX, LAYOUT & ACCESSIBILITY AUDITOR)\n"
    "# =============================================================================\n\n"
    "Source file: `skills/ui-ux-bug-finder/SKILL.md`\n\n",
    read("skills/ui-ux-bug-finder/SKILL.md"),
    "\n---\n",
    CLI,
    schema_part(read("schemas/scan-report.schema.json")),
    "\n---\n\n"
    "# END OF VIBE AEGIS COMPLETE FRAMEWORK\n\n"
    "Repository: https://github.com/Tacuns/vibe-aegis\n"
    "License: MIT\n"
    "Report issues and contribute new SEC-XX / UX-XX rules: see CONTRIBUTING.md\n"
    "Security policy and authorized-use scope: see SECURITY.md\n",
]

out = ROOT / "llms-full.txt"
out.write_text("".join(parts), encoding="utf-8")
print(f"Wrote {out} ({out.stat().st_size} bytes)")
