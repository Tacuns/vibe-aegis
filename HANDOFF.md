# Handoff — `aegis/v2.7-framework`

Context for anyone (human or agent) picking up this branch. Read this, then
`CLAUDE.md`, `AGENTS.md`, `CONTRIBUTING.md`, and the `2.5.0` / `2.6.0` entries in
`CHANGELOG.md`. Read `scripts/aegis_scan.py` in full before editing it.

> This branch is **work in progress**. `SCANNER_VERSION` is deliberately still `2.6.0`.
> Do not release from it and do not merge it to `main` until the items below are done.

---

## What this tool is

A zero-dependency Python scanner (`scripts/aegis_scan.py`, single file, ~3,200 lines)
plus nine agent skills. It answers one question — **"is what I built safe to ship?"** —
and it both finds the problem and gives the exact fix.

It is deliberately **not** a reverse-engineering tool. Source you own plus your own
build output, before you publish.

---

## Non-negotiable rules

1. **Zero dependencies.** Must run on a bare Python 3.8+ interpreter. CI fails if a
   `requirements.txt` appears. No `pip install`, ever.
2. **Single file.** `install.sh` copies only `scripts/aegis_scan.py` into target
   projects. A second scanner module silently breaks every installation.
3. **Every rule needs a negative test** proving it stays *silent* on correct code, not
   just a positive test proving it fires on bad code. Precision over recall: a noisy
   scanner is uninstalled within a week.
4. **Never print a credential.** Reports get committed and attached to issues. Provider
   secrets are detected in exactly **one** place — `scan_secrets_in_text()`, which
   redacts at construction. Never add a second detector whose snippet is a raw source
   line; that was a real credential leak, fixed in 2.5.0.
5. **Never claim a rule you did not implement.** `test_every_readme_rule_is_implemented`
   parses the README matrix and fails if a documented rule is missing.
6. **No AI-assistant attribution** in commit messages or pull requests.
7. **Regenerate `llms-full.txt`** (`python scripts/build_llms_full.py .`) after changing
   the README, `AGENTS.md`, any `SKILL.md`, the CLI, or the schema.

---

## The core design idea — do not weaken it

Three independent axes, never collapsed into one number:

| Axis | Question | Gate |
| :--- | :--- | :--- |
| **Coverage** | Did the check actually run? | `--fail-on-incomplete` |
| **Severity** | If it is real, how bad is it? | `--fail-on-high` / `--fail-on` |
| **Confidence** | How sure are we that it is real? | `--min-confidence` |

A check that **could not run** is an UNKNOWN, never a pass. A coverage gap is detected
three redundant ways — `status in {SKIPPED, SCAN_ERROR}`, `kind == "skipped_check"`, or
a rule id ending `-00` — so a caller hand-building a `Finding` still cannot obtain a
pass. Coverage gaps can **never** be suppressed by `.aegis-ignore` or `--baseline`:
suppression accepts known *defects*, and a check that did not run carries nothing to
accept.

Five verdicts:

| Verdict | Meaning |
| :--- | :--- |
| `BLOCKED` | A defect we can point at |
| `INCOMPLETE_SCAN` | Something was not examined; no opinion is possible |
| `REVIEW_REQUIRED` | Medium findings a human must decide on |
| `STATIC_CHECKS_PASSED` | The static checks that ran found nothing — **not** release-ready |
| `RELEASE_AUDIT_PASSED` | Every release stage ran and passed |

A static source scan must **never** claim release readiness. Only `--profile release`,
with every stage in `RELEASE_STAGES` actually completed, returns `RELEASE_AUDIT_PASSED`.

---

## Already done on this branch — do not redo

112 tests pass; CI is green on all three jobs.

- **`CoverageLedger`** — every skipped file, line and package is recorded and surfaced
  as a `COV-00` gap. Wired into oversized files (`--max-file-size`), unreadable files,
  minified bundles, lockfiles, lines over 4,000 characters, and OSV's 800-package batch
  truncation (previously a silent `deps[:800]`).
- **Profiles and verdicts** — `--profile quick|code|full|release` and the five-state
  model above. `--profile release` forces `--fail-on-incomplete`.
- **External engine adapters** (`--engine`) — semgrep, gitleaks, trivy, osv-scanner,
  scorecard. Detect-only through `PATH`; **never auto-install**. A missing, crashing or
  unparseable engine becomes an `ENG-00` coverage gap, never a pass. Imported findings
  keep the originating engine's rule id behind an `EXT-<ENGINE>:` prefix in the
  `EXTERNAL` domain. ZAP requires **both** `--authorize-network-scan` and `--url`.
  CodeQL is listed with no adapter because it needs a prebuilt database.
- **Schema** — `COVERAGE` and `EXTERNAL` domains; `coverage.items_not_examined` and
  `coverage.not_examined`.

---

## Remaining work

> **Start with item 5 (documentation).** This branch cannot be merged until it is done.
> The scanner here can never emit `READY TO PUBLISH`, yet `README.md` still promises it
> six times, and `--profile`, `--engine` and the new verdict names are undocumented.
> Shipping that to `main` would mean the docs describe a tool that no longer exists —
> the same defect `test_every_readme_rule_is_implemented` exists to prevent. Items 1–4
> then follow in the order given.

Do **one item per session**. Finish it completely, with tests and docs, before starting
the next. `aegis_scan.py` is a single large file, so parallel branches will conflict
badly — work sequentially.

### 1. Redaction regression suite
Prove secrets never reach findings, the JSON report, SARIF, terminal output, stderr,
exception messages, or imported external-engine output. Include a guard test that fails
if any future rule builds a snippet from a raw source line.

### 2. Test fixture corpus
`tests/fixtures/{vulnerable,safe}/` — matched pairs per rule, where the safe fixture is
the realistic **correct** implementation of the same feature. Report
false-positive/false-negative counts in CI.

### 3. Detection depth
Use Python's built-in `ast` module for `.py` files — stdlib, so rule 1 holds — in place
of regex for injection and auth checks. For JS/TS, improve the existing heuristics; do
**not** add a parser dependency. Known weak spots: `SEC-04` (IDOR), `SEC-03` (auth
recognition), and `FLOW-*` taint propagation across function boundaries.

### 4. Mobile package verification
`ART-11` currently checks v1 `META-INF` signatures plus the v2/v3 APK Signing Block
magic. `.aab` and `.ipa` use different signing models. Never report a signature as
absent or invalid without platform-correct verification — emit `ART-10` (coverage gap)
when the format cannot be verified.

### 5. Documentation — DO THIS FIRST, it is what blocks the merge
`README.md` and `AGENTS.md` still describe the older model. Required:

- **Remove every stale `READY TO PUBLISH`.** It appears in `README.md` (6×),
  `skills/vibe-aegis/SKILL.md`, `docs/prompts/01-full-prelaunch-audit.md` and
  `schemas/scan-report.schema.json`. That verdict no longer exists.
- Document the **three axes** (coverage, severity, confidence) and the gate flag for each.
- Document the **four profiles** (`--profile quick|code|full|release`) and state plainly
  that only `release` can return `RELEASE_AUDIT_PASSED`.
- Document the **five verdicts**, including that `STATIC_CHECKS_PASSED` is not a
  release-readiness claim.
- Document `--engine`, `--list-engines`, `--authorize-network-scan`, `--max-file-size`,
  and each engine's licence. Say that engines are never auto-installed and that a
  missing engine is a coverage gap.
- Document what leaves the machine: `--deps` queries `api.osv.dev`; `--url` touches only
  the supplied URL; `--offline` disables both; there is no telemetry.
- Add a **migration note to `CHANGELOG.md`**: any CI that greps `release_verdict` for
  `READY TO PUBLISH` breaks. Tell users what to match instead.
- Bump `SCANNER_VERSION`, `package.json` and both `.claude-plugin/*.json` **together**.
  Leaving `main` and this branch both on `2.6.0` with different behaviour is not an
  option.
- Regenerate `llms-full.txt` (`python scripts/build_llms_full.py .`) last.

---

## Verification — required before calling anything done

```bash
python -B -m unittest discover -s tests -v   # must stay green; never let the count drop
python scripts/build_llms_full.py .
python scripts/aegis_scan.py . --quiet       # self-scan still sane
```

CI must pass all three jobs: Unit Tests (3.8), Unit Tests (3.12), Installer Smoke Test.

The Installer Smoke Test carries its **own** inline fail-closed contract check inside
`.github/workflows/ci.yml`. If you change a verdict constant you must update it too —
and assert against the module constants (`a.VERDICT_STATIC_OK`, `a.VERDICT_INCOMPLETE`),
never literal strings. Two of those assertions once compared against a retired string,
became vacuously true, and would have passed with the contract completely broken.

---

## Editing traps — each of these has caused a real bug

- **Bash heredocs silently corrupt escapes.** `\b` became a literal backspace inside
  shipped regexes; `\n` became a real newline and once broke the CI YAML outright. Write
  code to a file with an editor tool, then splice it. Verify afterwards:
  ```bash
  python -c "s=open('scripts/aegis_scan.py',encoding='utf-8').read(); print(sum(s.count(chr(c)) for c in (7,8,11,12)))"
  ```
- **Never paste zero-width or smart characters** into the source:
  ```bash
  python -c "import unicodedata as u; s=open('scripts/aegis_scan.py',encoding='utf-8').read(); print(sum(1 for c in s if ord(c)>126 and u.category(c) in ('Cf','Cc')))"
  ```
- **`[^>]*` cannot scan a JSX tag**, because `=>` contains `>`. Use the existing
  `_IN_TAG` pattern, which permits `>` only when preceded by `=`.
- **Assemble fake keys at runtime** in fixtures (`"sk_live_" + "rest"`) or GitHub push
  protection blocks the push — correctly.
- **CRLF warnings on commit are normal.** `.gitattributes` forces LF in the repo.
