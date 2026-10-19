# Handoff — `aegis/v2.7-framework`

Context for anyone (human or agent) picking up this branch. Read this, then
`CLAUDE.md`, `AGENTS.md`, `CONTRIBUTING.md`, and the `2.5.0` / `2.6.0` entries in
`CHANGELOG.md`. Read `scripts/aegis_scan.py` in full before editing it.

> This branch is **work in progress**. `SCANNER_VERSION`, `package.json` and both
> `.claude-plugin/*.json` are `2.7.0` — bump all four together if that changes.
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
   redacts at construction. Every snippet is a constant, `redact(...)`, or
   `evidence(...)` — never a raw source line, and never sliced before masking. A test
   parses the scanner and enforces this; a raw-line snippet was a real credential leak
   in 2.5.0, and again in seven more rules until the redaction suite went in.
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

392 tests pass; CI is green on all four jobs.

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

> Items 1, 2, 4 and 5 are done; item 3 is done for JS/TS heuristics and Python request
> sources, with Python `ast` analysis and cross-file taint still open. Item 5 was the one
> blocking the merge: the documentation describes the tool this branch actually builds,
> and `TestDocumentationMatchesTheScanner` fails if it drifts again.

Do **one item per session**. Finish it completely, with tests and docs, before starting
the next. `aegis_scan.py` is a single large file, so parallel branches will conflict
badly — work sequentially.

### 1. Redaction regression suite — DONE
Secrets are proved absent from findings, the JSON report, SARIF, the SBOM, terminal
output, stderr, exception messages and imported external-engine output
(`TestNoOutputChannelCarriesASecret` and the classes after it). `TestEverySnippetIsBuiltThroughEvidence`
fails if any rule builds a snippet from raw text. `redact()` now prints only the public
provider prefix and the length; exact-value matching (`ART-01`, history dedupe, baseline
fingerprints) reads an in-memory vault instead of the snippet. Known limit: only
*recognisable* secrets are masked. Trivy's `Secrets` are now imported from the masked
`Match` only; its `Code` context lines are never read, because they hold neighbouring
source lines unmasked.

### Done outside the numbered items
OSV severity is read from each advisory record (no more blanket MEDIUM); `--offline`
covers external engines; the installer never modifies a project's own config files and
backs up its own before updating; every GitHub Action is pinned to a commit SHA.

The 25-issue review checklist (groups A–F) is worked through in `CHANGELOG.md` 2.7.0 under
the "checklist A" … "checklist E" headings, each issue reproduced before it was changed.

### 2. Test fixture corpus — DONE
`tests/corpus/<RULE>/{vulnerable,safe}/` holds a realistic insecure and a realistic correct
implementation for 51 rules; `ART-12`/`ART-15` packages are built in the test. `TestCorpus`
requires every rule to fire on its vulnerable case and stay silent on its safe one, and
fails when a rule id has neither a corpus pair nor an entry in `CORPUS_EXEMPT` naming the
test class that covers it (gaps, and rules that need git, the network, a live server or a
signed package). The **Release Gate** CI job runs it with `AEGIS_CORPUS_REPORT` and uploads
the TP/FN/FP/TN summary, and runs `tests/release_gate/run.py`: `--profile release` on a
clean, a vulnerable, a review-required and an incomplete project, asserting each exact
verdict and exit code. Building the corpus found three detection gaps, fixed: camelCase
secret names (`apiSecret`), quoted keys (JSON `"api_secret": ...`) and `.rules` files.

### 3. Detection depth — partly done
Done (checklist C): `SEC-03` per handler, `SEC-04` requires the owner from the session,
sink-specific sanitizers bound to the tainted value, one level of interprocedural taint
within a file, and Flask/Django/DRF request sources for `.py` files. Still open: use
Python's built-in `ast` module for `.py` files — stdlib, so rule 1 holds — in place of
regex for injection and auth checks, and taint across files. For JS/TS, keep improving the
heuristics; do **not** add a parser dependency.

### 4. Mobile package verification — DONE
An APK signature is verified by `apksigner` when it is on PATH (`ART-11` if it fails) and
is otherwise an `ART-10` gap; nothing cryptographic is reimplemented. The binary manifest
is decoded, so `ART-13`/`ART-14` read real values. `.aab` (protobuf manifest, signed by
Play) and `.ipa` remain `ART-10` gaps by design.

### 5. Documentation — DONE
README, `AGENTS.md`, the orchestrator and pre-flight skills, the full-audit prompt, the
schema and `llms-full.txt` now describe the three axes, four profiles, five verdicts (plus
`--diff`'s `NO CODE CHANGES TO REVIEW`), exit codes, engines with licences, and what leaves
the machine. `CHANGELOG.md` `2.7.0` carries the migration note. Three checklist claims were
tested and found inaccurate, so the docs say what the code does instead:

- `--url` also requests `/.env` and `/.git/config` on the same host, not only the URL.
- `--offline` does **not** apply to external engines; `semgrep --config auto` fetches its
  ruleset from the network.
- ZAP has no adapter: with both flags it records an `ENG-00` gap and never runs.

Documenting the profiles exposed real defects, fixed in `9073e8b` before the docs were
written: `--profile release` certified build-artifact and dependency stages that had read
nothing; `quick` dropped `--all`; `--artifact` with no value was rejected. Since then,
`--profile release` exits `1` on anything but `RELEASE_AUDIT_PASSED` unless `--fail-on`
is given. Still true and documented, not changed:
`quick` is identical to `code`.

---

## Verification — required before calling anything done

```bash
python -B -m unittest discover -s tests -v   # must stay green; never let the count drop
python scripts/build_llms_full.py .
python scripts/aegis_scan.py . --quiet       # self-scan still sane
```

CI must pass all four jobs: Unit Tests (3.8), Unit Tests (3.12), Release Gate, Installer
Smoke Test.

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
