# Contributing to Vibe Aegis

Thanks for helping make vibe-coded apps safer to ship. The highest-value contributions are **new detection rules** and **false-positive fixes**.

## Ground Rules

1. **Zero dependencies.** `scripts/aegis_scan.py` must run on a bare Python 3.8+ interpreter. Do not add `pip` packages.
2. **Defensive only.** Rules detect and explain weaknesses. Never add exploitation, payload delivery, or credential-testing behaviour.
3. **Every rule needs a test.** A rule without a unit test will not be merged.
4. **Precision over recall.** A noisy rule that fires on safe code is worse than no rule. If a pattern cannot be matched with reasonable confidence, set `confidence="MEDIUM"` and describe the limitation in the remediation text.

## Project Layout

```text
scripts/aegis_scan.py   # all deterministic rules live here
skills/                 # agent skill definitions (Markdown + YAML frontmatter)
adapters/               # per-agent config emitted by install.sh
schemas/                # JSON Schema for .aegis/scan-report.json
tests/test_scanner.py   # unit tests
```

## Adding a New Security Rule (`SEC-XX`)

1. Open `scripts/aegis_scan.py` and add an entry to the `SECURITY_PATTERNS` list. Each entry is a tuple of
   `(rule_id, severity, title, compiled_regex, cwe_or_standard, remediation, file_extensions_or_None)`:

   ```python
   (
       "SEC-18",
       "HIGH",
       "Short Human-Readable Title",
       re.compile(r"your_pattern", re.IGNORECASE),
       "CWE-XXX / OWASP AXX",
       "Concrete fix instruction.",
       {".ts", ".tsx"},
   )
   ```

2. Choose the **lowest severity that is still honest**:

   | Severity | Meaning |
   | :--- | :--- |
   | `CRITICAL` | Direct data breach, auth bypass, or financial loss with no further conditions |
   | `HIGH` | Exploitable with a realistic precondition (a logged-in attacker, a crafted input) |
   | `MEDIUM` | Weakens defence in depth, or exploitable only in combination |
   | `LOW` | Hygiene and hardening gaps |

3. Cite a real standard (CWE ID, OWASP Top 10 category, or WCAG success criterion). Do not invent identifiers.

## Adding a New UI/UX Rule (`UX-XX`)

Same process, but add to `UI_UX_PATTERNS`, set the domain to `UI_UX`, and cite a **WCAG 2.2 success criterion** (for example `WCAG 2.2 AA - 1.1.1 Non-text Content`) or a named usability heuristic rather than a CWE.

UI/UX severity guide: `HIGH` = the feature is broken or loses user data (dead button, double-submit, swallowed error). `MEDIUM` = confusing or inaccessible. `LOW` = polish.

## Rule Prefixes

| Prefix | Domain | Lives in |
| :--- | :--- | :--- |
| `SEC-XX` | Source security rules | `SECURITY_PATTERNS` + `check_contextual_file_rules` |
| `UX-XX` | UI/UX and accessibility | `UI_UX_PATTERNS` |
| `FLOW-XX` | Data-flow (taint) analysis | `TAINT_SINKS` |
| `DEP-XX` | Dependency vulnerabilities | `check_dependency_vulnerabilities` |
| `ART-XX` | Build artifacts and mobile packages | `scan_build_artifacts`, `scan_mobile_package` |
| `HIST-XX` | Git history forensics | `scan_git_history` |
| `LIVE-XX` | Live deployment posture | `check_live_url_posture` |

Adding a new prefix means updating the `rule_id` pattern in `schemas/scan-report.schema.json` and the matching regex in `load_ignore_rules`.

### Adding a credential pattern

Append to `PROVIDER_SECRETS` as `(label, severity, compiled_regex)`. Then add **both** a positive test and a negative test proving a placeholder form of the same key does not fire. Never widen a pattern enough to match a documentation example - `test_rejects_placeholders_and_documentation_keys` exists to stop exactly that.

### Adding a taint sink

Append to `TAINT_SINKS` as `(rule_id, severity, title, standard, compiled_regex)`. If the sink has a safe calling convention, add it to `SANITIZERS` too, and add a test proving the sanitised form produces **zero** findings. A taint rule without a negative test will be rejected.

### Never print a raw credential

Reports get committed and attached to issues, so every `snippet` is public. Build it in one of three ways only:

- a string constant: `snippet="Upload handling found with no size limit."`
- `redact(value)`, for a credential you detected yourself
- `evidence(text)`, for **anything** taken from a scanned file or an external tool: `snippet=evidence(lines[line_no - 1])`

`evidence()` masks provider keys, secret-named values, credentialed URLs and random tokens, and **then** truncates. Never slice before calling it (`evidence(line[:140])`): a cut through a key is how a partial key once escaped its own pattern. Pass a limit instead: `evidence(line, 200)`.

`TestEverySnippetIsBuiltThroughEvidence` parses the scanner and fails on any other spelling. Then add your rule to `REDACTION_CORPUS` in `tests/test_scanner.py`, with a canary on the line that triggers it. `test_every_rule_is_exercised_or_explicitly_exempt` fails until you do.

## Running the Tests

```bash
python3 -B -m unittest discover -s tests -v
```

Add your coverage to `tests/test_scanner.py`: write a fixture file containing the vulnerable pattern into the temporary directory, then assert your rule ID appears in the resulting `rule_ids` set. Also confirm your rule does **not** fire on a safe equivalent.

## Testing the Installer

```bash
bash install.sh --target /tmp/test-app --agent all
```

Verify the expected files land in `/tmp/test-app` for each agent, then delete the directory.

## Pull Request Checklist

- [ ] `python3 -B -m unittest discover -s tests -v` passes
- [ ] New rule has both a positive and a negative test case
- [ ] Rule is documented in the README coverage matrix
- [ ] `llms.txt` file map updated if you added or removed a file
- [ ] `python3 scripts/build_llms_full.py .` re-run if you changed README, AGENTS.md, a SKILL.md, the CLI or the schema
- [ ] No new dependencies

## Reporting Rule Accuracy Problems

Open an issue titled `[false-positive] SEC-XX` or `[false-negative] UX-XX` and include a minimal code snippet, the rule ID, what the scanner reported, and what it should have reported.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE), copyright Tacuns.
