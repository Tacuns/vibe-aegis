# Changelog

All notable changes to Vibe Aegis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2026-10-19

Adversarial self-audit prompted by the fail-open report. Every function was re-tested in isolation, not only through the full audit.

### Fixed - fail-closed readiness contract

- `compute_readiness_score(findings, skipped_checks=None, scanned_files=None, allow_skipped=False)`.
- **0 source files scanned** now returns `(0, "INCOMPLETE_SCAN ...")`. Previously an empty directory scored **100/100 READY TO PUBLISH** - the worst fail-open in the tool.
- A coverage gap is detected three independent ways - `status in {SKIPPED, SCAN_ERROR}`, `kind == "skipped_check"`, or a rule id ending `-00` - so a caller constructing a `Finding` by hand still cannot obtain a passing verdict. This is what the original report did.
- `READY TO PUBLISH` now requires all four: files scanned, no `CRITICAL`/`HIGH`, nothing skipped, score >= 90. `allow_skipped=True` is an explicit opt-in.
- New `GIT-00`: a missing `.git`, a missing git binary or a timeout previously returned an empty list, reporting "no credentials in history" for a check that never ran.
- `Finding` gains `status` (`VULNERABILITY` / `SKIPPED` / `SCAN_ERROR`) alongside the existing `kind`.

### Fixed - false positives

- **Commented-out code is no longer scanned.** `// eval(req.body.code)` and `# cursor.execute(f"...")` were producing findings a developer cannot act on. Comment masking preserves string literals, so `https://` inside a string is not mistaken for a comment, and `href="#"` in JSX is not mistaken for a `#` comment. Offsets are preserved, so line numbers and evidence snippets are unaffected.
- **Test and fixture files are excluded by default** (`*.test.*`, `*.spec.*`, `tests/`, `__tests__/`, `fixtures/`, `e2e/`, `conftest`). Fixtures contain deliberately insecure code; judging production readiness by them is meaningless. `--include-tests` audits them anyway.
- **Framework auth guards are recognised**: `passport.authenticate`, Clerk `auth.protect()`, `withApiAuth`, `Depends(...)`, `@login_required`, `@jwt_required`, `getServerAuthSession`, `isAuthenticated` and others. Protected routes were being reported as unauthenticated.

### Fixed - installer and CLI

- `install.sh` is now idempotent. Re-running it created a new `.aegis/AGENTS.vibe-aegis.md` on every run; it now compares content first. Paths containing spaces were already handled correctly and are covered by a test.
- `bin/vibe-aegis.mjs` hard-coded `python3`, which does not exist on a default Windows install. It now tries `python`, `python3` and `py` in a platform-appropriate order and prints a clear message instead of failing with `ENOENT`.

### Changed

- Schema: `status` added to findings, `GIT` added to the rule-id pattern, `release_verdict` documents all five states with examples.
- `--include-tests` added. Tests 50 -> 68.

## [2.3.0] - 2026-10-19

Two community reports, plus a full line-by-line audit they prompted.

### Fixed - a skipped check was being treated as a passing check

Reported: `check_dependency_vulnerabilities(deps, offline=True)` returned a `LOW` `DEP-00`, and passing that alone to `compute_readiness_score` gave 99/100 and `READY TO PUBLISH`. An audit where nothing ran could certify itself.

The answer to "is READY intended to cover only completed checks?" is yes, and it is now enforced:

- `Finding` gains `kind`: `finding` (a real defect) or `skipped_check` (a check that could not run).
- Coverage and severity are separate axes. Skipped checks never affect `readiness_score` or `summary_counts`.
- Any skipped check forces `release_verdict` to `INCOMPLETE`, naming which check was missed. `READY TO PUBLISH` is issued only for a complete audit.
- Report gains `coverage` and a separate `skipped_checks` array; the terminal output prints a "CHECKS THAT DID NOT RUN - result UNKNOWN, not clean" section.
- New `--fail-on-incomplete` so a green pipeline can be made to mean *fully audited* rather than *nothing found*.
- All four sites that mean "did not run" are marked: `DEP-00` (offline and OSV unreachable), `LIVE-00` (unreachable URL), `ART-10` (unopenable package).

### Fixed - the README promised six rules that did not exist

An audit of documented-versus-implemented rule ids found `PAY-03`, `SEC-04`, `SEC-14`, `SEC-15`, `UX-04` and `UX-06` listed in the coverage matrix but absent from the scanner - a silent false negative for anyone who trusted the table. All six are now implemented:

- `PAY-03` Critical: payment webhook route with no signature verification (`constructEvent` / HMAC) anywhere in the file.
- `SEC-04` Critical: a record addressed by a request-supplied id with no owner scoping in the WHERE clause (IDOR).
- `SEC-14` Medium: login, OTP, reset-password, signup and invite endpoints with no rate limiter.
- `SEC-15` Medium: upload handling with no MIME allowlist and no size limit.
- `UX-04` Medium: a `.map()` list render with no zero-length branch - the user sees a blank screen.
- `UX-06` Medium: form control with no accessible name. A `placeholder` is not a label.

A new test parses the README matrix and fails if any documented rule is missing from the scanner, so this cannot regress.

### Fixed - SEC-03 false positive on authentication routes

`SEC-03` flagged login, signup, OTP, callback and password-reset routes for "missing authentication". Authenticating is what those routes are for. The exclusion list now covers them, and a test confirms a genuinely unprotected mutation route still fires.

### Fixed - corrupted regex literals

Three regexes in `aegis_scan.py` contained literal control characters instead of `` word boundaries, introduced by earlier editing mistakes. The affected patterns could not match what they claimed to.

### Changed

- Schema: `coverage` and `skipped_checks` added; `kind` added to findings; `release_verdict` documents the `INCOMPLETE` state.
- Tests 37 -> 50, including negative fixtures proving all six restored rules stay silent on correct implementations.

## [2.2.0] - 2026-10-19

Acts on community feedback: an action rendered as a link is an accessibility bug, and the fix is to use the right element, not a better `href`.

### Added

- `UX-11` High: an action marked up as a link - `<a href="#" onClick={...}>` or `href="javascript:"`. A screen reader announces "link" so the user expects navigation, Space does not activate it, and `#` jumps the page to the top and pollutes browser history. Cites WCAG 2.2 AA 4.1.2 Name, Role, Value.
- `UX-12` High: a clickable `<div>`, `<span>`, `<li>` or `<td>` with no `role` and no `tabIndex`. Unreachable by Tab, not activatable by Enter or Space, announced as plain text - the control is invisible to anyone not using a mouse. Cites WCAG 2.2 AA 2.1.1 Keyboard and 4.1.2.
- Both rules recognise a correct retrofit (`role` + `tabIndex` + `onKeyDown`) and stay silent on it.

### Changed

- `UX-01` now fires only on genuinely dead controls - `href="#"` with no handler, or a no-op/`console.log` stub. Previously it also matched `<a href="#" onClick={realHandler}>`, which is a working control with the wrong semantics, and gave the wrong advice for it ("replace with a real route").
- `UX-01` now cites WCAG 2.2 AA 2.4.4 instead of the invented standard "UI/UX Functional Completeness".
- `skills/ui-ux-bug-finder/SKILL.md` gains a table separating the three cases, and states the principle: if it performs an action it is a button, if it navigates it is a link with a real `href`. Choosing the right element gives focus, Tab order, Enter and Space, and the correct role for free.
- Tests 30 -> 37, including a negative suite asserting a real `href`, a real `<button>` and a correctly retrofitted `<div>` produce zero findings, and that the remediation text actually names the `button` element.

### Fixed

- A corrupted comment in `scripts/aegis_scan.py` contained literal backspace characters instead of `secret`, introduced by an earlier editing mistake. Cosmetic only - the code was unaffected - but it was wrong text in a public repository.

## [2.1.0] - 2026-10-18

Expands Vibe Aegis into a 10-stage First-to-Last safeguard across 8 domains. Everything in 2.0.0 is retained; all flags behave identically.

### Added - Payments & Business Logic domain

- `PAY-01` Critical: `amount`, `unit_amount`, `price`, `quantity`, `currency` or `discount` taken from the request body. A user edits the request and sets their own price.
- `PAY-02` High: non-atomic balance updates. Read-then-write on credits lets two parallel requests both succeed (double-spend).
- `PAY-03` Critical: payment webhooks without signature verification against the raw unparsed body.
- New skill `skills/payments-logic-auditor/SKILL.md`, covering server-side pricing authority, webhook idempotency against replay, and atomic conditional updates.

### Added - Backend Reliability domain

- `REL-01` unbounded queries without pagination, `REL-02` N+1 database loops, `REL-03` passwords/tokens/PII written to logs, `REL-04` outbound requests with no timeout.
- Reported at `MEDIUM` confidence by design: a pattern cannot know your data volume, so the Skeptic stage confirms against real table sizes.
- New skill `skills/backend-reliability-scale/SKILL.md`, also covering indexes, serverless connection exhaustion and failure behaviour.

### Added - Three more domain skills

- `skills/architecture-threat-model/SKILL.md`: trust boundaries, tenant isolation, Row-Level Security policy-by-policy, and a STRIDE pass. Runs before line-level hunting so findings can be ranked by what an attacker gains.
- `skills/ai-llm-security-shield/SKILL.md`: prompt injection, denial-of-wallet, unsafe model-output handling, agent tool scope, and RAG tenant isolation.
- `skills/production-preflight-gate/SKILL.md`: live HTTP posture, exposed artifacts, container and CI hardening, privacy and account-deletion readiness, and the `READY` / `READY WITH KNOWN LIMITATIONS` / `NOT READY` verdict.

### Changed

- Master orchestrator is now a 10-stage protocol across the 8 domains.
- `AGENTS.md` gains always-on payment and reliability rules, so these are prevented while code is written rather than only caught at audit time.
- Schema: `domain` enum extended with `PAYMENTS` and `RELIABILITY`; rule-id pattern extended for `PAY` and `REL`; `summary_counts` gains `PAYMENTS_TOTAL` and `RELIABILITY_TOTAL`.
- `.aegis-ignore` accepts the new rule prefixes.
- Tests 25 -> 30, including a negative suite proving atomic SQL, paginated queries and `AbortSignal.timeout()` produce zero findings.

### Fixed

- `run_git()` decoded git output using the locale codec, which is cp1252 on Windows. Any non-ASCII byte raised `UnicodeDecodeError` and silently killed the entire `--git-history` stage, so it appeared to find nothing rather than failing.
- `.gitignore` hardened against `.env` files, private keys, keystores, service-account JSON, `.npmrc`/`.netrc`/`.pypirc` and build output.

## [2.0.0] - 2026-10-18

Closes the gap between "my source looks fine" and "what I ship is safe". Everything from 1.0.0 is retained; all previous flags still behave identically.

### Added - Shipped-Artifact Verification (`--artifact`)

- `ART-01` **cross-reference leak detection**: because the scanner reads your source first, it knows which credential to hunt for in the build output. The one finding in the framework confirmed by construction rather than inferred.
- `ART-02` source maps in build output, raised when `sourcesContent` ships original code.
- `ART-03` provider-format credentials found directly in shipped JS/HTML/JSON.
- `.apk`/`.aab`/`.ipa` inspection as a zip, with no external tooling: `ART-11` unsigned package, `ART-12` bundled `.env`/keystore/service-account files, `ART-13` cleartext traffic, `ART-14` debuggable release, `ART-15` credentials in packaged assets.
- New skill `skills/artifact-leak-hunter/SKILL.md`, including the publishable-vs-server-only classification step and the rotation-first remediation order.

### Added - Data-Flow (Taint) Analysis

- `FLOW-01`–`FLOW-05`: request input traced through assignments into SQL, shell/code execution, HTML rendering, server-side fetch (SSRF) and filesystem paths.
- Sanitiser awareness: a value passing `zod.parse`, `parseInt`, `encodeURIComponent`, an allowlist check or similar is treated as clean and not reported.
- Reported at `MEDIUM` confidence by design - the tracker is function-scoped, so the Skeptic stage confirms before anything is called CONFIRMED.

### Added - High-Precision Secret Detection

- Provider key formats: AWS, Stripe, GitHub, Google, Slack, OpenAI, Anthropic, SendGrid, Twilio, Razorpay, Mailgun, npm, PEM private keys, Supabase service-role JWTs, and database URLs with inline credentials.
- Shannon entropy scoring for secret-named variables holding random values.
- Placeholder rejection for `your-api-key-here`, `changeme`, `${process.env.X}`, `<insert-key>` and AWS's own documentation key `AKIAIOSFODNN7EXAMPLE`.
- **All credentials are redacted in all outputs** to first 6 / last 4 characters, so reports are safe to commit, attach to an issue or hand to an agent.

### Added - Git History Forensics (`--git-history`)

- `HIST-01`: credentials committed at any point, reported with commit hash, author and date, even when the file has since been deleted. Remediation states plainly that deleting the line does not help - only rotation does.

### Added - Supply Chain (`--deps`, `--sbom`)

- `DEP-01`: dependency vulnerabilities via the free OSV.dev batch API across npm, PyPI, crates.io and Go.
- CycloneDX 1.5 SBOM output.
- Severity is reported as MEDIUM with linked advisories, because the OSV batch endpoint returns advisory IDs without CVSS scores - grading them locally would be inventing a number.

### Added - Adoption On Real Codebases

- `--diff [REF]` scans only files changed against a ref, for pull requests.
- `--baseline` / `--write-baseline` accept pre-existing findings so a team sees only what they just introduced.
- `.aegis-ignore` supporting rule ids and path globs.
- Stable 16-character fingerprints that survive line-number shifts.
- `--fail-on <level>` for any severity threshold, and `--quiet` for one-line CI output.
- `--offline` to guarantee no network request is made.

### Added - Output Formats

- `--sarif`: SARIF 2.1.0 with `security-severity` and `partialFingerprints`, so findings appear natively in GitHub's Security tab.
- Report gains `stages` and `dependencies_parsed`; `summary_counts` gains per-domain totals and `SUPPRESSED`; every finding gains `fingerprint`.
- Schema updated: new domains `SUPPLY_CHAIN`, `ARTIFACT`, `HISTORY`, `DATAFLOW`; rule-id pattern extended for `DEP`/`ART`/`HIST`/`FLOW`.

### Fixed

- **Secret-named variables in `SCREAMING_SNAKE_CASE` were never matched.** `_` is a word character, so `secret` could not match inside `NEXT_PUBLIC_API_SECRET`. Separators are now normalised before the keyword test. This silently disabled client-exposure detection for the most common naming convention in the ecosystem.
- Dependency findings all collapsed into one, because they shared the same `file:line` dedupe key.
- Data-flow findings named the variable being assigned rather than the one carrying the taint.
- Build artifact paths are resolved before `relative_to`, so they display as repository-relative.
- `.env` and config files inside a mobile package are now swept for credentials, not merely reported as present.

### Changed

- Test suite expanded from 1 test to 25, covering secret precision and false-positive rejection, taint tracing and sanitiser handling, baseline and ignore behaviour, artifact cross-referencing, mobile package inspection, SARIF and SBOM shape, and scoring.
- CI additionally verifies the deep stages end to end, that reports never contain an unredacted credential, that the release gate exits 1, and that baseline adoption works.

## [1.0.0] - 2026-10-18

Initial public release.

### Added - Deterministic Scanner

- `scripts/aegis_scan.py`: zero-dependency Python 3.8+ static scanner with 40+ rules spanning `LOW` to `CRITICAL`.
- **Security rules `SEC-01`-`SEC-17`**: client-exposed secrets; Supabase/Postgres Row-Level Security and permissive Firebase rules; unprotected API routes and `"use server"` Server Actions; IDOR and broken ownership scoping; payment and checkout price tampering; unverified webhook signatures; SQL and raw-query injection; command and code injection; XSS via `dangerouslySetInnerHTML`, `v-html` and `innerHTML`; JWT `decode()`-without-`verify()` and `localStorage` token storage; SSRF; AI/LLM prompt-injection and unbounded token spend; wildcard CORS and CSRF; missing rate limiting; insecure file uploads; supply-chain and slopsquatting risk; live deployment posture.
- **UI/UX rules `UX-01`-`UX-10`**: dead buttons and `href="#"` placeholder links; missing async `disabled`/loading states (double-submit); silent `catch {}` blocks; missing empty and skeleton states; mobile viewport overflow traps; form label and validation gaps; icon-button and image accessibility; focus-ring suppression; unfinished AI placeholder content; z-index collisions and modal scroll-lock leaks.
- Tech-stack fingerprinting for Next.js, React, Vue, Svelte, Supabase, Firebase, Prisma, Stripe, Razorpay, FastAPI, Express, Tailwind, and major AI SDKs.
- Passive, read-only live deployment checks via `--url` (CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, wildcard CORS, and exposed `/.env` and `/.git/config`).
- 0-100 **Release Readiness Score** with a `READY TO PUBLISH` / `NEEDS REVIEW` / `BLOCKED` verdict.
- `--json`, `--output`, and `--fail-on-high` flags for CI/CD and agent ingestion.

### Added - Adversarial Agent Loop

- `skills/vibe-aegis/SKILL.md`: master 6-stage orchestrator (`Recon -> Security Hunter + UI/UX Hunter -> Adversarial Skeptic -> Evidence Referee -> Guarded Fixer`).
- `skills/security-redteam-loop/SKILL.md`: deep Low-to-Critical auditor across 5 trust boundaries using STRIDE and OWASP Top 10.
- `skills/ui-ux-bug-finder/SKILL.md`: 5-point UI/UX protocol including live `agent-browser` / Playwright DOM inspection at mobile and desktop viewports.
- Stage 6 Guarded Fixer: patches on a dedicated `aegis/hardening-<timestamp>` branch and auto-reverts any fix that breaks the build or tests.

### Added - Universal Agent Support

- `install.sh`: one-command installer for Claude Code, VS Code (GitHub Copilot), OpenAI Codex, Cursor, Windsurf, Cline, and Gemini CLI, with `--global` and per-agent modes.
- `bin/vibe-aegis.mjs`: `npx vibe-aegis setup | scan` Node 18+ CLI wrapper.
- `adapters/`: Claude `/aegis` slash command, Copilot workspace instructions and prompt file, VS Code task, Cursor `.mdc` rule, and a ready-to-use GitHub Actions pre-merge gate.
- `AGENTS.md` and `CLAUDE.md`: always-on prevention rules applied while code is being written, not only at audit time.

### Added - AI-First Discoverability

- `llms.txt` and `llms-full.txt` at the repository root, so any AI agent can learn and execute the entire framework from a single raw URL fetch.
- `.claude-plugin/marketplace.json` for `/plugin marketplace add` installation in Claude Code and OpenAI Codex.
- `skills/<name>/agents/openai.yaml` workspace skill metadata for OpenAI/Codex.
- `schemas/scan-report.schema.json`: strict JSON Schema (Draft 2020-12) for deterministic validation of `.aegis/scan-report.json`.
- `docs/prompts/`: three copy-paste bootstrap prompt recipes for full audit, security red-team, and UI/UX browser QA.

### Added - Project Governance

- `SECURITY.md` defining the defensive scope, the passive read-only behaviour of `--url`, and private vulnerability reporting.
- `CONTRIBUTING.md` covering how to add `SEC-XX` and `UX-XX` rules with tests.
- `.github/workflows/ci.yml` running the unit test suite and an installer smoke test on every push and pull request.

### Fixed

- Added the missing `---` YAML frontmatter delimiters to all three `SKILL.md` files. Without them Claude Code and Codex parse the `name:` and `description:` fields as body text and fail to register the skills.
