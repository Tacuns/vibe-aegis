# Changelog

All notable changes to Vibe Aegis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
