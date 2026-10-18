# Changelog

All notable changes to Vibe Aegis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
