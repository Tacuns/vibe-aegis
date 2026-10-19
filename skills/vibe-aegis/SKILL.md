---
name: vibe-aegis
description: Master 10-stage First-to-Last full-stack safeguard loop for vibe-coded apps across 8 domains. Orchestrates deterministic triage, deep Low-to-Critical security auditing, UI/UX design & browser bug finding, adversarial false-positive filtering (Skeptic), evidence grading (Referee), and guarded branch auto-fixing. Use whenever the user asks to audit, secure, test UI/UX, or prepare an app for production.
---

# Vibe Aegis — Master 10-Stage Pre-Launch Audit & Hardening Loop

Run a complete, adversarial pre-publication audit across both **Application Security (Low to Critical)** and **UI/UX Design & Functional Completeness** before any vibe-coded application ships to production.

## When to Trigger

- The user types `/aegis`, `/aegis-audit`, or `$vibe-aegis`
- The user asks to "check if my app is safe to publish", "find security holes and UI/UX bugs", "run a pre-launch audit", or "harden this vibe-coded app"

## The 8 Domains

| # | Domain | Skill |
| :--- | :--- | :--- |
| 1 | Architecture, tenancy & RLS | `architecture-threat-model` |
| 2 | Application security | `security-redteam-loop` |
| 3 | Payments & business logic | `payments-logic-auditor` |
| 4 | AI / LLM | `ai-llm-security-shield` |
| 5 | Backend reliability & scale | `backend-reliability-scale` |
| 6 | UI/UX & accessibility | `ui-ux-bug-finder` |
| 7 | Shipped artifacts | `artifact-leak-hunter` |
| 8 | Production readiness | `production-preflight-gate` |

## 10-Stage Execution Protocol

### Stage 1: Deterministic Recon & Triage (`aegis_scan.py`)

Run the bundled zero-dependency scanner first so you never waste context guessing the stack:

```bash
# Full sweep: source + data-flow + git history + dependencies + build artifacts
python3 .aegis/scripts/aegis_scan.py . --all --output .aegis/scan-report.json

# Release gate: every stage must run, and any CRITICAL/HIGH fails it
python3 .aegis/scripts/aegis_scan.py . --profile release --output .aegis/scan-report.json

# Fallback if running directly from the vibe-aegis repo:
python3 scripts/aegis_scan.py . --all --output .aegis/scan-report.json

# Reviewing a pull request? Scan only what changed, and suppress pre-existing noise:
python3 .aegis/scripts/aegis_scan.py . --diff origin/main --baseline .aegis/baseline.json
```

The scanner reports ten domains: `SECURITY`, `UI_UX`, `DATAFLOW` (request input traced to a
dangerous sink), `PAYMENTS`, `RELIABILITY`, `SUPPLY_CHAIN` (known dependency vulnerabilities),
`ARTIFACT` (what the build actually ships), `HISTORY` (credentials committed at any point),
`EXTERNAL` (findings imported from an installed engine via `--engine`), and `COVERAGE`
(something that was not examined - read `skipped_checks`, never treat it as clean).
Credentials in the report are always redacted, so `.aegis/scan-report.json` is safe to
attach to an issue.

In Claude Code, also run the built-in `/security-review` on the branch's pending changes. It
is an AI review of intent and complements the scanner's deterministic rules; report its
findings through the same Skeptic and Referee stages.

Read `.aegis/scan-report.json` to extract:
1. Detected frameworks, database/BaaS, auth libraries, payment SDKs, UI libraries, and AI SDKs.
2. All deterministic `SECURITY` and `UI_UX` candidate findings.
3. Map all public entry points (`app/api/**`, `pages/api/**`, `"use server"` actions, webhooks, public routes, and database schema/migrations).

### Stage 1.5: Architecture, Tenancy & Threat Model

Load `skills/architecture-threat-model/SKILL.md`. Map entry points, trust boundaries, assets and
actors, verify tenant isolation and Row-Level Security, and write `.aegis/THREAT_MODEL.md`.

Do this **before** line-level hunting. Without the map, a missing `aria-label` and a missing tenant
filter look like two findings of similar size. They are not.

### Stage 2: Deep Security Red-Team Hunter (Low -> Critical)

Load and follow the instructions in `skills/security-redteam-loop/SKILL.md` (or `.claude/skills/security-redteam-loop/SKILL.md`).
- Trace data flows across files—do not stop at single-line regex matches.
- Verify authentication, ownership scoping (IDOR), Row-Level Security (RLS), payment price integrity, webhook signatures, SSRF, SQLi/XSS/CSRF, JWT verification, rate limits, and LLM token/cost caps.
- Record each candidate finding with exact `file:line`, concrete trigger path, STRIDE category, and CWE ID.

### Stage 2.5: Payments, Webhooks & Race Conditions

Load `skills/payments-logic-auditor/SKILL.md`. Security bugs leak data; payment bugs leak money
while the app appears to work. Check server-side pricing authority (`PAY-01`), webhook signature
verification and idempotency (`PAY-03`), and atomic balance updates (`PAY-02`).

### Stage 2.6: AI / LLM Security & Spend

Load `skills/ai-llm-security-shield/SKILL.md`. Confirm every model call has authentication, rate
limits, an input cap and an explicit `max_tokens`. Map every untrusted text source reaching a
prompt, follow model output to its sinks, and state the blast radius of a successful injection.

### Stage 2.7: Backend Reliability & Scale

Load `skills/backend-reliability-scale/SKILL.md`. Find the failures that only appear under real
traffic: unbounded queries, N+1 loops, missing indexes, serverless connection exhaustion, missing
timeouts, and personal data written to logs.

### Stage 3: Deep UI/UX Design & Browser QA Hunter

Load and follow the instructions in `skills/ui-ux-bug-finder/SKILL.md` (or `.claude/skills/ui-ux-bug-finder/SKILL.md`).
- Inspect every user-facing page, form, modal, and navigation component.
- Check for dead buttons (`href="#"`, empty `onClick`), missing async `disabled`/`loading` states (double-submit bugs), missing empty/error states, mobile viewport overflow (`320px–375px`), z-index collisions, and WCAG 2.2 AA accessibility issues.
- If a local dev server is running and `agent-browser` or Playwright is installed, open the live app and inspect both desktop (`1440x900`) and mobile (`375x812`) viewports plus the accessibility tree (`agent-browser snapshot`).

### Stage 3.5: Shipped-Artifact Verification

Load and follow `skills/artifact-leak-hunter/SKILL.md`. Source code says what you wrote; the
build output says what users receive. Cross-reference the credentials found in Stage 2 against
`dist/`, `.next/`, `build/` and any `.apk`/`.aab`/`.ipa`.

An `ART-01` finding is the one result in this framework that is **confirmed by construction** -
the same value is demonstrably present in both the source and the shipped bundle. Never downgrade
it, and always give the rotation-first remediation order.

### Stage 4: Adversarial Skeptic (False-Positive Elimination)

Switch perspective to the **Skeptic**. For every candidate finding from Stages 1–3:
- Attempt to **disprove** the claim by checking upstream middleware (`middleware.ts`), layout auth guards, ORM automatic parameterization, framework auto-escaping, or parent responsive containers.
- If a defence completely blocks the trigger, mark the finding `DISMISSED` and cite the exact defensive `file:line`.
- `DATAFLOW` findings are reported at `MEDIUM` confidence by design: the tracker works within a
  single function scope, so confirm the value really is attacker-controlled and really is unvalidated
  before promoting one to `CONFIRMED`.
- `ART-01` is the exception - it is already confirmed evidence and must not be dismissed.
- A publishable key (Supabase anon, Stripe publishable, Firebase web config) in a bundle is **not**
  a leak. Instead verify the protection it depends on: an anon key is only safe when Row-Level
  Security is enabled and enforced. Check that, and report on the RLS, not the key.

### Stage 5: Evidence Referee & Release Readiness Report

Switch perspective to the **Referee**. Evaluate all surviving claims and write `.aegis/AUDIT_REPORT.md` containing:
1. **Release Readiness Score (0–100)** and Release Gate Status. Gate status is the scanner's `release_verdict`. Report its leading word exactly - `BLOCKED`, `INCOMPLETE_SCAN`, `REVIEW_REQUIRED`, `STATIC_CHECKS_PASSED` or `RELEASE_AUDIT_PASSED` - and never call the app release-ready unless it is `RELEASE_AUDIT_PASSED` from `--profile release` with zero open `CRITICAL`/`HIGH`. `STATIC_CHECKS_PASSED` means only that the source checks which ran found nothing.
2. **Confirmed Security Findings Table** (ordered `CRITICAL` -> `HIGH` -> `MEDIUM` -> `LOW` with `file:line`, CWE, trigger explanation, and exact code fix).
3. **Confirmed UI/UX & Accessibility Findings Table** (ordered `HIGH` -> `MEDIUM` -> `LOW` with component location, visual/interaction impact, and exact code fix).
4. **Dismissed False Positives Log** (showing why each dismissed item is already safe).

### Stage 6: Guarded Auto-Fix & Verification Loop (When `--fix` or Remediation is Requested)

Never edit source files during a scan-only run without user approval. When the user requests `--fix` or approves remediation:
1. Create a dedicated git branch (`git checkout -b aegis/hardening-$(date +%Y%m%d-%H%M)`).
2. Apply minimal, surgical fixes for each `CONFIRMED` finding in priority order (`CRITICAL` -> `HIGH` -> `MEDIUM` -> `LOW`).
3. Re-run `python3 .aegis/scripts/aegis_scan.py .` and the project's native typecheck/test/build command (`npm run build`, `npm test`, or `pytest`).
4. If any patch introduces a build or test failure, immediately revert that commit and flag the item for `MANUAL_REVIEW`.
5. Repeat until the Release Readiness Score reaches `>= 90/100` with zero open `CRITICAL` or `HIGH` issues.

### Stage 7: Production Pre-Flight Gate

Load `skills/production-preflight-gate/SKILL.md`. The final go/no-go: live HTTP posture, exposed
artifacts, container and CI hardening, privacy and account-deletion readiness, and operational
readiness (rollback, monitoring, tested backups).

Issue exactly one verdict - `READY`, `READY WITH KNOWN LIMITATIONS` or `NOT READY` - and say for
each section what was checked, how, and what was **not** covered. Never issue `READY` because a
check was not run; mark it `NOT VERIFIED` and say so.
