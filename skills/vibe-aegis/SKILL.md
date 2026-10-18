---
name: vibe-aegis
description: Master 6-stage pre-launch safeguard loop for vibe-coded apps. Orchestrates deterministic triage, deep Low-to-Critical security auditing, UI/UX design & browser bug finding, adversarial false-positive filtering (Skeptic), evidence grading (Referee), and guarded branch auto-fixing. Use whenever the user asks to audit, secure, test UI/UX, or prepare an app for production.
---

# Vibe Aegis — Master 6-Stage Pre-Launch Audit & Hardening Loop

Run a complete, adversarial pre-publication audit across both **Application Security (Low to Critical)** and **UI/UX Design & Functional Completeness** before any vibe-coded application ships to production.

## When to Trigger

- The user types `/aegis`, `/aegis-audit`, or `$vibe-aegis`
- The user asks to "check if my app is safe to publish", "find security holes and UI/UX bugs", "run a pre-launch audit", or "harden this vibe-coded app"

## 6-Stage Execution Protocol

### Stage 1: Deterministic Recon & Triage (`aegis_scan.py`)

Run the bundled zero-dependency scanner first so you never waste context guessing the stack:

```bash
python3 .aegis/scripts/aegis_scan.py . --output .aegis/scan-report.json
# Fallback if running directly from the vibe-aegis repo:
python3 scripts/aegis_scan.py . --output .aegis/scan-report.json
```

Read `.aegis/scan-report.json` to extract:
1. Detected frameworks, database/BaaS, auth libraries, payment SDKs, UI libraries, and AI SDKs.
2. All deterministic `SECURITY` and `UI_UX` candidate findings.
3. Map all public entry points (`app/api/**`, `pages/api/**`, `"use server"` actions, webhooks, public routes, and database schema/migrations).

### Stage 2: Deep Security Red-Team Hunter (Low -> Critical)

Load and follow the instructions in `skills/security-redteam-loop/SKILL.md` (or `.claude/skills/security-redteam-loop/SKILL.md`).
- Trace data flows across files—do not stop at single-line regex matches.
- Verify authentication, ownership scoping (IDOR), Row-Level Security (RLS), payment price integrity, webhook signatures, SSRF, SQLi/XSS/CSRF, JWT verification, rate limits, and LLM token/cost caps.
- Record each candidate finding with exact `file:line`, concrete trigger path, STRIDE category, and CWE ID.

### Stage 3: Deep UI/UX Design & Browser QA Hunter

Load and follow the instructions in `skills/ui-ux-bug-finder/SKILL.md` (or `.claude/skills/ui-ux-bug-finder/SKILL.md`).
- Inspect every user-facing page, form, modal, and navigation component.
- Check for dead buttons (`href="#"`, empty `onClick`), missing async `disabled`/`loading` states (double-submit bugs), missing empty/error states, mobile viewport overflow (`320px–375px`), z-index collisions, and WCAG 2.2 AA accessibility issues.
- If a local dev server is running and `agent-browser` or Playwright is installed, open the live app and inspect both desktop (`1440x900`) and mobile (`375x812`) viewports plus the accessibility tree (`agent-browser snapshot`).

### Stage 4: Adversarial Skeptic (False-Positive Elimination)

Switch perspective to the **Skeptic**. For every candidate finding from Stages 1–3:
- Attempt to **disprove** the claim by checking upstream middleware (`middleware.ts`), layout auth guards, ORM automatic parameterization, framework auto-escaping, or parent responsive containers.
- If a defence completely blocks the trigger, mark the finding `DISMISSED` and cite the exact defensive `file:line`.

### Stage 5: Evidence Referee & Release Readiness Report

Switch perspective to the **Referee**. Evaluate all surviving claims and write `.aegis/AUDIT_REPORT.md` containing:
1. **Release Readiness Score (0–100)** and Release Gate Status (`READY TO PUBLISH` vs `BLOCKED`).
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
