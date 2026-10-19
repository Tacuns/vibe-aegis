description: Run the Vibe Aegis pre-launch Security & UI/UX audit loop on this repository
argument-hint: [--fix] [--url <live-url>]

Execute the **Vibe Aegis Pre-Launch Safeguard Loop** for this repository - the condensed
form of the 10-stage protocol in `.claude/skills/vibe-aegis/SKILL.md`, which is the
authoritative description.
Arguments provided by user: `$ARGUMENTS`

1. **Stage 1 (Deterministic Recon)**:
   Run `python3 .aegis/scripts/aegis_scan.py . --output .aegis/scan-report.json` (or `python3 scripts/aegis_scan.py . --output .aegis/scan-report.json`). If `--url` was passed in `$ARGUMENTS`, include `--url <live-url>`.
2. **Stage 2 (Security Red-Team Hunter)**:
   Apply `.claude/skills/security-redteam-loop/SKILL.md` to trace all entry points, auth boundaries, database RLS/queries, payments/webhooks, and AI/LLM endpoints from Low to Critical severity.
3. **Stage 3 (UI/UX Design & Browser Bug Finder)**:
   Apply `.claude/skills/ui-ux-bug-finder/SKILL.md` to audit all pages/components for dead controls, missing async loading/empty/error states, mobile overflow traps, and WCAG 2.2 AA accessibility bugs.
4. **Stage 4 (Adversarial Skeptic)**:
   Challenge every candidate finding from Stages 1–3 against existing middleware, framework escaping, and layout containers to filter out false positives.
5. **Stage 5 (Evidence Referee & Report)**:
   Write the complete, severity-ranked audit scorecard and remediation plan to `.aegis/AUDIT_REPORT.md` with a 0–100 Release Readiness Score.
6. **Stage 6 (Guarded Fixer)**:
   If `--fix` is present in `$ARGUMENTS`, create a branch `aegis/hardening`, apply surgical fixes for all `CONFIRMED` findings, and re-run `aegis_scan.py` + project build/tests to verify zero regressions. Otherwise, present the report summary and ask if the user wants to run the automated fix loop.
