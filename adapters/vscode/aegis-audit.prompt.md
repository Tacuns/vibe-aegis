mode: agent
description: Run the Vibe Aegis 6-Stage Security & UI/UX Audit Loop

Run a complete pre-launch **Vibe Aegis** audit on this workspace:
1. Run `python3 .aegis/scripts/aegis_scan.py . --output .aegis/scan-report.json` in the terminal.
2. Read `.aegis/scan-report.json` and follow `.github/skills/vibe-aegis/SKILL.md` through all 6 stages (`Recon` -> `Security Hunter` -> `UI/UX Hunter` -> `Skeptic` -> `Referee` -> `Guarded Fixer`).
3. Save the full audit report and Release Readiness Score (0–100) to `.aegis/AUDIT_REPORT.md`.
