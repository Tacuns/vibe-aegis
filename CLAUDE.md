# 🛡️ Vibe Aegis — Claude Code Instructions

This repository uses **Vibe Aegis** for continuous security hardening and UI/UX quality assurance.

- Read and follow all engineering rules in `@AGENTS.md`.
- Available slash command: `/aegis` (defined in `.claude/commands/aegis.md`)
- Available skills:
  - `.claude/skills/vibe-aegis/SKILL.md` — Master 6-stage adversarial audit orchestrator
  - `.claude/skills/security-redteam-loop/SKILL.md` — Deep Low-to-Critical security vulnerability hunter
  - `.claude/skills/ui-ux-bug-finder/SKILL.md` — Deep UI/UX design, state completeness, responsive & accessibility bug hunter
  - `.claude/skills/artifact-leak-hunter/SKILL.md` — Verify what the build actually ships (bundles, source maps, .apk/.aab/.ipa)
- Deterministic scanner: `python3 .aegis/scripts/aegis_scan.py . --all` (or `python3 scripts/aegis_scan.py .`)
