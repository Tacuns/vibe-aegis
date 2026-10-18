# 🛡️ Vibe Aegis — Claude Code Instructions

This repository uses **Vibe Aegis** for continuous security hardening and UI/UX quality assurance.

- Read and follow all engineering rules in `@AGENTS.md`.
- Available slash command: `/aegis` (defined in `.claude/commands/aegis.md`)
- Available skills (8 domains + orchestrator):
  - `.claude/skills/vibe-aegis/SKILL.md` - Master 10-stage orchestrator
  - `.claude/skills/architecture-threat-model/SKILL.md` - Trust boundaries, tenancy, RLS, STRIDE
  - `.claude/skills/security-redteam-loop/SKILL.md` - Low-to-Critical security hunter
  - `.claude/skills/payments-logic-auditor/SKILL.md` - Pricing authority, webhooks, TOCTOU races
  - `.claude/skills/ai-llm-security-shield/SKILL.md` - Prompt injection, denial-of-wallet, tool scope
  - `.claude/skills/backend-reliability-scale/SKILL.md` - Unbounded queries, N+1, timeouts, PII logs
  - `.claude/skills/ui-ux-bug-finder/SKILL.md` - Dead controls, async states, responsive, WCAG 2.2 AA
  - `.claude/skills/artifact-leak-hunter/SKILL.md` - What the build actually ships (bundles, APK)
  - `.claude/skills/production-preflight-gate/SKILL.md` - Final go/no-go release verdict

- Deterministic scanner: `python3 .aegis/scripts/aegis_scan.py . --all` (or `python3 scripts/aegis_scan.py .`)
