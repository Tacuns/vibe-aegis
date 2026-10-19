# Prompt 01 - Full Pre-Launch Audit (Security + UI/UX)

Runs the complete 10-stage adversarial loop and writes `.aegis/AUDIT_REPORT.md` with a 0-100 Release Readiness Score.

Works in: **Claude Code, VS Code Copilot Chat, OpenAI Codex, Cursor, Windsurf, Cline, Gemini CLI, ChatGPT, Claude, Gemini, Perplexity, Grok.**

---

## The 2-Line Prompt (No Clone Needed)

Paste this into any AI chat or terminal agent while your project is open:

```text
Read https://raw.githubusercontent.com/Tacuns/vibe-aegis/main/llms-full.txt
Then run the complete Vibe Aegis 10-stage pre-launch audit on this project and write .aegis/AUDIT_REPORT.md.
```

If your agent cannot fetch URLs, clone first and point it at the local copy:

```bash
git clone https://github.com/Tacuns/vibe-aegis.git /tmp/vibe-aegis
bash /tmp/vibe-aegis/install.sh --target . --agent all
```

Then type `/aegis` (Claude Code), `/aegis-audit` (VS Code Copilot Chat), or `$vibe-aegis` (Codex).

---

## The Full Explicit Prompt

Use this when you want to spell out every stage rather than rely on the skill files:

```text
Act as the Vibe Aegis pre-launch audit system. Run all six stages in order on this repository and do not skip any stage.

STAGE 1 - DETERMINISTIC RECON
Run: python3 .aegis/scripts/aegis_scan.py . --json --output .aegis/scan-report.json
(If .aegis/ does not exist yet, run: python3 scripts/aegis_scan.py . --json --output .aegis/scan-report.json)
Read the report and summarise: detected frameworks, database/BaaS, auth library, payment SDK, UI library, AI SDK, total files scanned, and the deterministic candidate findings grouped by severity.
Then map every public entry point yourself: app/api/**, pages/api/**, "use server" actions, webhook handlers, public pages, and all database schema or migration files.

STAGE 2 - SECURITY HUNTER (Low to Critical)
Audit across five trust boundaries. For each candidate, trace the data flow across files - never stop at a single-line regex match.
1. Secrets, environment and supply chain: private keys in NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_/REACT_APP_ variables, committed .env or .pem files, hardcoded bearer tokens, unpinned or hallucinated package names.
2. Auth, session and access control: every route verifies the session server-side; every query taking an id/userId/orgId/slug filters by the authenticated owner (IDOR); JWTs use verify() not decode(); tokens live in HttpOnly Secure SameSite cookies, not localStorage.
3. Database and BaaS: every public-schema table runs ENABLE ROW LEVEL SECURITY with granular policies; flag USING (true) on writes or sensitive tables; flag Firebase "allow read, write: if true"; flag raw SQL interpolation and $queryRawUnsafe.
4. Payments and business logic: prices, plan IDs and trial eligibility resolved server-side from trusted records, never from the request body; webhooks verify signatures against the raw unparsed body and enforce idempotency on event.id; credit and quota updates are atomic (no TOCTOU race).
5. AI/LLM, network and deployment posture: LLM endpoints require auth, per-user rate limits and explicit max_tokens caps, and separate system instructions from untrusted user data; URL-fetching endpoints block private IPs and the cloud metadata service 169.254.169.254; production sets CSP, HSTS, X-Frame-Options, X-Content-Type-Options and strict CORS.
For each candidate record: exact file:line, the concrete trigger path an attacker would use, the STRIDE category, and the CWE ID.

STAGE 3 - UI/UX HUNTER
1. Dead controls: buttons with no onClick and no type="submit", href="#", handlers that are () => {} or only console.log; modals missing a close button, Escape dismissal, or body scroll-lock cleanup on unmount.
2. Async state matrix - every fetch or mutation must implement all four states: Loading (skeleton/spinner, and disabled={isLoading} on the submit control), Empty (helpful message plus a call to action when length === 0), Error (visible toast, banner or inline message with retry - never a silent catch {}), and Success (toast, redirect or optimistic update).
3. Responsive layout at 375x812, 768x1024 and 1440x900: flag hardcoded widths like w-[600px] or width: 800px, wide tables missing overflow-x-auto, 100vw containers causing horizontal scroll, and touch targets under 44x44px.
4. Accessibility, WCAG 2.2 AA: every input/select/textarea has a label or aria-label; every icon-only button has an aria-label; every informative img has alt text; focus rings are never removed without a focus-visible replacement; check low-contrast text pairings.
5. If a dev server is running and agent-browser or Playwright is available, open the app, screenshot both mobile and desktop viewports, and inspect the accessibility tree and console for errors.

STAGE 4 - ADVERSARIAL SKEPTIC
Now argue against yourself. For every candidate from Stages 1-3, actively try to DISPROVE it:
- Is there a middleware.ts, layout guard or route group that already authenticates this path?
- Does the ORM already parameterise this query?
- Does the framework already auto-escape this output?
- Does a parent container already constrain this width or handle the overflow?
- Does enforced RLS already scope this query even though the application code does not?
If a defence fully blocks the trigger, mark the finding DISMISSED and cite the exact defensive file:line. Dismiss anything speculative with no reachable trigger.

STAGE 5 - EVIDENCE REFEREE
Write .aegis/AUDIT_REPORT.md containing:
1. Release Readiness Score (0-100) and gate status: READY TO PUBLISH or BLOCKED. Score 100, minus 25 per CRITICAL, 10 per HIGH, 4 per MEDIUM, 1 per LOW. BLOCKED if any CRITICAL or HIGH remains open.
2. Confirmed security findings table ordered CRITICAL to LOW, each with file:line, CWE, CVSS 3.1 estimate, the trigger explanation, and the exact code fix.
3. Confirmed UI/UX and accessibility findings table ordered HIGH to LOW, each with component location, the user-visible impact, the WCAG criterion where relevant, and the exact code fix.
4. Dismissed false positives log explaining why each is already safe, with the defensive file:line.
Mark anything you could not verify as MANUAL_REVIEW rather than guessing. Never invent a finding, a CWE ID or a line number.

STAGE 6 - GUARDED FIXER (only if I say "fix")
Do not edit any source file unless I explicitly approve. When I do:
1. git checkout -b aegis/hardening-$(date +%Y%m%d-%H%M)
2. Patch one CONFIRMED finding at a time in priority order, smallest possible change.
3. After each patch re-run the scanner plus the project build and test command.
4. If a patch breaks the build or tests, revert that commit immediately and mark the item MANUAL_REVIEW.
5. Repeat until the score is >= 90/100 with zero open CRITICAL or HIGH findings.
```

---

## Expected Output

| Artifact | Contents |
| :--- | :--- |
| `.aegis/scan-report.json` | Deterministic machine-readable findings, validated by `schemas/scan-report.schema.json` |
| `.aegis/AUDIT_REPORT.md` | Confirmed findings, dismissed false positives, and the Release Readiness Score |

## Scope Reminder

Only run this against applications you own or are authorized to test. See [`SECURITY.md`](../../SECURITY.md).
