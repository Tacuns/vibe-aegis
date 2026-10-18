# Prompt 03 - Deep UI/UX Design & Browser QA Audit

A frontend-only deep audit. Use this when the app works but feels broken: dead buttons, spinners that never stop, blank screens, horizontal scroll on phones, or keyboard users getting stuck.

Works in: **Claude Code, VS Code Copilot Chat, OpenAI Codex, Cursor, Windsurf, Cline, Gemini CLI, ChatGPT, Claude, Gemini, Perplexity, Grok.**

---

## The 2-Line Prompt (No Clone Needed)

```text
Read https://raw.githubusercontent.com/Tacuns/vibe-aegis/main/llms-full.txt
Then run the Vibe Aegis ui-ux-bug-finder skill on this project: find every dead control, missing async state, mobile overflow trap and WCAG 2.2 AA failure, and write .aegis/UIUX_REPORT.md.
```

---

## The Full Explicit Prompt

```text
Act as the Vibe Aegis UI/UX Design & Browser QA Bug Finder. Audit this frontend for the visual, interaction, state-management and accessibility bugs that AI code generation routinely leaves behind.

First run: python3 .aegis/scripts/aegis_scan.py . --json --output .aegis/scan-report.json and read the UI_UX domain findings.
Then inspect every user-facing page, route, form, modal, drawer, table and navigation component yourself.

1. INTERACTIVE WIRING AND DEAD CONTROLS (HIGH)
- <button> elements with no onClick and no type="submit".
- <a href="#"> placeholder links that navigate nowhere.
- Stubbed handlers: onClick={() => {}}, onClick={() => console.log(...)}, or a TODO comment in place of the real call.
- Forms with no onSubmit, or a submit handler missing preventDefault where it is needed.
- Every modal, drawer and dialog: working close button, Escape key dismissal, click-outside-to-close, and cleanup of document.body.style.overflow on unmount (otherwise the page stays scroll-locked after close).

2. ASYNC STATE MATRIX COMPLETENESS (HIGH / MEDIUM)
For every component that fetches or mutates data, confirm ALL FOUR states exist:
- LOADING: a skeleton or spinner is rendered, AND the submit or action button sets disabled={isLoading}. A button that stays enabled during an async call causes double submissions - duplicate records and duplicate payment charges. Flag every one.
- EMPTY: when a list or query returns zero items, a helpful empty state with a call to action is rendered instead of a blank void. Check every .map() render for a length === 0 branch.
- ERROR: failures surface to the user via a toast, banner or inline field error with a retry path. Flag every catch block that is empty, or that only calls console.error/console.log, as a silent failure.
- SUCCESS: mutations give clear confirmation - toast, redirect, or an optimistic UI update.

3. RESPONSIVE LAYOUT AND TOUCH ERGONOMICS (MEDIUM)
Evaluate at Mobile 375x812, Tablet 768x1024 and Desktop 1440x900.
- Hardcoded pixel widths that cannot shrink: w-[600px], min-w-[500px], width: 800px, and 100vw containers (which overflow once a scrollbar appears).
- Wide tables and code blocks without an overflow-x-auto wrapper.
- Touch targets under 44x44px, and controls overlapping fixed bottom bars or floating action buttons.
- Text that truncates or overlaps at 320px width.

4. ACCESSIBILITY - WCAG 2.2 AA (MEDIUM / LOW)
- Every <input>, <select> and <textarea> is linked to a visible <label for=...> or has an aria-label (WCAG 3.3.2).
- Every icon-only <button> has an aria-label (WCAG 4.1.2); every informative <img> has descriptive alt text, decorative images use alt="" (WCAG 1.1.1).
- Focus indicators are never stripped: flag outline-none or outline: 0 without a focus-visible:ring replacement (WCAG 2.4.7).
- Colour contrast at least 4.5:1 for body text (WCAG 1.4.3) - flag low-contrast pairings such as text-gray-300 on white or text-gray-600 on a dark background.
- Logical Tab order; modals trap focus while open and restore it to the trigger on close.
- Interactive <div> or <span> elements without role, tabIndex and keyboard handlers.

5. UNFINISHED AI PLACEHOLDERS IN PRODUCTION VIEWS (HIGH)
- Leftover "Lorem ipsum", "TODO", "placeholder", "john@example.com", "example.com" links, or fabricated metrics such as a hardcoded "$99,999" or "1,234 users" presented as real data.

6. LIVE BROWSER DOM INSPECTION (if a dev server is running and agent-browser or Playwright is installed)
agent-browser open http://localhost:3000
agent-browser set viewport 375 812
agent-browser snapshot
agent-browser screenshot --annotate .aegis/mobile-audit.png
agent-browser set viewport 1440 900
agent-browser screenshot --annotate .aegis/desktop-audit.png
agent-browser close
Inspect the accessibility tree and screenshots for overlapping elements, clipped text, horizontal scrollbars, and console errors.

SKEPTIC STAGE - before reporting, try to disprove each finding. Does a parent container already constrain that width? Is the overflow already handled by an ancestor? Is the label provided by an aria-labelledby elsewhere? Is the button genuinely decorative? Does a global CSS rule already restore the focus ring? If so, mark it DISMISSED and cite the file:line that makes it safe.

REFEREE STAGE - write .aegis/UIUX_REPORT.md with:
- A findings table ordered HIGH -> MEDIUM -> LOW. Each row: rule ID, component file:line, what the user actually experiences, the WCAG success criterion where applicable, and the exact corrected JSX/CSS.
- A dismissed false positives log.
- A UI/UX readiness summary and a go / no-go verdict.

Rules: never invent a finding or a line number. If you cannot verify something without running the app, label it MANUAL_REVIEW and say what is needed. Do not modify any file unless I explicitly ask you to fix.
```

---

## Why These Bugs Matter

| Bug | What the user experiences |
| :--- | :--- |
| Button without `disabled={isLoading}` | Taps twice on a slow connection, gets charged twice |
| Empty `catch {}` | Submits a form, nothing happens, no error shown, assumes the app is broken |
| Missing empty state | Opens a new account and sees a blank white screen |
| `w-[600px]` on mobile | Page scrolls sideways, buttons sit off-screen |
| `outline-none` with no replacement | Keyboard and screen-reader users cannot tell where they are |

## Scope Reminder

Only audit applications you own or are authorized to test. See [`SECURITY.md`](../../SECURITY.md).
