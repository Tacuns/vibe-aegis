# 🛡️ Vibe Aegis — Always-On Security & UI/UX Engineering Rules

You are operating in a repository protected by **Vibe Aegis**. Every code change you write or review must satisfy both **Defensive Security Rules** and **UI/UX Production Quality Rules** before completion.

## 1. Non-Negotiable Security Rules (Prevent Vulnerabilities While Writing Code)

1. **Zero Client-Side Secrets (`SEC-01`)**:
   - Never place private API keys, database URLs, service-role keys, or webhook secrets in client-exposed variables (`NEXT_PUBLIC_*`, `VITE_*`, `EXPO_PUBLIC_*`, `REACT_APP_*`) or source files.
   - Keep `.env`, `.env.local`, and `.env.*` in `.gitignore`. Only commit `.env.example` with blank placeholders.
2. **Database Row-Level Security & Ownership Scoping (`SEC-02`, `SEC-04`)**:
   - Every Supabase/PostgreSQL table storing user or tenant data must run `ALTER TABLE <name> ENABLE ROW LEVEL SECURITY;` with explicit `SELECT`, `INSERT`, `UPDATE`, and `DELETE` policies scoped to `auth.uid()`. Never use `USING (true)` on non-public tables.
   - Every database read, update, or delete by ID must filter by the authenticated user's session ID or tenant ID (preventing IDOR).
3. **Server-Side Authentication & Input Validation (`SEC-03`, `SEC-07`, `SEC-08`)**:
   - Authenticate every API route, Server Action (`"use server"`), and RPC handler on the server. UI route hiding or client-side checks are never a security boundary.
   - Validate all external inputs (body, query, params, headers) using schema validators (e.g., `zod`, `pydantic`) before touching business logic.
   - Always use parameterized queries or safe ORM methods. Never interpolate strings into SQL, `$queryRawUnsafe`, or shell commands (`exec`, `subprocess` with `shell=True`).
4. **Payments, Webhooks & Rate Limiting (`SEC-05`, `SEC-06`, `SEC-12`, `SEC-14`)**:
   - Never trust client-submitted prices, discounts, or plan IDs; look up pricing on the server from trusted product tables.
   - Verify cryptographic signatures on every incoming webhook (`stripe.webhooks.constructEvent`, HMAC verification) using the raw request body.
   - Enforce rate limiting and token/cost budgets on login, OTP, password reset, email, and AI/LLM generation endpoints.
5. **Safe Output Rendering & Headers (`SEC-09`, `SEC-10`, `SEC-13`)**:
   - Never render unsanitized HTML via `dangerouslySetInnerHTML`, `v-html`, or `innerHTML`.
   - Store session tokens in `HttpOnly; Secure; SameSite=Lax/Strict` cookies—never in `localStorage`.

5. **Payments & Entitlements (`PAY-01`, `PAY-02`, `PAY-03`)**:
   - Never accept `amount`, `unit_amount`, `price`, `quantity`, `currency` or `discount` from the client. Take a plan or product ID and resolve the real price on the server.
   - Verify every webhook signature against the raw unparsed body, and store each processed `event.id` under a unique constraint so a replay cannot grant an entitlement twice.
   - Never read a balance, decide, then write it back. Use one atomic statement: `UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND balance >= $1`, and treat zero affected rows as insufficient funds.
6. **Reliability & Privacy (`REL-01` to `REL-04`)**:
   - Every list query needs an explicit maximum page size. `findMany()` with no `take` loads the whole table into memory.
   - Never `await` a database call inside a loop. Batch with `WHERE id IN (...)` or a join.
   - Attach `AbortSignal.timeout(10000)` to outbound `fetch()` so a hung dependency cannot consume your concurrency budget.
   - Never log passwords, tokens, API keys or personal data. Log an identifier instead of the value.

## 2. Non-Negotiable UI/UX Quality Rules (Prevent Broken Frontend Experiences)

1. **Complete Interactive States (`UX-01`, `UX-02`, `UX-03`, `UX-04`)**:
   - Never leave dead buttons or placeholder links (`href="#"`, empty `onClick={() => {}}`, or `console.log` stubs). Every interactive control must wire to real behavior.
   - Every async button or form submission must disable during flight (`disabled={isLoading}`) and display a clear loading indicator to prevent double submissions.
   - Every data view or list must explicitly handle 4 states: **Loading** (skeleton/spinner), **Empty** (clear message + call-to-action), **Error** (actionable retry/error banner, never a silent `catch {}`), and **Populated**.
2. **Responsive Layout & Touch Ergonomics (`UX-05`, `UX-10`)**:
   - Design mobile-first (`320px–375px` up to `1440px+`). Never use rigid unguarded pixel widths (`w-[600px]`, `width: 800px`) that cause horizontal overflow on mobile screens.
   - Keep interactive touch targets at least `44x44px` on mobile and maintain a clear z-index scale for modals, dropdowns, and toasts.
3. **Accessibility Floor — WCAG 2.2 AA (`UX-06`, `UX-07`, `UX-08`)**:
   - Every form control (`<input>`, `<select>`, `<textarea>`) must have an associated `<label>` or `aria-label`.
   - Every icon-only button must include an `aria-label`, and every informative `<img>` must include a descriptive `alt` attribute.
   - Never remove keyboard focus rings (`outline-none`) without providing a high-contrast `focus-visible:ring` replacement.
4. **Zero Synthetic Placeholders in Production Views (`UX-09`)**:
   - Never ship `"Lorem ipsum"`, `"TODO"`, `"john@example.com"`, or hardcoded fake metrics in user-facing components.

## 3. Running the Vibe Aegis 10-Stage Pre-Publish Audit Loop

Before publishing or merging major features, run the full Vibe Aegis loop:

1. Execute `python3 .aegis/scripts/aegis_scan.py . --json --output .aegis/scan-report.json` (or `python3 scripts/aegis_scan.py .`).
2. Follow the orchestration workflow in `.claude/skills/vibe-aegis/SKILL.md` (or `.agents/skills/vibe-aegis/SKILL.md`):
   - **Recon** -> **Security Hunter** -> **UI/UX Hunter** -> **Adversarial Skeptic** -> **Evidence Referee** -> **Guarded Fixer**.
3. Write the final verified scorecard to `.aegis/AUDIT_REPORT.md`. Do not declare an app ready for production until all `CRITICAL` and `HIGH` confirmed findings are resolved.
4. Read the scanner's `release_verdict` literally. Only `RELEASE_AUDIT_PASSED` - returned by `--profile release` when the dependency, git-history and build-artifact stages all ran and read what they needed - supports a release claim. `STATIC_CHECKS_PASSED` means only that the source checks which ran found nothing. `INCOMPLETE_SCAN` means something was not examined: say what, and never report it as clean. `--profile release` exits `1` on an incomplete stage, on any `MEDIUM` or worse finding, and on any verdict other than `RELEASE_AUDIT_PASSED`.
