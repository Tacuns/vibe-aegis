# Prompt 02 - Deep Security Red-Team Loop (Low to Critical)

A security-only deep audit. Use this when you have already shipped the UI and want a focused defensive review of secrets, auth, database rules, payments, and AI endpoints.

Works in: **Claude Code, VS Code Copilot Chat, OpenAI Codex, Cursor, Windsurf, Cline, Gemini CLI, ChatGPT, Claude, Gemini, Perplexity, Grok.**

---

## The 2-Line Prompt (No Clone Needed)

```text
Read https://raw.githubusercontent.com/Tacuns/vibe-aegis/main/llms-full.txt
Then run the Vibe Aegis security-redteam-loop skill on this project: hunt every Low-to-Critical vulnerability, apply the Skeptic and Referee stages, and write .aegis/SECURITY_REPORT.md.
```

---

## The Full Explicit Prompt

```text
Act as the Vibe Aegis Security Red-Team Loop. This is a DEFENSIVE audit of a codebase I own. Do not write exploits or attack any live system - identify weaknesses and give me the exact fix.

First run: python3 .aegis/scripts/aegis_scan.py . --json --output .aegis/scan-report.json
Then enumerate every entry point yourself: app/api/**, pages/api/**, "use server" Server Actions, FastAPI @app.post/put/delete, Express routers, webhook handlers, and every .sql migration or schema file.

Audit all five trust boundaries. Trace data flows across files; a regex match alone is not a finding.

1. SECRETS, ENVIRONMENT AND SUPPLY CHAIN (CRITICAL / HIGH)
- Private keys, service-role keys or database URLs exposed in client-bundled variables: NEXT_PUBLIC_*, VITE_*, EXPO_PUBLIC_*, REACT_APP_*.
- Committed .env, .pem or .key files; hardcoded bearer tokens or API keys in source.
- .gitignore actually covers .env and .env.local, and only .env.example is committed.
- Dependencies in package.json / requirements.txt are real, pinned packages - flag AI-hallucinated "slopsquatting" names and lockfile mismatches.

2. AUTHENTICATION, SESSION AND ACCESS CONTROL (CRITICAL)
- Does every route verify the caller's session ON THE SERVER before running logic? Hidden UI routes and client-side checks are not a security boundary.
- IDOR: for every read, update or delete that accepts an id, userId, orgId or slug from the request, confirm the query is scoped to the authenticated owner (WHERE id = $1 AND user_id = $2, or enforced RLS). This is the single most common vibe-coding breach - check every one.
- JWTs verified with jwt.verify(), never jwt.decode() alone; no weak or hardcoded JWT secrets.
- Session tokens in HttpOnly; Secure; SameSite=Lax/Strict cookies, not localStorage.

3. DATABASE AND BACKEND-AS-A-SERVICE (CRITICAL / HIGH)
- Supabase / PostgreSQL: every table in the public schema must run ALTER TABLE <name> ENABLE ROW LEVEL SECURITY, with explicit SELECT, INSERT, UPDATE and DELETE policies scoped to auth.uid(). Flag any USING (true) policy on a write or a sensitive table.
- Firebase: flag allow read, write: if true in firestore.rules or database.rules.json.
- Raw query injection: string interpolation in SQL, prisma.$queryRawUnsafe(), sequelize.query() with template literals, Python cursor.execute(f"...").
- Command and code injection: unsanitised input reaching child_process.exec, eval(), new Function(), os.system(), or subprocess(..., shell=True).

4. PAYMENTS, WEBHOOKS AND BUSINESS LOGIC (CRITICAL / HIGH)
- Price tampering: confirm Stripe / Razorpay / LemonSqueezy / PayPal checkout sessions resolve price, currency, plan ID, quantity and trial eligibility on the SERVER from trusted constants or database rows - never from the client request body.
- Webhook signature verification: stripe.webhooks.constructEvent or HMAC verification against the RAW unparsed body, plus idempotency so a replayed event.id cannot be processed twice.
- Race conditions (TOCTOU) in credit balances, coupon redemptions and quota counters: require atomic SQL such as UPDATE ... SET credits = credits - 1 WHERE credits >= 1.

5. AI/LLM, NETWORK AND DEPLOYMENT POSTURE (HIGH / MEDIUM / LOW)
- LLM endpoints (OpenAI, Anthropic, Gemini, open-weight): require authentication, per-user rate limits, explicit max_tokens / maxTokens caps, and a hard boundary between system instructions and untrusted user input (prompt injection).
- SSRF: server endpoints fetching user-supplied URLs must allowlist destinations and block 127.0.0.1, localhost, private ranges and the cloud metadata address 169.254.169.254.
- Rate limiting on login, OTP, password reset, email and AI generation endpoints.
- File uploads: MIME allowlist, size cap, and generated storage paths (never user-supplied paths - path traversal).
- XSS: unsanitised dangerouslySetInnerHTML, v-html, innerHTML, or javascript: URLs in user-controlled hrefs.
- CORS and CSRF: Access-Control-Allow-Origin: * combined with credentials; cookie-authenticated state changes without CSRF protection.
- Headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options: nosniff.

SKEPTIC STAGE - before reporting anything, try to disprove each finding. Check middleware.ts, layout auth guards, route groups, ORM parameterisation and enforced RLS. If a defence fully blocks the trigger, mark it DISMISSED and cite the defensive file:line.

REFEREE STAGE - write .aegis/SECURITY_REPORT.md with:
- A findings table ordered CRITICAL -> HIGH -> MEDIUM -> LOW. Each row: rule ID, file:line, CWE ID, CVSS 3.1 estimate, STRIDE category, the concrete trigger path, and the exact corrected code.
- A dismissed false positives log with the defensive file:line for each.
- A summary count by severity and a go / no-go publishing verdict.

Rules: never invent a finding, a CWE ID, a CVSS score or a line number. If you cannot verify something, label it MANUAL_REVIEW and say exactly what evidence is missing. Do not modify any file unless I explicitly ask you to fix.
```

---

## Optional: Live Deployment Posture Check

Only against a deployment **you own**:

```bash
python3 .aegis/scripts/aegis_scan.py . --url https://staging.yourapp.com
```

This performs passive read-only `GET` requests to read security headers and to detect publicly exposed `/.env` and `/.git/config`. It sends no payloads and no credentials. See [`SECURITY.md`](../../SECURITY.md).

## CI Gate

```bash
python3 .aegis/scripts/aegis_scan.py . --json --output .aegis/scan-report.json --fail-on-high
```

Exits `1` when any `CRITICAL` or `HIGH` finding exists, which fails the pipeline.
