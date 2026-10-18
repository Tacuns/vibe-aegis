---
name: security-redteam-loop
description: Deep Low-to-Critical application security auditor for vibe-coded apps. Performs multi-file data-flow analysis, STRIDE threat modeling, OWASP Top 10 auditing, BaaS/RLS verification, payment flow validation, and AI/LLM endpoint hardening.
---

# Security Red-Team Loop — Low-to-Critical Vulnerability Auditor

Perform a thorough, defensive architectural and source-code security audit tailored to the exact failure modes of AI-generated ("vibe-coded") applications.

## Audit Checklist Across 5 Trust Boundaries

### 1. Secrets, Environment & Supply Chain (`CRITICAL` / `HIGH`)

- Verify no private keys, database connection strings, or service-role keys appear in client-bundled env vars (`NEXT_PUBLIC_*`, `VITE_*`, `EXPO_PUBLIC_*`, `REACT_APP_*`).
- Check git history and root files for committed `.env`, `.pem`, `.key`, or hardcoded bearer tokens.
- Verify all package dependencies in `package.json` or `requirements.txt` are legitimate packages (catching AI-hallucinated "slopsquatting" package names).

### 2. Authentication, Session & Access Control (`CRITICAL`)

- Enumerate every API route (`app/api/**`, `pages/api/**`, FastAPI `@app.post/put/delete`, Express routers) and every Next.js Server Action (`"use server"`).
- Confirm each route verifies the caller's session on the server before executing logic.
- Trace every database read/write that accepts an `id`, `userId`, `orgId`, or `slug` from the request. Confirm the query filters by the authenticated session owner (`WHERE id = $1 AND user_id = $2` or enforced RLS) to prevent **Insecure Direct Object Reference (IDOR)**.
- Check that JWTs are verified with `jwt.verify()` (never just `jwt.decode()`) and session tokens are stored in `HttpOnly; Secure; SameSite` cookies rather than `localStorage`.

### 3. Database & Backend-as-a-Service (Supabase / Firebase / SQL / Prisma) (`CRITICAL` / `HIGH`)

- Inspect all `.sql` migrations: every table in the `public` schema must enable Row-Level Security (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY;`) and define granular policies. Flag any `USING (true)` policy on write operations or sensitive tables.
- Inspect `firestore.rules` / `database.rules.json`: flag `allow read, write: if true`.
- Check for raw SQL interpolation (`$queryRawUnsafe`, template literals inside `.query()`, Python `f"SELECT ..."`).

### 4. Payments, Webhooks & Business Logic (`CRITICAL` / `HIGH`)

- Trace Stripe, Razorpay, LemonSqueezy, or PayPal checkout creation: confirm prices, plan IDs, and trial eligibility are resolved on the server from trusted constants or database records—never from client request bodies.
- Confirm webhook endpoints verify cryptographic signatures (`stripe.webhooks.constructEvent`) using the raw unparsed request body and enforce idempotency against replay of already-processed `event.id`s.
- Check for race conditions (TOCTOU) in credit balances, coupon redemptions, or quota counters (require atomic `UPDATE ... SET credits = credits - 1 WHERE credits >= 1`).

### 5. AI/LLM Endpoints, Network & Deployment Posture (`HIGH` / `MEDIUM` / `LOW`)

- For apps calling OpenAI, Anthropic, Gemini, or open-weight models: verify authentication, per-user rate limits, explicit `max_tokens` / `maxTokens` caps, and separation between untrusted user data and system instructions.
- Check URL-fetching endpoints for Server-Side Request Forgery (SSRF) against internal metadata services (`169.254.169.254`, `localhost`).
- Verify production configuration sets `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options: nosniff`, and strict CORS origins.
