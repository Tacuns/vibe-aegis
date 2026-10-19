---
name: architecture-threat-model
description: Map trust boundaries, tenant isolation, database Row-Level Security and environment scaffolding, then build a STRIDE threat model before auditing individual lines. Use at the start of a full audit, on a new codebase, or when designing a feature that touches auth, tenancy or data ownership.
---

# Architecture, Tenancy & STRIDE Threat Model

Run this **first**. Line-level findings without an architectural map produce a list of symptoms with no sense of which ones matter. A missing `aria-label` and a missing tenant filter are not the same kind of problem, and only the map tells you which is which.

## When to Trigger

- Stage 1 of the master `vibe-aegis` loop
- A codebase you have not audited before
- Designing anything touching authentication, multi-tenancy, roles or data ownership
- The user asks "is my architecture sound?", "where are my weak points?", "threat model this"

## 1. Map Before You Hunt

Produce `.aegis/THREAT_MODEL.md` containing:

**Entry points** — every way data gets in: API routes, Server Actions, webhooks, file uploads, auth callbacks, scheduled jobs, websocket handlers, and public pages that read a query parameter.

**Trust boundaries** — where data crosses from less trusted to more trusted. Browser→server, server→database, server→third party, webhook→server. Each crossing is where validation and authorisation must live.

**Assets** — what an attacker actually wants: user records, payment details, API keys, generated content, admin capability, the ability to spend your model budget.

**Actors** — anonymous visitor, authenticated user, another tenant's user, admin, the payment provider, a compromised dependency.

## 2. Tenant Isolation (the one that ends companies)

In a multi-user app, the question is not "can a stranger get in" but **"can user A read user B's data"**. This is the most common catastrophic flaw in vibe-coded apps, because the happy path works perfectly — you only ever test with one account.

Audit every query that takes an identifier:

- Is it filtered by the **authenticated session's** user or tenant, taken from the server-side session and never from the request body?
- Is the filter applied on the **server**, not in client code or a hidden UI route?
- For predictable IDs (sequential integers), assume enumeration. UUIDs raise the effort; they are not an authorisation control.

Test it properly: create two accounts, take a resource ID from account A, request it while authenticated as account B. If it returns, that is a confirmed breach, not a theoretical one. `python3 scripts/aegis_scan.py . --idor-plan .aegis/idor-plan.md` writes this test, with a ready `curl` for every `SEC-03`/`SEC-04`/`DB-0x` finding — run it against a staging deployment you own. A clean scan is not a substitute: an IDOR returns a normal `200`.

## 3. Database Row-Level Security

With Supabase or any Postgres exposed to clients, **RLS is the actual security boundary** — the anon key is public by design, so application-layer checks are irrelevant to someone calling the database directly.

For every table in the `public` schema:

- `ALTER TABLE <name> ENABLE ROW LEVEL SECURITY;` — present, and not disabled later in a migration.
- Explicit policies for `SELECT`, `INSERT`, `UPDATE` **and** `DELETE`. A table with only a `SELECT` policy and RLS enabled silently blocks writes; a table with a permissive write policy is wide open.
- Policies scoped to `auth.uid()` or verified tenant membership. Flag every `USING (true)` on anything non-public.
- `WITH CHECK` on `INSERT`/`UPDATE`, otherwise a user can write rows that claim to belong to someone else.
- Confirm the `service_role` key is **never** in client code. It bypasses RLS entirely.

Migrations are not the database: a table made in the dashboard or a policy edited by hand never appears in them. With `AEGIS_DATABASE_URL` set (a read-only role is enough), `--db-check` reads the live catalog and reports tables the API roles reach with RLS off (`DB-01`), permissive `true` policies (`DB-02`) and views that bypass RLS (`DB-03`).

Remember RLS is only enforced on the anon/authenticated roles. Server code using the service key must do its own scoping — enabling RLS does not protect queries that bypass it.

## 4. Environment & Secret Scaffolding

- `.env`, `.env.local`, `.env.*` in `.gitignore` **and** `.dockerignore`. Only `.env.example` with blank values is committed.
- No private key, database URL or service-role key in any `NEXT_PUBLIC_*`, `VITE_*`, `EXPO_PUBLIC_*` or `REACT_APP_*` variable — those are compiled into JavaScript every visitor can read.
- Different credentials for development, staging and production. A shared key means a dev leak is a production breach.
- A documented rotation path. If you cannot rotate a key quickly, a leak becomes an outage.

## 5. STRIDE Pass

For each entry point, ask all six and record the answer:

| Threat | The question |
| :--- | :--- |
| **S**poofing | Can someone act as another user? Session fixation, weak reset flows, unverified OAuth state |
| **T**ampering | Can someone change data they should not? Mass assignment, client-trusted prices, unverified webhooks |
| **R**epudiation | Could someone deny an action? Are security-relevant events logged immutably? |
| **I**nformation disclosure | Can data leak? IDOR, verbose errors, over-fetching APIs, source maps, cross-tenant reads |
| **D**enial of service | Can one user degrade it for everyone? Unbounded queries, no rate limits, unbounded LLM spend |
| **E**levation of privilege | Can a user become an admin? Role from a client-supplied field, missing server-side role checks |

## Output

`.aegis/THREAT_MODEL.md` with the entry-point inventory, trust-boundary diagram (an indented list is fine), asset and actor lists, the RLS table-by-table status, and the STRIDE findings ranked by **what an attacker gains**, not by how easy they were to spot.

Mark anything you could not verify as `UNKNOWN` with the evidence you would need. A threat model with honest gaps is useful; one with confident guesses is dangerous, because later stages will trust it.
