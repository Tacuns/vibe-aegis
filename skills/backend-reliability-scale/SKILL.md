---
name: backend-reliability-scale
description: Catch the failures that only appear under real traffic - unbounded queries, N+1 loops, missing indexes, serverless connection exhaustion, missing timeouts, and PII written to logs. Use before launch, before a traffic spike, or when an app is slow or falling over in production.
---

# Backend Reliability, Scale & Privacy

These bugs pass every test and every demo, because they only appear at a row count or a request rate you did not have yet. The app does not break when you ship it. It breaks the day it succeeds.

## When to Trigger

- Before launch, a marketing push, or any expected traffic spike
- The app is timing out, running out of memory, or the database is pegged
- The user asks "will this handle load?", "why is it slow?", "is it production-ready?"

## 1. Unbounded Queries (`REL-01`)

`findMany()` with no limit is fine with 100 rows and fatal at 100,000. It loads every row into memory, serialises all of it, and takes the process down with it.

```ts
const orders = await prisma.order.findMany();              // BROKEN
const orders = await prisma.order.findMany({ take: 50 });  // CORRECT
```

Audit every list endpoint, every export, every admin dashboard and every `SELECT *`. Enforce a **maximum** page size on the server — never let the client pass `limit=100000`. Prefer cursor pagination over `OFFSET`, which gets slower the deeper the user goes.

Watch for the subtler version: a bounded query whose **result** is then fully loaded into memory for an in-process `.filter()` or `.reduce()`. Push that work into the database.

## 2. N+1 Query Loops (`REL-02`)

One query per iteration. Ten items in development, ten thousand in production.

```ts
for (const item of items) {                                 // BROKEN - N round trips
  const user = await db.user.findUnique({ where: { id: item.userId } });
}

const users = await db.user.findMany({                      // CORRECT - one round trip
  where: { id: { in: items.map(i => i.userId) } },
});
const byId = new Map(users.map(u => [u.id, u]));
```

The same pattern hides inside `.map(async ...)`, inside GraphQL resolvers (use a dataloader), and in ORM lazy-loading when a relation is accessed in a loop without `include`/`join`.

## 3. Indexes

Every column used in a `WHERE`, `ORDER BY` or `JOIN` needs an index, and a foreign key does not always get one automatically. The symptom is a query that is instant on a seeded dev database and times out on real data.

Check the obvious ones first: `user_id`, `tenant_id`, `created_at`, `status`, and anything used for lookups such as `email` or `slug`. For a query filtering on two columns, a single composite index usually beats two separate ones — and column order matters.

Confirm with `EXPLAIN ANALYZE` rather than guessing. A sequential scan on a large table is the finding.

## 4. Serverless Connection Exhaustion

Each serverless invocation can open its own database connection. A hundred concurrent requests exhaust the connection limit and every subsequent request fails — including the ones that would have succeeded.

- Use a **singleton** client cached on `globalThis`, not a new client per request.
- Put a **pooler** in front (PgBouncer, Supabase pooler, Prisma Accelerate, Neon pooling) and use the pooled connection string in serverless.
- Set a connection limit per instance deliberately rather than taking the default.

## 5. Missing Timeouts (`REL-04`)

An upstream call with no timeout holds your function open until the platform kills it, consuming concurrency the whole time. One slow dependency becomes your outage.

```ts
await fetch(url, { signal: AbortSignal.timeout(10_000) });
```

Set timeouts on outbound HTTP, database queries, and any lock acquisition. Add a retry with **exponential backoff and a bounded attempt count** — naive immediate retries amplify an upstream incident into a self-inflicted denial of service.

## 6. Sensitive Data In Logs (`REL-03`)

Logs go to third-party services, persist for months, and are readable by anyone with dashboard access. A password in a log is a breach with a long tail.

Flag `console.log` and logger calls carrying passwords, tokens, API keys, card numbers, or personal data. Watch for the indirect cases: logging an entire request body, an entire user object, or an error object whose message embeds the connection string. Log an identifier, never the value, and configure redaction at the logger.

## 7. Failure Behaviour

- What happens when the database is down — a clear error, or an unhandled rejection that takes the process with it?
- Are background jobs idempotent? They will be retried.
- Does a partial failure leave data half-written? Wrap multi-step writes in a transaction.
- Is there a health check that actually checks dependencies, rather than returning 200 unconditionally?

## Investigation Protocol

1. Run `python3 .aegis/scripts/aegis_scan.py . --output .aegis/scan-report.json` and read the `RELIABILITY` domain.
2. List every database query. Mark each bounded or unbounded, indexed or not.
3. Find every loop containing an `await` on a database or network call.
4. Check client instantiation: one per process, or one per request?
5. Grep outbound calls for a timeout. Absence is the finding.
6. Estimate the row count each query will face in a year, not today.

## Reporting

Say when it breaks, not just that it is suboptimal: "this endpoint loads the full orders table; at ~50k rows it will exhaust the 1 GB function memory limit". `REL` findings are reported at `MEDIUM` confidence because a pattern cannot know your data volume — confirm against real table sizes before promoting one to CONFIRMED.
