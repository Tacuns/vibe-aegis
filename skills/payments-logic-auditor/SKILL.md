---
name: payments-logic-auditor
description: Audit payments, billing, credits and entitlements for client-trusted prices, unverified or replayable webhooks, and TOCTOU double-spend race conditions. Use whenever an app takes money, grants credits, applies discounts, or gates features behind a subscription.
---

# Payments, Webhooks & Business-Logic Auditor

Security bugs leak data. **Payment bugs leak money**, and they do it quietly — the app works perfectly, the revenue is just wrong. This domain gets its own pass because the failure is in the *logic*, not in any dangerous function a pattern scan can point at.

## When to Trigger

- The project contains Stripe, Razorpay, LemonSqueezy, Paddle or PayPal
- Anything tracks credits, tokens, balances, quotas, seats or usage
- A feature is gated behind a plan, trial, coupon or entitlement
- The user asks "can someone pay less than they should?", "check my billing", "audit my checkout"

## The Three Failures That Actually Happen

### 1. Client-Trusted Pricing (`PAY-01`, Critical)

The browser sends the price. The server believes it.

```ts
// BROKEN - the user edits the request and pays 1 cent
const session = await stripe.checkout.sessions.create({
  line_items: [{ price_data: { unit_amount: body.price } }]
});

// CORRECT - client sends only an identifier; the server decides the price
const plan = await db.plan.findUniqueOrThrow({ where: { id: planId } });
const session = await stripe.checkout.sessions.create({
  line_items: [{ price: plan.stripePriceId, quantity: 1 }]
});
```

Audit **every** field that influences the final charge, not just the obvious one: `amount`, `unit_amount`, `quantity`, `currency`, `discount`, `coupon`, `planId`→price mapping, `trialDays`, `taxRate`, and `successUrl` if it grants anything.

Check the **currency** specifically. Accepting a client-supplied currency on a fixed numeric amount lets someone pay 500 of a much weaker unit instead of 500 of yours.

### 2. Unverified Or Replayable Webhooks (`PAY-03`, Critical)

A webhook endpoint is a public URL that grants entitlements. Anyone can POST to it.

- **Verify the signature** with `stripe.webhooks.constructEvent()` (or HMAC) against the **raw, unparsed body**. A framework that auto-parses JSON silently breaks signature verification — in Next.js App Router use `await req.text()`, never `await req.json()`.
- **Enforce idempotency.** Store each processed `event.id` in a column with a unique constraint. Providers legitimately retry, and without this a retry grants the entitlement twice. An attacker who captures one valid payload can replay it indefinitely.
- **Check the event belongs to you** — verify the account/livemode fields match your account.
- **Never trust `?session_id=` on the success page** as proof of payment. The user controls that URL. Entitlements are granted by the verified webhook, or by a server-side retrieve of the session from the provider.

### 3. TOCTOU Double-Spend (`PAY-02`, High)

Read the balance, check it, write it back. Two requests at once both pass the check.

```ts
// BROKEN - two parallel requests both read 1, both write 0, user gets 2 things
const user = await db.user.findUnique({ where: { id } });
if (user.credits < 1) throw new Error("no credits");
await db.user.update({ where: { id }, data: { credits: user.credits - 1 } });

// CORRECT - the database decides, atomically, in one statement
const { count } = await db.user.updateMany({
  where: { id, credits: { gte: 1 } },
  data: { credits: { decrement: 1 } },
});
if (count === 0) throw new Error("no credits");
```

The giveaway is **any read, then a decision, then a write** against the same row. Apply the same fix to coupon redemptions ("single use" that redeems five times under load), seat limits, referral bonuses, and inventory.

To prove it rather than assume it: fire the same request 20 times in parallel against a test account and assert the balance is correct.

## Investigation Protocol

1. Run the deterministic pass: `python3 .aegis/scripts/aegis_scan.py . --output .aegis/scan-report.json` and read the `PAYMENTS` domain findings.
2. Enumerate every route that moves money or grants entitlement — checkout creation, webhook handlers, credit spend, plan change, cancellation, refund, coupon redemption.
3. For each, answer in writing: **where does the price come from**, **who verified the caller**, and **what happens if this runs twice at the same time**.
4. Trace the entitlement path end to end: payment succeeds → webhook verified → database updated → feature unlocked. Find the step that would still unlock the feature if the payment failed.
5. Check refunds and cancellations revoke access. Access that outlives payment is the same bug in reverse.

## Reporting

State the **financial** consequence in plain terms: "a user can buy a $99 plan for $0.01", "a user can spend 10 credits while holding 1", "a replayed webhook grants unlimited subscription months". A severity label alone does not convey that a payment bug is actively losing money for every day it stays open.

Never test these against production or a live payment account. Use the provider's test mode.
