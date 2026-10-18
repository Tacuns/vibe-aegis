---
name: production-preflight-gate
description: The final go/no-go check before launch - live HTTP posture, exposed artifacts, container and CI hardening, privacy and account-deletion readiness, and the Release Readiness verdict. Use immediately before switching DNS, publishing a store release, or announcing a launch.
---

# Final Production Pre-Flight Gate

The last stage. Everything before this looked at code; this looks at **the running deployment and the release process around it**. Its job is to produce one decision — ship or do not ship — and to make that decision defensible.

## When to Trigger

- Immediately before switching DNS, promoting to production, or uploading a store release
- Stage 9–10 of the master `vibe-aegis` loop
- The user asks "am I ready to launch?", "final check", "can I go live?"

## 1. Live HTTP Posture

```bash
python3 .aegis/scripts/aegis_scan.py . --url https://your-production-url.com
```

These checks are strictly passive: read-only `GET` requests that read headers and detect accidentally public files. Only run them against a deployment **you own**.

| Header | Why |
| :--- | :--- |
| `Content-Security-Policy` | The main structural defence against XSS |
| `Strict-Transport-Security` | Stops downgrade to plain HTTP |
| `X-Frame-Options` / CSP `frame-ancestors` | Stops clickjacking |
| `X-Content-Type-Options: nosniff` | Stops MIME-type confusion |

Also confirm: CORS is scoped to your real origins and not `*` with credentials; session cookies carry `HttpOnly`, `Secure` and `SameSite`; and `/.env`, `/.git/config` and `/.well-known/` return 403 or 404 rather than content.

A CSP in report-only mode is **not** enforcing. Check the header name.

## 2. Exposed Build Artifacts

Run the artifact stage and resolve anything it finds:

```bash
python3 .aegis/scripts/aegis_scan.py . --all --output .aegis/scan-report.json
```

Any `ART-01` is a confirmed credential leak and is an automatic **no-go** until the key is rotated — see `skills/artifact-leak-hunter/SKILL.md`. Also confirm source maps are not publicly served if the source is proprietary, and that no `.map`, `.env` or backup file is reachable.

## 3. Container & Pipeline Hardening

- `Dockerfile` runs as a non-root `USER`, uses a pinned base image digest, and multi-stage builds so compilers and secrets do not reach the final image.
- No secret baked into an image layer — `ARG` values persist in history even when later unset.
- CI workflows use least-privilege `permissions:` (`contents: read` unless more is genuinely needed).
- No `pull_request_target` combined with checking out untrusted PR code — that combination hands repository secrets to anyone who opens a pull request.
- Third-party actions pinned to a version or commit SHA, not a moving branch.
- Dependencies installed from a lockfile (`npm ci`, not `npm install`).

## 4. Privacy & Legal Readiness

- A privacy policy that matches what the app **actually** collects — verify against the real data inventory, not the intention.
- A working account-deletion path. GDPR and both app stores require it, and store review rejects releases without it.
- Cookie and analytics consent where required, with the tracker genuinely not loading before consent.
- Data retention: logs and backups containing personal data have a defined lifetime.
- Third-party processors listed, including the AI providers — user content sent to a model leaves your infrastructure, and that belongs in the policy.

## 5. Operational Readiness

The questions that matter at 3am:

- **Rollback**: can you revert in minutes, and has that been tested? Database migrations are the usual trap — is the previous version compatible with the new schema?
- **Monitoring**: will you learn about an outage from your tooling or from a user complaint?
- **Error tracking**: wired up, and scrubbing PII before it is sent?
- **Backups**: taken, and has a **restore** actually been performed? An untested backup is a hope.
- **Key rotation**: if a credential leaks tonight, what is the procedure?

## 6. The Verdict

State one of three, with the evidence behind it:

| Verdict | Condition |
| :--- | :--- |
| `READY` | Score ≥ 90/100, zero open `CRITICAL`/`HIGH`, all sections above verified |
| `READY WITH KNOWN LIMITATIONS` | No blockers, but specific items unverified or accepted — **list each one explicitly** |
| `NOT READY` | Any open `CRITICAL`/`HIGH`, or any section that could not be verified at all |

Write it to `.aegis/AUDIT_REPORT.md` with, for each section: what was checked, how, the result, and what was **not** covered. A gate that cannot say what it failed to check is not a gate.

Never issue `READY` on the basis that nothing was found. Absence of findings in an unrun check is not a pass — mark it `NOT VERIFIED` and say so plainly. And never describe a launch as "fully secure": state what was verified, when, and against which version.
