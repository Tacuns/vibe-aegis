# Prompt 04 - Shipped-Artifact & Release Verification

Prove that no credential reached the thing your users actually download. Use this right before deploying a web build or uploading a mobile release.

Works in: **Claude Code, VS Code Copilot Chat, OpenAI Codex, Cursor, Windsurf, Cline, Gemini CLI, ChatGPT, Claude, Gemini, Perplexity, Grok.**

---

## The 2-Line Prompt (No Clone Needed)

```text
Read https://raw.githubusercontent.com/Tacuns/vibe-aegis/main/llms-full.txt
Then run the Vibe Aegis artifact-leak-hunter skill on this project: verify my build output and release package carry no credentials, and write .aegis/ARTIFACT_REPORT.md.
```

---

## Why This Is Different From A Source Scan

Reading source tells you what you wrote. Reading the build tells you what users receive. A key can be absent from the source you reviewed and still ship, through a bundler inline, an `env` define, a committed `.env` copied by the build, or a dependency that embeds it.

Because the scanner reads your source **first**, it knows which specific credential to hunt for in the output. That is the difference between a guess and proof:

> A generic scanner: *"this bundle contains something that looks like a key."*
> Vibe Aegis: *"the key at `.env.local:3` is in `dist/assets/index-abc.js` — every visitor can read it."*

---

## The Full Explicit Prompt

```text
Act as the Vibe Aegis Artifact Leak Hunter. Verify what this project actually ships.

STEP 1 - RUN THE DETERMINISTIC STAGE
Web build:    python3 .aegis/scripts/aegis_scan.py . --artifact --output .aegis/scan-report.json
Explicit dir: python3 .aegis/scripts/aegis_scan.py . --artifact dist/
Mobile:       python3 .aegis/scripts/aegis_scan.py . --artifact path/to/app-release.apk
Everything:   python3 .aegis/scripts/aegis_scan.py . --all --output .aegis/scan-report.json

STEP 2 - CLASSIFY EVERY CREDENTIAL BEFORE JUDGING IT
List each secret the app holds and mark it:
- SERVER-ONLY: must never appear in a client bundle or mobile package. In a bundle = confirmed breach.
- PUBLISHABLE: designed to be public (Supabase anon key, Stripe publishable key, Firebase web config).
  These are NOT leaks. Instead verify the protection they depend on: an anon key is only safe when
  Row-Level Security is enabled AND enforced with real policies. Audit the RLS, report on that.
Do not skip this step. Calling a publishable key a breach destroys trust in every other finding.

STEP 3 - CONFIRM THE BUILD IS CURRENT
A stale dist/ proves nothing about what is live. Compare the build output timestamp against the
newest source change. If the build is older, say so plainly and ask for a rebuild before certifying.

STEP 4 - TRACE EVERY CONFIRMED LEAK TO ITS CAUSE
For each ART-01 / ART-03, find HOW it got in; the fix depends entirely on the mechanism:
- NEXT_PUBLIC_ / VITE_ / EXPO_PUBLIC_ / REACT_APP_ prefix -> drop the prefix, use it server-side only
- Imported into a client component -> move the call behind an API route
- Bundler define/env injection -> remove it from the bundler config
- Committed .env copied by the build -> remove from the image/package, add to .gitignore and .dockerignore

STEP 5 - MOBILE PACKAGE CHECKS (.apk / .aab / .ipa)
A store package is a zip anyone can download and unpack. Treat everything inside as public.
- Signed with the correct upload key (ART-11)
- android:debuggable absent or false (ART-14) - a debuggable release exposes memory and data
- android:usesCleartextTraffic="false" plus a network security config requiring HTTPS (ART-13)
- No .env, keystore, service-account JSON or private key under assets/ or res/ (ART-12)
- No static API keys in packaged assets or code (ART-15). Keys that must reach the device should be
  short-lived and server-issued.

STEP 6 - SOURCE MAPS
Flag any .map in the build output. If it contains sourcesContent, your original unminified source
ships to every visitor. Either disable production source maps
(Next.js productionBrowserSourceMaps: false, Vite build.sourcemap: false) or upload them privately
to your error tracker and strip them from the deployed bundle.

STEP 7 - WRITE .aegis/ARTIFACT_REPORT.md
- Confirmed leaks table: credential type, source location, artifact location, how it got there, exact fix.
- Publishable-key table: each one, plus the status of the protection it relies on.
- Mobile posture table: signing, debuggable, cleartext, bundled files.
- Build freshness statement.

RULES
- ART-01 is confirmed evidence - never downgrade or dismiss it.
- ART-13 and ART-14 are read from the decoded binary manifest; a LOW-confidence one takes its value
  from a resource - report it as MANUAL_REVIEW. If ART-10 says the signature was not verified, run
  `apksigner verify --print-certs` before calling the package signed.
- Never print a full credential in the report - the scanner redacts, and so must you.
- Say a credential is EXPOSED, never that it was exploited. You cannot know that.
```

---

## The Rotation Rule

If a credential reached a published bundle or an uploaded package, **it is already public.** Removing it from the next build does not undo that — bundles get cached, mirrored and archived.

Always in this order, and never stop at step 2:

1. **Rotate the credential now** at the provider
2. Change the architecture so it cannot re-enter the client build
3. Rebuild and re-scan to prove the new build is clean
4. Check provider access logs for use of the old credential

## CI Usage

```bash
# Block a release that ships a secret
python3 .aegis/scripts/aegis_scan.py . --artifact dist/ --fail-on-high

# Full pre-release sweep with machine-readable outputs
python3 .aegis/scripts/aegis_scan.py . --all \
  --output .aegis/scan-report.json \
  --sarif .aegis/results.sarif \
  --sbom .aegis/sbom.json
```

## Scope Reminder

Only verify artifacts from applications you own or are authorized to test. See [`SECURITY.md`](../../SECURITY.md).
