---
name: artifact-leak-hunter
description: Verify what an application actually ships, not just what its source says. Cross-references credentials found in source against the built bundle, inspects source maps, and audits .apk/.aab/.ipa packages for bundled config files, signing state, debuggable and cleartext flags, and embedded credentials. Use before publishing a web build or uploading a mobile release.
---

# Artifact Leak Hunter - Verify What You Actually Ship

Reading source code tells you what you wrote. Reading the build output tells you what your users actually receive. **Those are not the same thing**, and the gap between them is where real leaks live.

A credential can be absent from the source you reviewed and still end up in the deployed bundle through a build-time inline, a bundler define, a committed `.env` that the build copied, or a dependency that embeds it. Equally, a mobile release can be published debuggable, unsigned, or carrying an `.env` file inside its assets.

## When to Trigger

- Before deploying a web build, or uploading an `.apk` / `.aab` / `.ipa` to a store
- The user asks "did my API key leak?", "is my key in the bundle?", "check my build", "check my APK"
- As Stage 1.5 of the master `vibe-aegis` loop, after the source scan and before the Referee stage

## Why This Finds What Source Scanning Cannot

The scanner reads your source first, so it knows **which specific credential** to hunt for in the build output. That turns a guess into proof:

> A generic scanner says *"this bundle contains something that looks like a key."*
> This skill says *"the key at `.env.local:3` is in `dist/assets/index-abc.js` — every visitor can read it."*

That cross-reference is rule `ART-01`, and it is the only finding in the whole framework that is **confirmed by construction** rather than inferred.

## Run The Deterministic Stage First

```bash
# Auto-detect dist/, build/, out/, .next/, .output/, .svelte-kit/
python3 .aegis/scripts/aegis_scan.py . --artifact

# Or point at an explicit build directory or mobile package
python3 .aegis/scripts/aegis_scan.py . --artifact dist/
python3 .aegis/scripts/aegis_scan.py . --artifact app/build/outputs/apk/release/app-release.apk

# Everything: source + git history + dependencies + artifacts
python3 .aegis/scripts/aegis_scan.py . --all --output .aegis/scan-report.json
```

## Rule Reference

| Rule | Severity | What it proves |
| :--- | :--- | :--- |
| `ART-01` | Critical | **Confirmed leak.** A credential found in your source is present in the shipped bundle |
| `ART-02` | Medium / Low | A source map is in the build output. With `sourcesContent`, your original unminified source ships to every visitor |
| `ART-03` | Critical–Medium | A provider-format credential found directly in shipped JavaScript, HTML or JSON |
| `ART-11` | High | Mobile package has no signature block under `META-INF/` |
| `ART-12` | Critical | A config file (`.env`, `id_rsa`, `service-account.json`, `.npmrc`) is bundled inside the app package |
| `ART-13` | Medium | Manifest references cleartext traffic |
| `ART-14` | High | Manifest may mark the app debuggable |
| `ART-15` | Critical–Medium | A credential is embedded in packaged assets, resources or code sections |

## Investigation Protocol

### 1. Establish what should be secret

Read the source findings first (`SEC-01`, `SEC-01B`, `SEC-01C`). List every credential the app holds and classify each:

- **Server-only** - must never appear in any client bundle or mobile package
- **Publishable** - designed to be public (a Supabase anon key, a Stripe publishable key, a Firebase web config). These are *not* leaks, but confirm the protection they rely on actually exists: anon keys are only safe when Row-Level Security is enabled and enforced.

This classification step matters. Flagging a publishable key as a breach destroys trust in every other finding you report.

### 2. Confirm the build is current

A stale `dist/` proves nothing about what is live. Check the build output is newer than the source, or rebuild before trusting a clean result. State plainly in your report when the build timestamp predates the latest source change.

### 3. Trace every confirmed leak to its cause

For each `ART-01` or `ART-03`, find *how* it got there. The fix depends entirely on the mechanism:

| Cause | Fix |
| :--- | :--- |
| `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_` prefix | Drop the prefix, access it only in a server route or Server Action |
| Imported into a client component | Move the call behind an API route; the browser never sees the key |
| Bundler `define` / `env` injection | Remove it from the bundler config |
| Committed `.env` copied by the build | Remove from the image or package, add to `.gitignore` and `.dockerignore` |

### 4. Mobile package specifics

An `.apk` or `.aab` is a zip archive that anyone can download from the store and unpack. Treat everything inside it as public:

- Confirm the release is signed with the correct upload key
- Confirm `android:debuggable` is absent or false — a debuggable release lets anyone inspect memory and data
- Confirm `android:usesCleartextTraffic="false"` and that a network security config requires HTTPS
- Confirm no `.env`, keystore, service-account JSON or private key is in `assets/` or `res/`
- Any key that must reach the device should be short-lived and server-issued, never static in the package

### 5. Report honestly

Every `ART-01` is **CONFIRMED** — the value is demonstrably in both places; do not downgrade it. `ART-13` and `ART-14` are derived from strings inside binary XML, so report them as **MANUAL_REVIEW** unless you can decode the manifest properly. Never state a leak is exploited; state it is exposed.

## The Rotation Rule

If a credential reached a published bundle or an uploaded package, **it is already public**. Removing it from the next build does not undo that — anyone could have copied it, and bundles get cached, mirrored and archived.

Always give this order, and never let a fix stop at step 2:

1. **Rotate the credential now** at the provider
2. Change the architecture so it cannot re-enter the client build
3. Rebuild and re-scan to prove the new build is clean
4. Check provider access logs for use of the old credential
