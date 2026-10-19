# 🛡️ Vibe Aegis (`vibe-aegis`)

**The 10-Stage First-to-Last Full-Stack Safeguard for Vibe-Coded Apps — across 8 domains.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+ Zero-Deps](https://img.shields.io/badge/Python-3.8%2B%20zero--deps-3776AB?logo=python&logoColor=white)](scripts/aegis_scan.py)
[![Node >= 18 NPX CLI](https://img.shields.io/badge/Node-%3E%3D18%20npx%20CLI-339933?logo=node.js&logoColor=white)](bin/vibe-aegis.mjs)
[![CI](https://github.com/Tacuns/vibe-aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/Tacuns/vibe-aegis/actions/workflows/ci.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![AI-Ready llms.txt](https://img.shields.io/badge/AI--Ready-llms.txt-8A2BE2)](llms.txt)
[![SARIF + SBOM](https://img.shields.io/badge/output-SARIF%20%7C%20SBOM%20%7C%20JSON-0A7E8C)](schemas/scan-report.schema.json)

---

## ⚡ Start in 2 Lines (Paste into Any AI Agent)

Open your project in **Claude Code, VS Code Copilot, OpenAI Codex, Cursor, Windsurf, Cline, Gemini CLI**, ChatGPT, Claude, Gemini, Perplexity or Grok — and paste this. Nothing to clone, nothing to install first:

```text
Read https://raw.githubusercontent.com/Tacuns/vibe-aegis/main/llms.txt and run the Vibe Aegis setup and 10-stage Security + UI/UX audit in this project.
```

That single URL teaches the agent the whole framework. For everything in one fetch, point it at [`llms-full.txt`](llms-full.txt) instead.

**Prefer a plugin?**

```text
/plugin marketplace add Tacuns/vibe-aegis        # Claude Code, then type /aegis
codex plugin marketplace add Tacuns/vibe-aegis   # OpenAI Codex, then type $vibe-aegis
```

---

AI coding assistants build features at lightning speed, but they routinely ship hidden security holes (exposed client secrets, missing Row-Level Security, IDOR, unverified webhooks, prompt injection) and broken UI/UX states (dead placeholder buttons, missing loading/disabled states, mobile overflow traps, WCAG accessibility failures).

**Vibe Aegis** combines a **zero-dependency static + live deployment scanner** (`aegis_scan.py`) with a **10-stage adversarial multi-agent analysis loop across 8 domains** that installs in one command across **Claude Code, VS Code (GitHub Copilot), OpenAI Codex, Cursor, Windsurf, Cline, Gemini CLI, and OpenCode**.


## 🧭 The 8 Domains

A single pass over eight separate failure modes. Each has its own skill, its own rules, and its own place in the 10-stage loop.

| # | Domain | Catches | Skill |
| :--- | :--- | :--- | :--- |
| 1 | **Architecture & Tenancy** | Broken tenant isolation, missing RLS, weak trust boundaries | `architecture-threat-model` |
| 2 | **Application Security** | Secrets, IDOR, injection, XSS, SSRF, auth & session flaws | `security-redteam-loop` |
| 3 | **Payments & Business Logic** | Client-trusted prices, replayable webhooks, double-spend races | `payments-logic-auditor` |
| 4 | **AI / LLM** | Prompt injection, denial-of-wallet, unsafe output, tool scope | `ai-llm-security-shield` |
| 5 | **Backend Reliability** | Unbounded queries, N+1 loops, missing timeouts, PII in logs | `backend-reliability-scale` |
| 6 | **UI/UX & Accessibility** | Dead buttons, missing async states, mobile overflow, WCAG 2.2 AA | `ui-ux-bug-finder` |
| 7 | **Shipped Artifacts** | Secrets in the built bundle, source maps, unsigned/debuggable APKs | `artifact-leak-hunter` |
| 8 | **Production Readiness** | Headers, exposed files, container & CI hardening, go/no-go verdict | `production-preflight-gate` |

Security bugs leak data. **Payment bugs leak money.** **Reliability bugs only appear the day you succeed.** They need separate passes, because each one looks fine from inside the others.

## 🔄 The Adversarial Analysis Loop

```mermaid
flowchart TD
    A["🔍 Stage 1 — Recon & Triage<br/>aegis_scan.py<br/>Fingerprint stack · 40+ deterministic rules"]
    B["🛡️ Stage 2 — Security Hunter<br/>Secrets · Auth & IDOR · RLS<br/>Payments · SSRF · AI/LLM"]
    C["🎨 Stage 3 — UI/UX Hunter<br/>Dead controls · Async states<br/>Mobile overflow · WCAG 2.2 AA"]
    D["🤔 Stage 4 — Adversarial Skeptic<br/>Try to DISPROVE every claim<br/>middleware · ORM · auto-escaping"]
    E["⚖️ Stage 5 — Evidence Referee<br/>CONFIRMED · MANUAL_REVIEW · DISMISSED<br/>CWE · CVSS · Readiness Score 0-100"]
    F{"Every release stage ran<br/>and nothing is open?"}
    G["✅ RELEASE_AUDIT_PASSED<br/>--profile release only"]
    H["🔧 Stage 6 — Guarded Fixer --fix<br/>Branch · patch one at a time<br/>re-scan + rebuild · auto-revert regressions"]

    A --> B
    A --> C
    B --> D
    C --> D
    D --> E
    E --> F
    F -->|Yes| G
    F -->|No| H
    H --> A

    style A fill:#1e3a8a,stroke:#3b82f6,color:#fff
    style B fill:#7f1d1d,stroke:#ef4444,color:#fff
    style C fill:#713f12,stroke:#f59e0b,color:#fff
    style D fill:#4c1d95,stroke:#8b5cf6,color:#fff
    style E fill:#164e63,stroke:#06b6d4,color:#fff
    style F fill:#374151,stroke:#9ca3af,color:#fff
    style G fill:#14532d,stroke:#22c55e,color:#fff
    style H fill:#78350f,stroke:#f97316,color:#fff
```

1. **Stage 1 — Deterministic Recon & Triage (`scripts/aegis_scan.py`)**
   Runs the fast local scanner to fingerprint your stack (frameworks, auth, database, payment provider, UI library), map trust boundaries, and produce `.aegis/scan-report.json` with zero LLM token waste.
2. **Stage 2 — Deep Security Hunter (`skills/security-redteam-loop/SKILL.md`)**
   Traces every entry point, API route, Server Action, database query, webhook, and environment variable from **Low to Critical** severity using STRIDE threat modeling and OWASP Top 10 + AI-specific vulnerability rules.
3. **Stage 3 — Deep UI/UX Design & Flow Bug Finder (`skills/ui-ux-bug-finder/SKILL.md`)**
   Audits every page and component for dead click handlers (`href="#"`, empty `onClick`), missing async `loading`/`disabled` states (double-submit bugs), missing empty/error states, responsive overflow traps, z-index collisions, and WCAG 2.2 AA accessibility violations. If `agent-browser` or Playwright is available, it also inspects the live rendered DOM across mobile (`375x812`) and desktop (`1440x900`) viewports.
4. **Stage 4 — Adversarial Skeptic (False-Positive Filter)**
   Challenges every claim from Stages 2 and 3 by checking middleware (`middleware.ts`), ORM parameterization, framework auto-escaping, and parent layout containers. Any speculative claim without a reachable trigger is dismissed.
5. **Stage 5 — Evidence Referee & Release Readiness Scorecard**
   Assigns final verdicts (`CONFIRMED`, `MANUAL_REVIEW`, `DISMISSED`), CWE IDs, CVSS 3.1 / UX severity scores, and calculates a **0–100 Release Readiness Score** inside `.aegis/AUDIT_REPORT.md`. Publishing is blocked if any `CRITICAL` or `HIGH` issue remains open.
6. **Stage 6 — Guarded Fixer & Verification Loop (Opt-In `--fix`)**
   Creates a safe git branch (`aegis/hardening-<timestamp>`), patches confirmed bugs one by one, re-runs `aegis_scan.py` plus your project's build/test suite after each patch, and automatically reverts any fix that introduces a regression.

## ⚡ Why Vibe Aegis?

| Capability | Single-Skill Security Checklists | Binary Reverse-Engineering Tools | **Vibe Aegis (`vibe-aegis`)** |
| :--- | :--- | :--- | :--- |
| **Pre-Publish Vibe-Code Security Gate** | Partial (15–30 static rules) | No (focused on binary/app decompilation) | **40+ Static + Live HTTP Posture Checks (Low to Critical)** |
| **Adversarial Verification Loop** | Single-pass prompt (high false positives) | Evidence tracing only | **10 stages: Hunter → Skeptic → Referee → Guarded Fixer** |
| **UI/UX Design & Browser QA Bug Finder** | None | None | **Detects dead buttons, missing async loading states, mobile overflow, a11y & visual bugs** |
| **Stack-Aware Rules** | Basic | JS/Electron/Native | **Next.js, React, Supabase, Firebase, Prisma, Stripe, Razorpay, FastAPI, Express, Mobile** |
| **Universal Agent Support** | 1–2 agents | MCP clients | **Claude Code, VS Code, Codex, Cursor, Windsurf, Cline, Gemini CLI, GitHub Actions** |
| **Machine-Readable Output** | Prose only | Tool-specific | **`.aegis/scan-report.json` validated by a published JSON Schema** |

## 🚀 Install Options

### Option 1: Universal Shell Installer (macOS / Linux / WSL / Git Bash)

```bash
git clone https://github.com/Tacuns/vibe-aegis.git
cd vibe-aegis

# Install into a project for ALL agents (Claude Code, VS Code Copilot, Codex, Cursor, Windsurf, Cline, Gemini)
bash install.sh --target /path/to/your/app --agent all

# Or install globally for your user profile
bash install.sh --global --agent all
```

**Your existing files are safe.** The installer writes two kinds of file and never
confuses them:

| Kind | Examples | If it already exists and differs |
| :--- | :--- | :--- |
| Your project's own config | `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `.vscode/tasks.json`, `.cursorrules`, `.clinerules`, `GEMINI.md` | **Never modified.** Our version goes to `.aegis/suggested/<same path>` for you to merge, and the installer lists what it kept |
| Files only Vibe Aegis writes | the scanner, our skills, `.claude/commands/aegis.md`, `.cursor/rules/vibe-aegis.mdc` | Updated, after the previous copy is saved to `.aegis/backup/<timestamp>/<same path>` |

Re-running the installer with nothing changed touches nothing.

### Option 2: `npx` CLI Installer (Node.js 18+)

```bash
npx vibe-aegis setup --target . --agent all

# Or select a specific agent: claude-code | vscode | codex | cursor | windsurf | cline | gemini
npx vibe-aegis setup --target . --agent claude-code
```

### Option 3: Run the Deterministic Scanner Directly (Python 3.8+, Zero Dependencies)

```bash
# 1. Full static codebase audit (Security + UI/UX bugs)
python3 scripts/aegis_scan.py /path/to/your/app

# 2. Scan codebase + verify live/staging URL headers, CORS & exposed files (.env, .git)
python3 scripts/aegis_scan.py /path/to/your/app --url https://staging.yourapp.com

# 3. Export structured JSON report for CI/CD or agent ingestion
python3 scripts/aegis_scan.py /path/to/your/app --json --output .aegis/scan-report.json

# 4. CI gate — exit code 1 if any CRITICAL or HIGH finding exists
python3 scripts/aegis_scan.py /path/to/your/app --fail-on-high

# 5. Release gate — every stage must run AND nothing high may be open
python3 scripts/aegis_scan.py /path/to/your/app --profile release --fail-on-high
```

### Scanner CLI Reference

**Output**

| Argument | Description |
| :--- | :--- |
| `target` | Path to the repository to scan (default `.`) |
| `--json` | Print the full JSON report to stdout |
| `--output <PATH>` | Write the JSON report to a file (parent directories are created) |
| `--sarif <PATH>` | Write SARIF 2.1.0 so findings appear in GitHub's Security tab |
| `--sbom <PATH>` | Write a CycloneDX 1.5 SBOM of all detected dependencies |
| `--quiet` | Print only the one-line summary |

**Release gate**

| Argument | Description |
| :--- | :--- |
| `--profile <name>` | `quick` / `code` (default) / `full` / `release` — which stages run by default. Only `release` can return `RELEASE_AUDIT_PASSED`. See [Profiles](#profiles) |
| `--fail-on-high` | Exit `1` if any `CRITICAL` or `HIGH` finding exists |
| `--fail-on <level>` | Exit `1` at or above `critical`/`high`/`medium`/`low` |
| `--include-tests` | Also audit test and fixture files (excluded by default — they contain deliberately insecure code) |
| `--fail-on-incomplete` | Exit `1` if any check could not run, **or if zero source files were scanned** — use when a green pipeline must mean *fully audited*, not merely *nothing found* |
| `--min-confidence <level>` | `high` / `medium` / `low` (default `low`). Only findings at or above this confidence affect the **exit code**; everything is still reported |

**Three axes, not one** - coverage, severity and confidence each have their own gate flag;
see [Coverage, Severity, Confidence - and the Verdict](#coverage-severity-confidence---and-the-verdict).

Some rules cannot prove their case — `SEC-03` matches a list of known auth helpers and
cannot recognise a guard it has never seen; `REL-*` cannot know your data volume. Those are
reported at `MEDIUM` confidence. `--min-confidence high` gates only on what is demonstrable:

```bash
# Block only on findings the scanner can actually prove, but still refuse to
# certify an audit that did not fully run.
python3 scripts/aegis_scan.py . --fail-on-high --min-confidence high --fail-on-incomplete
```

**Scope — how you adopt this on a real codebase**

| Argument | Description |
| :--- | :--- |
| `--diff [REF]` | Scan only files changed vs `REF` (default `origin/main`). Ideal for pull requests |
| `--baseline <PATH>` | Suppress findings recorded in a baseline file |
| `--write-baseline <PATH>` | Accept every current finding as pre-existing, so future scans show only new issues. Coverage gaps are never recorded |
| `--max-file-size <BYTES>` | Skip source files larger than this (default `1500000`). Each skipped file is reported as a `COV-00` coverage gap, never as clean |

**Deep analysis**

| Argument | Description |
| :--- | :--- |
| `--artifact [PATH]` | Verify a build directory or an `.apk`/`.aab`/`.ipa`. With no value, auto-detects `dist/`, `build/`, `out/`, `.next/`, `.output/`, `.svelte-kit/`, `www/`, `public/`, `release/`. Finding none is an `ART-00` gap, and so is finding only `public/`: static assets are read, but they are not a build |
| `--git-history [N]` | Hunt credentials committed in the newest `N` commits (default 300) reachable from **every** ref (`git log --all`: branches, tags, remote-tracking refs, the stash). More commits than `N`, a shallow clone, or a commit git could not show is a `GIT-00` gap |
| `--deps` | Check dependencies against the OSV vulnerability database |
| `--url <URL>` | Passive, read-only live header & exposure checks |
| `--all` | Enable artifacts + git history + dependencies |
| `--offline` | No network request from this run: disables `--deps` and `--url`, and starts only the external engines verified to work without a network (`gitleaks`, `trufflehog`) — see below |

**External engines (optional)**

Vibe Aegis is complete with nothing else installed. If you already have one of these
tools, `--engine` also runs it and imports its findings. Engines are found on `PATH` and
**never downloaded or installed for you**. A requested engine that is missing, crashes,
times out or prints something unparseable becomes an `ENG-00` coverage gap — *"semgrep did
not run"* is never reported as *"semgrep found nothing"*.

| Argument | Description |
| :--- | :--- |
| `--engine <name>` | Also run an installed engine. Repeatable |
| `--list-engines` | Show which engines are installed, with role and licence, and exit |
| `--authorize-network-scan` | Required, together with `--url`, before any engine that sends traffic to a live target |

| Engine | Role | Licence | Command Vibe Aegis runs |
| :--- | :--- | :--- | :--- |
| `semgrep` | AST pattern analysis across languages | LGPL-2.1-only (CLI) | `semgrep scan --config auto --json --quiet --timeout 300 <target>` |
| `gitleaks` | Secrets across full git history | MIT | `gitleaks detect --source <target> --report-format json --report-path - --no-banner --exit-code 0` |
| `trufflehog` | Secrets in git history and files | AGPL-3.0 | `trufflehog filesystem <target> --no-verification --no-update --json` — or `trufflehog git file://<target> ...` with the same flags when `<target>` is a git repository |
| `trivy` | Dependencies, IaC misconfiguration, secrets | Apache-2.0 | `trivy fs --format json --quiet --scanners vuln,misconfig,secret <target>` |
| `osv-scanner` | Lockfile-accurate vulnerability scan | Apache-2.0 | `osv-scanner --format json -r <target>` |
| `scorecard` | Supply-chain posture of the repository | Apache-2.0 | `scorecard --local <target> --format json` |
| `codeql` | Interprocedural data flow | GitHub CodeQL Terms (restricted for some commercial use) | **No adapter.** Needs a prebuilt database; requesting it records an `ENG-00` gap |
| `zap` | Dynamic scan of a running deployment | Apache-2.0 | **No adapter yet.** Without `--authorize-network-scan` *and* `--url` it is refused; with both it records an `ENG-00` gap |

Imported findings keep the engine's own rule id behind an `EXT-<ENGINE>:` prefix (for
example `EXT-SEMGREP:generic.secrets...`) in the `EXTERNAL` domain, so another tool's output
is never presented as ours, and their text is masked for credentials like everything else.
Only fields that cannot carry a secret are read, plus the matched value through `redact()`:
TruffleHog's `RawV2`, `SecretParts`, `StructuredData`, `ExtraData` and committer email,
and Trivy's `Code` context lines (which hold neighbouring source lines unmasked), are never
read. TruffleHog always runs with `--no-verification` - verifying a credential means
sending it to its provider - and `--no-update`. Licences apply to the tools you install;
Vibe Aegis copies no code or rules from them and only reads their JSON output.

**What leaves your machine.** A default scan (`--profile code`) makes no network request,
and there is no telemetry, ever. The scanner itself has exactly two network features, both
opt-in:

| Enabled by | Request | What is disclosed |
| :--- | :--- | :--- |
| `--deps`, `--all`, `--profile full` or `--profile release` | `POST https://api.osv.dev/v1/querybatch`, then one `GET https://api.osv.dev/v1/vulns/<id>` per advisory found (at most 200) to read its severity | Your dependency **names and versions**, and the advisory ids they matched — not your source, not your file names |
| `--url <URL>` | One `GET` to that URL, plus one `GET` each to `/.env` and `/.git/config` on the **same host** | Nothing of yours; it reads your own deployment's response headers and the first 512 bytes of those two paths |

`--offline` disables both. A stage that could not reach the network is recorded as a
coverage gap (`DEP-00` / `LIVE-00`), so the verdict becomes `INCOMPLETE_SCAN` instead of
silently passing.

**`--offline` covers external engines too.** They are separate programs with network
behaviour of their own - `semgrep --config auto` fetches its rules, `trivy` its
vulnerability database, `osv-scanner` queries its API - so under `--offline` only
`gitleaks` and `trufflehog` are started: each was run with the exact command above inside
a network namespace with no network at all and produced its normal results. Every other
requested engine is recorded as an `ENG-00` coverage gap naming `--offline`, never run.

**Credentials in reports are redacted** before anything is written: only the provider's
public prefix (`sk_live_`, `AKIA`) and the length remain - no character of the secret itself.
`.aegis/scan-report.json` is safe to commit, attach to an issue, or upload as a CI artifact.

**Exit codes:** see [Exit codes](#exit-codes) — the verdict alone never sets them.

Also honoured: a `.aegis-ignore` file in the repo root, one entry per line — either a rule id (`SEC-03`) or a path glob (`src/legacy/**`).

## 🔍 Complete Audit Coverage Matrix (Low to Critical)

### A. Security & Architecture Safeguards

| ID | Category | Severity | What Vibe Aegis Catches |
| :--- | :--- | :--- | :--- |
| `SEC-01` | **Client-Exposed Secrets** | Critical | Private keys or tokens in `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, or hardcoded in source files |
| `SEC-02` | **Database RLS Disabled** | Critical | Supabase/PostgreSQL tables without `ENABLE ROW LEVEL SECURITY` or permissive `USING (true)` policies; Firebase `allow read, write: if true` |
| `SEC-03` | **Unprotected API / Server Actions** | Critical | Next.js `/api/*` routes, `"use server"` actions, FastAPI, or Express mutations lacking session/auth verification |
| `SEC-04` | **Broken Access Control (IDOR)** | Critical | Queries fetching/mutating records by user-supplied `id` without scoping to `auth.uid()` / authenticated session owner |
| `SEC-05` | **Payment & Checkout Tampering** | Critical | Trusting client-submitted prices, plan tiers, or quantities in Stripe/Razorpay checkout sessions |
| `SEC-06` | **Unverified Webhooks** | Critical | Payment or auth webhooks processing payloads without cryptographic signature verification (`stripe.webhooks.constructEvent`) |
| `SEC-07` | **SQL / Raw Query Injection** | High | String interpolation in SQL, `prisma.$queryRawUnsafe()`, `sequelize.query()`, or Python `cursor.execute(f"...")` |
| `SEC-08` | **Command & Code Injection** | High | Unsanitized input passed to `child_process.exec`, `eval()`, `new Function()`, `os.system()`, or `subprocess(..., shell=True)` |
| `SEC-09` | **Cross-Site Scripting (XSS)** | High | Unsanitized `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, or `javascript:` URLs in user-controlled hrefs |
| `SEC-10` | **JWT & Session Flaws** | High | `jwt.decode()` used without `jwt.verify()`, weak JWT secrets, or sensitive auth tokens stored in `localStorage` |
| `SEC-11` | **Server-Side Request Forgery (SSRF)** | High | Server endpoints fetching user-supplied URLs without allowlisting or private-IP (`127.0.0.1`, `169.254.169.254`) blocking |
| `SEC-12` | **AI / LLM Prompt Injection & Spend** | High | Unbounded LLM endpoints without auth, rate limiting, max-token caps, or system/user prompt boundary separation |
| `SEC-13` | **Wildcard CORS & CSRF** | High | `Access-Control-Allow-Origin: *` combined with credentials, or cookie-authenticated state changes lacking CSRF protection |
| `SEC-14` | **Missing Rate Limiting** | Medium | Auth login, OTP, password reset, AI generation, and email endpoints lacking IP/user rate limiters |
| `SEC-15` | **Insecure File Uploads** | Medium | Upload handlers accepting arbitrary MIME types, missing size limits, or storing files with user-supplied paths (path traversal) |
| `SEC-16` | **Supply-Chain & Slopsquatting** | Medium | Unpinned dependencies, suspicious AI-hallucinated package names, or lockfile mismatches |
| `SEC-17` | **Live Posture & Exposed Artifacts** | Low–Crit | Publicly reachable `.env`, `.git/config`, `.map` source maps, debug endpoints, or missing CSP / HSTS / `X-Frame-Options` headers |
| `SEC-18` | **`SECURITY DEFINER` Without A Fixed `search_path`** | Medium | A function that runs with its owner's rights but resolves names through the caller's `search_path` — any role that can create objects can hijack it. Fix: `SET search_path = ''` |
| `SEC-19` | **Public View Exposing `auth.users`** | Critical | A view in `public` reading `auth.users` with its owner's rights, so the anon key reads every user's email |
| `SEC-20` | **Public View Bypassing RLS** | Medium | A view without `security_invoker = true` (or any materialized view) checks RLS against its owner, not the caller |
| `SEC-21` | **RLS Policy Trusting `user_metadata`** | High | A policy reading a role from `user_metadata`, which every signed-in user can edit about themselves. Use `app_metadata` |

`SEC-18` to `SEC-21` are each proven against a real PostgreSQL by
`TestPostgresPrivilegeRulesAgainstARealDatabase`: the attack succeeds on the flagged
migration (an ordinary role becomes superuser; anon reads every email; one user reads
another's rows; an edited claim unlocks an admin table) and fails on the fix. A grant or
revoke in the same migration sets the confidence — no grant to the API roles means it
depends on the project's default privileges, so it is reported at `MEDIUM` confidence.

### B. UI/UX Design & Frontend QA Bug Finder

**The element must match the behaviour.** If it performs an action it is a `<button>`; if it navigates it is an `<a>` with a real `href`. Get that right and the browser supplies focus, Tab order, Enter *and* Space, and the correct screen-reader role for free — no `role`, `tabIndex` or `onKeyDown` needed. These three rules are separated because each has a different fix.

| ID | Category | Severity | What Vibe Aegis Catches |
| :--- | :--- | :--- | :--- |
| `UX-01` | **Dead Buttons & Placeholder Links** | High | A control that does nothing: `<a href="#">` with no handler, or `onClick={() => {}}` / `console.log` stubs |
| `UX-11` | **Action Rendered As A Link** | High | `<a href="#" onClick={...}>` or `href="javascript:"` — works with a mouse, but screen readers announce "link", Space does not activate it, and the page jumps to top. Use `<button>` |
| `UX-12` | **Clickable `div` / `span`** | High | An `onClick` on a non-interactive element with no `role` or `tabIndex` — unreachable by Tab, unusable by keyboard, announced as plain text |
| `UX-02` | **Missing Async Loading / Disabled State** | High | Async form submissions or mutation buttons that don't disable during flight, allowing duplicate charges or duplicate records |
| `UX-03` | **Silent Catch & Missing Error Feedback** | High | `catch (err) {}` blocks that swallow API failures without showing a toast, inline error message, or fallback UI |
| `UX-04` | **Missing Empty & Skeleton States** | Medium | `.map()` list renders that show a blank screen when the array is empty (`length === 0`) or loading |
| `UX-05` | **Mobile Viewport & Overflow Traps** | Medium | Fixed pixel widths (`w-[600px]`, `min-w-[500px]`, `width: 700px`) and `100vw` containers causing horizontal scrollbars on mobile |
| `UX-06` | **Form Accessibility & Validation Gaps** | Medium | `<input>`, `<select>`, or `<textarea>` missing associated `<label>`, `id`/`name`, or accessible error states |
| `UX-07` | **Icon Buttons & Image Accessibility** | Medium | Icon-only buttons without `aria-label` and `<img>` tags missing `alt` attributes |
| `UX-08` | **Focus Ring Suppression** | Low | `outline-none` or `outline: 0` applied without a replacement `focus-visible:ring` keyboard indicator |
| `UX-09` | **Unfinished AI Placeholders in UI** | High | Leftover `"Lorem ipsum"`, `"TODO:"`, `"placeholder"`, `"example.com"`, or fake `$99,999` mock metrics in production views |
| `UX-10` | **Z-Index & Modal Scroll Traps** | Low | Arbitrary `z-[99999]` collisions or modals that lock `document.body.style.overflow` without cleanup on unmount |

### C. Payments & Business Logic

| ID | Category | Severity | What it catches |
| :--- | :--- | :--- | :--- |
| `PAY-01` | Client-trusted price | Critical | `amount`, `unit_amount`, `price`, `quantity`, `currency` or `discount` taken from the request body |
| `PAY-02` | Non-atomic balance update | High | Read-then-write on credits or balances — two parallel requests both succeed (double-spend) |
| `PAY-03` | Unverified webhook | Critical | Payment webhook without signature verification against the raw body |

### D. Backend Reliability & Privacy

| ID | Category | Severity | What it catches |
| :--- | :--- | :--- | :--- |
| `REL-01` | Unbounded query | Medium | `findMany()` with no `take` — fine at 100 rows, fatal at 100,000 |
| `REL-02` | N+1 query loop | Medium | A database `await` inside a `for` loop or `.map(async …)` |
| `REL-03` | Sensitive data in logs | High | Passwords, tokens, API keys or PII passed to `console.log` or a logger |
| `REL-04` | Missing timeout | Medium | `await fetch()` with no `AbortSignal.timeout()` — a hung upstream eats your concurrency |

`REL` findings are reported at `MEDIUM` confidence: a pattern cannot know your data volume, so the Skeptic stage confirms against real table sizes.

### E. Data-Flow Analysis (follows the value, not the pattern)

A regex says *"there is a template literal in a query."* Taint analysis says *"**this** value came from the request and reaches **that** query unvalidated."* Input is traced from request sources (`req.body`, `req.json()`, `searchParams.get`, `formData.get`, route `params`) through assignments to dangerous sinks. A value that passes a validator (`zod.parse`, `parseInt`, `encodeURIComponent`, an allowlist check) is treated as clean and **not** reported.

| ID | Flow | Severity |
| :--- | :--- | :--- |
| `FLOW-01` | Request input reaches a raw SQL query | Critical |
| `FLOW-02` | Request input reaches a shell or code-execution sink | Critical |
| `FLOW-03` | Request input reaches an HTML rendering sink | High |
| `FLOW-04` | Request input reaches a server-side fetch (SSRF) | High |
| `FLOW-05` | Request input reaches a filesystem path | High |

Reported at `MEDIUM` confidence by design — the tracker works within a function scope, so the Skeptic stage confirms before anything is called CONFIRMED.

### F. Shipped-Artifact Verification (what your users actually receive)

Source code says what you wrote. The build output says what ships. Because the scanner already read your source, it can **cross-reference** — turning a guess into proof.

| ID | Category | Severity | What it proves |
| :--- | :--- | :--- | :--- |
| `ART-01` | **Confirmed secret leak** | Critical | A credential from your source is present in the shipped bundle. Confirmed by construction |
| `ART-02` | Source map shipped | Medium / Low | With `sourcesContent`, your original unminified source reaches every visitor |
| `ART-03` | Credential in bundle | Critical–Medium | A provider-format key found directly in shipped JS/HTML/JSON |
| `ART-11` | Unsigned package | High | Neither a v1 signature under `META-INF/` nor a v2/v3 APK Signing Block. A v2-only release (the modern default) is correctly recognised as signed; an unreadable archive or an `.aab` reports `ART-10` instead of guessing |
| `ART-12` | Config bundled in app | Critical | `.env`, `id_rsa` or `service-account.json` inside the `.apk`/`.aab`/`.ipa` |
| `ART-13` | Cleartext traffic | Medium | Manifest references cleartext HTTP |
| `ART-14` | Debuggable release | Medium | The `debuggable` attribute appears in the manifest. A binary manifest stores the *value* separately, so correct `debuggable="false"` hardening looks identical — verify with `aapt dump badging` |
| `ART-15` | Credential in package | Critical–Medium | A key embedded in packaged assets, resources or code |

### G. Supply Chain & Git History

| ID | Category | Severity | What it catches |
| :--- | :--- | :--- | :--- |
| `DEP-01` | Known dependency vulnerability | Low–Crit | Package versions with OSV advisories (npm, PyPI, crates.io, Go). Severity is the highest of every signal in each advisory's own record: its CVSS v3.x and v2 vectors (scored here), and its database or Ubuntu rating. A `MAL-` (malicious package) advisory is `CRITICAL`; an advisory whose severity cannot be read is `HIGH` at `MEDIUM` confidence, never guessed lower |
| `HIST-01` | Credential in git history | Critical–Medium | A key committed at any point — **even if deleted later**, it is still readable and still compromised |

### Rule Variants

Some rules have narrower sub-variants, reported with their own id so you can suppress them individually:

| ID | Covers |
| :--- | :--- |
| `SEC-01B` | Secret-named value exposed through a client-bundled env prefix |
| `SEC-01C` | An environment file (`.env`, `.env.local`, ...) anywhere in the project that is committed to git, or that git would commit - asked of git itself (`git ls-files`, `git check-ignore`); templates such as `.env.example` are exempt |
| `SEC-02B` | Permissive Firebase / Firestore rule (`allow read, write: if true`) |
| `SEC-10B` | Auth token stored in `localStorage` rather than an HttpOnly cookie |
| `SEC-17B` | `/.env` or `/.git/config` publicly reachable on the live server |
| `DEP-00`, `LIVE-00`, `GIT-00`, `ART-00`, `ART-10`, `COV-00`, `ENG-00` | **Coverage gaps**, not defects — a check that could not run, or something it did not read. Any id ending `-00` is always a gap |

### Secret Detection Precision

A noisy scanner gets uninstalled. Credential rules only fire on real provider key shapes (AWS, Stripe, GitHub, Google, Slack, OpenAI, Anthropic, SendGrid, Twilio, Razorpay, npm, PEM private keys, Supabase service-role JWTs, database URLs with inline credentials) or on secret-named variables holding high-entropy values. Placeholders such as `your-api-key-here`, `changeme`, `${process.env.X}` and AWS's own documentation key `AKIAIOSFODNN7EXAMPLE` are rejected.

**Every credential in every report is redacted** down to its public provider prefix and its length, so `.aegis/scan-report.json` is safe to commit, attach to an issue, or hand to an agent. This covers credentials the scanner can recognise - provider key formats, secret-named values, credentialed URLs and long random tokens; a short password with nothing to mark it as one cannot be told apart from code.

### Coverage, Severity, Confidence - and the Verdict

A release gate can be wrong in three separate ways, so the scanner keeps them apart and
never folds them into one number:

| Axis | Question | Gate flag |
| :--- | :--- | :--- |
| **Coverage** | Did the check actually run, and read what it claims to have read? | `--fail-on-incomplete` |
| **Severity** | If this finding is real, how bad is it? | `--fail-on-high` / `--fail-on <level>` |
| **Confidence** | How sure are we that it is real? | `--min-confidence <level>` |

A check that **could not run** is an unknown, never a pass. Every such gap is reported in
`skipped_checks` (rule ids ending `-00`), never counted in the score, and can never be
suppressed by `.aegis-ignore` or `--baseline` - suppression accepts known *defects*, and a
check that did not run carries nothing to accept.

#### Profiles

A profile is a default set of stages. It is never a ceiling: an explicit flag
(`--deps`, `--git-history`, `--artifact`, `--all`) always adds its stage.

| Profile | Stages run by default | Can return `RELEASE_AUDIT_PASSED`? |
| :--- | :--- | :--- |
| `quick` | Source analysis only - currently **identical** to `code` | No |
| `code` *(default)* | Source analysis: patterns, data-flow and secret detection | No |
| `full` | `code` + dependencies + git history + build artifacts | No |
| `release` | Everything in `full`; forces `--fail-on-incomplete`, and without `--fail-on` exits `1` on anything but `RELEASE_AUDIT_PASSED` | **Yes** - the only one |

`--profile release` exits `1` when any stage was incomplete, on any `MEDIUM` or worse
finding at or above `--min-confidence`, and - at the default `--min-confidence low` - on
any verdict other than `RELEASE_AUDIT_PASSED`. `REVIEW_REQUIRED` says a human must decide
before release, so the gate does not decide for them by exiting `0`. An explicit
`--fail-on <level>` still wins, so a team can deliberately gate a release on severity
alone:

```bash
python3 scripts/aegis_scan.py . --profile release                       # anything but RELEASE_AUDIT_PASSED -> exit 1
python3 scripts/aegis_scan.py . --profile release --fail-on critical    # incomplete or CRITICAL -> exit 1
```

A release stage that had nothing to read is a gap, not a pass: no build output, a missing
`--artifact` path, a bundle over 12 MB, files past the first 4000, no dependency manifest,
a lockfile format the scanner does not parse (`yarn.lock`, `pnpm-lock.yaml`,
`poetry.lock`, ...), a lockfile in a subdirectory, a `package.json` without
`package-lock.json`, or a `requirements.txt` line not pinned with `==`.

#### Verdicts

`release_verdict` starts with one of five words, followed by an explanation in
parentheses. They are checked in this order, and the first that applies wins:

| # | Verdict | When |
| :--- | :--- | :--- |
| 1 | `INCOMPLETE_SCAN` | Zero source files were scanned. Score forced to `0` |
| 2 | `BLOCKED` | Any open `CRITICAL` or `HIGH` finding. A real defect outranks a coverage gap |
| 3 | `INCOMPLETE_SCAN` | Any check did not run or did not read what it should have. Names the checks |
| 4 | `REVIEW_REQUIRED` | Any `MEDIUM` finding, or a score below 90 - a human decides |
| 5 | `RELEASE_AUDIT_PASSED` | `--profile release`, and the dependency, git-history and artifact stages all ran and read what they needed, with nothing found |
| 6 | `STATIC_CHECKS_PASSED` | Anything else that is clean |

**`STATIC_CHECKS_PASSED` is not a release-readiness claim.** It means only that the checks
which ran found nothing. A source scan reads no lockfile, no git history, no built bundle
and no running deployment, so it can never certify a release.

One more string can appear: with `--diff`, a changeset containing no scannable source files
returns `NO CODE CHANGES TO REVIEW (diff contained no scannable source files)` at `100/100`.
A docs-only pull request is the normal case, not a failed audit.

**Matching verdicts in CI.** Match the leading word, never the full string - the
explanation in parentheses names counts and checks and changes from run to run. Better
still, use the exit code, which already applies the gate flags you chose:

```bash
verdict=$(jq -r .release_verdict .aegis/scan-report.json)
case "$verdict" in
  RELEASE_AUDIT_PASSED*|STATIC_CHECKS_PASSED*) echo "clean" ;;
  *) echo "not clean: $verdict"; exit 1 ;;
esac
```

#### Exit codes

| Code | Meaning |
| :--- | :--- |
| `0` | No gate tripped. **The verdict alone never sets the exit code** - outside `--profile release`, `BLOCKED` exits `0` unless `--fail-on-high` or `--fail-on` is set |
| `1` | `--fail-on-high` / `--fail-on` (implied `medium` by `--profile release`) met a finding at or above `--min-confidence`; or `--fail-on-incomplete` (forced by `--profile release`) met a gap or a scan of zero files; or `--profile release` without `--fail-on`, at the default `--min-confidence low`, ended in any verdict but `RELEASE_AUDIT_PASSED` |
| `2` | The target path does not exist |

#### Release Readiness Score

The score starts at **100** and subtracts **25** per `CRITICAL`, **10** per `HIGH`, **4**
per `MEDIUM` and **1** per `LOW`, floored at `0`. Coverage gaps are not scored - ten
skipped checks do not cost ten points, they make the verdict `INCOMPLETE_SCAN`.

Called directly, `compute_readiness_score([DEP-00])` also fails closed: any rule id ending
`-00` is a gap however the `Finding` was built. `allow_skipped=True` is the explicit opt-out.

## 🧩 Pair It With Platform Controls

A static scan reads files. Some protections can only live on the platform that hosts
your code or data, and they catch things no scan of a checkout can see. Turn these on as
well - Vibe Aegis does not replace them:

| Control | What it adds that a scan of your files cannot |
| :--- | :--- |
| **GitHub secret scanning + push protection** | Blocks a credential at `git push`, *before* it reaches the remote - after that it must be rotated. Free for public repositories; enable it in the repository's security settings |
| **Dependabot** (`.github/dependabot.yml`) | Opens pull requests to update vulnerable or outdated dependencies and Actions as advisories appear, between scans. This repository ships one for its own Actions |
| **Supabase Security Advisor** | Inspects the *live* database - the grants and policies actually in force - while `SEC-02` and `SEC-18`..`SEC-21` can only read your migration files. Supabase's default grants on `public` are also changing ([changelog](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically)), which only the live database can show |
| **Claude Code `/security-review`** | Built into Claude Code: an AI review of the pending changes on your branch. Complementary - it reasons about intent, this scanner gives deterministic, repeatable rules |

Commercial dependency services (Snyk, Socket.dev) are not integrated: they need an account
and send your dependency list to the vendor. `--engine osv-scanner` or `--engine trivy`
covers the same ground locally.

## 🖥️ How to Use Across Every AI Coding Agent

| AI Agent / IDE | Installed Files | How to Trigger the Full Audit Loop |
| :--- | :--- | :--- |
| **Claude Code** | `.claude/skills/vibe-aegis/SKILL.md`, `.claude/commands/aegis.md`, `CLAUDE.md` | Type `/aegis` or `/aegis --fix` in Claude Code |
| **VS Code (GitHub Copilot)** | `.github/copilot-instructions.md`, `.github/prompts/aegis-audit.prompt.md`, `.vscode/tasks.json` | Run `/aegis-audit` in Copilot Chat or run task `Vibe Aegis: Full Audit` |
| **OpenAI Codex** | `.agents/skills/vibe-aegis/SKILL.md`, `AGENTS.md` | Type `$vibe-aegis` or ask *"Run the Vibe Aegis security and UI/UX audit loop"* |
| **Cursor** | `.cursor/rules/vibe-aegis.mdc`, `.cursorrules`, `AGENTS.md` | Tag `@vibe-aegis.mdc` or ask *"Run the Vibe Aegis pre-publish audit loop"* |
| **Windsurf / Cline / Gemini CLI** | `.windsurf/rules/vibe-aegis.md`, `.clinerules`, `GEMINI.md`, `AGENTS.md` | Ask *"Run the Vibe Aegis security and UI/UX audit loop on this repo"* |
| **Any AI chat (ChatGPT, Claude, Gemini, Perplexity, Grok)** | none — remote fetch | Paste the 2-line prompt at the top of this README |

## 🤖 AI-First Discoverability

This repository is built to be consumed by AI agents in a single pass:

| File | Purpose |
| :--- | :--- |
| [`llms.txt`](llms.txt) | Structured index following the llms.txt standard: summary, one-line remote execution prompts, and a complete annotated file map |
| [`llms-full.txt`](llms-full.txt) | Self-contained document holding the README, agent rules, all three skills, the CLI reference, and the JSON report schema |
| [`schemas/scan-report.schema.json`](schemas/scan-report.schema.json) | Draft 2020-12 JSON Schema so CI pipelines and agents can validate `.aegis/scan-report.json` deterministically |
| [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json) | Plugin marketplace registration for Claude Code and OpenAI Codex |
| [`docs/prompts/`](docs/prompts/) | Three copy-paste bootstrap prompt recipes requiring no clone |

## 📁 Repository Structure

```text
vibe-aegis/
├── README.md                                  # Full documentation & usage guide
├── llms.txt                                   # AI-agent index (llms.txt standard) with remote execution prompts
├── llms-full.txt                              # Entire framework in one fetchable document
├── AGENTS.md                                  # Universal always-on safeguard rules (Codex, Cursor, Windsurf, Copilot)
├── CLAUDE.md                                  # Claude Code bridge & workflow triggers
├── SECURITY.md                                # Defensive scope, passive --url behaviour, vulnerability reporting
├── CONTRIBUTING.md                            # How to add SEC-XX / UX-XX rules with tests
├── CHANGELOG.md                               # Release history
├── LICENSE                                    # MIT License
├── package.json                               # NPX installer & CLI entry point
├── install.sh                                 # Universal zero-dependency shell installer
├── bin/
│   └── vibe-aegis.mjs                         # Node CLI wrapper (`npx vibe-aegis setup | scan`)
├── scripts/
│   └── aegis_scan.py                          # Deterministic 40+ rule static + live HTTP security & UI/UX scanner
├── schemas/
│   └── scan-report.schema.json                # JSON Schema (Draft 2020-12) for .aegis/scan-report.json
├── skills/
│   ├── vibe-aegis/
│   │   ├── SKILL.md                           # Master 10-stage orchestrator skill
│   │   └── agents/openai.yaml                 # OpenAI/Codex workspace skill metadata
│   ├── security-redteam-loop/
│   │   ├── SKILL.md                           # Deep security auditor skill (OWASP, RLS, Auth, Payments, AI/LLM)
│   │   └── agents/openai.yaml                 # OpenAI/Codex workspace skill metadata
│   ├── ui-ux-bug-finder/
│   │   ├── SKILL.md                           # Deep UI/UX, layout, state & accessibility skill
│   │   └── agents/openai.yaml                 # OpenAI/Codex workspace skill metadata
│   └── artifact-leak-hunter/
│       ├── SKILL.md                           # Verify what the build actually ships (bundles, maps, APK)
│       └── agents/openai.yaml                 # OpenAI/Codex workspace skill metadata
├── docs/
│   └── prompts/
│       ├── 01-full-prelaunch-audit.md         # Full 10-stage Security + UI/UX audit prompt
│       ├── 02-security-redteam-loop.md        # Security-only deep red-team prompt
│       └── 03-ui-ux-and-browser-qa.md         # UI/UX & accessibility browser QA prompt
├── adapters/
│   ├── claude/aegis.md                        # Claude Code `/aegis` slash command
│   ├── vscode/                                # Copilot instructions, prompt file, VS Code task
│   ├── cursor/vibe-aegis.mdc                  # Cursor `.cursor/rules/` rule file
│   └── github-actions/vibe-aegis-ci.yml       # Ready-to-use GitHub Actions pre-merge gate
├── .claude-plugin/
│   ├── marketplace.json                       # Claude Code / Codex plugin marketplace manifest
│   └── plugin.json                            # Plugin manifest (4 skills + /aegis command)
├── .github/
│   └── workflows/ci.yml                       # Unit tests, installer smoke test, schema validation
└── tests/
    └── test_scanner.py                        # Automated unit test suite for `aegis_scan.py`
```

## 🧪 Development

```bash
# Run the unit test suite
python3 -B -m unittest discover -s tests -v

# Smoke-test the installer
bash install.sh --target /tmp/test-app --agent all
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the rule-authoring guide and severity rubric.

## ⚖️ Responsible Use & Scope

Vibe Aegis is a **defensive pre-deployment security and UI/UX quality assurance framework**. Its live URL posture checks (`--url`) perform strictly passive, read-only HTTP `GET` requests to inspect security headers and accidental file exposure. It sends no payloads and no credentials.

**Only scan applications and deployments that you own or have explicit authorization to test.** See [`SECURITY.md`](SECURITY.md) for the full scope statement and vulnerability reporting process.

## 📄 License

[MIT](LICENSE) © Tacuns
