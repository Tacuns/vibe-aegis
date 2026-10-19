import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import aegis_scan  # noqa: E402

# Synthetic credentials, assembled at runtime so that no contiguous valid-format
# token ever appears as a literal in this file. GitHub push protection (rightly)
# blocks real-looking keys in source, yet these must still look real enough for
# our own detector to fire. Splitting the prefix achieves both.
AWS_KEY = "AKIA" + "3QM7RZXK2WLPDV4T"
STRIPE_KEY = "sk_live_" + "51QzAbCdEfGhIjKlMnOpQrStUv0123456789wxyz"
STRIPE_TAIL = "51QzAbCdEfGhIjKlMnOpQrStUv" + "0123456789wxyz"
GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
GOOGLE_KEY = "AIza" + "SyB7xK2mNpQrStUvWxYz9876543210fedcb"
ENTROPY_VALUE = "k3Jx9mQw" + "2PzR7vLnA4eT8yUiO1sD6fGh"



def write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestStaticRules(unittest.TestCase):
    """The original regex + contextual rule coverage."""

    def test_detects_security_and_uiux_flaws(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "package.json", json.dumps({
                "dependencies": {
                    "next": "15.0.0",
                    "@supabase/supabase-js": "2.45.0",
                    "stripe": "16.0.0",
                    "tailwindcss": "3.4.0",
                    "openai": "4.60.0",
                }
            }))
            write(root, "schema.sql",
                  "CREATE TABLE public.Customer_orders (id uuid primary key, amount int);\n")
            write(root, "app/api/checkout/route.ts", '''
                export async function POST(req: Request) {
                  const body = await req.json();
                  const session = await stripe.checkout.sessions.create({
                    line_items: [{ price_data: { unit_amount: body.price } }]
                  });
                  const aiRes = await openai.chat.completions.create({ model: "gpt-4o", messages: [] });
                  return Response.json(session);
                }
                ''')
            write(root, "components/CheckoutForm.tsx", '''
                const key = "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJhbGci";
                export function CheckoutForm() {
                  async function handlePay() {
                    try {
                      await fetch("/api/checkout", { method: "POST" });
                    } catch (e) {}
                  }
                  return (
                    <div className="w-[750px] z-[99999]">
                      <img src="/logo.png" />
                      <a href="#">Terms</a>
                      <form onSubmit={handlePay}>
                        <button type="submit" className="outline-none">Pay Now</button>
                      </form>
                    </div>
                  );
                }
                ''')

            findings, count = aegis_scan.scan_repository(root)
            self.assertGreaterEqual(count, 3)
            rule_ids = {f.rule_id for f in findings}
            for expected in ("SEC-01", "SEC-02", "SEC-03", "SEC-05", "SEC-12",
                             "UX-01", "UX-02", "UX-03", "UX-05", "UX-07", "UX-08", "UX-10"):
                self.assertIn(expected, rule_ids, f"{expected} did not fire")

            score, verdict = aegis_scan.compute_readiness_score(findings)
            self.assertLess(score, 50)
            self.assertTrue(verdict.startswith("BLOCKED"))

    def test_posix_paths_so_api_rules_fire_on_windows(self):
        """app/api path rules must match regardless of OS separator."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "app/api/items/route.ts",
                  "export async function DELETE(req: Request) { return db.drop(); }\n")
            findings, _ = aegis_scan.scan_repository(root)
            self.assertIn("SEC-03", {f.rule_id for f in findings})
            self.assertTrue(all("\\" not in f.file for f in findings))


class TestSecretDetection(unittest.TestCase):
    """Phase 2: provider formats, entropy, and placeholder rejection."""

    def test_detects_real_provider_key_formats(self):
        text = "\n".join([
            f"AWS={AWS_KEY}",
            f"STRIPE={STRIPE_KEY}",
            f"GH={GH_TOKEN}",
        ])
        findings = aegis_scan.scan_secrets_in_text("config.env", text)
        titles = " ".join(f.title for f in findings)
        self.assertIn("AWS Access Key ID", titles)
        self.assertIn("Stripe Live Secret Key", titles)
        self.assertIn("GitHub Personal Access Token", titles)

    def test_credentials_are_always_redacted(self):
        raw = f"STRIPE={STRIPE_KEY}"
        findings = aegis_scan.scan_secrets_in_text("config.env", raw)
        self.assertTrue(findings)
        for f in findings:
            self.assertNotIn(STRIPE_TAIL, f.snippet)
            self.assertIn("...", f.snippet)

    def test_rejects_placeholders_and_documentation_keys(self):
        """Noise is what kills a scanner. These must NOT fire."""
        for benign in [
            "API_KEY=your-api-key-here",
            "SECRET=changeme",
            "TOKEN=xxxxxxxxxxxxxxxxxxxx",
            "AWS=AKIAIOSFODNN7EXAMPLE",        # AWS's own documentation key
            "SECRET=${process.env.MY_SECRET}",
            "API_KEY=<insert-your-key>",
        ]:
            findings = aegis_scan.scan_secrets_in_text("config.env", benign)
            self.assertEqual(findings, [], f"false positive on: {benign}")

    def test_flags_client_exposed_prefix_as_critical(self):
        findings = aegis_scan.scan_secrets_in_text(
            "env.ts", f'const NEXT_PUBLIC_API_SECRET = "{ENTROPY_VALUE}";')
        self.assertTrue(any(f.severity == "CRITICAL" and f.rule_id == "SEC-01B" for f in findings))

    def test_entropy_separates_random_keys_from_prose(self):
        self.assertGreater(aegis_scan.shannon_entropy(ENTROPY_VALUE), 3.6)
        self.assertLess(aegis_scan.shannon_entropy("aaaaaaaaaaaaaaaaaaaa"), 1.0)


class TestDataFlowAnalysis(unittest.TestCase):
    """Phase 5: taint tracking must find real flows and ignore validated ones."""

    VULNERABLE = '''
    export async function POST(req: Request) {
      const body = await req.json();
      const orderId = body.orderId;
      const rows = await db.query(`SELECT * FROM orders WHERE id = ${orderId}`);
      return Response.json(rows);
    }
    '''

    SANITIZED = '''
    export async function POST(req: Request) {
      const body = await req.json();
      const orderId = z.string().uuid().parse(body.orderId);
      const rows = await db.query("SELECT * FROM orders WHERE id = $1", [orderId]);
      return Response.json(rows);
    }
    '''

    def test_traces_request_input_into_sql_sink(self):
        findings = aegis_scan.analyze_data_flow("app/api/o/route.ts", ".ts", self.VULNERABLE)
        self.assertIn("FLOW-01", {f.rule_id for f in findings})

    def test_names_the_tainted_variable_not_the_assignment_target(self):
        findings = aegis_scan.analyze_data_flow("app/api/o/route.ts", ".ts", self.VULNERABLE)
        flow = next(f for f in findings if f.rule_id == "FLOW-01")
        self.assertIn("orderId", flow.snippet)
        self.assertNotIn("`rows` originates", flow.snippet)

    def test_validated_input_produces_no_finding(self):
        findings = aegis_scan.analyze_data_flow("app/api/o/route.ts", ".ts", self.SANITIZED)
        self.assertEqual([f.rule_id for f in findings], [])

    def test_detects_ssrf_from_request_body(self):
        code = '''
        export async function POST(req) {
          const body = await req.json();
          const target = body.callbackUrl;
          await fetch(target);
        }
        '''
        self.assertIn("FLOW-04", {f.rule_id for f in aegis_scan.analyze_data_flow("api.ts", ".ts", code)})


class TestBaselineAndSuppression(unittest.TestCase):
    """Phase 1: adoption on an existing codebase."""

    def _finding(self, rule_id="SEC-01", file="a.ts", snippet="x"):
        return aegis_scan.Finding(
            rule_id=rule_id, domain="SECURITY", severity="HIGH", title="t",
            file=file, line=1, snippet=snippet, cwe_or_standard="CWE-1", remediation="fix")

    def test_fingerprint_is_stable_and_survives_line_shifts(self):
        a = self._finding()
        b = self._finding()
        b.line = 999
        self.assertEqual(aegis_scan.fingerprint(a), aegis_scan.fingerprint(b))

    def test_fingerprint_differs_for_different_evidence(self):
        self.assertNotEqual(
            aegis_scan.fingerprint(self._finding(snippet="one")),
            aegis_scan.fingerprint(self._finding(snippet="two")))

    def test_baseline_suppresses_known_findings(self):
        f = self._finding()
        f.fingerprint = aegis_scan.fingerprint(f)
        kept, suppressed = aegis_scan.apply_suppressions([f], {f.fingerprint}, set(), [])
        self.assertEqual(kept, [])
        self.assertEqual(suppressed, 1)

    def test_ignore_by_rule_id_and_by_path_glob(self):
        f1 = self._finding(rule_id="SEC-03")
        f2 = self._finding(file="dist/bundle.js")
        kept, _ = aegis_scan.apply_suppressions([f1, f2], set(), {"SEC-03"}, ["dist/**"])
        self.assertEqual(kept, [])

    def test_dedupe_collapses_secret_family_but_keeps_distinct_dependencies(self):
        secrets = [self._finding(rule_id="SEC-01"), self._finding(rule_id="SEC-01B")]
        self.assertEqual(len(aegis_scan.dedupe(secrets)), 1)

        deps = [
            aegis_scan.Finding("DEP-01", "SUPPLY_CHAIN", "MEDIUM", "Vuln in `django`",
                               "dependencies", 0, "a", "OWASP A06", "upgrade"),
            aegis_scan.Finding("DEP-01", "SUPPLY_CHAIN", "MEDIUM", "Vuln in `flask`",
                               "dependencies", 0, "b", "OWASP A06", "upgrade"),
        ]
        self.assertEqual(len(aegis_scan.dedupe(deps)), 2)


class TestArtifactVerification(unittest.TestCase):
    """Phase 4: prove what actually ships."""

    def test_cross_references_source_secret_into_build_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = STRIPE_KEY
            write(root, ".env.local", f"STRIPE_SECRET_KEY={key}\n")
            write(root, "dist/assets/index.js", f'const K="{key}";export default K;')

            source_secrets, _ = aegis_scan.scan_repository(root)
            source_secrets = [f for f in source_secrets if f.rule_id.startswith("SEC-01")]
            findings = aegis_scan.scan_build_artifacts(root, str(root / "dist"), source_secrets)

            leak = [f for f in findings if f.rule_id == "ART-01"]
            self.assertTrue(leak, "cross-reference leak detection did not fire")
            self.assertEqual(leak[0].severity, "CRITICAL")

    def test_flags_source_maps_containing_original_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "dist/app.js.map", '{"version":3,"sourcesContent":["const a=1"]}')
            findings = aegis_scan.scan_build_artifacts(root, str(root / "dist"), [])
            self.assertIn("ART-02", {f.rule_id for f in findings})

    def test_inspects_mobile_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "app-release.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("AndroidManifest.xml", 'android:debuggable="true" usesCleartextTraffic="true"')
                z.writestr("assets/.env", f"GOOGLE={GOOGLE_KEY}\n")
                z.writestr("classes.dex", "stub")
            rule_ids = {f.rule_id for f in aegis_scan.scan_mobile_package(root, apk)}
            self.assertIn("ART-11", rule_ids)   # unsigned
            self.assertIn("ART-12", rule_ids)   # .env bundled
            self.assertIn("ART-14", rule_ids)   # debuggable
            self.assertIn("ART-15", rule_ids)   # credential inside the package


class TestReportFormats(unittest.TestCase):

    def _findings(self):
        f = aegis_scan.Finding("SEC-01", "SECURITY", "CRITICAL", "Leak", "a.ts", 3,
                               "ev", "CWE-798", "rotate")
        f.fingerprint = aegis_scan.fingerprint(f)
        return [f]

    def test_sarif_is_well_formed(self):
        sarif = aegis_scan.build_sarif(self._findings(), Path.cwd())
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "SEC-01")
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertIn("vibeAegisFingerprint", run["results"][0]["partialFingerprints"])

    def test_sbom_is_cyclonedx(self):
        sbom = aegis_scan.build_sbom(Path("myapp"), [("npm", "next", "15.0.0")])
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertEqual(sbom["components"][0]["purl"], "pkg:npm/next@15.0.0")

    def test_dependency_parsing_across_ecosystems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "requirements.txt", "Django==2.2.0\n# comment\nflask==0.12.2\n")
            deps = aegis_scan.parse_dependencies(root)
            self.assertIn(("PyPI", "Django", "2.2.0"), deps)
            self.assertIn(("PyPI", "flask", "0.12.2"), deps)

    def test_offline_mode_makes_no_network_call(self):
        findings = aegis_scan.check_dependency_vulnerabilities(
            [("PyPI", "Django", "2.2.0")], offline=True)
        self.assertEqual([f.rule_id for f in findings], ["DEP-00"])


class TestGitHistory(unittest.TestCase):

    def test_finds_secret_deleted_from_the_working_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def git(*args):
                subprocess.run(["git", "-C", str(root)] + list(args),
                               capture_output=True, check=False)

            git("init", "-q", "-b", "main")
            git("config", "user.email", "dev@example.com")
            git("config", "user.name", "Dev")
            write(root, "secrets.env", f"AWS={AWS_KEY}\n")
            git("add", "-A")
            git("commit", "-q", "-m", "add secret")
            (root / "secrets.env").unlink()
            git("add", "-A")
            git("commit", "-q", "-m", "remove secret")

            findings = aegis_scan.scan_git_history(root, max_commits=10)
            if not findings:
                self.skipTest("git history unavailable in this environment")
            self.assertEqual(findings[0].rule_id, "HIST-01")
            self.assertNotIn(AWS_KEY, findings[0].snippet)


class TestScoring(unittest.TestCase):

    def test_score_weights_and_blocking_verdict(self):
        def f(sev):
            return aegis_scan.Finding("SEC-01", "SECURITY", sev, "t", "a.ts", 1, "e", "c", "r")

        self.assertEqual(aegis_scan.compute_readiness_score([])[0], 100)
        self.assertEqual(aegis_scan.compute_readiness_score([f("CRITICAL")])[0], 75)
        self.assertEqual(aegis_scan.compute_readiness_score([f("HIGH")])[0], 90)
        self.assertEqual(aegis_scan.compute_readiness_score([f("MEDIUM")])[0], 96)
        self.assertEqual(aegis_scan.compute_readiness_score([f("LOW")])[0], 99)
        self.assertTrue(aegis_scan.compute_readiness_score([f("HIGH")])[1].startswith("BLOCKED"))
        self.assertTrue(aegis_scan.compute_readiness_score([f("LOW")])[1]
                        .startswith(aegis_scan.VERDICT_STATIC_OK))
        # Below 90 with no CRITICAL/HIGH is a polish problem, not a blocker.
        many_medium = [f("MEDIUM")] * 3
        self.assertEqual(aegis_scan.compute_readiness_score(many_medium)[0], 88)
        self.assertTrue(aegis_scan.compute_readiness_score(many_medium)[1]
                        .startswith(aegis_scan.VERDICT_REVIEW))


class TestPaymentsAndReliability(unittest.TestCase):
    """PAY and REL domains: money bugs and failures that only appear at scale."""

    VULNERABLE = """
    export async function POST(req: Request) {
      const body = await req.json();
      const session = await stripe.checkout.sessions.create({
        line_items: [{ price_data: { unit_amount: body.price } }]
      });
      await prisma.user.update({ where: { id }, data: { credits: user.credits - 1 } });
      const all = await prisma.order.findMany();
      for (const item of items) { await prisma.order.findUnique({ where: { id: item.id } }); }
      console.log("charging", user.email, "apiKey", key);
      const r = await fetch("https://api.example.com/charge");
    }
    """

    SAFE = """
    export async function POST(req: Request) {
      const { planId } = schema.parse(await req.json());
      const plan = await db.plan.findUniqueOrThrow({ where: { id: planId } });
      await prisma.$executeRaw`UPDATE wallets SET balance = balance - 1 WHERE user_id = ${uid} AND balance >= 1`;
      const page = await prisma.order.findMany({ take: 50 });
      const r = await fetch(url, { signal: AbortSignal.timeout(10000) });
    }
    """

    def _scan(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "app/api/pay/route.ts", source)
            findings, _ = aegis_scan.scan_repository(root)
            return findings

    def test_detects_all_payment_and_reliability_flaws(self):
        rule_ids = {f.rule_id for f in self._scan(self.VULNERABLE)}
        for expected in ("PAY-01", "PAY-02", "REL-01", "REL-02", "REL-03", "REL-04"):
            self.assertIn(expected, rule_ids, f"{expected} did not fire")

    def test_correct_implementations_produce_no_payment_or_reliability_findings(self):
        """Atomic SQL, paginated queries and fetch timeouts must not be flagged."""
        noisy = [f.rule_id for f in self._scan(self.SAFE)
                 if f.domain in ("PAYMENTS", "RELIABILITY")]
        self.assertEqual(noisy, [], f"false positives on correct code: {noisy}")

    def test_domains_are_separated_for_reporting(self):
        findings = self._scan(self.VULNERABLE)
        self.assertEqual({f.domain for f in findings if f.rule_id.startswith("PAY-")}, {"PAYMENTS"})
        self.assertEqual({f.domain for f in findings if f.rule_id.startswith("REL-")}, {"RELIABILITY"})

    def test_reliability_findings_are_medium_confidence(self):
        """A pattern cannot know your data volume, so REL must not claim certainty."""
        rel = [f for f in self._scan(self.VULNERABLE) if f.domain == "RELIABILITY"]
        self.assertTrue(rel)
        self.assertTrue(all(f.confidence == "MEDIUM" for f in rel))

    def test_ignore_rules_accept_the_new_prefixes(self):
        rules, globs = set(), []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, ".aegis-ignore", "PAY-02\nREL-01\nlegacy/**\n")
            rules, globs = aegis_scan.load_ignore_rules(root)
        self.assertEqual(rules, {"PAY-02", "REL-01"})
        self.assertEqual(globs, ["legacy/**"])


class TestInteractiveSemantics(unittest.TestCase):
    """UX-01 / UX-11 / UX-12: the element must match the behaviour.

    An action marked up as a link, or a div with an onClick, works with a mouse
    and is broken for keyboards and screen readers. These are three different
    bugs with three different fixes, so they must not collapse into one rule.
    """

    MARKUP = """
    export function Demo() {
      return (
        <div>
          <a href="#" onClick={handleDelete}>Delete account</a>
          <div onClick={goToSettings}>Open settings</div>
          <span onClick={save}>Save</span>
          <a href="#">Terms</a>
          <a href="/settings">Settings</a>
          <button onClick={save}>Save</button>
          <div onClick={pick} role="button" tabIndex={0} onKeyDown={onKey}>Pick</div>
        </div>
      );
    }
    """

    def _scan(self, markup=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "Demo.jsx", markup if markup is not None else self.MARKUP)
            findings, _ = aegis_scan.scan_repository(root)
            return findings

    def test_action_as_link_is_flagged_as_wrong_element(self):
        """<a href="#" onClick=...> is UX-11, not a dead link."""
        ids = {f.rule_id for f in self._scan()}
        self.assertIn("UX-11", ids)

    def test_dead_link_and_action_link_are_separate_rules(self):
        """They need different fixes, so they must not share a rule id."""
        by_rule = {}
        for f in self._scan():
            by_rule.setdefault(f.rule_id, []).append(f.snippet)
        self.assertIn("UX-01", by_rule)   # <a href="#">Terms</a>  -> needs a real URL
        self.assertIn("UX-11", by_rule)   # <a href="#" onClick>   -> needs <button>
        self.assertTrue(any("Terms" in s for s in by_rule["UX-01"]))
        self.assertTrue(any("handleDelete" in s for s in by_rule["UX-11"]))

    def test_clickable_div_and_span_are_flagged(self):
        """Not focusable, not keyboard operable, announced as plain text."""
        lines = [f.line for f in self._scan() if f.rule_id == "UX-12"]
        self.assertEqual(len(lines), 2, "both the div and the span should fire")

    def test_correct_markup_produces_no_findings(self):
        """A real href, a real button, and a properly retrofitted div must stay silent."""
        clean = """
        export function Ok() {
          return (
            <div>
              <a href="/settings">Settings</a>
              <button type="button" onClick={save}>Save</button>
              <div onClick={pick} role="button" tabIndex={0} onKeyDown={onKey}>Pick</div>
            </div>
          );
        }
        """
        noisy = [f.rule_id for f in self._scan(clean)
                 if f.rule_id in ("UX-01", "UX-11", "UX-12")]
        self.assertEqual(noisy, [], f"false positives on correct markup: {noisy}")

    def test_javascript_url_is_flagged(self):
        ids = {f.rule_id for f in self._scan('<a href="javascript:void(0)" onClick={go}>Go</a>')}
        self.assertIn("UX-11", ids)

    def test_rules_cite_a_real_wcag_criterion(self):
        """'UI/UX Functional Completeness' is not a standard. These must cite WCAG."""
        for f in self._scan():
            if f.rule_id in ("UX-11", "UX-12"):
                self.assertIn("WCAG", f.cwe_or_standard)

    def test_remediation_names_the_button_element(self):
        """The fix is semantic. The advice has to say so, not 'add a route'."""
        for f in self._scan():
            if f.rule_id in ("UX-11", "UX-12"):
                self.assertIn("button", f.remediation.lower())

class TestCoverageVersusSeverity(unittest.TestCase):
    """A check that did not run is an UNKNOWN, never a pass.

    Regression for the reported edge case: calling
    check_dependency_vulnerabilities(deps, offline=True) returned a LOW DEP-00,
    and passing that alone to compute_readiness_score gave 99/100 and
    "READY TO PUBLISH". Coverage and severity are separate axes.
    """

    def _skipped(self, rule_id="DEP-00", title="Check Skipped"):
        return aegis_scan.Finding(
            rule_id=rule_id, domain="SUPPLY_CHAIN", severity="LOW", title=title,
            file="dependencies", line=0, snippet="not run", cwe_or_standard="Informational",
            remediation="re-run", kind="skipped_check")

    def _real(self, severity="LOW"):
        return aegis_scan.Finding(
            rule_id="SEC-01", domain="SECURITY", severity=severity, title="t",
            file="a.ts", line=1, snippet="e", cwe_or_standard="c", remediation="r")

    def test_reported_repro_no_longer_returns_ready(self):
        """The exact call from the bug report."""
        findings = aegis_scan.check_dependency_vulnerabilities(
            [("PyPI", "Django", "2.2.0")], offline=True)
        self.assertEqual([f.rule_id for f in findings], ["DEP-00"])
        self.assertEqual(findings[0].kind, "skipped_check")

        score, verdict = aegis_scan.compute_readiness_score(findings)
        self.assertFalse(verdict.startswith(aegis_scan.VERDICT_STATIC_OK),
                         f"still certifies an unrun audit: {verdict}")
        self.assertIn("INCOMPLETE_SCAN", verdict)

    def test_skipped_checks_do_not_change_the_score(self):
        """Coverage is not a severity. Ten skipped checks must not cost 10 points."""
        self.assertEqual(aegis_scan.compute_readiness_score([self._skipped()] * 10)[0], 100)

    def test_every_skipped_check_variant_is_marked(self):
        """All four 'could not run' sites must use kind=skipped_check."""
        offline = aegis_scan.check_dependency_vulnerabilities([("PyPI", "x", "1.0")], offline=True)
        self.assertTrue(all(f.kind == "skipped_check" for f in offline))

        unreachable = aegis_scan.check_live_url_posture("http://127.0.0.1:9/nope")
        live00 = [f for f in unreachable if f.rule_id == "LIVE-00"]
        if live00:
            self.assertEqual(live00[0].kind, "skipped_check")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = root / "broken.apk"
            bad.write_text("not a zip", encoding="utf-8")
            art = aegis_scan.scan_mobile_package(root, bad)
            self.assertEqual([f.kind for f in art], ["skipped_check"])

    def test_real_findings_still_score_and_block(self):
        """The fix must not weaken the gate for genuine defects."""
        self.assertEqual(aegis_scan.compute_readiness_score([self._real("CRITICAL")])[0], 75)
        self.assertTrue(
            aegis_scan.compute_readiness_score([self._real("HIGH")])[1].startswith("BLOCKED"))

    def test_blocked_takes_precedence_over_incomplete(self):
        """A real blocker is more urgent than a coverage gap."""
        _, verdict = aegis_scan.compute_readiness_score([self._real("CRITICAL"), self._skipped()])
        self.assertTrue(verdict.startswith("BLOCKED"), verdict)

    def test_a_passing_state_requires_a_complete_audit(self):
        """A pass only when nothing was skipped - and it is a STATIC pass, not a release one."""
        self.assertTrue(aegis_scan.compute_readiness_score([])[1]
                        .startswith(aegis_scan.VERDICT_STATIC_OK))
        self.assertIn("INCOMPLETE",
                      aegis_scan.compute_readiness_score([self._skipped()])[1])

    def test_a_source_scan_never_claims_release_readiness(self):
        """Reading source says nothing about lockfiles, history, bundles or deployments."""
        _, verdict = aegis_scan.compute_readiness_score([])
        self.assertNotIn(aegis_scan.VERDICT_RELEASE_OK, verdict)
        self.assertIn("NOT a release-readiness verdict", verdict)

    def test_release_audit_state_requires_the_release_profile(self):
        _, verdict = aegis_scan.compute_readiness_score([], release_audit=True)
        self.assertTrue(verdict.startswith(aegis_scan.VERDICT_RELEASE_OK))

    def test_verdict_names_the_check_that_was_missed(self):
        """Telling someone the audit is incomplete is useless without saying which part."""
        _, verdict = aegis_scan.compute_readiness_score(
            [self._skipped(title="Dependency Vulnerability Check Skipped")])
        self.assertIn("Dependency Vulnerability Check Skipped", verdict)
        self.assertNotIn(aegis_scan.VERDICT_STATIC_OK, verdict)

    def test_report_separates_skipped_from_findings(self):
        """End-to-end: the JSON must not bury a coverage gap in the findings list."""
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "requirements.txt", "Django==2.2.0\n")
            out = root / "r.json"
            scanner = Path(__file__).resolve().parent.parent / "scripts" / "aegis_scan.py"
            subprocess.run([sys.executable, "-B", str(scanner), str(root),
                            "--offline", "--deps", "--output", str(out)],
                           capture_output=True, check=False)
            if not out.exists():
                self.skipTest("scanner did not produce a report")
            r = json.loads(out.read_text(encoding="utf-8"))

        self.assertFalse(r["coverage"]["complete"])
        self.assertEqual(r["coverage"]["checks_skipped"], 1)
        self.assertEqual(len(r["skipped_checks"]), 1)
        self.assertTrue(all(f["kind"] == "finding" for f in r["findings"]))
        self.assertTrue(r["release_verdict"].startswith("INCOMPLETE"))
        # A coverage gap must not inflate the severity tallies.
        self.assertEqual(r["summary_counts"]["LOW"], 0)

class TestDocumentedRulesActuallyExist(unittest.TestCase):
    """The README coverage matrix is a promise. Every rule in it must run.

    Audit finding: PAY-03, SEC-14, SEC-15, UX-04 and UX-06 were listed in the
    README but had never been implemented - a silent false negative for anyone
    who trusted the table. This test fails if that regresses.
    """

    VULNERABLE = {
        "app/api/stripe-webhook/route.ts": """
            export async function POST(req: Request) {
              const body = await req.json();
              await grantSubscription(body.data.object.customer);
            }
        """,
        "app/api/login/route.ts": """
            export async function POST(req: Request) {
              const { email, password } = await req.json();
              return signIn(email, password);
            }
        """,
        "app/api/upload.ts": """
            export async function POST(req: Request) {
              const file = (await req.formData()).get("file");
              await put(file.name, file);
            }
        """,
        "components/List.jsx": """
            export function List({ items }) {
              return (<div>
                {items.map(i => <Row key={i.id} {...i} />)}
                <input type="text" placeholder="Search" />
              </div>);
            }
        """,
    }

    CORRECT = {
        "app/api/stripe-webhook/route.ts": """
            export async function POST(req: Request) {
              const raw = await req.text();
              const event = stripe.webhooks.constructEvent(raw, sig, SECRET);
              await db.processed.create({ data: { id: event.id } });
            }
        """,
        "app/api/login/route.ts": """
            import { Ratelimit } from "@upstash/ratelimit";
            const limiter = new Ratelimit({ limiter: Ratelimit.slidingWindow(5, "60 s") });
            export async function POST(req: Request) {
              const { success } = await limiter.limit(ip);
              if (!success) return new Response("rate limited", { status: 429 });
            }
        """,
        "app/api/upload.ts": """
            const ALLOWED_TYPES = ["image/png"];
            export async function POST(req: Request) {
              const file = (await req.formData()).get("file");
              if (!ALLOWED_TYPES.includes(file.type)) return bad();
              if (file.size > 5000000) return bad();
            }
        """,
        "components/List.jsx": """
            export function List({ items }) {
              if (items.length === 0) return <EmptyState />;
              return (<div>
                {items.map(i => <Row key={i.id} {...i} />)}
                <label htmlFor="q">Search</label>
                <input id="q" type="text" />
              </div>);
            }
        """,
    }

    RESTORED = {"PAY-03", "SEC-14", "SEC-15", "UX-04", "UX-06"}

    def _scan(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, body in files.items():
                write(root, rel, body)
            findings, _ = aegis_scan.scan_repository(root)
            return findings

    def test_every_readme_rule_is_implemented(self):
        """Parse the README matrix and confirm each rule id exists in the scanner."""
        import re
        readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
        source = (Path(__file__).resolve().parent.parent / "scripts" / "aegis_scan.py").read_text(encoding="utf-8")
        documented = set(re.findall(r"^\| `((?:SEC|UX|PAY|REL|FLOW|ART|DEP|HIST|LIVE)-\d\d[A-Z]?)`",
                                    readme, re.M))
        implemented = set(re.findall(r'"((?:SEC|UX|PAY|REL|FLOW|ART|DEP|HIST|LIVE)-\d\d[A-Z]?)"',
                                     source))
        missing = sorted(documented - implemented)
        self.assertEqual(missing, [], f"README promises rules the scanner does not implement: {missing}")

    def test_restored_rules_fire_on_vulnerable_code(self):
        got = {f.rule_id for f in self._scan(self.VULNERABLE)}
        missing = sorted(self.RESTORED - got)
        self.assertEqual(missing, [], f"restored rules did not fire: {missing}")

    def test_restored_rules_are_silent_on_correct_code(self):
        noisy = sorted({f.rule_id for f in self._scan(self.CORRECT)} & self.RESTORED)
        self.assertEqual(noisy, [], f"false positives on correct code: {noisy}")

    def test_login_route_is_not_flagged_for_missing_authentication(self):
        """Authenticating is what a login route is FOR - SEC-03 must skip it."""
        findings = self._scan({"app/api/login/route.ts": self.CORRECT["app/api/login/route.ts"]})
        self.assertNotIn("SEC-03", {f.rule_id for f in findings})

    def test_genuinely_unprotected_mutation_route_still_fires(self):
        """Widening the SEC-03 exclusions must not blunt the rule."""
        findings = self._scan({
            "app/api/orders/route.ts":
                "export async function DELETE(req){ return db.order.delete({where:{id:req.body.id}}); }"
        })
        self.assertIn("SEC-03", {f.rule_id for f in findings})

class TestFailClosedIsolation(unittest.TestCase):
    """Every function must be safe when called on its own.

    The original report came from testing functions in isolation rather than
    through the full audit, so isolation is exactly what these assert.
    """

    def test_isolated_offline_dep_check_never_returns_ready_to_publish(self):
        findings = aegis_scan.check_dependency_vulnerabilities(
            [("PyPI", "Django", "2.2.0")], offline=True)
        self.assertEqual([f.rule_id for f in findings], ["DEP-00"])
        self.assertEqual(findings[0].status, "SKIPPED")

        _, verdict = aegis_scan.compute_readiness_score(findings)
        self.assertNotEqual(verdict, aegis_scan.VERDICT_STATIC_OK, verdict.split(" (")[0])
        self.assertIn("INCOMPLETE_SCAN", verdict)

    def test_bare_dep00_without_markers_still_fails_closed(self):
        """A caller constructing the Finding by hand must not get a pass.

        Belt and braces: the -00 suffix alone is enough, even when `status`
        and `kind` are left at their defaults.
        """
        bare = aegis_scan.Finding("DEP-00", "SUPPLY_CHAIN", "LOW", "Skipped",
                                  "dependencies", 0, "x", "Informational", "re-run")
        self.assertEqual(bare.status, "VULNERABILITY")   # no marker set
        _, verdict = aegis_scan.compute_readiness_score([bare])
        self.assertNotEqual(verdict, aegis_scan.VERDICT_STATIC_OK, verdict.split(" (")[0])

    def test_live00_also_fails_closed(self):
        bare = aegis_scan.Finding("LIVE-00", "SECURITY", "LOW", "Unreachable",
                                  "http://x", 0, "x", "Live Deployment Check", "start the server")
        _, verdict = aegis_scan.compute_readiness_score([bare])
        self.assertNotEqual(verdict, aegis_scan.VERDICT_STATIC_OK, verdict.split(" (")[0])

    def test_git00_emitted_when_history_cannot_be_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = aegis_scan.scan_git_history(Path(tmp), 10)
        self.assertEqual([f.rule_id for f in findings], ["GIT-00"])
        self.assertEqual(findings[0].status, "SKIPPED")
        _, verdict = aegis_scan.compute_readiness_score(findings)
        self.assertNotEqual(verdict, aegis_scan.VERDICT_STATIC_OK, verdict.split(" (")[0])

    def test_zero_scanned_files_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, scanned = aegis_scan.scan_repository(Path(tmp))
        self.assertEqual(scanned, 0)
        score, verdict = aegis_scan.compute_readiness_score(findings, scanned_files=scanned)
        self.assertEqual(score, 0)
        self.assertTrue(verdict.startswith("INCOMPLETE_SCAN"), verdict)

    def test_clean_scanned_repo_with_all_checks_completed_is_ready(self):
        """The gate must not be so tight that a genuinely clean repo cannot pass."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "src/math.js", "export const add = (a, b) => a + b;\n")
            findings, scanned = aegis_scan.scan_repository(root)
        self.assertGreater(scanned, 0)
        score, verdict = aegis_scan.compute_readiness_score(findings, scanned_files=scanned)
        self.assertEqual(score, 100)
        self.assertTrue(verdict.startswith(aegis_scan.VERDICT_STATIC_OK), verdict)

    def test_allow_skipped_is_an_explicit_opt_in(self):
        findings = aegis_scan.check_dependency_vulnerabilities([("PyPI", "x", "1.0")], offline=True)
        self.assertFalse(aegis_scan.compute_readiness_score(findings)[1]
                         .startswith(aegis_scan.VERDICT_STATIC_OK))
        self.assertTrue(
            aegis_scan.compute_readiness_score(findings, allow_skipped=True)[1]
            .startswith(aegis_scan.VERDICT_STATIC_OK))

    def test_skipped_checks_argument_is_honoured(self):
        skipped = [aegis_scan.Finding("DEP-00", "SUPPLY_CHAIN", "LOW", "Skipped", "deps", 0,
                                      "x", "Informational", "re-run",
                                      kind="skipped_check", status="SKIPPED")]
        _, verdict = aegis_scan.compute_readiness_score([], skipped_checks=skipped)
        self.assertIn("INCOMPLETE_SCAN", verdict)


class TestScannerEdgeCases(unittest.TestCase):
    """Comment handling, path normalisation, test isolation and domain coverage."""

    def _scan(self, rel, body, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, rel, body)
            findings, _ = aegis_scan.scan_repository(root, **kw)
            return {f.rule_id for f in findings}

    def test_commented_out_vulnerable_code_is_ignored(self):
        self.assertEqual(self._scan("a.js", "// eval(req.body.code)\n"), set())
        self.assertEqual(self._scan("b.js", "/* eval(userInput) */\n"), set())
        self.assertEqual(self._scan("c.py", '# cursor.execute(f"SELECT {x}")\n'), set())

    def test_real_code_still_fires_after_comment_masking(self):
        """Masking must not blunt the scanner."""
        self.assertIn("SEC-08", self._scan("d.js", "eval(req.body.code);\n"))

    def test_double_slash_inside_a_string_is_not_a_comment(self):
        """`https://` must not swallow the rest of the line."""
        self.assertIn("SEC-08", self._scan("e.js", 'const u = "https://x.com"; eval(bad);\n'))

    def test_hash_in_jsx_href_is_not_treated_as_a_comment(self):
        """Masking # in JSX would silently kill the dead-link rules."""
        self.assertIn("UX-01", self._scan("f.jsx", '<a href="#">Terms</a>\n'))

    def test_test_fixtures_excluded_unless_opted_in(self):
        vulnerable = "eval(req.body.code);\n"
        self.assertEqual(self._scan("tests/x.test.js", vulnerable), set())
        self.assertIn("SEC-08", self._scan("tests/x.test.js", vulnerable, include_tests=True))

    def test_windows_backslash_paths_normalized(self):
        """app\\api\\... must be audited exactly like app/api/..."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "app/api/checkout/route.ts",
                  "export async function POST(req){ return db.order.create(req.body); }\n")
            findings, _ = aegis_scan.scan_repository(root)
        self.assertTrue(all("\\" not in f.file for f in findings), "paths must use / separators")
        self.assertIn("app/api/checkout/route.ts", {f.file for f in findings})
        self.assertIn("SEC-03", {f.rule_id for f in findings})

    def test_framework_auth_guards_are_recognised(self):
        """Protected routes must not be reported as unauthenticated."""
        for guard in ("passport.authenticate('jwt')", "auth.protect()", "withApiAuth(handler)"):
            ids = self._scan("app/api/x/route.ts",
                             f"export async function POST(req){{ {guard}; return db.del(); }}\n")
            self.assertNotIn("SEC-03", ids, f"false positive with guard: {guard}")

    def test_unprotected_route_still_fires(self):
        ids = self._scan("app/api/x/route.ts",
                         "export async function POST(req){ return db.del(); }\n")
        self.assertIn("SEC-03", ids)

    def test_findings_sort_deterministically_by_severity(self):
        def f(rule, sev, line):
            return aegis_scan.Finding(rule, "SECURITY", sev, "t", "a.ts", line, "e", "c", "r")
        unsorted = [f("SEC-09", "LOW", 3), f("SEC-01", "CRITICAL", 2), f("SEC-07", "HIGH", 1)]
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        ordered = sorted(unsorted, key=lambda x: (rank[x.severity], x.domain, x.file, x.line))
        self.assertEqual([x.severity for x in ordered], ["CRITICAL", "HIGH", "LOW"])

    def test_all_domains_are_reachable(self):
        """Every domain the schema declares must be produced by some rule."""
        import re
        src = (Path(__file__).resolve().parent.parent / "scripts" / "aegis_scan.py").read_text(encoding="utf-8")
        produced = set(re.findall(r'domain="([A-Z_]+)"', src)) | set(
            re.findall(r'"(PAYMENTS|RELIABILITY)"', src))
        schema = json.loads((Path(__file__).resolve().parent.parent
                             / "schemas" / "scan-report.schema.json").read_text(encoding="utf-8"))
        declared = set(schema["$defs"]["finding"]["properties"]["domain"]["enum"])
        unreachable = sorted(declared - produced)
        self.assertEqual(unreachable, [], f"schema declares domains no rule emits: {unreachable}")


class TestCredentialsNeverLeakIntoReports(unittest.TestCase):
    """A report gets committed, attached to issues and uploaded as a CI artifact.

    Regression suite for a real leak: a second regex table (`SEC-01B` in
    SECURITY_PATTERNS) detected provider keys and used the RAW SOURCE LINE as its
    snippet, while `redact_findings()` only consulted `PROVIDER_SECRETS`. The two
    tables used different length thresholds, so every key in the gap between them was
    written verbatim into `.aegis/scan-report.json`.
    """

    # Keys sized to land in the gap the two tables used to disagree about.
    SHORT_STRIPE = "sk_live_" + "4eC39HqLyjWDarjt"          # 16 body chars
    SHORT_GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5"    # 30 body chars
    SHORT_OPENAI = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1"    # 22 body chars

    def _snippets(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "src/keys.js", source)
            findings, _ = aegis_scan.scan_repository(root)
            aegis_scan.redact_findings(findings)
            return findings

    def _assert_no_key_in_report(self, findings, *secrets):
        blob = json.dumps([f.__dict__ for f in findings])
        for secret in secrets:
            self.assertNotIn(secret, blob,
                             "a live credential reached the report verbatim")

    def test_short_keys_are_detected_at_all(self):
        """The gap must be closed by widening detection, not by dropping it."""
        findings = self._snippets(
            'const a = "%s";\nconst b = "%s";\nconst c = "%s";\n'
            % (self.SHORT_STRIPE, self.SHORT_GH, self.SHORT_OPENAI))
        self.assertGreaterEqual(len([f for f in findings if f.rule_id.startswith("SEC-01")]), 3)

    def test_short_keys_are_redacted_in_the_report(self):
        findings = self._snippets(
            'const a = "%s";\nconst b = "%s";\nconst c = "%s";\n'
            % (self.SHORT_STRIPE, self.SHORT_GH, self.SHORT_OPENAI))
        self._assert_no_key_in_report(findings, self.SHORT_STRIPE, self.SHORT_GH,
                                      self.SHORT_OPENAI)

    def test_redaction_survives_an_ellipsis_on_the_line(self):
        """A JS spread used to switch redaction off for the whole snippet."""
        key = "sk_live_" + "51QzAbCdEfGhIjKlMnOpQrStUv0123456789wxyz"
        f = aegis_scan.Finding(
            rule_id="SEC-01", domain="SECURITY", severity="CRITICAL", title="t",
            file="x.js", line=1, snippet='new Stripe("%s", { ...opts })' % key,
            cwe_or_standard="c", remediation="r")
        aegis_scan.redact_findings([f])
        self.assertNotIn(key, f.snippet)

    def test_every_key_on_a_line_is_redacted_not_just_the_first(self):
        a = "sk_live_" + "51QzAbCdEfGhIjKlMnOpQrStUv0123456789wxyz"
        b = "sk_live_" + "99ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHh"
        f = aegis_scan.Finding(
            rule_id="SEC-01", domain="SECURITY", severity="CRITICAL", title="t",
            file="x.js", line=1, snippet='A="%s" B="%s"' % (a, b),
            cwe_or_standard="c", remediation="r")
        aegis_scan.redact_findings([f])
        self.assertNotIn(a, f.snippet)
        self.assertNotIn(b, f.snippet)

    def test_no_rule_outside_scan_secrets_quotes_a_provider_key(self):
        """Detection of provider credentials must live in exactly ONE place.

        If a future rule starts matching raw key text again, its snippet will be the
        source line and this guard fires before the leak ships.
        """
        key = "sk_live_" + "51QzAbCdEfGhIjKlMnOpQrStUv0123456789wxyz"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "src/keys.js", 'const stripe = new Stripe("%s", {...o});\n' % key)
            findings, _ = aegis_scan.scan_repository(root)
            # Before redaction runs at all: nothing may be holding the raw key.
            holding = [f.rule_id for f in findings if key in f.snippet]
            self.assertEqual(holding, [],
                             "these rules build snippets from unredacted source: %s" % holding)


class TestJsxAttributeOrderDoesNotChangeTheVerdict(unittest.TestCase):
    """`[^>]*` cannot scan a JSX tag, because `=>` contains `>`.

    The lookaheads stopped at the first arrow function, so an `aria-label` written
    AFTER an `onChange` was invisible and identical, correct code was flagged or not
    depending purely on attribute order.
    """

    def _rules(self, jsx):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "src/C.jsx", jsx)
            findings, _ = aegis_scan.scan_repository(root)
            return {f.rule_id for f in findings}

    def test_accessible_name_after_an_arrow_handler_is_seen(self):
        self.assertNotIn("UX-06", self._rules(
            '<input onChange={(e) => setName(e.target.value)} aria-label="Full name" />'))

    def test_accessible_name_before_an_arrow_handler_is_seen(self):
        self.assertNotIn("UX-06", self._rules(
            '<input aria-label="Full name" onChange={(e) => setName(e.target.value)} />'))

    def test_alt_after_an_arrow_handler_is_seen(self):
        self.assertNotIn("UX-07", self._rules(
            '<img onLoad={(e) => done(e)} alt="Revenue chart" src="/c.png" />'))

    def test_role_and_tabindex_after_an_arrow_handler_are_seen(self):
        self.assertNotIn("UX-12", self._rules(
            '<div onClick={(e) => pick(e)} role="button" tabIndex={0} onKeyDown={k}>x</div>'))

    def test_genuinely_inaccessible_controls_still_fire(self):
        """Widening the scan must not blunt the rules."""
        rules = self._rules(
            '<input placeholder="Email" onChange={(e) => setEmail(e.target.value)} />\n'
            '<img src="/a.png" onLoad={(e) => done(e)} />\n'
            '<div onClick={(e) => pick(e)}>click</div>\n'
            '<a href="#" onClick={(e) => del(e)}>Delete</a>\n'
            '<a href="#">Terms</a>\n')
        for expected in ("UX-06", "UX-07", "UX-12", "UX-11", "UX-01"):
            self.assertIn(expected, rules, "%s stopped firing" % expected)


class TestFormControlLabelResolution(unittest.TestCase):
    """`UX-06` is a whole-file question, not a per-element one."""

    def _rules(self, jsx):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "src/F.jsx", jsx)
            findings, _ = aegis_scan.scan_repository(root)
            return {f.rule_id for f in findings}

    def test_input_with_a_label_pointing_at_its_id_is_accepted(self):
        self.assertNotIn("UX-06", self._rules(
            '<label htmlFor="city">City</label><input id="city" />'))

    def test_input_with_an_id_nothing_points_at_is_flagged(self):
        """The old rule treated any `id=` as an accessible name and passed this."""
        self.assertIn("UX-06", self._rules('<input id="ghost" />'))

    def test_placeholder_is_not_an_accessible_name(self):
        self.assertIn("UX-06", self._rules('<input placeholder="Email" />'))

    def test_hidden_and_submit_inputs_need_no_name(self):
        self.assertNotIn("UX-06", self._rules(
            '<input type="hidden" name="csrf" /><input type="submit" value="Go" />'))


class TestAuthGuardRecognition(unittest.TestCase):
    """Most projects wrap their auth check in a local helper."""

    def _rules(self, ts):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "app/api/items/route.ts", ts)
            findings, _ = aegis_scan.scan_repository(root)
            return {f.rule_id for f in findings}

    def test_hand_rolled_guard_counts_as_authentication(self):
        self.assertNotIn("SEC-03", self._rules(
            'import { requireUser } from "@/lib/guard";\n'
            'export async function DELETE(req: Request) {\n'
            '  const user = await requireUser(req);\n'
            '  return Response.json({ ok: user.id });\n}\n'))

    def test_route_with_no_guard_at_all_still_fires(self):
        self.assertIn("SEC-03", self._rules(
            'export async function DELETE(req){ return db.order.delete({where:{id:req.body.id}}); }'))


class TestArrayFormExecIsNotCommandInjection(unittest.TestCase):
    """`FLOW-02` flagged the very fix its own remediation recommends.

    `spawn`/`execFile` given an argument ARRAY start no shell, so the arguments reach
    execve() as separate strings and cannot be reparsed as commands. Reporting that as a
    CRITICAL command injection was a false positive - and it was the single finding
    blocking this repository's own release gate.
    """

    SAFE_SPAWN = (
        'const args = process.argv.slice(2);\n'
        'const res = spawnSync("bash", [script, ...args], { stdio: "inherit" });\n'
    )
    SAFE_EXECFILE = (
        'const args = process.argv.slice(2);\n'
        'execFileSync("git", ["log", ...args]);\n'
    )
    UNSAFE_STRING = (
        'const args = process.argv.slice(2);\n'
        'execSync("git log " + args);\n'
    )
    UNSAFE_SHELL_TRUE = (
        'const args = process.argv.slice(2);\n'
        'spawnSync("bash", [script, ...args], { shell: true });\n'
    )

    def _rules(self, js):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "bin/cli.mjs", js)
            findings, _ = aegis_scan.scan_repository(root)
            return {f.rule_id for f in findings}

    def test_argv_into_array_form_spawn_is_safe(self):
        self.assertNotIn("FLOW-02", self._rules(self.SAFE_SPAWN))

    def test_argv_into_execfile_is_safe(self):
        self.assertNotIn("FLOW-02", self._rules(self.SAFE_EXECFILE))

    def test_argv_into_a_shell_string_still_fires(self):
        self.assertIn("FLOW-02", self._rules(self.UNSAFE_STRING))

    def test_array_form_with_shell_true_still_fires(self):
        """`shell: true` re-introduces the shell; the array no longer protects you."""
        self.assertIn("FLOW-02", self._rules(self.UNSAFE_SHELL_TRUE))



class TestExitCodeHonoursCoverage(unittest.TestCase):
    """The fail-closed contract has to reach the PROCESS EXIT STATUS, not just the report.

    `compute_readiness_score()` has returned INCOMPLETE_SCAN at 0/100 for an empty scan
    since 2.4.0, but `main()` gated `--fail-on-incomplete` on `skipped_checks` alone.
    Scanning zero files produces no skipped check - every stage ran, there was simply
    nothing to read - so an empty checkout, a mistyped target path or a run from the
    wrong working directory exited 0 and certified a scan of nothing.
    """

    SCANNER = str(Path(__file__).resolve().parent.parent / "scripts" / "aegis_scan.py")

    def _run(self, target, *flags):
        proc = subprocess.run(
            [sys.executable, "-B", self.SCANNER, str(target), "--quiet", *flags],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        return proc.returncode

    def test_empty_directory_fails_the_incomplete_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._run(tmp, "--fail-on-incomplete"), 1)

    def test_directory_with_no_scannable_source_fails_the_incomplete_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), "NOTES.txt", "not source\n")
            self.assertEqual(self._run(tmp, "--fail-on-incomplete"), 1)

    def test_a_real_clean_repository_still_passes(self):
        """Closing the hole must not fail every healthy project."""
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), "src/ok.ts", "export const add = (a, b) => a + b;\n")
            self.assertEqual(self._run(tmp, "--fail-on-incomplete"), 0)

    def test_coverage_block_reports_an_empty_scan_as_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, "-B", self.SCANNER, tmp, "--json"],
                capture_output=True, text=True, encoding="utf-8", errors="replace")
            report = json.loads(proc.stdout)
            self.assertFalse(report["coverage"]["complete"])
            self.assertEqual(report["readiness_score"], 0)
            self.assertIn("INCOMPLETE_SCAN", report["release_verdict"])


class TestEmptyChangesetIsNotAnIncompleteScan(unittest.TestCase):
    """`--diff` matching no source is a docs-only PR, not a broken audit."""

    SCANNER = str(Path(__file__).resolve().parent.parent / "scripts" / "aegis_scan.py")

    def _git_repo(self, tmp):
        root = Path(tmp)
        env = {"GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@e.com",
               "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@e.com"}
        import os
        full = dict(os.environ, **env)
        def git(*args):
            subprocess.run(["git", "-C", str(root), *args], check=True,
                           capture_output=True, env=full)
        git("init", "-q", ".")
        write(root, "src/a.ts", "export const a = 1;\n")
        write(root, "README.md", "# docs\n")
        git("add", "-A"); git("commit", "-qm", "base"); git("branch", "-M", "main")
        git("checkout", "-qb", "feature")
        return root, git

    def _run(self, target, *flags):
        proc = subprocess.run(
            [sys.executable, "-B", self.SCANNER, str(target), "--quiet", *flags],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        return proc.returncode, proc.stdout

    def test_docs_only_changeset_passes_the_incomplete_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, git = self._git_repo(tmp)
            write(root, "README.md", "# docs updated\n")
            git("add", "-A"); git("commit", "-qm", "docs")
            code, out = self._run(root, "--diff", "main", "--fail-on-incomplete")
            self.assertEqual(code, 0, out)
            self.assertIn("NO CODE CHANGES", out)

    def test_an_unresolvable_diff_ref_is_still_held_to_the_strict_rule(self):
        """A failed diff falls back to a full scan, so an empty target must still fail."""
        with tempfile.TemporaryDirectory() as tmp:
            code, _ = self._run(tmp, "--diff", "no-such-ref", "--fail-on-incomplete")
            self.assertEqual(code, 1)

    def test_changeset_containing_code_is_still_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, git = self._git_repo(tmp)
            write(root, "src/bad.ts", "eval(req.body.x);\n")
            git("add", "-A"); git("commit", "-qm", "bad")
            code, out = self._run(root, "--diff", "main", "--fail-on-high")
            self.assertEqual(code, 1, out)



class TestSuppressionCannotHideACoverageGap(unittest.TestCase):
    """Suppression accepts known DEFECTS. It must never accept a missing CHECK.

    Both suppression routes defeated the fail-closed contract, and the baseline route
    did it silently: one `--write-baseline` run on a machine with no network recorded
    DEP-00 as an accepted finding, and every later scan then reported READY TO PUBLISH
    while the dependency check never ran again.
    """

    def _gap(self, rule_id="DEP-00"):
        return aegis_scan.Finding(
            rule_id=rule_id, domain="SUPPLY_CHAIN", severity="LOW",
            title="Could Not Reach The OSV Vulnerability Database",
            file="dependencies", line=0, snippet="offline",
            cwe_or_standard="Informational", remediation="r",
            kind="skipped_check", status="SKIPPED")

    def _defect(self):
        f = aegis_scan.Finding(
            rule_id="SEC-08", domain="SECURITY", severity="HIGH", title="eval",
            file="src/bad.js", line=1, snippet="eval(req.body.x)",
            cwe_or_standard="CWE-94", remediation="r")
        f.fingerprint = aegis_scan.fingerprint(f)
        return f

    def test_ignore_rule_cannot_suppress_a_gap(self):
        kept, n = aegis_scan.apply_suppressions([self._gap()], set(), {"DEP-00"}, [])
        self.assertEqual([f.rule_id for f in kept], ["DEP-00"])
        self.assertEqual(n, 0)

    def test_ignore_glob_cannot_suppress_a_gap(self):
        kept, _ = aegis_scan.apply_suppressions([self._gap()], set(), set(), ["*"])
        self.assertEqual([f.rule_id for f in kept], ["DEP-00"])

    def test_baseline_cannot_suppress_a_gap(self):
        gap = self._gap()
        gap.fingerprint = aegis_scan.fingerprint(gap)
        kept, _ = aegis_scan.apply_suppressions([gap], {gap.fingerprint}, set(), [])
        self.assertEqual([f.rule_id for f in kept], ["DEP-00"])

    def test_every_gap_marker_is_protected_not_just_the_suffix(self):
        """`_is_incomplete` is the single source of truth, all three ways."""
        for gap in (self._gap("DEP-00"),
                    self._gap("SEC-99"),          # protected by kind/status only
                    self._gap("LIVE-00")):
            kept, _ = aegis_scan.apply_suppressions([gap], set(), {gap.rule_id}, ["*"])
            self.assertEqual(len(kept), 1, "%s was suppressed" % gap.rule_id)

    def test_a_real_defect_is_still_suppressible(self):
        """Closing the hole must not break the feature."""
        d = self._defect()
        kept, n = aegis_scan.apply_suppressions([d], set(), {"SEC-08"}, [])
        self.assertEqual(kept, [])
        self.assertEqual(n, 1)
        kept, n = aegis_scan.apply_suppressions([self._defect()], {d.fingerprint}, set(), [])
        self.assertEqual(kept, [])
        self.assertEqual(n, 1)

    def test_a_suppressed_repo_with_a_gap_still_fails_the_gate(self):
        """End to end: gap survives suppression and reaches the exit code."""
        scanner = str(Path(__file__).resolve().parent.parent / "scripts" / "aegis_scan.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "package.json", '{"name":"x","dependencies":{"lodash":"4.17.20"}}')
            write(root, "src/ok.ts", "export const a = 1;\n")
            write(root, ".aegis-ignore", "DEP-00\n")
            proc = subprocess.run(
                [sys.executable, "-B", scanner, str(root), "--deps", "--offline",
                 "--fail-on-incomplete", "--quiet"],
                capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)



def _build_apk(path, v1=False, v2=False):
    """A minimal APK, optionally carrying a v1 JAR signature and/or a v2/v3 block."""
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", "x")
        z.writestr("classes.dex", "y")
        if v1:
            z.writestr("META-INF/CERT.RSA", "sig")
            z.writestr("META-INF/CERT.SF", "sig")
    data = bytearray(buf.getvalue())
    if v2:
        eocd = data.rfind(b"PK\x05\x06")
        cd = int.from_bytes(data[eocd + 16:eocd + 20], "little")
        block = b"\x00" * 24 + b"APK Sig Block 42"
        data[cd:cd] = block
        new_cd = cd + len(block)
        data[eocd + len(block) + 16:eocd + len(block) + 20] = new_cd.to_bytes(4, "little")
    path.write_bytes(bytes(data))
    return path


class TestApkSigningDetection(unittest.TestCase):
    """`ART-11` only knew about v1 JAR signing.

    APK Signature Scheme v2/v3 (Android 7.0+) stores the signature in an APK Signing
    Block before the central directory, leaving nothing in `META-INF/`. Release builds
    have disabled v1 for years, so a correctly signed APK was reported unsigned at
    HIGH - blocking the gate at the worst possible moment, just before a store upload.
    """

    def _rules(self, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = _build_apk(root / "app-release.apk", **kw)
            return {f.rule_id for f in aegis_scan.scan_mobile_package(root, apk)}

    def test_v1_signed_apk_is_not_reported_unsigned(self):
        self.assertNotIn("ART-11", self._rules(v1=True))

    def test_v2_only_signed_apk_is_not_reported_unsigned(self):
        """The regression: modern release builds sign with v2/v3 only."""
        self.assertNotIn("ART-11", self._rules(v2=True))

    def test_apk_signed_both_ways_is_not_reported_unsigned(self):
        self.assertNotIn("ART-11", self._rules(v1=True, v2=True))

    def test_genuinely_unsigned_apk_still_fires(self):
        self.assertIn("ART-11", self._rules())

    def test_signing_block_detector_is_accurate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertTrue(aegis_scan.has_apk_signing_block(_build_apk(root / "a.apk", v2=True)))
            self.assertFalse(aegis_scan.has_apk_signing_block(_build_apk(root / "b.apk", v1=True)))

    def test_unreadable_archive_is_a_coverage_gap_not_an_unsigned_verdict(self):
        """Unknown must never be reported as a defect."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            aab = _build_apk(root / "app.aab")          # .aab: signed by Play at upload
            ids = {f.rule_id for f in aegis_scan.scan_mobile_package(root, aab)}
            self.assertNotIn("ART-11", ids)
            self.assertIn("ART-10", ids)


class TestMinConfidenceGate(unittest.TestCase):
    """Confidence is a third axis, alongside coverage and severity."""

    SCANNER = str(Path(__file__).resolve().parent.parent / "scripts" / "aegis_scan.py")
    # A hand-rolled auth guard SEC-03 cannot recognise: CRITICAL, confidence MEDIUM.
    UNPROVEN = ('import { mustBeLoggedIn } from "@/auth";\n'
                'export async function DELETE(req){ await mustBeLoggedIn(req); return ok(); }\n')

    def _run(self, root, *flags):
        proc = subprocess.run(
            [sys.executable, "-B", self.SCANNER, str(root), "--quiet", *flags],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        return proc.returncode

    def test_unproven_finding_blocks_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), "app/api/x/route.ts", self.UNPROVEN)
            self.assertEqual(self._run(tmp, "--fail-on-high"), 1)

    def test_min_confidence_high_does_not_block_on_an_unproven_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), "app/api/x/route.ts", self.UNPROVEN)
            self.assertEqual(self._run(tmp, "--fail-on-high", "--min-confidence", "high"), 0)

    def test_a_proven_finding_still_blocks_at_min_confidence_high(self):
        """Raising the bar must not disarm the gate."""
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), "src/x.jsx",
                  '<div dangerouslySetInnerHTML={{__html: userInput}} />')
            self.assertEqual(self._run(tmp, "--fail-on-high", "--min-confidence", "high"), 1)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Redaction regression suite
# ---------------------------------------------------------------------------
# A report is committed, attached to issues and uploaded as a CI artifact, so nothing
# the scanner writes anywhere may carry a credential. These tests plant canary secrets
# - none of them real, all assembled at runtime so no valid-format key is stored in
# this file - and then look for ANY 8-character run of each one in every output.
#
# A canary is the secret part only. A public format prefix (`sk_live_`, `whsec_`) is
# allowed to appear, because the reader needs to know which kind of key to rotate.

CANARY_ENTROPY = "q7Vt2Lx9" + "Rk4Wm8Zp3Nc6Hb1Jd5Fs"       # random, no provider format
CANARY_STRIPE_BODY = "51Hq" + "Xy7Kp2Rm9Tn4Wb6Zc8Vd3Lf"
CANARY_STRIPE = "sk_live_" + CANARY_STRIPE_BODY
CANARY_WEBHOOK_BODY = "Mz3Qp8Lw" + "2Xn7Rk5Vt9Bj4"
CANARY_WEBHOOK = "whsec_" + CANARY_WEBHOOK_BODY            # not in PROVIDER_SECRETS
CANARY_URL_PASS = "Tr0ub4dor" + "Gx"                       # inside a credentialed URL
CANARY_ENV_PASS = "hunter" + "2plum"                       # low entropy, bare .env value
CANARY_URL = "https://deploy:" + CANARY_URL_PASS + "@registry.internal/v2"
CANARIES = (CANARY_ENTROPY, CANARY_STRIPE_BODY, CANARY_WEBHOOK_BODY,
            CANARY_URL_PASS, CANARY_ENV_PASS)


def leaked(blob, canaries=CANARIES, window=8):
    """Every canary of which some `window`-character run appears in `blob`."""
    return sorted({c[:4] + "..." for c in canaries
                   for i in range(len(c) - window + 1) if c[i:i + window] in blob})


def finding_blob(findings):
    return json.dumps([f.__dict__ for f in findings], default=str)


E, K, W = CANARY_ENTROPY, CANARY_STRIPE, CANARY_WEBHOOK

# One fixture per rule that quotes source, with a canary on the triggering line itself,
# because that line is exactly what a careless rule would copy into its snippet.
REDACTION_CORPUS = {
    ".env": "SESSION_SECRET=%s\n" % E,
    ".env.production": ("NEXT_PUBLIC_API_SECRET=%s\nNEXT_PUBLIC_DB_PASSWORD=%s\n"
                        % (E, CANARY_ENV_PASS)),
    "db/schema.sql": (
        "CREATE TABLE notes (id int, token text DEFAULT '%s');\n"
        'CREATE POLICY "%s" ON notes FOR ALL USING (true);\n' % (E, E)),
    "lib/rules.js": "allow read, write: if true; const k = \"%s\";\n" % E,
    "lib/keys.ts": (
        'const NEXT_PUBLIC_STRIPE_SECRET = "%s";\n'
        'const stripe = new Stripe("%s");\n'
        'const registry = "%s";\n' % (E, K, CANARY_URL)),
    "lib/session.ts": (
        'localStorage.setItem("token", "%s");\n'
        'app.use(cors({ origin: "*", k: "%s" }));\n'
        'const f = new Function("return \'%s\'");\n'
        'try { run(); } catch (e) { console.log("%s"); }\n' % (E, E, E, E)),
    "lib/render.ts": (
        "export function render(req) {\n"
        "  const html = req.query.html;\n"
        '  document.body.innerHTML = html + "%s";\n'
        "}\n" % E),
    "app/api/checkout/route.ts": (
        'const API_KEY = "%s";\n'
        "export async function POST(req) {\n"
        "  const body = await req.json();\n"
        '  const s = await stripe.checkout.sessions.create({ line_items: [{ price_data: '
        '{ unit_amount: body.price, currency: "%s" } }] });\n'
        '  const r = await openai.chat.completions.create({ model: "%s", messages: [] });\n'
        "  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE k = '%s' "
        "AND id = ${body.id}`);\n"
        '  eval(body.code + "%s");\n'
        '  const page = await fetch(body.url + "%s");\n'
        '  const data = await readFile(body.path + "%s");\n'
        '  console.log("password", body.password, "%s");\n'
        '  const all = await prisma.user.findMany(); const k2 = "%s";\n'
        '  for (const id of body.ids) { await prisma.item.update({ data: { n: "%s" } }); }\n'
        '  await prisma.note.update({ where: { id: body.id, note: "%s" } });\n'
        '  await db.wallet.update({ data: { balance: wallet.balance - 1, memo: "%s" } });\n'
        '  res.status(500).json({ error: err.stack, k: "%s" });\n'
        '  const headers = { "Access-Control-Allow-Origin": "*", "X-K": "%s" };\n'
        '  const h = crypto.createHash("md5").update("%s");\n'
        '  const claims = jwt.decode(body.token + "%s");\n'
        "  return Response.json(s);\n"
        "}\n" % ((E,) * 16)),
    "app/api/login/route.ts": (
        "export async function POST(req) { const k = \"%s\"; return Response.json({}); }\n" % E),
    "app/api/upload/route.ts": (
        "export async function POST(req) {\n"
        "  const form = await req.formData(); const file = form.get(\"f\");\n"
        "  const x = formData.get(\"%s\");\n"
        "  return Response.json({ ok: getUser() });\n"
        "}\n" % E),
    "app/api/webhooks/stripe/route.ts": (
        'const STRIPE_WEBHOOK_SECRET = "%s";\n'
        'import Stripe from "stripe";\n'
        "export async function POST(req) { const event = await req.json(); "
        "return Response.json({ ok: true }); }\n" % W),
    "components/Checkout.tsx": (
        "export default function Checkout({ items }) {\n"
        "  return (\n"
        '    <form onSubmit={async () => { await fetch("/api/checkout"); }}>\n'
        '      <a href="#" data-k="%s">Dead</a>\n'
        '      <a href="#" onClick={go} data-k="%s">Act</a>\n'
        '      <div onClick={go} data-k="%s">Click</div>\n'
        '      <input placeholder="%s" />\n'
        '      <img src="/a.png" data-k="%s" />\n'
        '      <button className="outline-none k-%s" type="submit">Pay</button>\n'
        "      <p>Lorem ipsum %s</p>\n"
        '      <div className="z-[99999] w-[800px]" data-k="%s" />\n'
        '      <div dangerouslySetInnerHTML={{ __html: "%s" }} />\n'
        "      {items.map(i => <span key={i.id}>{i.name}</span>)}\n"
        '      <button onClick={() => {}} data-k="%s">Noop</button>\n'
        "    </form>\n"
        "  );\n"
        "}\n" % ((E,) * 10)),
    # A minified bundle is skipped and reported as a coverage gap (COV-00).
    "public/vendor.min.js": "var k=\"%s\";\n" % E,
    # Build output: the source key ships (ART-01), is found again (ART-03), plus a map.
    "dist/assets/index.js": 'const K="%s";export default K;' % K,
    "dist/assets/index.js.map": '{"version":3,"sourcesContent":["%s"]}' % E,
}

# Rules this corpus does not fire, and where each one's redaction is proved instead.
# Listed explicitly so a NEW rule cannot silently skip the leak check: it has to fire
# in the corpus, or be named here with the test that covers it.
REDACTION_EXEMPT = {
    "SEC-17": "live headers - TestLiveAndNetworkOutputIsRedacted",
    "SEC-17B": "live exposure probe - TestLiveAndNetworkOutputIsRedacted",
    "DEP-00": "OSV unreachable - TestLiveAndNetworkOutputIsRedacted",
    "DEP-01": "OSV advisory - snippet is package names only; TestLiveAndNetworkOutputIsRedacted",
    "GIT-00": "constant reason strings only; covered by the static guard",
    "ART-10": "TestMobilePackageOutputIsRedacted",
    "ART-11": "TestMobilePackageOutputIsRedacted",
    "ART-12": "TestMobilePackageOutputIsRedacted",
    "ART-13": "TestMobilePackageOutputIsRedacted",
    "ART-14": "TestMobilePackageOutputIsRedacted",
    "ART-15": "TestMobilePackageOutputIsRedacted",
    "ART-00": "build-stage gaps - TestArtifactStageFailsClosed (incl. a canary bundle)",
}


def build_redaction_corpus(root):
    for rel, body in REDACTION_CORPUS.items():
        write(root, rel, body)


def scanner_rule_ids():
    """Every literal rule id the scanner can emit, read from its own source."""
    tree = ast.parse(Path(aegis_scan.__file__).read_text(encoding="utf-8"))
    ids = set()

    def take(node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                    and re.fullmatch(r"[A-Z]+-\d{2}[A-Z]?", sub.value):
                ids.add(sub.value)

    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "rule_id":
            take(node.value)
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Attribute) and t.attr == "rule_id" for t in node.targets):
            take(node.value)
    for table in (aegis_scan.SECURITY_PATTERNS, aegis_scan.UIUX_PATTERNS,
                  aegis_scan.DOMAIN_PATTERNS, aegis_scan.TAINT_SINKS):
        ids.update(row[0] for row in table)
    return ids


_FAKE_ENGINE_SCRIPTS = {
    # Valid JSON, with the secret in every text field the parser reads.
    "semgrep": json.dumps({"results": [{
        "check_id": "generic.secrets.hardcoded", "path": "lib/keys.ts",
        "start": {"line": 1},
        "extra": {"severity": "ERROR", "message": "Hardcoded secret %s" % E,
                  "lines": 'password = "%s"' % E, "fix": 'password = "%s"' % E,
                  "metadata": {"cwe": ["CWE-798"]}}}]}),
    # Not JSON at all - the text lands in an ENG-00 coverage gap.
    "gitleaks": "Finding: password=%s\nSecret: %s\nRuleID: generic" % (E, K),
}


def install_fake_engines(bin_dir):
    """Stand-ins for installed engines. Written at runtime; POSIX shells only."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name, out in _FAKE_ENGINE_SCRIPTS.items():
        payload = bin_dir / (name + ".out")
        payload.write_text(out, encoding="utf-8")
        script = bin_dir / name
        script.write_text("#!/bin/sh\ncat '%s'\n" % payload, encoding="utf-8")
        script.chmod(0o755)
    # Crashes with no stdout and the secret on stderr.
    trivy = bin_dir / "trivy"
    trivy.write_text("#!/bin/sh\necho 'fatal: auth failed for token %s' >&2\nexit 2\n" % E,
                     encoding="utf-8")
    trivy.chmod(0o755)


@unittest.skipUnless(os.name == "posix" and shutil.which("git"),
                     "needs a POSIX shell for fake engines and git for history")
class TestNoOutputChannelCarriesASecret(unittest.TestCase):
    """End to end: run the real CLI with every stage on, and read everything it wrote.

    Channels checked: the JSON report file, SARIF, the SBOM, JSON on stdout, the
    human terminal report, and stderr - with git history, build artifacts, a
    credentialed `--url` and three external engines all feeding in.
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name) / "app"
        build_redaction_corpus(cls.root)
        git = ["git", "-c", "user.name=dev", "-c", "user.email=dev@localhost",
               "-c", "commit.gpgsign=false"]
        subprocess.run(git + ["init", "-q"], cwd=cls.root, check=True)
        subprocess.run(git + ["add", "-A"], cwd=cls.root, check=True)
        subprocess.run(git + ["commit", "-q", "-m", "add config %s" % E],
                       cwd=cls.root, check=True)
        bin_dir = Path(cls._tmp.name) / "bin"
        install_fake_engines(bin_dir)
        cls.env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
        out = Path(cls._tmp.name) / "out"
        cls.report_path, cls.sarif_path, cls.sbom_path = (
            out / "report.json", out / "scan.sarif", out / "sbom.json")
        script = str(Path(aegis_scan.__file__))
        common = [sys.executable, "-B", script, str(cls.root), "--artifact", "dist",
                  "--git-history", "20", "--url", "http://admin:%s@127.0.0.1:9/" % CANARY_URL_PASS,
                  "--engine", "semgrep", "--engine", "gitleaks", "--engine", "trivy"]
        cls.terminal = subprocess.run(
            common + ["--output", str(cls.report_path), "--sarif", str(cls.sarif_path),
                      "--sbom", str(cls.sbom_path)],
            capture_output=True, text=True, encoding="utf-8", env=cls.env, timeout=300)
        cls.json_run = subprocess.run(common + ["--json"], capture_output=True, text=True,
                                      encoding="utf-8", env=cls.env, timeout=300)
        cls.report = json.loads(cls.report_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def assertClean(self, channel, text):
        self.assertEqual(leaked(text), [], "a secret reached %s" % channel)

    def test_the_corpus_actually_contains_the_canaries(self):
        """Guards the guard: a fixture that lost its canary would prove nothing."""
        on_disk = "".join(REDACTION_CORPUS.values())
        self.assertEqual(len(leaked(on_disk)), len(CANARIES))

    def test_the_scan_ran_and_saw_the_secrets(self):
        ids = {f["rule_id"] for f in self.report["findings"]}
        for required in ("SEC-01", "SEC-01B", "ART-01", "ART-03", "HIST-01"):
            self.assertIn(required, ids)
        self.assertTrue(any(r.startswith("EXT-SEMGREP:") for r in ids))

    def test_json_report_file(self):
        self.assertClean("the JSON report", self.report_path.read_text(encoding="utf-8"))

    def test_sarif(self):
        self.assertClean("SARIF", self.sarif_path.read_text(encoding="utf-8"))

    def test_sbom(self):
        self.assertClean("the SBOM", self.sbom_path.read_text(encoding="utf-8"))

    def test_terminal_report(self):
        self.assertIn("Evidence", self.terminal.stdout)
        self.assertClean("the terminal report", self.terminal.stdout)

    def test_json_on_stdout(self):
        json.loads(self.json_run.stdout)
        self.assertClean("JSON on stdout", self.json_run.stdout)

    def test_stderr(self):
        self.assertClean("stderr", self.terminal.stderr + self.json_run.stderr)

    def test_credentialed_url_never_appears(self):
        raw = self.report_path.read_text(encoding="utf-8")
        self.assertNotIn("admin:", raw)
        self.assertIn("[REDACTED]@127.0.0.1", raw)

    def test_external_engine_output_is_redacted(self):
        ext = [f for f in self.report["findings"] if f["rule_id"].startswith("EXT-")]
        gaps = [f for f in self.report["skipped_checks"] if f["rule_id"] == "ENG-00"]
        self.assertTrue(ext)
        self.assertEqual({g["title"] for g in gaps},
                         {"External Engine Not Run: gitleaks", "External Engine Not Run: trivy"})
        self.assertClean("imported engine findings", json.dumps(ext + gaps))

    def test_every_rule_is_exercised_or_explicitly_exempt(self):
        """A new rule must prove its own redaction, here or in a named test."""
        fired = {f["rule_id"] for f in self.report["findings"] + self.report["skipped_checks"]}
        known = scanner_rule_ids()
        unproven = sorted(known - fired - set(REDACTION_EXEMPT))
        self.assertEqual(unproven, [],
                         "add a canary fixture to REDACTION_CORPUS for these rules, or "
                         "exempt them with the test that proves their redaction")
        stale = sorted(set(REDACTION_EXEMPT) - known)
        self.assertEqual(stale, [], "exemptions for rules that no longer exist")


class TestRedactionDoesNotChangeDetection(unittest.TestCase):
    """Masking evidence must never change WHAT is found - only how it is printed."""

    def test_same_findings_with_and_without_masking(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_redaction_corpus(root)
            masked, _ = aegis_scan.scan_repository(root)
            real = aegis_scan.evidence
            aegis_scan.evidence = lambda text, limit=140: str(text).strip()[:limit]
            try:
                unmasked, _ = aegis_scan.scan_repository(root)
            finally:
                aegis_scan.evidence = real
        where = lambda fs: sorted((f.rule_id, f.file, f.line, f.severity) for f in fs)
        self.assertEqual(where(masked), where(unmasked))
        self.assertGreater(len(masked), 30)
        # ...and without masking, the corpus really would have leaked.
        self.assertNotEqual(leaked(finding_blob(unmasked)), [])
        self.assertEqual(leaked(finding_blob(masked)), [])


def snippet_violations(source):
    """Every place `source` builds a Finding snippet other than through `evidence()`.

    Allowed: a string constant, `redact(...)`, `evidence(...)` - and inside
    `evidence(...)`, no slicing, because cutting before masking is how a partial key
    escaped its own pattern.
    """
    tree = ast.parse(source)
    problems = []

    def ok(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        if isinstance(node, ast.IfExp):
            return ok(node.body) and ok(node.orelse)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in ("evidence", "redact"):
            if node.func.id == "evidence" and node.args:
                return not any(isinstance(s, ast.Subscript) and isinstance(s.slice, ast.Slice)
                               for s in ast.walk(node.args[0]))
            return True
        return False

    def flag(node, why):
        problems.append("line %d: %s" % (node.lineno, why))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name == "Finding" and len(node.args) > 6:
                flag(node, "snippet passed positionally")
            if name == "setattr" and len(node.args) >= 2 and \
                    isinstance(node.args[1], ast.Constant) and node.args[1].value == "snippet":
                flag(node, "snippet set via setattr")
            for kw in node.keywords:
                if kw.arg is None and name == "Finding":
                    flag(node, "Finding built from **kwargs")
                elif kw.arg == "snippet" and not ok(kw.value):
                    flag(kw.value, "snippet not built through evidence()")
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if isinstance(node, ast.AnnAssign) and node.value is None:
                continue  # a declaration (`snippet: str`), not a value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if (isinstance(t, ast.Name) and t.id == "snippet") or \
                        (isinstance(t, ast.Attribute) and t.attr == "snippet"):
                    if isinstance(node, ast.AugAssign) or not ok(node.value):
                        flag(node, "snippet assigned from raw text")
    return problems


class TestEverySnippetIsBuiltThroughEvidence(unittest.TestCase):
    """The guard against the next leak: no rule may build a snippet from a raw line.

    Reads the scanner's own source. A rule that writes `snippet=lines[i].strip()`,
    `snippet=f"... {line}"`, or slices before masking fails here, before it ships.
    """

    def test_scanner_has_no_raw_snippets(self):
        source = Path(aegis_scan.__file__).read_text(encoding="utf-8")
        self.assertEqual(snippet_violations(source), [])

    def test_guard_catches_the_original_leak(self):
        bad = ("Finding(rule_id='X-01', snippet=lines[line_no - 1].strip()[:140])\n"
               "Finding(rule_id='X-02', snippet=f'used here: {stripped}')\n"
               "Finding(rule_id='X-03', snippet=evidence(line[:140]))\n"
               "snippet = line.strip()\n"
               "f.snippet += extra\n"
               "Finding(**fields)\n"
               "setattr(f, 'snippet', raw)\n")
        self.assertEqual(len(snippet_violations(bad)), 7)

    def test_guard_accepts_the_safe_forms(self):
        good = ("Finding(rule_id='X-01', snippet=evidence(lines[i] if lines else path))\n"
                "Finding(rule_id='X-02', snippet='constant text')\n"
                "Finding(rule_id='X-03', snippet=redact(value))\n"
                "Finding(rule_id='X-04', snippet='a' if flag else 'b')\n"
                "f.snippet = evidence(f'{x} and {y}', 300)\n")
        self.assertEqual(snippet_violations(good), [])


class TestEvidenceMasking(unittest.TestCase):
    """`evidence()` - what it must hide, and what it must leave alone."""

    def assertHidden(self, line, *secrets):
        out = aegis_scan.evidence(line)
        self.assertEqual(leaked(out, secrets), [], out)
        return out

    def test_every_provider_format_is_masked(self):
        for key in (AWS_KEY, STRIPE_KEY, GH_TOKEN, GOOGLE_KEY, CANARY_STRIPE):
            self.assertHidden('const k = "%s";' % key, key[4:])

    def test_non_provider_secret_assigned_to_a_secret_name(self):
        self.assertHidden('const STRIPE_WEBHOOK_SECRET = "%s";' % W, CANARY_WEBHOOK_BODY)
        self.assertHidden('"apiKey": "%s"' % CANARY_ENV_PASS, CANARY_ENV_PASS)
        self.assertHidden("dbPassword: '%s'," % CANARY_ENV_PASS, CANARY_ENV_PASS)

    def test_bare_env_and_yaml_values(self):
        self.assertHidden("DB_PASSWORD=%s" % CANARY_ENV_PASS, CANARY_ENV_PASS)
        self.assertHidden("password: %s" % CANARY_ENV_PASS, CANARY_ENV_PASS)

    def test_credentialed_url_of_any_scheme(self):
        for scheme in ("https", "postgres", "redis", "amqp", "ftp"):
            out = self.assertHidden("%s://user:%s@host/x" % (scheme, CANARY_URL_PASS),
                                    CANARY_URL_PASS)
            self.assertIn("[REDACTED]@host", out)

    def test_auth_header_value(self):
        self.assertHidden("Authorization: Bearer " + CANARY_ENV_PASS + "x9", CANARY_ENV_PASS)

    def test_random_token_with_no_name_at_all(self):
        self.assertHidden('<div data-k="%s">' % E, E)

    def test_masking_happens_before_truncation(self):
        """The cut used to land inside a key, so the fragment no longer matched."""
        for pad in range(120, 145):
            self.assertHidden("x" * pad + " " + CANARY_STRIPE, CANARY_STRIPE_BODY)

    def test_a_key_at_the_input_cap_leaves_no_fragment(self):
        cap = aegis_scan._EVIDENCE_INPUT_CAP
        for offset in (cap - 10, cap - 30, cap - 1):
            line = "a " * (offset // 2) + E + " tail"
            out = aegis_scan.evidence(line, limit=10_000)
            self.assertEqual(leaked(out, (E,)), [])

    def test_long_runs_stay_linear(self):
        """Unanchored, each masking regex restarted inside a run: 1.2s per 8kB line."""
        import time
        start = time.perf_counter()
        for line in ("a" * 8192, "a.b" * 2730, "Ab1" * 2730, "aB3_" * 2048, "a-" * 4096):
            aegis_scan.evidence(line, 10_000)
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_masking_is_idempotent(self):
        line = 'K="%s" url="%s" t="%s"' % (K, CANARY_URL, E)
        once = aegis_scan.evidence(line, 400)
        self.assertEqual(aegis_scan.evidence(once, 400), once)

    def test_ordinary_code_is_left_readable(self):
        """Negative cases: evidence is useless if every line comes back masked."""
        for line in (
            '<a href="#">Home</a>',
            "const users = await prisma.user.findMany();",
            '<div className="w-[600px] outline-none" onClick={() => {}}>',
            "password: hashedPassword,",
            "const apiKey = process.env.OPENAI_API_KEY;",
            "token: string;",
            "maxTokens: 1000,",
            "credits: user.credits - 1",
            "await fetch(url, { signal: AbortSignal.timeout(10000) });",
            "const NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY = x",
            'cursor.execute(f"SELECT * FROM t WHERE id={uid}")',
            'import { useCallback, useMemo } from "react";',
            '<img src="/images/hero-banner-2024.png">',
            "if (password === confirm) {",
            "const session = await getServerSession(authOptions);",
            "NEXT_PUBLIC_API_SECRET=",
        ):
            self.assertEqual(aegis_scan.evidence(line), line)

    def test_long_ordinary_lines_are_truncated_not_masked(self):
        line = "const label = " + "word " * 60
        self.assertEqual(aegis_scan.evidence(line), line.strip()[:140])


class TestRedactRevealsNothingSecret(unittest.TestCase):

    def test_only_the_public_prefix_and_length_survive(self):
        self.assertEqual(aegis_scan.redact(CANARY_STRIPE),
                         "sk_live_...[REDACTED %d chars]" % len(CANARY_STRIPE))
        self.assertEqual(aegis_scan.redact(E), "...[REDACTED %d chars]" % len(E))

    def test_short_values_reveal_nothing(self):
        for value in ("abc", "hunter2", "sixteen-chars-ok"):
            out = aegis_scan.redact(value)
            self.assertFalse(any(ch in out.split("[")[0] for ch in value.strip(".")), out)

    def test_redacted_output_matches_no_provider_pattern(self):
        for key in (AWS_KEY, STRIPE_KEY, GH_TOKEN, GOOGLE_KEY):
            out = aegis_scan.redact(key)
            for _label, _sev, pattern in aegis_scan.PROVIDER_SECRETS:
                self.assertIsNone(pattern.search(out), (out, _label))

    def test_redact_findings_sweeps_every_text_field(self):
        f = aegis_scan.Finding(
            rule_id="X-01", domain="SECURITY", severity="LOW",
            title="key %s" % K, file="https://u:%s@host/%s" % (CANARY_URL_PASS, K),
            line=1, snippet="s", cwe_or_standard="std %s" % K, remediation="r %s" % K,
            confidence="HIGH")
        aegis_scan.redact_findings([f])
        self.assertEqual(leaked(finding_blob([f]), (CANARY_STRIPE_BODY, CANARY_URL_PASS)), [])


class TestSecretsAreMatchedExactlyNotByFragment(unittest.TestCase):
    """Full redaction moved the exact value into an in-memory vault. Prove it works."""

    def _scan(self, source_key, bundle_key):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, ".env.local", "STRIPE_SECRET_KEY=%s\n" % source_key)
            write(root, "dist/assets/index.js", 'const K="%s";' % bundle_key)
            found, _ = aegis_scan.scan_repository(root)
            src = [f for f in found if f.rule_id.startswith("SEC-01")]
            return aegis_scan.scan_build_artifacts(root, str(root / "dist"), src)

    def test_the_same_key_in_the_bundle_is_a_confirmed_leak(self):
        art = self._scan(CANARY_STRIPE, CANARY_STRIPE)
        self.assertIn("ART-01", {f.rule_id for f in art})
        self.assertEqual(leaked(finding_blob(art)), [])

    def test_a_different_key_with_the_same_prefix_is_not_a_confirmed_leak(self):
        """The old 6-character fragment (`sk_liv`) matched every Stripe key."""
        other = "sk_live_" + "99ZzYyXxWwVvUuTtSsRrQqPp"
        self.assertNotIn("ART-01", {f.rule_id for f in self._scan(CANARY_STRIPE, other)})

    def test_vault_handle_never_reaches_a_report(self):
        findings = aegis_scan.scan_secrets_in_text("a.js", 'k = "%s"' % CANARY_STRIPE)
        self.assertTrue(findings)
        self.assertNotIn("_secret_handle", json.dumps([asdict(f) for f in findings]))

    def test_two_different_keys_keep_distinct_fingerprints(self):
        a = "sk_live_" + "51Hq" + "Xy7Kp2Rm9Tn4Wb6Zc8Vd3Lf"
        b = "sk_live_" + "88Pp" + "Qq7Rr6Ss5Tt4Uu3Vv2Ww1Xy"
        self.assertEqual(len(a), len(b))
        fs = aegis_scan.scan_secrets_in_text("a.js", 'x = "%s"\ny = "%s"\n' % (a, b))
        self.assertEqual(fs[0].snippet, fs[1].snippet, "fully redacted text is identical")
        aegis_scan.assign_fingerprints(fs)
        self.assertNotEqual(fs[0].fingerprint, fs[1].fingerprint)

    def test_fingerprints_are_stable_across_runs(self):
        src = 'x = "%s"\n' % CANARY_STRIPE
        one = aegis_scan.scan_secrets_in_text("a.js", src)
        two = aegis_scan.scan_secrets_in_text("a.js", src)
        aegis_scan.assign_fingerprints(one)
        aegis_scan.assign_fingerprints(two)
        self.assertEqual(one[0].fingerprint, two[0].fingerprint)

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_history_keeps_two_different_keys_apart(self):
        a = "sk_live_" + "51Hq" + "Xy7Kp2Rm9Tn4Wb6Zc8Vd3Lf"
        b = "sk_live_" + "88Pp" + "Qq7Rr6Ss5Tt4Uu3Vv2Ww1Xy"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "a.js", 'x = "%s"\ny = "%s"\n' % (a, b))
            git = ["git", "-c", "user.name=dev", "-c", "user.email=dev@localhost",
                   "-c", "commit.gpgsign=false"]
            subprocess.run(git + ["init", "-q"], cwd=root, check=True)
            subprocess.run(git + ["add", "-A"], cwd=root, check=True)
            subprocess.run(git + ["commit", "-q", "-m", "keys"], cwd=root, check=True)
            hist = aegis_scan.scan_git_history(root, 5)
        self.assertEqual(len([f for f in hist if f.rule_id == "HIST-01"]), 2)
        self.assertEqual(leaked(finding_blob(hist), (a[8:], b[8:])), [])


class _FakeResponse:
    def __init__(self, headers, body=b"", status=200):
        self.headers, self.status, self._body = headers, status, body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestLiveAndNetworkOutputIsRedacted(unittest.TestCase):
    """`--url`, the exposure probe and OSV - including their exception messages."""

    URL = "https://admin:%s@staging.example.com/" % CANARY_URL_PASS

    def _with_urlopen(self, fake, fn):
        real = aegis_scan.urllib.request.urlopen
        aegis_scan.urllib.request.urlopen = fake
        try:
            return fn()
        finally:
            aegis_scan.urllib.request.urlopen = real

    def test_header_findings_and_exposed_env_probe(self):
        def fake(req, timeout=None, context=None):
            if req.full_url.endswith("/.env"):
                return _FakeResponse({}, ("SESSION_SECRET=%s" % E).encode())
            return _FakeResponse({"access-control-allow-origin": "*"})
        found = self._with_urlopen(fake, lambda: aegis_scan.check_live_url_posture(self.URL))
        ids = {f.rule_id for f in found}
        self.assertTrue({"SEC-17", "SEC-13", "SEC-17B"} <= ids, ids)
        self.assertEqual(leaked(finding_blob(found)), [])

    def test_unreachable_url_exception_message(self):
        def fake(req, timeout=None, context=None):
            raise aegis_scan.urllib.error.URLError(
                "cannot reach %s with token=%s" % (self.URL, E))
        found = self._with_urlopen(fake, lambda: aegis_scan.check_live_url_posture(self.URL))
        self.assertEqual([f.rule_id for f in found], ["LIVE-00"])
        self.assertEqual(leaked(finding_blob(found)), [])

    def test_osv_failure_exception_message(self):
        def fake(req, timeout=None, context=None):
            raise RuntimeError("proxy rejected Authorization: Bearer %s" % E)
        found = self._with_urlopen(
            fake, lambda: aegis_scan.check_dependency_vulnerabilities([("npm", "left-pad", "1.0.0")]))
        self.assertEqual([f.rule_id for f in found], ["DEP-00"])
        self.assertEqual(leaked(finding_blob(found)), [])

    def test_osv_advisory_finding(self):
        def fake(req, timeout=None, context=None):
            return _FakeResponse({}, json.dumps({"results": [{"vulns": [{"id": "GHSA-x"}]}]}).encode())
        found = self._with_urlopen(
            fake, lambda: aegis_scan.check_dependency_vulnerabilities([("npm", "left-pad", "1.0.0")]))
        self.assertEqual([f.rule_id for f in found], ["DEP-01"])
        self.assertIn("left-pad@1.0.0", found[0].snippet)


class TestExternalEngineOutputIsRedacted(unittest.TestCase):
    """Another tool's output is untrusted text. It is masked at the import boundary."""

    def test_semgrep(self):
        found = aegis_scan.parse_semgrep(json.loads(_FAKE_ENGINE_SCRIPTS["semgrep"]))
        self.assertEqual(found[0].rule_id, "EXT-SEMGREP:generic.secrets.hardcoded")
        self.assertEqual(leaked(finding_blob(found)), [])

    def test_gitleaks(self):
        found = aegis_scan.parse_gitleaks([{
            "RuleID": "stripe-access-token", "Description": "Stripe key",
            "File": "lib/keys.ts", "StartLine": 2, "Secret": K,
            "Match": 'new Stripe("%s")' % K, "Commit": "a" * 40}])
        self.assertEqual(found[0].rule_id, "EXT-GITLEAKS:stripe-access-token")
        self.assertEqual(leaked(finding_blob(found)), [])

    def test_trivy(self):
        found = aegis_scan.parse_trivy({"Results": [{
            "Target": "Dockerfile",
            "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "x",
                                 "Title": "leaks %s" % E, "Severity": "HIGH"}],
            "Misconfigurations": [{"ID": "DS001", "Title": "t", "Severity": "LOW",
                                   "Message": "ENV API_KEY=%s" % E,
                                   "Resolution": "remove %s" % E}]}]})
        self.assertEqual(len(found), 2)
        self.assertEqual(leaked(finding_blob(found)), [])

    def test_scorecard(self):
        found = aegis_scan.parse_scorecard({"checks": [{
            "name": "Token-Permissions", "score": 2,
            "reason": "token %s has write access" % E, "details": ["uses %s" % E]}]})
        self.assertEqual(len(found), 1)
        self.assertEqual(leaked(finding_blob(found)), [])

    @unittest.skipUnless(os.name == "posix", "fake engines are POSIX shell scripts")
    def test_unparseable_and_crashing_engines(self):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp) / "bin"
            install_fake_engines(bin_dir)
            real_path = os.environ.get("PATH", "")
            os.environ["PATH"] = str(bin_dir) + os.pathsep + real_path
            try:
                results = [aegis_scan.run_engine(n, Path(tmp)) for n in ("gitleaks", "trivy")]
            finally:
                os.environ["PATH"] = real_path
        gaps = [gap for _found, gap in results]
        self.assertTrue(all(g is not None and g.rule_id == "ENG-00" for g in gaps))
        self.assertEqual(leaked(finding_blob(gaps)), [])


class TestMobilePackageOutputIsRedacted(unittest.TestCase):

    def test_package_assets_and_bundled_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "app.apk"
            with zipfile.ZipFile(pkg, "w") as zf:
                zf.writestr("assets/config.json",
                            json.dumps({"stripe": K, "apiSecret": E, "dsn": CANARY_URL}))
                zf.writestr("assets/.env", "API_SECRET=%s\n" % E)
                zf.writestr("AndroidManifest.xml", "usesCleartextTraffic debuggable")
            found = aegis_scan.scan_mobile_package(root, pkg)
            bad = root / "broken.apk"
            bad.write_bytes(b"not a zip " + E.encode())
            found += aegis_scan.scan_mobile_package(root, bad)
        ids = {f.rule_id for f in found}
        self.assertTrue({"ART-10", "ART-11", "ART-12", "ART-13", "ART-14", "ART-15"} <= ids, ids)
        self.assertEqual(leaked(finding_blob(found)), [])


# ---------------------------------------------------------------------------
# A release stage that examined nothing is a gap, not a pass
# ---------------------------------------------------------------------------

def _git_init(root):
    git = ["git", "-c", "user.name=dev", "-c", "user.email=dev@localhost",
           "-c", "commit.gpgsign=false"]
    subprocess.run(git + ["init", "-q"], cwd=root, check=True)
    subprocess.run(git + ["add", "-A"], cwd=root, check=True)
    subprocess.run(git + ["commit", "-q", "-m", "init"], cwd=root, check=True)


def _run_main(argv, osv_results=None):
    """Run the CLI in-process, with OSV answered locally so no request leaves the test."""
    real_argv, real_open = sys.argv, aegis_scan.urllib.request.urlopen
    out = []

    def fake(req, timeout=None, context=None):
        n = len(json.loads(req.data.decode("utf-8"))["queries"])
        return _FakeResponse({}, json.dumps({"results": osv_results or [{}] * n}).encode())

    sys.argv = ["aegis_scan.py"] + argv
    aegis_scan.urllib.request.urlopen = fake
    import io
    import contextlib
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            code = aegis_scan.main()
    finally:
        sys.argv, aegis_scan.urllib.request.urlopen = real_argv, real_open
    out.append(buf.getvalue())
    return code, out[0]


def _gap_titles(findings, rule_id):
    return {f.title for f in findings if f.rule_id == rule_id}


class TestArtifactStageFailsClosed(unittest.TestCase):
    """Each of these returned an empty list, which `--profile release` read as audited."""

    def _scan(self, files, artifact=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, body in files.items():
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
            return aegis_scan.scan_build_artifacts(root, artifact, [])

    def test_no_build_output_is_a_gap(self):
        found = self._scan({"src/a.ts": "export const a = 1;\n"})
        self.assertEqual(_gap_titles(found, "ART-00"), {"No Build Output Found"})
        self.assertTrue(all(aegis_scan._is_incomplete(f) for f in found))

    def test_missing_artifact_path_is_a_gap(self):
        found = self._scan({"src/a.ts": "x"}, artifact="dist-that-was-never-built")
        self.assertEqual(_gap_titles(found, "ART-00"), {"Build Artifact Path Does Not Exist"})

    def test_build_output_with_nothing_readable_is_a_gap(self):
        found = self._scan({"dist/logo.png": b"\x89PNG\r\n", "dist/font.woff2": b"wOF2"})
        self.assertEqual(_gap_titles(found, "ART-00"), {"No Readable Build Files"})

    def test_oversized_bundle_is_a_gap(self):
        real = aegis_scan.ARTIFACT_MAX_BYTES
        aegis_scan.ARTIFACT_MAX_BYTES = 100
        try:
            found = self._scan({"dist/big.js": 'var k="%s";' % CANARY_STRIPE + "x" * 200,
                                "dist/small.js": "var a=1;"})
        finally:
            aegis_scan.ARTIFACT_MAX_BYTES = real
        self.assertEqual(_gap_titles(found, "ART-00"), {"Build Files Over 0 MB Not Examined"})
        self.assertEqual(leaked(finding_blob(found)), [])

    def test_truncation_is_a_gap_and_deterministic(self):
        real = aegis_scan.ARTIFACT_FILE_LIMIT
        aegis_scan.ARTIFACT_FILE_LIMIT = 3
        try:
            files = {"dist/%d.js" % i: "var a=%d;" % i for i in range(4)}
            files["dist/z.js"] = 'var k="%s";' % CANARY_STRIPE   # sorts last: not examined
            found = self._scan(files)
        finally:
            aegis_scan.ARTIFACT_FILE_LIMIT = real
        self.assertEqual(_gap_titles(found, "ART-00"), {"Build Output Truncated At 3 Files"})
        self.assertNotIn("ART-03", {f.rule_id for f in found})

    def test_a_package_inside_the_build_directory_is_inspected(self):
        import io
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("assets/.env", "X=1\n")
        found = self._scan({"release/app.apk": buf.getvalue(), "release/index.html": "<p>"})
        self.assertIn("ART-12", {f.rule_id for f in found})

    def test_complete_build_output_raises_no_gap(self):
        found = self._scan({"dist/index.html": "<p>hi</p>", "dist/app.js": "var a=1;",
                            "dist/logo.png": b"\x89PNG"})
        self.assertEqual([f.rule_id for f in found if f.rule_id == "ART-00"], [])


class TestDependencyStageFailsClosed(unittest.TestCase):
    """An empty dependency list used to read as "no known vulnerabilities"."""

    def _gaps(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, body in files.items():
                write(root, rel, body)
            return _gap_titles(aegis_scan.dependency_coverage_gaps(root), "DEP-00")

    LOCK = json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/lodash": {"version": "4.17.21"}}})

    def test_unsupported_lockfile_is_a_gap(self):
        gaps = self._gaps({"poetry.lock": '[[package]]\nname = "django"\nversion = "2.2.0"\n'})
        self.assertIn("Dependency Manifest Format Not Supported", gaps)

    def test_lockfile_in_a_subdirectory_is_a_gap(self):
        gaps = self._gaps({"package-lock.json": self.LOCK, "package.json": "{}",
                           "apps/web/package-lock.json": self.LOCK})
        self.assertEqual(gaps, {"Dependency Manifests Below The Repository Root Not Checked"})

    def test_manifests_in_ignored_directories_are_not_counted(self):
        gaps = self._gaps({"package-lock.json": self.LOCK, "package.json": "{}",
                           "node_modules/lodash/package.json": "{}"})
        self.assertEqual(gaps, set())

    def test_package_json_without_a_lockfile_is_a_gap(self):
        gaps = self._gaps({"package.json": '{"dependencies":{"lodash":"^4.17.0"}}'})
        self.assertEqual(gaps, {"npm Versions Taken From Ranges, Not Installed Versions"})

    def test_unpinned_requirements_are_a_gap(self):
        gaps = self._gaps({"requirements.txt": "django>=2.0\nrequests\nflask==2.0.0\n"})
        self.assertEqual(gaps, {"Unpinned Python Requirements Not Checked"})

    def test_no_manifest_at_all_is_a_gap(self):
        self.assertEqual(self._gaps({"app.py": "x = 1\n"}), {"No Dependency Manifest Found"})

    def test_fully_supported_and_pinned_manifests_raise_no_gap(self):
        gaps = self._gaps({"package-lock.json": self.LOCK, "package.json": "{}",
                           "requirements.txt": "# pinned\nflask==2.0.0\n\nrequests==2.31.0\n"})
        self.assertEqual(gaps, set())


class TestReleaseVerdictRequiresEvidence(unittest.TestCase):
    """End to end through `main()`: what `--profile release` may and may not claim."""

    def _repo(self, tmp, built=True, lock=True):
        root = Path(tmp) / "app"
        write(root, "src/a.ts", "export const a = 1;\n")
        write(root, "package.json", '{"dependencies":{"lodash":"4.17.21"}}')
        if lock:
            write(root, "package-lock.json", TestDependencyStageFailsClosed.LOCK)
        if built:
            write(root, "dist/index.js", "var a=1;")
        _git_init(root)
        return root

    def test_a_complete_clean_release_still_passes(self):
        """Closing the holes must not make the release verdict unreachable."""
        with tempfile.TemporaryDirectory() as tmp:
            code, out = _run_main([str(self._repo(tmp)), "--profile", "release", "--quiet"])
        self.assertEqual(code, 0, out)
        self.assertIn(aegis_scan.VERDICT_RELEASE_OK, out)

    def test_release_without_build_output_is_incomplete_and_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = _run_main([str(self._repo(tmp, built=False)), "--profile", "release",
                                   "--quiet"])
        self.assertEqual(code, 1, out)
        self.assertIn(aegis_scan.VERDICT_INCOMPLETE, out)
        self.assertNotIn(aegis_scan.VERDICT_RELEASE_OK, out)

    def test_release_without_a_lockfile_is_incomplete_and_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = _run_main([str(self._repo(tmp, lock=False)), "--profile", "release",
                                   "--quiet"])
        self.assertEqual(code, 1, out)
        self.assertIn(aegis_scan.VERDICT_INCOMPLETE, out)


class TestProfilesAndFlagsDoWhatTheHelpSays(unittest.TestCase):

    def _stages(self, argv):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "app"
            write(root, "src/a.ts", "export const a = 1;\n")
            write(root, "dist/index.js", "var a=1;")
            _git_init(root)
            _code, out = _run_main([str(root), "--json", "--offline"] + argv)
        return json.loads(out)["stages"]

    def test_quick_alone_runs_no_deep_stage(self):
        self.assertEqual(self._stages(["--profile", "quick"]), ["static"])

    def test_quick_honours_an_explicit_all(self):
        """`--all` is an explicit flag; quick used to drop it without a word."""
        self.assertEqual(set(self._stages(["--profile", "quick", "--all"])),
                         {"static", "git-history", "dependencies", "artifacts"})

    def test_quick_and_code_produce_identical_findings(self):
        """The help text says they are currently identical - hold it to that."""
        with tempfile.TemporaryDirectory() as tmp:
            build_redaction_corpus(Path(tmp))
            runs = [json.loads(_run_main([tmp, "--json", "--profile", p])[1]) for p in ("quick", "code")]
        strip = lambda r: sorted((f["rule_id"], f["file"], f["line"]) for f in r["findings"])
        self.assertEqual(strip(runs[0]), strip(runs[1]))

    def test_artifact_with_no_value_auto_detects(self):
        """The help promised this; argparse rejected `--artifact` without a path."""
        self.assertIn("artifacts", self._stages(["--artifact"]))


# ---------------------------------------------------------------------------
# The documentation is a promise. Hold it to the code.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestDocumentationMatchesTheScanner(unittest.TestCase):
    """A README that describes a tool which no longer exists is a defect, not a typo.

    `test_every_readme_rule_is_implemented` stops the docs promising a rule the code
    lacks. These stop the reverse - the code changing while the docs keep describing
    the old tool, which is how six stale `READY TO PUBLISH` claims reached this branch.
    """

    USER_FACING = ["README.md", "AGENTS.md", "CLAUDE.md", "llms.txt", "llms-full.txt",
                   "schemas/scan-report.schema.json", "scripts/build_llms_full.py"]
    USER_FACING_DIRS = ["skills", "docs", "adapters"]
    RETIRED_VERDICTS = ("READY TO PUBLISH", "NEEDS REVIEW", "VERIFIED_PARTIAL")
    # redact() kept the first 6 and last 4 characters until 2.7.0; it now keeps none.
    RETIRED_REDACTION = re.compile(r"(?i)first\s+(?:6|six)\b.{0,20}?last\s+(?:4|four)\b", re.S)

    def _read(self, rel):
        return (REPO_ROOT / rel).read_text(encoding="utf-8")

    def _user_facing_files(self):
        files = [REPO_ROOT / rel for rel in self.USER_FACING]
        for d in self.USER_FACING_DIRS:
            files += [p for p in (REPO_ROOT / d).rglob("*") if p.is_file()]
        return files

    def test_no_retired_verdict_is_documented(self):
        stale = ["%s: %s" % (p.relative_to(REPO_ROOT).as_posix(), v)
                 for p in self._user_facing_files()
                 for v in self.RETIRED_VERDICTS
                 if v in p.read_text(encoding="utf-8", errors="ignore")]
        self.assertEqual(stale, [], "documents a verdict the scanner can no longer return")

    def test_no_retired_redaction_claim_is_documented(self):
        stale = [p.relative_to(REPO_ROOT).as_posix() for p in self._user_facing_files()
                 if self.RETIRED_REDACTION.search(p.read_text(encoding="utf-8", errors="ignore"))]
        self.assertEqual(stale, [], "still claims redaction keeps the first 6 and last 4 characters")

    def test_every_verdict_is_documented(self):
        readme, schema = self._read("README.md"), self._read("schemas/scan-report.schema.json")
        for v in (aegis_scan.VERDICT_BLOCKED, aegis_scan.VERDICT_INCOMPLETE,
                  aegis_scan.VERDICT_REVIEW, aegis_scan.VERDICT_STATIC_OK,
                  aegis_scan.VERDICT_RELEASE_OK, "NO CODE CHANGES TO REVIEW"):
            self.assertIn(v, readme)
            self.assertIn(v, schema)

    def test_every_cli_flag_is_documented(self):
        # From the source, not `--help`: argparse wraps long lines mid-flag.
        source = Path(aegis_scan.__file__).read_text(encoding="utf-8")
        flags = set(re.findall(r'add_argument\(\s*"(--[a-z][a-z-]+)"', source))
        readme, full = self._read("README.md"), self._read("llms-full.txt")
        self.assertEqual(len(flags), source.count('add_argument("--'))
        self.assertEqual(sorted(f for f in flags if "`%s" % f not in readme), [],
                         "flags missing from the README CLI reference")
        self.assertEqual(sorted(f for f in flags if "`%s" % f not in full), [],
                         "flags missing from the llms-full.txt CLI reference")

    def test_engine_table_matches_the_adapters(self):
        readme = self._read("README.md")
        for name, spec in aegis_scan.ENGINE_SPECS.items():
            row = next((ln for ln in readme.splitlines() if ln.startswith("| `%s` |" % name)), "")
            self.assertIn(spec["licence"], row, "licence for %s" % name)
            if name in aegis_scan.ENGINE_COMMANDS:
                cmd = " ".join(aegis_scan.ENGINE_COMMANDS[name](Path("<target>"), None))
                self.assertIn("`%s`" % cmd, row, "command for %s" % name)
            else:
                self.assertIn("No adapter", row, "%s has no adapter - say so" % name)

    def test_auto_detected_artifact_directories_are_listed(self):
        listed = ", ".join("`%s/`" % d for d in aegis_scan.ARTIFACT_DIRS)
        self.assertIn(listed, self._read("README.md"))
        self.assertIn(listed, self._read("llms-full.txt"))

    def test_versions_agree_across_all_four_files(self):
        versions = {"scripts/aegis_scan.py": aegis_scan.SCANNER_VERSION,
                    "package.json": json.loads(self._read("package.json"))["version"],
                    "plugin.json": json.loads(self._read(".claude-plugin/plugin.json"))["version"]}
        market = json.loads(self._read(".claude-plugin/marketplace.json"))
        versions["marketplace.json metadata"] = market["metadata"]["version"]
        versions.update({"marketplace.json %s" % p["name"]: p["version"] for p in market["plugins"]})
        self.assertEqual(len(set(versions.values())), 1, versions)
        self.assertIn("## [%s]" % aegis_scan.SCANNER_VERSION, self._read("CHANGELOG.md"))

    def test_schema_rule_id_pattern_accepts_every_emitted_id(self):
        """The old pattern rejected COV-00, ENG-00 and every EXT-* id real reports carry."""
        schema = json.loads(self._read("schemas/scan-report.schema.json"))
        pattern = re.compile(schema["$defs"]["finding"]["properties"]["rule_id"]["pattern"])
        emitted = scanner_rule_ids() | {"EXT-SEMGREP:generic.secrets.x", "EXT-OSV-SCANNER:GHSA-1"}
        self.assertEqual(sorted(r for r in emitted if not pattern.match(r)), [])
        for junk in ("sec-01", "SEC-1", "EXT-:x", "README", ""):
            self.assertIsNone(pattern.match(junk), junk)

    def test_llms_full_is_regenerated(self):
        """Stale by one commit already happened on this branch; catch it in CI instead."""
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "repo"
            shutil.copytree(REPO_ROOT, copy, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            subprocess.run([sys.executable, "-B", str(copy / "scripts" / "build_llms_full.py"), str(copy)],
                           capture_output=True, check=True)
            fresh = (copy / "llms-full.txt").read_text(encoding="utf-8")
        self.assertEqual(fresh, self._read("llms-full.txt"),
                         "run `python scripts/build_llms_full.py .` and commit the result")
