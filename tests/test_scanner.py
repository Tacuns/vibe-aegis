import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
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
        self.assertTrue(aegis_scan.compute_readiness_score([f("LOW")])[1].startswith("READY"))
        # Below 90 with no CRITICAL/HIGH is a polish problem, not a blocker.
        many_medium = [f("MEDIUM")] * 3
        self.assertEqual(aegis_scan.compute_readiness_score(many_medium)[0], 88)
        self.assertTrue(aegis_scan.compute_readiness_score(many_medium)[1].startswith("NEEDS REVIEW"))


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
        self.assertFalse(verdict.startswith("READY"), f"still certifies an unrun audit: {verdict}")
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

    def test_ready_requires_a_complete_audit(self):
        """READY only when nothing was skipped."""
        self.assertTrue(aegis_scan.compute_readiness_score([])[1].startswith("READY"))
        self.assertIn("INCOMPLETE_SCAN",
                      aegis_scan.compute_readiness_score([self._skipped()])[1])

    def test_verdict_names_the_check_that_was_missed(self):
        """Telling someone the audit is incomplete is useless without saying which part."""
        _, verdict = aegis_scan.compute_readiness_score(
            [self._skipped(title="Dependency Vulnerability Check Skipped")])
        self.assertIn("Dependency Vulnerability Check Skipped", verdict)
        self.assertNotIn("READY TO PUBLISH", verdict)

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
        self.assertNotEqual(verdict, "READY TO PUBLISH")
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
        self.assertNotEqual(verdict, "READY TO PUBLISH")

    def test_live00_also_fails_closed(self):
        bare = aegis_scan.Finding("LIVE-00", "SECURITY", "LOW", "Unreachable",
                                  "http://x", 0, "x", "Live Deployment Check", "start the server")
        _, verdict = aegis_scan.compute_readiness_score([bare])
        self.assertNotEqual(verdict, "READY TO PUBLISH")

    def test_git00_emitted_when_history_cannot_be_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = aegis_scan.scan_git_history(Path(tmp), 10)
        self.assertEqual([f.rule_id for f in findings], ["GIT-00"])
        self.assertEqual(findings[0].status, "SKIPPED")
        _, verdict = aegis_scan.compute_readiness_score(findings)
        self.assertNotEqual(verdict, "READY TO PUBLISH")

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
        self.assertEqual(verdict, "READY TO PUBLISH")

    def test_allow_skipped_is_an_explicit_opt_in(self):
        findings = aegis_scan.check_dependency_vulnerabilities([("PyPI", "x", "1.0")], offline=True)
        self.assertNotEqual(aegis_scan.compute_readiness_score(findings)[1], "READY TO PUBLISH")
        self.assertEqual(
            aegis_scan.compute_readiness_score(findings, allow_skipped=True)[1], "READY TO PUBLISH")

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


if __name__ == "__main__":
    unittest.main()
