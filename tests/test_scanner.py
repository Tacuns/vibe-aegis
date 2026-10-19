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


ANDROID_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "android"


def android_manifest(name: str) -> bytes:
    """A binary AndroidManifest.xml compiled by aapt - see tests/fixtures/android/README.md."""
    return (ANDROID_FIXTURES / (name + ".axml")).read_bytes()


class _NoApksigner:
    """Hide any installed `apksigner`, so a test does not depend on the machine."""

    def __enter__(self):
        import shutil as _sh
        self._real = _sh.which
        _sh.which = lambda name, *a, **k: None if name == "apksigner" else self._real(name, *a, **k)

    def __exit__(self, *exc):
        import shutil as _sh
        _sh.which = self._real
        return False


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
                z.writestr("AndroidManifest.xml", android_manifest("debuggable_cleartext_true"))
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
            with _NoApksigner():
                return {f.title for f in aegis_scan.scan_mobile_package(root, apk)}

    UNSIGNED = "Mobile Package Appears Unsigned"

    def test_v1_signed_apk_is_not_reported_unsigned(self):
        self.assertNotIn(self.UNSIGNED, self._rules(v1=True))

    def test_v2_only_signed_apk_is_not_reported_unsigned(self):
        """The regression: modern release builds sign with v2/v3 only."""
        self.assertNotIn(self.UNSIGNED, self._rules(v2=True))

    def test_apk_signed_both_ways_is_not_reported_unsigned(self):
        self.assertNotIn(self.UNSIGNED, self._rules(v1=True, v2=True))

    def test_genuinely_unsigned_apk_still_fires(self):
        self.assertIn(self.UNSIGNED, self._rules())

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
    "db/privileges.sql": (
        "create function public.rec(m text) returns void language plpgsql security definer "
        "as $$ begin perform w('%s'); end $$;\n"
        "create view public.v1 as select email, '%s' as k from auth.users;\n"
        "create view public.v2 as select '%s' as k from public.notes;\n"
        "create policy p on public.t using (auth.jwt()->'user_metadata'->>'k' = '%s');\n"
        % (E, E, E, E)),
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

    # Every string constant that IS a rule id, wherever it appears. Looking only at
    # `rule_id=` keywords missed rules that pass their id positionally to a helper -
    # SEC-18..21 did exactly that and slipped past this guard when first added.
    take(tree)
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
                zf.writestr("AndroidManifest.xml", android_manifest("debuggable_cleartext_true"))
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


# ---------------------------------------------------------------------------
# Postgres / Supabase privilege rules (SEC-18 .. SEC-21)
# ---------------------------------------------------------------------------

def _sql_findings(sql):
    masked = aegis_scan.mask_comments(sql, ".sql")
    return aegis_scan.check_postgres_privilege_rules("db/migration.sql", masked)


def _sql_ids(sql):
    return sorted(f.rule_id for f in _sql_findings(sql))


class TestPostgresPrivilegeRules(unittest.TestCase):
    """Each rule fires on the vulnerable migration and stays silent on the correct one."""

    # SEC-18 ---------------------------------------------------------------
    def test_security_definer_without_search_path_fires(self):
        sql = ("create function public.record(m text) returns void language plpgsql "
               "security definer as $$ begin perform write_audit(m); end $$;\n")
        found = _sql_findings(sql)
        self.assertEqual([f.rule_id for f in found], ["SEC-18"])
        self.assertEqual((found[0].severity, found[0].line), ("MEDIUM", 1))

    def test_security_definer_with_pinned_search_path_is_silent(self):
        self.assertEqual(_sql_ids(
            "create or replace function public.record(m text) returns void language plpgsql\n"
            "security definer set search_path = '' as $$ begin perform public.w(m); end $$;\n"), [])

    def test_search_path_pinned_later_by_alter_function_is_silent(self):
        self.assertEqual(_sql_ids(
            "create function public.record() returns void language sql security definer as $$ select 1 $$;\n"
            "alter function public.record() set search_path = '';\n"), [])

    def test_security_invoker_function_is_silent(self):
        self.assertEqual(_sql_ids(
            "create function public.f() returns int language sql as $$ select 1 $$;\n"), [])

    def test_keywords_inside_a_function_body_do_not_fire(self):
        """A body is code, not DDL: text in $$ ... $$ or $tag$ ... $tag$ is ignored."""
        self.assertEqual(_sql_ids(
            "create function public.f() returns void language plpgsql set search_path = '' as $body$\n"
            "begin execute 'create view public.v as select * from auth.users'; "
            "raise notice 'security definer'; end $body$;\n"), [])

    def test_keywords_inside_an_untagged_dollar_body_do_not_fire(self):
        """The bare `$$` form is the common one, and once was never blanked."""
        self.assertEqual(_sql_ids(
            "create function public.f() returns void language sql set search_path = '' as $$\n"
            "select 1;\ncreate view public.v as select * from auth.users;\n"
            "create function public.g() returns void language sql security definer as 'select 1';\n"
            "$$;\n"), [])

    # SEC-19 ---------------------------------------------------------------
    def test_public_view_over_auth_users_fires(self):
        found = _sql_findings("create view public.user_emails as select id, email from auth.users;\n"
                              "grant select on public.user_emails to anon;\n")
        self.assertEqual([(f.rule_id, f.severity, f.confidence) for f in found],
                         [("SEC-19", "CRITICAL", "HIGH")])

    def test_unqualified_view_is_in_public(self):
        self.assertEqual(_sql_ids("create view user_emails as select email from auth.users;\n"), ["SEC-19"])

    def test_without_a_grant_confidence_is_medium(self):
        """Supabase no longer grants the API roles new public objects by default."""
        found = _sql_findings("create view public.v as select email from auth.users;\n")
        self.assertEqual([(f.rule_id, f.confidence) for f in found], [("SEC-19", "MEDIUM")])

    def test_view_over_auth_users_with_security_invoker_is_silent(self):
        self.assertEqual(_sql_ids(
            "create view public.v with (security_invoker = true) as select email from auth.users;\n"), [])

    def test_view_in_a_private_schema_is_silent(self):
        self.assertEqual(_sql_ids("create view private.v as select email from auth.users;\n"), [])

    def test_view_revoked_from_both_api_roles_is_silent(self):
        self.assertEqual(_sql_ids(
            "create view public.v as select email from auth.users;\n"
            "revoke all on public.v from anon, authenticated;\n"), [])

    def test_revoking_only_anon_still_fires(self):
        self.assertEqual(_sql_ids("create view public.v as select email from auth.users;\n"
                                  "revoke all on public.v from anon;\n"), ["SEC-19"])

    # SEC-20 ---------------------------------------------------------------
    def test_plain_public_view_fires(self):
        found = _sql_findings("create view public.all_notes as select * from public.notes;\n"
                              "grant select on public.all_notes to authenticated;\n")
        self.assertEqual([(f.rule_id, f.severity, f.confidence) for f in found],
                         [("SEC-20", "MEDIUM", "HIGH")])

    def test_materialized_view_fires_even_with_security_invoker_text(self):
        self.assertEqual(_sql_ids("create materialized view public.stats as select count(*) from public.notes;\n"),
                         ["SEC-20"])

    def test_security_invoker_view_is_silent(self):
        for spelling in ("security_invoker = true", "security_invoker=on", "security_invoker = 'true'"):
            self.assertEqual(_sql_ids("create view public.v with (%s) as select * from public.notes;\n"
                                      % spelling), [], spelling)

    def test_security_invoker_set_later_by_alter_view_is_silent(self):
        self.assertEqual(_sql_ids("create view public.v as select * from public.notes;\n"
                                  "alter view public.v set (security_invoker = true);\n"), [])

    def test_security_invoker_false_still_fires(self):
        self.assertEqual(_sql_ids(
            "create view public.v with (security_invoker = false) as select * from public.notes;\n"), ["SEC-20"])

    # SEC-21 ---------------------------------------------------------------
    def test_policy_reading_user_metadata_fires(self):
        found = _sql_findings(
            "create policy admins on public.reports for select to authenticated\n"
            "  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');\n")
        self.assertEqual([(f.rule_id, f.severity) for f in found], [("SEC-21", "HIGH")])

    def test_policy_reading_raw_user_meta_data_fires(self):
        self.assertEqual(_sql_ids(
            "create policy p on public.r using (exists (select 1 from auth.users u where "
            "u.id = auth.uid() and u.raw_user_meta_data->>'role' = 'admin'));\n"), ["SEC-21"])

    def test_policy_reading_app_metadata_is_silent(self):
        self.assertEqual(_sql_ids(
            "create policy admins on public.reports for select\n"
            "  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');\n"), [])

    def test_user_metadata_outside_a_policy_is_silent(self):
        self.assertEqual(_sql_ids(
            "create table public.profiles (id uuid, user_metadata jsonb);\n"), [])

    # general --------------------------------------------------------------
    def test_commented_out_vulnerable_sql_is_silent(self):
        self.assertEqual(_sql_ids(
            "-- create view public.v as select email from auth.users;\n"
            "/* create policy p on t using (auth.jwt()->'user_metadata'->>'r' = 'a'); */\n"), [])

    def test_rules_run_through_the_repository_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), "supabase/migrations/001.sql",
                  "create view public.v as select email from auth.users;\n")
            findings, _ = aegis_scan.scan_repository(Path(tmp))
        self.assertIn("SEC-19", {f.rule_id for f in findings})

    def test_snippets_are_masked(self):
        found = _sql_findings("create view public.v as select email, '%s' as k from auth.users;\n" % E)
        self.assertEqual(leaked(finding_blob(found)), [])


def _find_postgres_bin():
    import glob
    # Newest first, numerically: as text, "9.6" sorts above "16".
    def major(d):
        m = re.search(r"/postgresql/(\d+)", d)
        return int(m.group(1)) if m else 0
    for d in sorted(glob.glob("/usr/lib/postgresql/*/bin"), key=major, reverse=True) + [""]:
        initdb = os.path.join(d, "initdb") if d else shutil.which("initdb")
        if initdb and os.path.exists(initdb):
            return os.path.dirname(initdb)
    return None


_PG_BIN = _find_postgres_bin()


@unittest.skipUnless(_PG_BIN and hasattr(os, "geteuid") and os.geteuid() != 0,
                     "needs PostgreSQL binaries and a non-root user (initdb refuses root)")
class TestPostgresPrivilegeRulesAgainstARealDatabase(unittest.TestCase):
    """Run the attacks for real, then check the scanner flags exactly what was exploitable.

    `tests/sql/privilege_proofs.sql` performs each attack against a throwaway cluster:
    anon reading auth.users, RLS bypassed through a view, a policy fooled by edited
    metadata, and a search_path hijack that makes an ordinary role superuser - each next
    to its documented fix. The scanner must flag every statement shown exploitable and
    none of the fixes.
    """

    PROOF = REPO_ROOT / "tests" / "sql" / "privilege_proofs.sql"

    @classmethod
    def setUpClass(cls):
        version = subprocess.run([os.path.join(_PG_BIN, "postgres"), "--version"],
                                 capture_output=True, text=True).stdout
        found = re.search(r"(\d+)(?:\.\d+)?", version)
        if not found or int(found.group(1)) < 15:
            # The documented fix for SEC-19/SEC-20 is `security_invoker`, which only
            # exists from PostgreSQL 15. On 14 the fixture cannot even create the fix.
            raise unittest.SkipTest("security_invoker needs PostgreSQL 15+, found: %s" % version.strip())
        cls._tmp = tempfile.TemporaryDirectory()
        data, sock = Path(cls._tmp.name) / "data", Path(cls._tmp.name) / "s"
        sock.mkdir()
        run = lambda *a: subprocess.run(list(a), capture_output=True, text=True, timeout=120)
        r = run(os.path.join(_PG_BIN, "initdb"), "-D", str(data), "-A", "trust", "-U", "postgres")
        assert r.returncode == 0, r.stderr
        r = run(os.path.join(_PG_BIN, "pg_ctl"), "-D", str(data), "-w", "-l", str(data / "log"),
                "-o", "-k %s -c listen_addresses=" % sock, "start")
        assert r.returncode == 0, r.stdout + r.stderr
        cls._stop = lambda: run(os.path.join(_PG_BIN, "pg_ctl"), "-D", str(data), "-m", "fast", "stop")
        psql = os.path.join(_PG_BIN, "psql")
        out = run(psql, "-h", str(sock), "-U", "postgres", "-d", "postgres", "-X", "-q",
                  "-f", str(cls.PROOF))
        cls.output = out.stdout + out.stderr
        cls.results = dict(re.findall(r"NOTICE:\s+(\w+)=(\w+)", cls.output))

    @classmethod
    def tearDownClass(cls):
        cls._stop()
        cls._tmp.cleanup()

    def test_every_attack_works_and_every_fix_blocks_it(self):
        self.assertEqual(self.results, {
            "SEC19_VULNERABLE_ROWS": "2", "SEC19_FIXED": "denied",
            "SEC20_TABLE_ROWS": "1", "SEC20_VULNERABLE_ROWS": "2", "SEC20_FIXED_ROWS": "1",
            "SEC21_VULNERABLE_ROWS": "1", "SEC21_FIXED_ROWS": "0",
            "SEC18_FIXED_SUPERUSER": "false", "SEC18_VULNERABLE_SUPERUSER": "true",
        }, self.output)

    def test_scanner_flags_exactly_the_exploitable_statements(self):
        sql = self.PROOF.read_text(encoding="utf-8")
        found = _sql_findings(sql)
        lines = sql.splitlines()
        name = lambda ln: re.search(r"(?:function|view|policy)\s+([\w.]+)", ln).group(1)
        flagged = sorted((f.rule_id, name(lines[f.line - 1])) for f in found)
        self.assertEqual(flagged, [("SEC-18", "public.record_event"), ("SEC-19", "public.user_emails"),
                                   ("SEC-20", "public.all_notes"), ("SEC-21", "meta_admin")])


# ---------------------------------------------------------------------------
# TruffleHog adapter, Trivy secrets, and the release profile's severity gate
# ---------------------------------------------------------------------------

def _trufflehog_row(raw, verified=False, git=True):
    """The shape real TruffleHog v3 emits, one object per line, with a canary in every
    field that can hold the secret or personal data."""
    loc = ({"Git": {"commit": "97b8e68b4cb50d85b17ee5b3f76ee5098159e971", "file": "k.py",
                    "email": "Dev <dev-%s@corp.example>" % CANARY_ENV_PASS, "line": 2,
                    "repository": "file:///work/app", "timestamp": "2026-10-19 02:00:00 +0000"}}
           if git else {"Filesystem": {"file": "/work/app/k.py", "line": 2}})
    return {"SourceMetadata": {"Data": loc}, "SourceID": 1, "SourceType": 16, "SourceName": "trufflehog - git",
            "DetectorType": 8, "DetectorName": "Github", "DetectorDescription": "GitHub token",
            "DecoderName": "PLAIN", "Verified": verified, "VerificationFromCache": False,
            "Raw": raw, "RawV2": raw + CANARY_WEBHOOK_BODY, "Redacted": "",
            "ExtraData": {"username": CANARY_URL_PASS}, "StructuredData": {"token": CANARY_ENTROPY},
            "SecretParts": {"key": CANARY_ENTROPY}}


class TestTruffleHogAdapter(unittest.TestCase):

    def test_parser_reads_only_raw_and_only_through_redact(self):
        found = aegis_scan.parse_trufflehog([_trufflehog_row(CANARY_STRIPE)])
        self.assertEqual(len(found), 1)
        f = found[0]
        self.assertEqual((f.rule_id, f.file, f.line), ("EXT-TRUFFLEHOG:Github", "k.py", 2))
        self.assertIn("sk_live_...[REDACTED", f.snippet)
        self.assertIn("commit 97b8e68b4c", f.snippet)
        self.assertEqual(leaked(finding_blob(found)), [], "RawV2 / ExtraData / email leaked")

    def test_unverified_is_high_and_medium_confidence_verified_is_critical(self):
        unverified, verified = aegis_scan.parse_trufflehog(
            [_trufflehog_row(CANARY_STRIPE), _trufflehog_row(CANARY_STRIPE, verified=True)])
        self.assertEqual((unverified.severity, unverified.confidence), ("HIGH", "MEDIUM"))
        self.assertEqual((verified.severity, verified.confidence), ("CRITICAL", "HIGH"))

    def test_filesystem_mode_rows_parse(self):
        f = aegis_scan.parse_trufflehog([_trufflehog_row(CANARY_STRIPE, git=False)])[0]
        self.assertEqual((f.file, f.line), ("/work/app/k.py", 2))

    def test_command_always_disables_verification_and_updates(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp)
            repo = Path(tmp) / "repo"
            (repo / ".git").mkdir(parents=True)
            for root, mode in ((plain, "filesystem"), (repo, "git")):
                cmd = aegis_scan.ENGINE_COMMANDS["trufflehog"](root, None)
                self.assertEqual(cmd[1], mode)
                self.assertIn("--no-verification", cmd)
                self.assertIn("--no-update", cmd)
        self.assertTrue(cmd[2].startswith("file://"))

    def _run_fake(self, script):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir, root = Path(tmp) / "bin", Path(tmp) / "app"
            bin_dir.mkdir(); root.mkdir()
            exe = bin_dir / "trufflehog"
            exe.write_text("#!/bin/sh\n" + script, encoding="utf-8")
            exe.chmod(0o755)
            real = os.environ.get("PATH", "")
            os.environ["PATH"] = str(bin_dir) + os.pathsep + real
            try:
                return aegis_scan.run_engine("trufflehog", root)
            finally:
                os.environ["PATH"] = real

    @unittest.skipUnless(os.name == "posix", "fake engines are POSIX shell scripts")
    def test_empty_output_with_exit_zero_is_clean_not_a_gap(self):
        """Clean TruffleHog prints nothing at all; that must not read as 'did not run'."""
        self.assertEqual(self._run_fake("exit 0\n"), ([], None))

    @unittest.skipUnless(os.name == "posix", "fake engines are POSIX shell scripts")
    def test_non_zero_exit_is_a_gap(self):
        found, gap = self._run_fake("echo 'fatal: repo not found' >&2\nexit 1\n")
        self.assertEqual((found, gap.rule_id), ([], "ENG-00"))
        self.assertIn("exited 1", gap.snippet)

    @unittest.skipUnless(os.name == "posix", "fake engines are POSIX shell scripts")
    def test_unparseable_lines_are_a_gap(self):
        found, gap = self._run_fake("echo 'not json %s'\nexit 0\n" % E)
        self.assertEqual((found, gap.rule_id), ([], "ENG-00"))
        self.assertEqual(leaked(finding_blob([gap])), [])

    @unittest.skipUnless(os.name == "posix", "fake engines are POSIX shell scripts")
    def test_json_lines_are_imported(self):
        rows = "\n".join(json.dumps(_trufflehog_row(CANARY_STRIPE, git=g)) for g in (True, False))
        found, gap = self._run_fake("cat <<'EOF'\n%s\nEOF\n" % rows)
        self.assertIsNone(gap)
        self.assertEqual(len(found), 2)
        self.assertEqual(leaked(finding_blob(found)), [])


class TestTrivySecretsAreImported(unittest.TestCase):

    def test_secrets_imported_from_match_never_from_code(self):
        """Real trivy masks Match, but Code carries neighbouring lines verbatim."""
        payload = {"Results": [{"Target": "k.py", "Class": "secret", "Secrets": [{
            "RuleID": "github-pat", "Category": "GitHub", "Severity": "CRITICAL",
            "Title": "GitHub Personal Access Token", "StartLine": 1, "EndLine": 1,
            "Match": 'token = "****************************************"', "Offset": 9,
            "Code": {"Lines": [
                {"Number": 1, "Content": 'token = "****"', "IsCause": True},
                {"Number": 2, "Content": 'url = "postgres://app:%s@db/app"' % CANARY_URL_PASS,
                 "IsCause": False},
                {"Number": 3, "Content": 'other = "%s"' % E, "IsCause": False}]}}]}]}
        found = aegis_scan.parse_trivy(payload)
        self.assertEqual([(f.rule_id, f.severity, f.file, f.line) for f in found],
                         [("EXT-TRIVY:github-pat", "CRITICAL", "k.py", 1)])
        self.assertEqual(leaked(finding_blob(found)), [])

    def test_an_unmasked_match_is_still_redacted(self):
        found = aegis_scan.parse_trivy({"Results": [{"Target": "a.js", "Secrets": [{
            "RuleID": "stripe", "Severity": "HIGH", "Title": "t", "StartLine": 3,
            "Match": 'k = "%s"' % CANARY_STRIPE}]}]})
        self.assertEqual(leaked(finding_blob(found)), [])

    def test_vulnerabilities_and_misconfigurations_still_parse(self):
        found = aegis_scan.parse_trivy({"Results": [{"Target": "Dockerfile",
            "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "x", "Severity": "HIGH"}],
            "Misconfigurations": [{"ID": "DS001", "Title": "t", "Severity": "LOW"}]}]})
        self.assertEqual(len(found), 2)


class TestEngineFilePathsAreRepositoryRelative(unittest.TestCase):

    def test_absolute_paths_under_the_root_become_relative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = aegis_scan._engine_finding("x", "r", "LOW", "t", str(root / "src" / "a.py"), 1, "s", "c", "r")
            outside = aegis_scan._engine_finding("x", "r", "LOW", "t", "/elsewhere/b.py", 1, "s", "c", "r")
            aegis_scan._relative_to(root, [f, outside])
        self.assertEqual((f.file, outside.file), ("src/a.py", "/elsewhere/b.py"))


@unittest.skipUnless(all(shutil.which(b) for b in ("trufflehog", "gitleaks", "trivy", "git")),
                     "needs the real trufflehog, gitleaks and trivy binaries on PATH")
class TestRealEnginesThroughOurAdapters(unittest.TestCase):
    """Run when the real tools are installed: a fake-binary test proves our assumptions
    about their output, this proves the assumptions were right."""

    def test_real_engines_find_and_redact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "app"
            write(root, "k.py", 'token = "%s"\nurl = "postgres://app:%s@db.internal/app"\n'
                  % (GH_TOKEN, "Zx9Qw2" + "Lp7Rt4"))
            _git_init(root)
            results = {n: aegis_scan.run_engine(n, root) for n in ("trufflehog", "gitleaks", "trivy")}
        for name, (found, gap) in results.items():
            self.assertIsNone(gap, "%s: %s" % (name, gap and gap.snippet))
            self.assertTrue(found, name)
            blob = finding_blob(found)
            self.assertEqual(leaked(blob, (GH_TOKEN[4:], "Zx9Qw2" + "Lp7Rt4")), [], name)
            self.assertNotIn("dev@localhost", blob, name)
            self.assertTrue(all(not Path(f.file).is_absolute() for f in found), name)


class TestReleaseProfileFailsOnHighByDefault(unittest.TestCase):
    """`--profile release` used to exit 0 on a BLOCKED verdict unless --fail-on-high."""

    def _release(self, extra):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "app"
            write(root, "app.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")   # SEC-08 HIGH
            write(root, "requirements.txt", "flask==3.0.3\n")
            write(root, "dist/index.js", "var a=1;")
            _git_init(root)
            return _run_main([str(root), "--profile", "release", "--quiet"] + extra)

    def test_a_high_finding_fails_the_release_profile_without_any_flag(self):
        code, out = self._release([])
        self.assertIn(aegis_scan.VERDICT_BLOCKED, out)
        self.assertEqual(code, 1, out)

    def test_an_explicit_fail_on_still_wins(self):
        """A team may deliberately gate a release on CRITICAL only."""
        code, out = self._release(["--fail-on", "critical"])
        self.assertIn(aegis_scan.VERDICT_BLOCKED, out)
        self.assertEqual(code, 0, out)

    def test_other_profiles_are_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), "app.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
            code, out = _run_main([tmp, "--quiet"])
        self.assertIn(aegis_scan.VERDICT_BLOCKED, out)
        self.assertEqual(code, 0, out)


# ---------------------------------------------------------------------------
# Dependency severity, offline mode, installer safety, pinned Actions
# ---------------------------------------------------------------------------

class TestCvssCalculators(unittest.TestCase):
    """Exhaustively cross-checked against an independent implementation (all 5,184
    v3.x and 729 v2 base vectors agree); these pin the published reference values."""

    def test_cvss3_reference_scores(self):
        for vector, score in (
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 9.1),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.4),
            ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
            # Scope changed with privileges required: PR weighs differently (0.68 / 0.5).
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
            ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N", 5.5),
        ):
            self.assertEqual(aegis_scan.cvss3_base_score(vector), score, vector)

    def test_cvss3_rejects_what_it_cannot_score(self):
        for bad in ("", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    "CVSS:3.1/AV:N/AC:L", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
            self.assertIsNone(aegis_scan.cvss3_base_score(bad), bad)

    def test_cvss2_reference_scores(self):
        self.assertEqual(aegis_scan.cvss2_base_score("AV:N/AC:L/Au:N/C:C/I:C/A:C"), 10.0)
        self.assertEqual(aegis_scan.cvss2_base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P"), 7.5)
        self.assertIsNone(aegis_scan.cvss2_base_score("AV:N/AC:L"))


def _osv(vid="GHSA-test-0001", v3=None, v4=None, label=None, pkg_severity=None, ubuntu=None):
    """An OSV record shaped like the real ones in github/advisory-database."""
    severity = []
    if v3:
        severity.append({"type": "CVSS_V3", "score": v3})
    if v4:
        severity.append({"type": "CVSS_V4", "score": v4})
    if ubuntu:
        severity.append({"type": "Ubuntu", "score": ubuntu})
    affected = {"package": {"ecosystem": "npm", "name": "x"}}
    if pkg_severity:
        affected["severity"] = [{"type": "CVSS_V3", "score": pkg_severity}]
    rec = {"id": vid, "affected": [affected]}
    if severity:
        rec["severity"] = severity
    if label:
        rec["database_specific"] = {"severity": label, "github_reviewed": True}
    return rec


V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


class TestOsvRecordSeverity(unittest.TestCase):

    def sev(self, record):
        return aegis_scan.osv_record_severity(record)[0]

    def test_cvss3_vector_is_scored(self):
        self.assertEqual(self.sev(_osv(v3="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H")), "CRITICAL")

    def test_v4_only_record_falls_back_to_its_label(self):
        """1,349 of 5,239 sampled GitHub-reviewed records carry only CVSS v4."""
        self.assertEqual(self.sev(_osv(v4=V4, label="HIGH")), "HIGH")

    def test_label_only_record(self):
        self.assertEqual(self.sev(_osv(label="MODERATE")), "MEDIUM")

    def test_the_higher_signal_wins_when_vector_understates(self):
        """Real pattern: a v3 vector scoring 8.1 HIGH on an advisory rated CRITICAL."""
        self.assertEqual(self.sev(_osv(v3="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                       label="CRITICAL")), "CRITICAL")

    def test_the_higher_signal_wins_when_label_understates(self):
        self.assertEqual(self.sev(_osv(v3="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                       label="MODERATE")), "CRITICAL")

    def test_package_level_severity_is_read(self):
        """The schema allows severity per affected package instead of top level."""
        self.assertEqual(self.sev(_osv(pkg_severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
                         "CRITICAL")

    def test_ubuntu_priority_is_read(self):
        self.assertEqual(self.sev(_osv(ubuntu="high")), "HIGH")

    def test_malicious_package_is_critical(self):
        self.assertEqual(self.sev(_osv(vid="MAL-2026-1234")), "CRITICAL")

    def test_unreadable_record_is_unknown_not_low(self):
        self.assertIsNone(self.sev(_osv()))
        self.assertIsNone(self.sev(_osv(v4=V4)))


class TestDependencySeverityReachesTheGate(unittest.TestCase):
    """DEP-01 used to be MEDIUM for every advisory, so --fail-on-high never saw one."""

    def _check(self, records, deps=(("npm", "lodash", "4.17.4"),), batch=None, fail_ids=()):
        real = aegis_scan.urllib.request.urlopen

        def fake(req, timeout=None, context=None):
            url = req.full_url
            if url.endswith("/querybatch"):
                n = len(json.loads(req.data.decode("utf-8"))["queries"])
                return _FakeResponse({}, json.dumps({"results": batch or
                    [{"vulns": [{"id": r["id"]} for r in records]}] * n}).encode())
            vid = url.rsplit("/", 1)[-1]
            if vid in fail_ids:
                raise OSError("connection reset")
            rec = next(r for r in records if r["id"] == vid)
            return _FakeResponse({}, json.dumps(rec).encode())

        aegis_scan.urllib.request.urlopen = fake
        try:
            return aegis_scan.check_dependency_vulnerabilities(list(deps))
        finally:
            aegis_scan.urllib.request.urlopen = real

    def test_a_critical_advisory_is_reported_critical(self):
        found = self._check([_osv("GHSA-aaaa-0001", v3="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H")])
        self.assertEqual([(f.rule_id, f.severity, f.confidence) for f in found],
                         [("DEP-01", "CRITICAL", "HIGH")])
        self.assertIn("GHSA-aaaa-0001 CRITICAL (CVSS 9.1)", found[0].snippet)

    def test_the_worst_of_several_advisories_wins(self):
        found = self._check([_osv("GHSA-aaaa-0001", label="LOW"), _osv("GHSA-aaaa-0002", label="HIGH")])
        self.assertEqual(found[0].severity, "HIGH")

    def test_a_failed_lookup_is_high_never_medium(self):
        found = self._check([_osv("GHSA-aaaa-0001", label="LOW")], fail_ids=("GHSA-aaaa-0001",))
        self.assertEqual((found[0].severity, found[0].confidence), ("HIGH", "MEDIUM"))
        self.assertIn("could not be determined", found[0].snippet)

    def test_advisories_past_the_lookup_cap_are_high(self):
        real = aegis_scan.OSV_DETAIL_LIMIT
        aegis_scan.OSV_DETAIL_LIMIT = 1
        try:
            found = self._check([_osv("GHSA-aaaa-0001", label="LOW"), _osv("GHSA-aaaa-0002", label="LOW")])
        finally:
            aegis_scan.OSV_DETAIL_LIMIT = real
        self.assertEqual(found[0].severity, "HIGH")
        self.assertIn("too many advisories", found[0].snippet)

    def test_a_low_advisory_stays_low(self):
        """Negative: the fix must not inflate a genuinely low advisory."""
        found = self._check([_osv("GHSA-aaaa-0001", v3="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")])
        self.assertEqual(found[0].severity, "LOW")

    def test_each_advisory_is_fetched_once(self):
        calls = []
        real = aegis_scan.fetch_osv_record
        aegis_scan.fetch_osv_record = lambda vid: calls.append(vid) or _osv(vid, label="HIGH")
        try:
            self._check([_osv("GHSA-aaaa-0001", label="HIGH")],
                        deps=(("npm", "a", "1"), ("npm", "b", "1"), ("npm", "c", "1")))
        finally:
            aegis_scan.fetch_osv_record = real
        self.assertEqual(calls, ["GHSA-aaaa-0001"])


class TestOfflineMeansOffline(unittest.TestCase):
    """--offline is a promise about the whole run, external engines included."""

    def test_no_network_connection_is_attempted_by_any_stage(self):
        import socket
        attempts = []
        real = (socket.socket.connect, socket.getaddrinfo, socket.create_connection)

        def refuse(*a, **k):
            attempts.append(a[1:] if len(a) > 1 else a)
            raise OSError("network blocked by test")

        socket.socket.connect = refuse
        socket.getaddrinfo = lambda *a, **k: refuse(None, *a)
        socket.create_connection = lambda *a, **k: refuse(None, *a)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "app"
                write(root, "src/a.ts", "export const a = 1;\n")
                write(root, "requirements.txt", "django==2.2.0\n")
                write(root, "dist/index.js", "var a=1;")
                _git_init(root)
                code, out = _run_main([str(root), "--profile", "release", "--offline", "--json",
                                       "--url", "https://staging.example.com"])
        finally:
            socket.socket.connect, socket.getaddrinfo, socket.create_connection = real
        self.assertEqual(attempts, [], "a network connection was attempted under --offline")
        report = json.loads(out)
        self.assertNotIn("live-url", report["stages"])
        self.assertIn("DEP-00", {g["rule_id"] for g in report["skipped_checks"]})

    @unittest.skipUnless(os.name == "posix", "fake engines are POSIX shell scripts")
    def test_network_engines_are_not_started_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir, root = Path(tmp) / "bin", Path(tmp) / "app"
            bin_dir.mkdir()
            write(root, "a.ts", "export const a = 1;\n")
            marker = Path(tmp) / "started"
            for name in ("semgrep", "trivy", "osv-scanner", "scorecard", "gitleaks", "trufflehog"):
                exe = bin_dir / name
                exe.write_text("#!/bin/sh\necho %s >> '%s'\n%s\n" % (
                    name, marker, "echo '[]'" if name != "trufflehog" else "exit 0"), encoding="utf-8")
                exe.chmod(0o755)
            real = os.environ.get("PATH", "")
            os.environ["PATH"] = str(bin_dir) + os.pathsep + real
            try:
                engines = []
                for name in ("semgrep", "trivy", "osv-scanner", "scorecard", "gitleaks", "trufflehog"):
                    engines += ["--engine", name]
                _code, out = _run_main([str(root), "--offline", "--json"] + engines)
            finally:
                os.environ["PATH"] = real
            started = marker.read_text().split() if marker.exists() else []
        self.assertEqual(sorted(started), ["gitleaks", "trufflehog"])
        refused = {g["title"].rsplit(": ", 1)[-1] for g in json.loads(out)["skipped_checks"]
                   if g["rule_id"] == "ENG-00" and "--offline" in g["snippet"]}
        self.assertEqual(refused, {"semgrep", "trivy", "osv-scanner", "scorecard"})

    def test_without_offline_engines_are_not_blocked(self):
        """Negative: the gate applies to --offline only."""
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), "a.ts", "export const a = 1;\n")
            _code, out = _run_main([tmp, "--json", "--engine", "semgrep"])
        snippets = [g["snippet"] for g in json.loads(out)["skipped_checks"] if g["rule_id"] == "ENG-00"]
        self.assertTrue(snippets)
        self.assertFalse(any("--offline" in s for s in snippets))


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class TestInstallerNeverClobbersProjectFiles(unittest.TestCase):

    INSTALL = str(REPO_ROOT / "install.sh")

    def _install(self, target, *extra, home=None):
        env = dict(os.environ, HOME=str(home)) if home else None
        return subprocess.run(["bash", self.INSTALL, "--target", str(target), "--agent", "all", *extra],
                              capture_output=True, text=True, env=env, timeout=120)

    def _files(self, root):
        return sorted(p.relative_to(root).as_posix() for p in Path(root).rglob("*") if p.is_file())

    def test_existing_shared_config_is_never_modified(self):
        shared = {".github/copilot-instructions.md": "OUR TEAM RULES\n", "CLAUDE.md": "MINE\n",
                  "AGENTS.md": "OURS\n", ".vscode/tasks.json": "{}\n", ".cursorrules": "x\n",
                  ".clinerules": "y\n", "GEMINI.md": "z\n"}
        with tempfile.TemporaryDirectory() as tmp:
            for rel, body in shared.items():
                write(Path(tmp), rel, body)
            r = self._install(tmp)
            self.assertEqual(r.returncode, 0, r.stderr)
            for rel, body in shared.items():
                self.assertEqual((Path(tmp) / rel).read_text(), body, rel)
                self.assertTrue((Path(tmp) / ".aegis" / "suggested" / rel).is_file(), rel)
            self.assertIn("Kept your existing files unchanged", r.stdout)

    def test_an_edited_owned_file_is_backed_up_before_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), ".claude/commands/aegis.md", "MY EDIT\n")
            r = self._install(tmp)
            backups = list((Path(tmp) / ".aegis" / "backup").rglob("aegis.md"))
            self.assertEqual(len(backups), 1, r.stdout)
            self.assertEqual(backups[0].read_text(), "MY EDIT\n")
            self.assertEqual((Path(tmp) / ".claude/commands/aegis.md").read_text(),
                             (REPO_ROOT / "adapters/claude/aegis.md").read_text())

    def test_fresh_install_writes_everything_and_reruns_change_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._install(tmp)
            first = self._files(tmp)
            self.assertNotIn(".aegis/suggested", " ".join(first))
            self.assertNotIn(".aegis/backup", " ".join(first))
            r = self._install(tmp)
            self.assertEqual(self._files(tmp), first)
            self.assertNotIn("Kept your existing", r.stdout)

    def test_global_install_backs_up_too(self):
        with tempfile.TemporaryDirectory() as home:
            write(Path(home), ".claude/commands/aegis.md", "GLOBAL EDIT\n")
            r = subprocess.run(["bash", self.INSTALL, "--global"], capture_output=True, text=True,
                               env=dict(os.environ, HOME=home), timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr)
            backups = list((Path(home) / ".aegis" / "backup").rglob("aegis.md"))
            self.assertEqual([b.read_text() for b in backups], ["GLOBAL EDIT\n"])


class TestGitHubActionsArePinned(unittest.TestCase):
    """A tag can be moved to new code; a commit SHA cannot. Covers this repo's CI and
    the workflow we ship to users."""

    FILES = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")) + \
        sorted((REPO_ROOT / "adapters" / "github-actions").glob("*.yml"))

    def test_every_action_is_pinned_to_a_full_commit_sha(self):
        unpinned = []
        for f in self.FILES:
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                m = re.match(r"\s*(?:-\s*)?uses:\s*(\S+)(.*)", line)
                if not m or m.group(1).startswith("./"):
                    continue
                if not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", m.group(1)) \
                        or not re.match(r"\s*#\s*v\d", m.group(2)):
                    unpinned.append("%s:%d %s" % (f.relative_to(REPO_ROOT).as_posix(), n, line.strip()))
        self.assertEqual(unpinned, [], "pin to a commit SHA with a `# vN` comment for Dependabot")

    def test_the_check_has_something_to_check(self):
        self.assertGreaterEqual(sum(f.read_text().count("uses:") for f in self.FILES), 7)


# ---------------------------------------------------------------------------
# Checklist A: secret detection and sensitive-data protection
# ---------------------------------------------------------------------------

class TestTestContextIsDecidedByPathSegment(unittest.TestCase):
    """`test`, `spec` and `mock` as substrings made production code "test code"."""

    PRODUCTION = ("src/latest/payment-service.ts", "src/inspector/keys.ts", "lib/hammock.js",
                  "app/contest/route.ts", "src/special/billing.ts", "src/attestation/sign.ts")
    TESTS = ("tests/billing.ts", "src/__tests__/billing.ts", "src/billing.test.ts",
             "src/billing.spec.ts", "fixtures/keys.ts", "src/examples/demo.ts",
             "config/.env.example", "app/settings.sample")

    def test_production_paths_are_not_test_context(self):
        for path in self.PRODUCTION:
            self.assertFalse(aegis_scan.is_test_context(path), path)

    def test_real_test_and_example_paths_still_are(self):
        for path in self.TESTS:
            self.assertTrue(aegis_scan.is_test_context(path), path)

    def test_provider_key_keeps_its_severity_on_a_production_path(self):
        for path in self.PRODUCTION:
            found = aegis_scan.scan_secrets_in_text(path, 'const k = "%s";\n' % STRIPE_KEY)
            self.assertEqual([f.severity for f in found], ["CRITICAL"], path)

    def test_provider_key_is_not_downgraded_in_a_test_path_either(self):
        found = aegis_scan.scan_secrets_in_text("tests/billing.ts", 'const k = "%s";\n' % STRIPE_KEY)
        self.assertEqual([f.severity for f in found], ["CRITICAL"])

    def test_a_placeholder_in_a_test_path_is_still_ignored(self):
        found = aegis_scan.scan_secrets_in_text("tests/billing.ts", 'const k = "%s";\n' % ("sk_live_" + "x" * 24))
        self.assertEqual(found, [])

    def test_data_flow_runs_on_production_paths_and_not_on_tests(self):
        code = TestDataFlowAnalysis.VULNERABLE
        for path in self.PRODUCTION[:4]:
            self.assertIn("FLOW-01", {f.rule_id for f in aegis_scan.analyze_data_flow(path, ".ts", code)}, path)
        self.assertEqual(aegis_scan.analyze_data_flow("tests/route.ts", ".ts", code), [])


class TestEveryCredentialOnALineIsReported(unittest.TestCase):
    """Dedupe keyed on (file, line) discarded the second credential for good."""

    OTHER_STRIPE = "sk_live_" + "99ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHh"

    def _scan(self, line):
        return aegis_scan.dedupe(aegis_scan.scan_secrets_in_text("src/keys.ts", line + "\n"))

    def test_two_keys_of_the_same_provider(self):
        found = self._scan('const a = "%s", b = "%s";' % (STRIPE_KEY, self.OTHER_STRIPE))
        self.assertEqual(len(found), 2)
        self.assertEqual({aegis_scan._vaulted(f) for f in found}, {STRIPE_KEY, self.OTHER_STRIPE})

    def test_keys_of_two_providers(self):
        found = self._scan('const a = "%s", b = "%s";' % (AWS_KEY, STRIPE_KEY))
        self.assertEqual({aegis_scan._vaulted(f) for f in found}, {AWS_KEY, STRIPE_KEY})

    def test_the_same_key_twice_on_a_line_is_one_finding(self):
        self.assertEqual(len(self._scan('f("%s", "%s");' % (STRIPE_KEY, STRIPE_KEY))), 1)

    def test_rules_describing_one_credential_still_collapse(self):
        # The provider pattern and the secret-named assignment both match this value.
        found = self._scan('STRIPE_SECRET_KEY = "%s"' % STRIPE_KEY)
        self.assertEqual(len(found), 1)

    def test_a_full_scan_reports_one_credential_once(self):
        # Three rules fire on this line: the provider pattern and the client-exposed
        # name (both carry the value) and the SEC-01 line pattern (carries none).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "src/a.ts", 'const NEXT_PUBLIC_API_SECRET = "%s";\n' % STRIPE_KEY)
            raw, _ = aegis_scan.scan_repository(root)
        secrets = [f for f in raw if f.rule_id.startswith("SEC-01")]
        self.assertGreaterEqual(len(secrets), 3)
        self.assertEqual(len([f for f in aegis_scan.dedupe(raw) if f.rule_id.startswith("SEC-01")]), 1)

    def test_a_key_on_a_very_long_line_is_found_every_time(self):
        line = "x" * (aegis_scan.LONG_LINE_LIMIT + 10) + ' "%s" "%s"' % (STRIPE_KEY, self.OTHER_STRIPE)
        self.assertEqual(len(self._scan(line)), 2)


class TestEnvFileProtectionAsksGit(unittest.TestCase):
    """A substring search of .gitignore for ".env" decided this before."""

    def _scan(self, gitignore, env=".env", tracked=False, git=True):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, env, "SESSION_SECRET=x\n")
            if gitignore is not None:
                write(root, ".gitignore", gitignore)
            if git:
                run = ["git", "-c", "user.name=dev", "-c", "user.email=dev@localhost",
                       "-c", "commit.gpgsign=false"]
                subprocess.run(run + ["init", "-q"], cwd=root, check=True)
                if tracked:
                    subprocess.run(run + ["add", "-f", env], cwd=root, check=True)
                    subprocess.run(run + ["commit", "-q", "-m", "x"], cwd=root, check=True)
            return [f for f in aegis_scan.check_env_files(root) if f.rule_id == "SEC-01C"]

    def test_a_comment_mentioning_env_does_not_protect_it(self):
        found = self._scan("# never commit .env files\nnode_modules\n")
        self.assertEqual([f.title for f in found], ["Environment File `.env` Is Not Ignored By Git"])

    def test_ignoring_only_the_template_does_not_protect_it(self):
        self.assertEqual(len(self._scan(".env.example\n")), 1)

    def test_a_later_negation_un_ignores_it(self):
        self.assertEqual(len(self._scan(".env\n!.env\n")), 1)

    def test_an_ignored_but_committed_env_is_reported_as_committed(self):
        found = self._scan(".env\n", tracked=True)
        self.assertEqual([f.title for f in found], ["Environment File `.env` Is Committed To Git"])
        self.assertEqual(found[0].confidence, "HIGH")

    def test_properly_ignored_env_files_are_silent(self):
        for gitignore, env in ((".env\n", ".env"), (".env*\n!.env.example\n", ".env.local"),
                               ("**/.env\n", "apps/web/.env"), ("config/\n", "config/.env")):
            self.assertEqual(self._scan(gitignore, env=env), [], (gitignore, env))

    def test_a_template_is_never_reported(self):
        self.assertEqual(self._scan("", env=".env.example"), [])

    def test_without_git_the_fallback_is_medium_confidence(self):
        found = self._scan("# .env\n", git=False)
        self.assertEqual([f.confidence for f in found], ["MEDIUM"])
        self.assertEqual(self._scan(".env\n", git=False), [])

    def test_fallback_agrees_with_git_check_ignore(self):
        """Differential test of the no-git fallback against real git on the same rules."""
        patterns = [".env", "/.env", ".env*", "!.env", "!.env.local", "config/", "**/.env",
                    "config/**", "!config/", "!config/.env", "*", "!*/", "app/**/*", "# .env"]
        paths = [".env", ".env.local", "config/.env", "app/.env", "app/config/.env", "a/b/.env"]
        differ = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            combos = [(p,) for p in patterns] + [(a, b) for a in patterns for b in patterns if a != b]
            for combo in combos:
                write(root, ".gitignore", "\n".join(combo) + "\n")
                out = subprocess.run(["git", "check-ignore", "--stdin", "-v", "-n"], cwd=root,
                                     input="\n".join(paths), capture_output=True, text=True,
                                     check=False).stdout.splitlines()
                self.assertEqual(len(out), len(paths))
                for path, line in zip(paths, out):
                    source = line.split("\t")[0]
                    git_says = source != "::" and not source.split(":", 2)[2].startswith("!")
                    if aegis_scan._gitignore_says_ignored(root, path) != git_says:
                        differ.append((combo, path, git_says))
        self.assertEqual(differ, [])


class TestMobileSweepRecordsWhatItSkips(unittest.TestCase):
    """Skipped package entries left the package looking clean."""

    def _scan(self, build):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "app.apk"
            with zipfile.ZipFile(pkg, "w", zipfile.ZIP_DEFLATED) as zf:
                build(zf)
            return aegis_scan.scan_mobile_package(root, pkg), pkg

    def test_entries_past_the_budget_are_a_gap(self):
        def build(zf):
            for i in range(aegis_scan.MOBILE_ENTRY_LIMIT + 5):
                zf.writestr("assets/f%04d.json" % i, "{}")
            zf.writestr("assets/zz_last.json", '{"k":"%s"}' % STRIPE_KEY)
        found, _ = self._scan(build)
        gaps = [f for f in found if f.rule_id == "ART-00"]
        self.assertEqual([f.title for f in gaps],
                         ["Mobile Package Sweep Stopped At %d Entries" % aegis_scan.MOBILE_ENTRY_LIMIT])
        self.assertIn("the last 6 in archive order", gaps[0].snippet)
        self.assertTrue(aegis_scan._is_incomplete(gaps[0]))

    def test_an_oversized_entry_is_a_gap(self):
        found, _ = self._scan(lambda zf: zf.writestr(
            "assets/big.json", b"\0" * (aegis_scan.MOBILE_ENTRY_MAX_BYTES + 1)))
        gaps = [f for f in found if f.rule_id == "ART-00"]
        self.assertEqual(len(gaps), 1)
        self.assertIn("assets/big.json", gaps[0].snippet)

    def test_an_entry_that_fails_to_decompress_is_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "app.apk"
            with zipfile.ZipFile(pkg, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("assets/bad.json", b"x" * 1000)
            raw = bytearray(pkg.read_bytes())
            at = raw.find(b"assets/bad.json") + len("assets/bad.json")
            raw[at + 2] ^= 0xFF
            raw[at + 3] ^= 0xFF
            pkg.write_bytes(bytes(raw))
            found = aegis_scan.scan_mobile_package(root, pkg)
        self.assertEqual([f.title for f in found if f.rule_id == "ART-00"],
                         ["1 Mobile Package Entries Could Not Be Read"])

    def test_a_package_read_in_full_has_no_gap(self):
        def build(zf):
            for i in range(aegis_scan.MOBILE_ENTRY_LIMIT - 1):   # exactly at the limit
                zf.writestr("assets/f%04d.json" % i, "{}")
            zf.writestr("assets/zz_last.json", '{"k":"%s"}' % STRIPE_KEY)
            zf.writestr("res/raw/image.png", b"\0" * 100)   # not an eligible entry
        found, _ = self._scan(build)
        self.assertEqual([f for f in found if f.rule_id == "ART-00"], [])
        self.assertIn("ART-15", {f.rule_id for f in found})


class TestUrlsAreSanitisedEverywhere(unittest.TestCase):
    """Only `user:password@` was removed; tokens in the query reached the report."""

    def test_query_values_fragment_and_path_tokens_are_removed(self):
        url = ("https://admin:%s@app.example.com:8443/share/%s/view?token=%s&sig=%s#access_token=%s"
               % (CANARY_URL_PASS, ENTROPY_VALUE, ENTROPY_VALUE, E, ENTROPY_VALUE))
        shown = aegis_scan.display_url(url)
        self.assertEqual(shown, "https://[REDACTED]@app.example.com:8443/share/[REDACTED]/view"
                                "?token=[REDACTED]&sig=[REDACTED]#[REDACTED]")
        self.assertEqual(leaked(shown), [])

    def test_a_provider_key_in_the_path_is_removed(self):
        self.assertEqual(aegis_scan.display_url("https://x.io/hooks/%s" % STRIPE_KEY),
                         "https://x.io/hooks/[REDACTED]")

    def test_a_bare_query_item_is_removed(self):
        self.assertEqual(aegis_scan.display_url("https://x.io/?%s" % ENTROPY_VALUE),
                         "https://x.io/?[REDACTED]")

    def test_ordinary_urls_are_unchanged(self):
        for url in ("http://localhost:3000", "http://localhost:3000/",
                    "https://app.example.com/docs/getting-started/installation-guide",
                    "https://staging.example.com/api/v2/orders"):
            self.assertEqual(aegis_scan.display_url(url), url)

    def test_the_report_live_url_and_every_output_are_clean(self):
        url = "https://staging.example.com/?token=%s#access_token=%s" % (ENTROPY_VALUE, ENTROPY_VALUE)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "README.md", "hello\n")
            # _run_main answers every request locally, so nothing leaves the test.
            _code, out = _run_main([str(root), "--url", url, "--output", str(root / "r.json"),
                                    "--sarif", str(root / "r.sarif")])
            report = json.loads((root / "r.json").read_text())
            blob = out + (root / "r.json").read_text() + (root / "r.sarif").read_text()
        self.assertEqual(report["live_url"], "https://staging.example.com/?token=[REDACTED]#[REDACTED]")
        self.assertNotIn(ENTROPY_VALUE, blob)


# ---------------------------------------------------------------------------
# Checklist B: release gate and coverage correctness
# ---------------------------------------------------------------------------

def _osv_scanner_payload(vulns, groups):
    return {"results": [{"source": {"path": "package-lock.json", "type": "lockfile"},
                         "packages": [{"package": {"name": "minimist", "version": "1.2.5",
                                                   "ecosystem": "npm"},
                                       "vulnerabilities": vulns, "groups": groups}]}]}


class TestOsvScannerSeverity(unittest.TestCase):
    """The adapter called every advisory MEDIUM. Records trimmed from real
    osv-scanner 2.2.2 output for minimist 1.2.5 and lodash 4.17.15."""

    CRITICAL = {"id": "GHSA-xvch-5gv4-984h", "aliases": ["CVE-2021-44906"],
                "summary": "Prototype Pollution in minimist",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "database_specific": {"severity": "CRITICAL", "github_reviewed": True}}
    MODERATE = {"id": "GHSA-29mw-wpgm-hmr9", "summary": "ReDoS in lodash",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
                "database_specific": {"severity": "MODERATE"}}

    def _sev(self, vulns, groups=()):
        found = aegis_scan.parse_osv_scanner(_osv_scanner_payload(vulns, list(groups)))
        return [(f.rule_id.split(":", 1)[1], f.severity, f.confidence) for f in found]

    def test_real_records_keep_their_severity(self):
        self.assertEqual(self._sev([self.CRITICAL, self.MODERATE],
                                   [{"ids": ["GHSA-xvch-5gv4-984h"], "max_severity": "9.8"},
                                    {"ids": ["GHSA-29mw-wpgm-hmr9"], "max_severity": "5.3"}]),
                         [("GHSA-xvch-5gv4-984h", "CRITICAL", "HIGH"),
                          ("GHSA-29mw-wpgm-hmr9", "MEDIUM", "HIGH")])

    def test_the_group_score_is_a_signal_too(self):
        bare = {"id": "GHSA-aaaa-bbbb-cccc"}
        self.assertEqual(self._sev([bare], [{"ids": ["GHSA-aaaa-bbbb-cccc"], "max_severity": "7.5"}]),
                         [("GHSA-aaaa-bbbb-cccc", "HIGH", "HIGH")])

    def test_the_highest_signal_wins(self):
        self.assertEqual(self._sev([self.MODERATE], [{"ids": ["GHSA-29mw-wpgm-hmr9"],
                                                       "max_severity": "9.1"}])[0][1], "CRITICAL")

    def test_no_readable_severity_is_high_at_medium_confidence(self):
        self.assertEqual(self._sev([{"id": "GHSA-zzzz-zzzz-zzzz"}],
                                   [{"ids": ["GHSA-zzzz-zzzz-zzzz"], "max_severity": ""}]),
                         [("GHSA-zzzz-zzzz-zzzz", "HIGH", "MEDIUM")])

    def test_malicious_package_is_critical(self):
        self.assertEqual(self._sev([{"id": "MAL-2024-1"}])[0][1], "CRITICAL")


class TestReleaseProfileRequiresAPass(unittest.TestCase):
    """REVIEW_REQUIRED says a human must decide before release; it exited 0."""

    def _release(self, source, extra=()):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "app"
            write(root, "src/page.tsx", source)
            write(root, "requirements.txt", "flask==3.0.3\n")
            write(root, "dist/index.js", "var a=1;")
            _git_init(root)
            return _run_main([str(root), "--profile", "release", "--quiet"] + list(extra))

    def test_review_required_fails_the_release_profile(self):
        code, out = self._release('<img src="a.png">\n')     # UX-07, MEDIUM
        self.assertIn(aegis_scan.VERDICT_REVIEW, out)
        self.assertEqual(code, 1, out)

    def test_a_clean_release_audit_passes(self):
        code, out = self._release("export const x = 1;\n")
        self.assertIn(aegis_scan.VERDICT_RELEASE_OK, out)
        self.assertEqual(code, 0, out)

    def test_an_explicit_fail_on_gates_on_severity_alone(self):
        code, out = self._release('<img src="a.png">\n', ["--fail-on", "high"])
        self.assertIn(aegis_scan.VERDICT_REVIEW, out)
        self.assertEqual(code, 0, out)

    def test_review_required_from_low_findings_alone_fails_too(self):
        # Eleven LOW findings and no MEDIUM: the score drops below 90, so the verdict is
        # REVIEW_REQUIRED although no finding reaches the MEDIUM threshold.
        code, out = self._release('<div className="outline-none">x</div>\n' * 11)
        self.assertIn(aegis_scan.VERDICT_REVIEW, out)
        self.assertIn("0C 0H 0M 11L", out)
        self.assertEqual(code, 1, out)

    def test_raising_min_confidence_does_not_drop_a_confident_finding(self):
        code, _out = self._release('<img src="a.png">\n', ["--min-confidence", "high"])
        self.assertEqual(code, 1)


class TestGitHistoryCoverageIsStated(unittest.TestCase):
    """The limit, other refs, renames and failed commits were all silent."""

    G = ["git", "-c", "user.name=dev", "-c", "user.email=dev@localhost", "-c", "commit.gpgsign=false"]
    OTHER = "sk_live_" + "99ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHh"

    def _commit(self, root, msg):
        subprocess.run(self.G + ["add", "-A"], cwd=root, check=True)
        subprocess.run(self.G + ["commit", "-q", "-m", msg], cwd=root, check=True)

    def _repo(self, tmp):
        root = Path(tmp) / "r"
        root.mkdir()
        subprocess.run(self.G + ["init", "-q", "-b", "main"], cwd=root, check=True)
        write(root, "a.txt", "0\n")
        self._commit(root, "first")
        return root

    @staticmethod
    def _keys(found):
        return {aegis_scan._vaulted(f) for f in found if f.rule_id == "HIST-01"}

    def test_a_truncated_history_is_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            write(root, "k.ts", 'const k = "%s";\n' % STRIPE_KEY)
            self._commit(root, "key")
            for i in range(4):
                write(root, "a.txt", "change %d\n" % i)
                self._commit(root, "c%d" % i)
            short = aegis_scan.scan_git_history(root, 3)
            full = aegis_scan.scan_git_history(root, 300)
        self.assertEqual(_gap_titles(short, "GIT-00"), {"Git History Truncated At 3 Commits"})
        self.assertIn("the 3 oldest were NOT examined", next(f for f in short if f.rule_id == "GIT-00").snippet)
        self.assertEqual(_gap_titles(full, "GIT-00"), set())
        self.assertEqual(self._keys(full), {STRIPE_KEY})

    def test_a_key_on_another_branch_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            subprocess.run(self.G + ["checkout", "-q", "-b", "feature"], cwd=root, check=True)
            write(root, "f.ts", 'const f = "%s";\n' % self.OTHER)
            self._commit(root, "feature key")
            subprocess.run(self.G + ["checkout", "-q", "main"], cwd=root, check=True)
            self.assertEqual(self._keys(aegis_scan.scan_git_history(root)), {self.OTHER})

    def test_a_key_added_in_a_rename_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            body = "".join("line %d of a stable file\n" % i for i in range(40))
            write(root, "cfg.ts", body)
            self._commit(root, "cfg")
            (root / "cfg.ts").unlink()
            write(root, "settings.ts", body + 'const z = "%s";\n' % STRIPE_KEY)
            self._commit(root, "rename and add a key")
            self.assertEqual(self._keys(aegis_scan.scan_git_history(root)), {STRIPE_KEY})

    def test_a_key_written_while_resolving_a_merge_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            subprocess.run(self.G + ["checkout", "-q", "-b", "f"], cwd=root, check=True)
            write(root, "f.txt", "f\n")
            self._commit(root, "f")
            subprocess.run(self.G + ["checkout", "-q", "main"], cwd=root, check=True)
            write(root, "b.txt", "b\n")
            self._commit(root, "b")
            subprocess.run(self.G + ["merge", "-q", "--no-commit", "f"], cwd=root, check=True)
            write(root, "m.ts", 'const m = "%s";\n' % STRIPE_KEY)
            self._commit(root, "merge")
            self.assertEqual(self._keys(aegis_scan.scan_git_history(root)), {STRIPE_KEY})

    def test_a_shallow_clone_is_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            write(root, "a.txt", "1\n")
            self._commit(root, "second")
            clone = Path(tmp) / "clone"
            subprocess.run(["git", "clone", "-q", "--depth", "1", root.as_uri(), str(clone)], check=True)
            self.assertIn("Git History Is A Shallow Clone",
                          _gap_titles(aegis_scan.scan_git_history(clone), "GIT-00"))
            self.assertEqual(_gap_titles(aegis_scan.scan_git_history(root), "GIT-00"), set())

    def test_a_commit_git_cannot_show_is_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            real = aegis_scan.run_git

            def failing_show(r, args, timeout=60):
                return None if args[:1] == ["show"] else real(r, args, timeout)
            aegis_scan.run_git = failing_show
            try:
                found = aegis_scan.scan_git_history(root)
            finally:
                aegis_scan.run_git = real
        self.assertEqual(_gap_titles(found, "GIT-00"), {"1 Commit(s) Could Not Be Read"})


class TestStaticAssetsAreNotABuild(unittest.TestCase):
    """A readable `public/robots.txt` satisfied the artifact stage on its own."""

    def _gaps(self, files, artifact=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, body in files.items():
                write(root, rel, body)
            return _gap_titles(aegis_scan.scan_build_artifacts(root, artifact, []), "ART-00")

    def test_only_public_is_a_gap(self):
        self.assertEqual(self._gaps({"public/robots.txt": "User-agent: *\n"}), {"No Build Output Found"})

    def test_public_beside_a_build_is_fine(self):
        self.assertEqual(self._gaps({"public/robots.txt": "x\n", "dist/index.js": "var a=1;"}), set())

    def test_public_is_still_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "public/config.js", 'window.K="%s";' % STRIPE_KEY)
            found = aegis_scan.scan_build_artifacts(root, None, [])
        self.assertIn("ART-03", {f.rule_id for f in found})

    def test_an_explicit_artifact_path_is_trusted(self):
        self.assertEqual(self._gaps({"public/index.html": "<html></html>"}, "public"), set())


class TestCoverageLedgerIsOrderIndependent(unittest.TestCase):
    """The first occurrence's `material` flag decided for every later one."""

    REASON = "minified bundle or lockfile not scanned"

    def _ledger(self, order):
        ledger = aegis_scan.CoverageLedger()
        for name in order:
            ledger.record(self.REASON, name, material=name.endswith(".min.js"))
        return ledger

    def test_either_order_gives_the_same_gap(self):
        a = self._ledger(["package-lock.json", "app.min.js"])
        b = self._ledger(["app.min.js", "package-lock.json"])
        for ledger in (a, b):
            gaps = ledger.gaps()
            self.assertEqual([g.title for g in gaps], ["Not Examined: %s (1 item(s))" % self.REASON])
            self.assertEqual(gaps[0].file, "app.min.js")
            self.assertEqual(ledger.material_total(), 1)
            self.assertEqual(ledger.total(), 2)
            self.assertTrue(ledger.as_dict()[self.REASON]["material"])

    def test_immaterial_skips_alone_raise_no_gap(self):
        ledger = self._ledger(["package-lock.json", "yarn.lock"])
        self.assertEqual(ledger.gaps(), [])
        self.assertFalse(ledger.as_dict()[self.REASON]["material"])


class TestLiveProbeFailuresAreGaps(unittest.TestCase):
    """A timed-out `/.env` probe read exactly like "not exposed"."""

    HEADERS = {"content-security-policy": "default-src 'self'", "x-frame-options": "DENY",
               "x-content-type-options": "nosniff", "strict-transport-security": "max-age=63072000"}

    def _probe(self, probe_error):
        def fake(req, timeout=None, context=None):
            if req.full_url.endswith(("/.env", "/.git/config")):
                raise probe_error(req.full_url)
            return _FakeResponse(self.HEADERS)
        real = aegis_scan.urllib.request.urlopen
        aegis_scan.urllib.request.urlopen = fake
        try:
            return aegis_scan.check_live_url_posture("https://app.example.com/")
        finally:
            aegis_scan.urllib.request.urlopen = real

    def test_a_timeout_is_a_gap(self):
        found = self._probe(lambda url: aegis_scan.urllib.error.URLError("timed out"))
        self.assertEqual(_gap_titles(found, "LIVE-00"),
                         {"Exposure Probe Did Not Complete (`/.env`)",
                          "Exposure Probe Did Not Complete (`/.git/config`)"})
        self.assertTrue(all(aegis_scan._is_incomplete(f) for f in found if f.rule_id == "LIVE-00"))

    def test_a_404_is_an_answer(self):
        found = self._probe(lambda url: aegis_scan.urllib.error.HTTPError(url, 404, "Not Found", {}, None))
        self.assertEqual(found, [])

    def test_a_server_error_is_not(self):
        found = self._probe(lambda url: aegis_scan.urllib.error.HTTPError(url, 503, "Unavailable", {}, None))
        self.assertEqual(len(_gap_titles(found, "LIVE-00")), 2)


class TestChangeScopeDoesNotOverrideTheVerdict(unittest.TestCase):
    """A docs-only diff replaced the verdict, even beside a CRITICAL from another stage."""

    def _diff_scan(self, files, extra=()):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "README.md", "a\n")
            for rel, body in files.items():
                write(root, rel, body)
            _git_init(root)
            write(root, "README.md", "b\n")
            subprocess.run(["git", "-c", "user.name=dev", "-c", "user.email=dev@localhost",
                            "-c", "commit.gpgsign=false", "commit", "-q", "-am", "docs"],
                           cwd=root, check=True)
            code, _out = _run_main([str(root), "--diff", "HEAD~1", "--offline",
                                    "--output", str(root / "r.json")] + list(extra))
            return code, json.loads((root / "r.json").read_text())

    def test_a_finding_from_another_stage_keeps_its_verdict(self):
        code, report = self._diff_scan({"dist/app.js": 'const k="%s";' % STRIPE_KEY},
                                       ["--artifact", "dist", "--fail-on-high"])
        self.assertTrue(report["release_verdict"].startswith(aegis_scan.VERDICT_BLOCKED), report["release_verdict"])
        self.assertLess(report["readiness_score"], 100)
        self.assertEqual(code, 1)

    def test_a_docs_only_diff_with_nothing_else_says_so(self):
        code, report = self._diff_scan({})
        self.assertTrue(report["release_verdict"].startswith("NO CODE CHANGES TO REVIEW"))
        self.assertEqual(code, 0)

    def test_an_unchanged_bundle_is_not_a_gap_in_the_diff(self):
        _code, report = self._diff_scan({"web/vendor.min.js": "var a=1;"})
        self.assertTrue(report["release_verdict"].startswith("NO CODE CHANGES TO REVIEW"),
                        report["release_verdict"])


# ---------------------------------------------------------------------------
# Checklist C: authentication, IDOR and data-flow accuracy
# ---------------------------------------------------------------------------

def _rule_hits(rel, code, rules):
    with tempfile.TemporaryDirectory() as tmp:
        write(Path(tmp), rel, code)
        found, _ = aegis_scan.scan_repository(Path(tmp))
    return sorted((f.rule_id, f.line, f.confidence) for f in found if f.rule_id in rules)


class TestEachHandlerMustAuthenticate(unittest.TestCase):
    """One file-wide search: client setup counted as auth, and GET's check covered DELETE."""

    ROUTE = "app/api/orders/route.ts"

    def _sec03(self, code, rel=ROUTE):
        return [(line, conf) for _r, line, conf in _rule_hits(rel, code, {"SEC-03"})]

    def test_creating_a_client_is_not_authentication(self):
        self.assertEqual(len(self._sec03(
            "export async function POST(req: Request) {\n"
            "  const supabase = createServerClient(URL, KEY, { cookies })\n"
            "  await supabase.from('orders').delete().eq('id', (await req.json()).id)\n}\n")), 1)

    def test_a_client_that_is_asked_for_the_user_is(self):
        self.assertEqual(self._sec03(
            "export async function POST(req: Request) {\n"
            "  const supabase = createServerClient(URL, KEY, { cookies })\n"
            "  const { data: { user } } = await supabase.auth.getUser()\n"
            "  if (!user) return new Response(null, { status: 401 })\n}\n"), [])

    def test_auth_in_one_handler_does_not_cover_another(self):
        self.assertEqual(self._sec03(
            "export async function GET(req: Request) {\n  const user = await getUser(req)\n}\n"
            "export async function DELETE(req: Request) {\n  await db.order.deleteMany({})\n}\n"),
            [(4, "MEDIUM")])

    def test_a_read_only_handler_is_not_a_mutation(self):
        self.assertEqual(self._sec03(
            "export async function GET(req: Request) {\n  return Response.json(await db.post.findMany())\n}\n"
            "export async function POST(req: Request) {\n  const s = await auth()\n"
            "  await db.post.create({})\n}\n"), [])

    def test_wrapped_handlers_and_local_guards_count(self):
        self.assertEqual(self._sec03(
            "export const POST = withAuth(async (req) => {\n  await db.o.create({})\n})\n"), [])
        self.assertEqual(self._sec03(
            "'use server'\nasync function mustBeOwner() {\n  const s = await auth()\n"
            "  if (!s) throw new Error('no')\n  return s\n}\n"
            "export async function deletePost(id) {\n  const s = await mustBeOwner()\n"
            "  await db.post.deleteMany({})\n}\n", "app/actions.ts"), [])

    def test_an_inline_server_action_is_checked(self):
        page = ("export default function Page() {\n  async function save(fd) {\n    'use server'\n"
                "%s    await db.post.deleteMany({})\n  }\n  return <form action={save} />\n}\n")
        self.assertEqual(self._sec03(page % "", "app/page.tsx"), [(2, "MEDIUM")])
        self.assertEqual(self._sec03(page % "    const s = await auth()\n", "app/page.tsx"), [])

    def test_the_directive_must_be_a_directive(self):
        # Quoting the string is not declaring server actions - in JS or anywhere else.
        self.assertEqual(self._sec03("const label = 'use server'\nexport async function x() {\n"
                                     "  await db.x.deleteMany({})\n}\n", "app/lib.ts"), [])
        self.assertEqual(self._sec03('SAMPLE = """\'use server\'\nexport async function x() {}\n"""\n',
                                     "tools/gen.py"), [])

    def test_every_unauthenticated_server_action_is_named(self):
        self.assertEqual(self._sec03(
            "'use server'\nexport async function a() {\n  await db.x.deleteMany({})\n}\n"
            "export async function b() {\n  const s = await auth()\n}\n"
            "export async function c() {\n  await db.y.deleteMany({})\n}\n", "app/actions.ts"),
            [(2, "MEDIUM"), (8, "MEDIUM")])


class TestOwnershipMustComeFromTheSession(unittest.TestCase):
    """`userId: body.userId` satisfied the owner check; the attacker sets it."""

    def _sec04(self, body):
        code = ("export async function POST(req: Request) {\n  const session = await auth()\n"
                + body + "\n}\n")
        return [(line, conf) for _r, line, conf in _rule_hits("app/api/o/route.ts", code, {"SEC-04"})]

    def test_owner_from_the_parsed_body_fires(self):
        self.assertEqual(self._sec04(
            "  const body = await req.json()\n"
            "  return db.o.findFirst({ where: { id: body.id, userId: body.userId } })"), [(4, "MEDIUM")])

    def test_owner_destructured_from_the_body_fires(self):
        self.assertEqual(self._sec04(
            "  const { id, userId } = await req.json()\n"
            "  return db.o.findFirst({ where: { id, userId } })"), [(4, "MEDIUM")])

    def test_owner_copied_through_variables_still_fires(self):
        self.assertEqual(self._sec04(
            "  const body = await req.json()\n  const claims = body.claims\n  const owner = claims.userId\n"
            "  return db.o.findFirst({ where: { id: body.id, userId: owner } })"), [(6, "MEDIUM")])

    def test_owner_from_the_session_is_silent(self):
        self.assertEqual(self._sec04(
            "  const body = await req.json()\n"
            "  return db.o.findFirst({ where: { id: body.id, userId: session.user.id } })"), [])
        self.assertEqual(self._sec04(
            "  const { id } = await req.json()\n  const userId = session.user.id\n"
            "  return db.o.findFirst({ where: { id, userId } })"), [])

    def test_owner_from_an_auth_call_on_a_request_token_is_silent(self):
        self.assertEqual(self._sec04(
            "  const body = await req.json()\n  const user = await getUser(body.token)\n"
            "  return db.o.findFirst({ where: { id: body.id, userId: user.id } })"), [])

    def test_a_mutable_request_field_is_low_confidence(self):
        # Express middleware may overwrite req.body.UserId from the token; a file
        # cannot see that, so it is a prompt to verify, not a demonstrated defect.
        self.assertEqual(self._sec04(
            "  return db.o.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })"),
            [(3, "LOW")])

    def test_a_lookup_by_a_non_id_field_is_not_addressed_by_id(self):
        self.assertEqual(self._sec04(
            "  const email = (await req.json()).email\n"
            "  return db.user.findFirst({ where: { email: email } })"), [])

    def test_no_owner_at_all_still_fires(self):
        self.assertEqual(self._sec04(
            "  const body = await req.json()\n  return db.o.findFirst({ where: { id: body.id } })"),
            [(4, "MEDIUM")])


class TestSanitizersAreSinkSpecific(unittest.TestCase):
    """Matched safe/vulnerable pairs for every sink, in TypeScript and Python."""

    JS_SINKS = {
        "FLOW-01": ("db.query(`SELECT * FROM t WHERE id = ${v}`)", ["Number(", "z.string().uuid().parse("],
                    ["encodeURIComponent(", "validateId("]),
        "FLOW-02": ("exec(`convert ${v} out.png`)", ["parseInt(", "Schema.parse("],
                    ["encodeURIComponent(", "sanitizeInput("]),
        "FLOW-03": ("el.innerHTML = v", ["escapeHtml(", "DOMPurify.sanitize("],
                    ["encodeURIComponent(", "validateText("]),
        "FLOW-04": ("await fetch(`https://api.example.com/u/${v}`)", ["encodeURIComponent(", "Schema.parse("],
                    ["Number(", "validateUrl("]),
        "FLOW-05": ("readFileSync(path.join(DIR, v))", ["path.basename(", "Schema.parse("],
                    ["encodeURIComponent(", "cleanPath("]),
    }
    PY_SINKS = {
        "FLOW-01": ('cursor.execute(f"SELECT * FROM t WHERE id = {v}")', "int("),
        "FLOW-02": ('subprocess.run(f"convert {v}", shell=True)', "shlex.quote("),
        "FLOW-04": ('requests.get(f"https://api.example.com/u/{v}")', "quote_plus("),
        "FLOW-05": ("open(os.path.join(DIR, v))", "secure_filename("),
    }

    @staticmethod
    def _js(wrap, sink):
        code = "export async function GET(req) {\n  const v = %sreq.query.x%s\n  %s\n}\n" % (
            wrap, ")" if wrap else "", sink)
        return {f.rule_id: f.confidence for f in aegis_scan.analyze_data_flow("app/api/r/route.ts", ".ts", code)}

    @staticmethod
    def _py(wrap, sink):
        code = "def view(request):\n    v = %srequest.args.get('x')%s\n    %s\n" % (
            wrap, ")" if wrap else "", sink)
        return {f.rule_id for f in aegis_scan.analyze_data_flow("app/views.py", ".py", code)}

    def test_every_js_sink_fires_unsanitized(self):
        for rule, (sink, _safe, _wrong) in self.JS_SINKS.items():
            self.assertEqual(self._js("", sink), {rule: "MEDIUM"}, rule)

    def test_the_right_sanitizer_clears_each_js_sink(self):
        for rule, (sink, safe, _wrong) in self.JS_SINKS.items():
            for fn in safe:
                self.assertEqual(self._js(fn, sink), {}, (rule, fn))

    def test_the_wrong_sanitizer_does_not(self):
        for rule, (sink, _safe, wrong) in self.JS_SINKS.items():
            self.assertEqual(self._js(wrong[0], sink), {rule: "MEDIUM"}, (rule, wrong[0]))

    def test_a_generic_validator_is_reported_at_low_confidence(self):
        for rule, (sink, _safe, wrong) in self.JS_SINKS.items():
            self.assertEqual(self._js(wrong[1], sink), {rule: "LOW"}, (rule, wrong[1]))

    def test_json_parse_is_not_validation(self):
        self.assertEqual(self._js("JSON.parse(", self.JS_SINKS["FLOW-01"][0]), {"FLOW-01": "MEDIUM"})

    def test_python_views_are_analysed(self):
        for rule, (sink, fn) in self.PY_SINKS.items():
            self.assertEqual(self._py("", sink), {rule}, rule)
            self.assertEqual(self._py(fn, sink), set(), (rule, fn))


class TestASanitizerMustWrapTheTaintedValue(unittest.TestCase):
    """A sanitizer anywhere on the line suppressed the finding."""

    def _flow(self, sink_line):
        code = "export async function GET(req) {\n  const name = req.query.name\n  %s\n}\n" % sink_line
        return {f.rule_id for f in aegis_scan.analyze_data_flow("app/api/q/route.ts", ".ts", code)}

    def test_a_sanitizer_on_another_value_does_not_count(self):
        self.assertEqual(self._flow("db.query(`SELECT * FROM t WHERE name = '${name}' LIMIT ${Number(10)}`)"),
                         {"FLOW-01"})

    def test_a_sanitizer_around_the_value_does(self):
        self.assertEqual(self._flow("db.query(`SELECT * FROM t WHERE id = ${Number(name)}`)"), set())

    def test_a_bound_parameter_is_the_fix(self):
        self.assertEqual(self._flow('db.query("SELECT * FROM t WHERE name = $1", [name])'), set())
        self.assertEqual(self._flow("await fetch('https://api.example.com/x', { body: name })"), set())

    def test_a_request_value_used_inline_fires(self):
        code = ("export async function POST(req) {\n"
                "  return db.query(`SELECT * FROM u WHERE email = '${req.body.email}'`)\n}\n")
        self.assertEqual({f.rule_id for f in aegis_scan.analyze_data_flow("app/api/l/route.ts", ".ts", code)},
                         {"FLOW-01"})

    def test_a_typescript_annotation_does_not_hide_an_assignment(self):
        code = ("export async function GET(req) {\n  let criteria: any = req.query.q ?? ''\n"
                "  return db.query(`SELECT * FROM p WHERE name LIKE '%${criteria}%'`)\n}\n")
        self.assertEqual({f.rule_id for f in aegis_scan.analyze_data_flow("app/api/s/route.ts", ".ts", code)},
                         {"FLOW-01"})


class TestTaintCrossesLocalFunctions(unittest.TestCase):
    """Data handed to a helper, or returned by one, escaped the per-function tracker."""

    @staticmethod
    def _flow(code):
        return sorted((f.rule_id, f.line) for f in aegis_scan.analyze_data_flow("app/api/q/route.ts", ".ts", code))

    def test_a_helper_whose_parameter_reaches_a_sink(self):
        self.assertEqual(self._flow(
            "function runQuery(value) {\n  return db.query(`SELECT * FROM t WHERE name = '${value}'`)\n}\n"
            "export async function GET(req) {\n  const name = req.query.name\n  return runQuery(name)\n}\n"),
            [("FLOW-01", 6)])

    def test_a_helper_that_returns_request_data(self):
        self.assertEqual(self._flow(
            "function getName(req) {\n  return req.query.name\n}\n"
            "export async function GET(req) {\n  const name = getName(req)\n"
            "  return db.query(`SELECT * FROM t WHERE name = '${name}'`)\n}\n"),
            [("FLOW-01", 6)])

    def test_a_validated_argument_to_the_helper_is_safe(self):
        self.assertEqual(self._flow(
            "function runQuery(value) {\n  return db.query(`SELECT * FROM t WHERE id = ${value}`)\n}\n"
            "export async function GET(req) {\n  const id = Number(req.query.id)\n  return runQuery(id)\n}\n"),
            [])

    def test_a_helper_that_binds_its_parameter_is_safe(self):
        self.assertEqual(self._flow(
            "function runQuery(value) {\n  return db.query('SELECT * FROM t WHERE name = $1', [value])\n}\n"
            "export async function GET(req) {\n  const name = req.query.name\n  return runQuery(name)\n}\n"),
            [])


# ---------------------------------------------------------------------------
# Checklist D: mobile package verification
# ---------------------------------------------------------------------------

def _apk_with_manifest(root, manifest, name="app.apk"):
    apk = root / name
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as z:
        if manifest is not None:
            z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", b"dex\n035\0" + b"\0" * 100)
    return apk


class TestManifestIsDecodedNotGrepped(unittest.TestCase):
    """The string pool holds the attribute NAME whatever its value, so the correct
    `debuggable="false"` was flagged exactly like `true`. Fixtures are aapt output."""

    def _manifest(self, fixture=None, raw=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = _apk_with_manifest(root, raw if raw is not None else android_manifest(fixture))
            with _NoApksigner():
                found = aegis_scan.scan_mobile_package(root, apk)
        return sorted((f.rule_id, f.severity, f.confidence) for f in found
                      if f.rule_id in ("ART-13", "ART-14") or f.title.startswith(("Android Manifest", "App Bundle")))

    def test_debuggable_true_is_high(self):
        self.assertIn(("ART-14", "HIGH", "HIGH"), self._manifest("debuggable_cleartext_true"))

    def test_debuggable_false_is_silent(self):
        self.assertNotIn("ART-14", {r for r, _s, _c in self._manifest("debuggable_false")})

    def test_cleartext_true_fires_and_false_is_silent(self):
        self.assertIn(("ART-13", "MEDIUM", "HIGH"), self._manifest("debuggable_cleartext_true"))
        self.assertEqual(self._manifest("cleartext_false"), [])

    def test_the_default_depends_on_target_sdk(self):
        # Android docs: cleartext defaults to allowed for targetSdkVersion 27 or lower.
        self.assertEqual(self._manifest("no_attributes_sdk23"), [("ART-13", "MEDIUM", "HIGH")])
        self.assertEqual(self._manifest("no_attributes_sdk28"), [])

    def test_a_resource_reference_is_a_prompt_to_verify(self):
        self.assertIn(("ART-14", "MEDIUM", "LOW"), self._manifest("debuggable_from_resource"))

    def test_an_undecodable_manifest_is_a_gap(self):
        self.assertEqual(self._manifest(raw=b"android:debuggable usesCleartextTraffic"),
                         [("ART-10", "LOW", "HIGH")])

    def test_an_app_bundle_manifest_is_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            aab = root / "app.aab"
            with zipfile.ZipFile(aab, "w") as z:
                z.writestr("base/manifest/AndroidManifest.xml", b"\x0a\x07android")
            titles = {f.title for f in aegis_scan.scan_mobile_package(root, aab)}
        self.assertIn("App Bundle Manifest Not Decoded", titles)

    def test_decoder_reads_the_exact_values(self):
        def app(name):
            d = aegis_scan.decode_android_manifest(android_manifest(name))
            a = next(at for el, at in d if el == "application")
            return {k: (v[1], v[2]) for k, v in a.items() if k in ("debuggable", "usesCleartextTraffic")}
        self.assertEqual(app("debuggable_cleartext_true"),
                         {"debuggable": (0x12, 0xFFFFFFFF), "usesCleartextTraffic": (0x12, 0xFFFFFFFF)})
        self.assertEqual(app("debuggable_false"), {"debuggable": (0x12, 0)})
        self.assertEqual(app("debuggable_from_resource")["debuggable"][0], 0x01)

    def test_attributes_are_identified_by_resource_id_not_name(self):
        """Obfuscators rename attribute strings; the resource-id map still says what an
        attribute is (aapt decodes it the same way)."""
        renamed = android_manifest("debuggable_cleartext_true").replace(
            "debuggable".encode("utf-16-le"), "xyzzyabcde".encode("utf-16-le"))
        self.assertIn(("ART-14", "HIGH", "HIGH"), self._manifest(raw=renamed))

    def test_a_utf8_string_pool_decodes_identically(self):
        """aapt2 writes UTF-8 string pools; these fixtures (aapt) are UTF-16. Re-encode
        one fixture's pool as UTF-8 (ResStringPool_header UTF8_FLAG) and compare."""
        import struct
        buf = android_manifest("debuggable_cleartext_true")
        _t, hs, _total = struct.unpack_from("<HHI", buf, 0)
        ptype, phs, psize = struct.unpack_from("<HHI", buf, hs)
        self.assertEqual(ptype, 0x0001)
        strings = aegis_scan._axml_strings(buf, hs)
        body, offsets = b"", []
        for text in strings:
            raw = text.encode("utf-8")
            self.assertLess(len(raw), 0x80)
            offsets.append(len(body))
            body += bytes([len(text), len(raw)]) + raw + b"\0"
        body += b"\0" * (-len(body) % 4)
        start = phs + 4 * len(strings)
        pool_hdr = struct.pack("<HHIIIIII", 0x0001, phs, start + len(body), len(strings), 0, 0x100, start, 0)
        pool = pool_hdr + struct.pack("<%dI" % len(strings), *offsets) + body
        rest = buf[hs + psize:]
        utf8 = struct.pack("<HHI", 0x0003, hs, hs + len(pool) + len(rest)) + buf[8:hs] + pool + rest
        self.assertEqual(aegis_scan.decode_android_manifest(utf8),
                         aegis_scan.decode_android_manifest(buf))

    def test_a_network_security_config_governs_the_default(self):
        decoded = [("manifest", {}), ("uses-sdk", {"targetSdkVersion": (0x01010270, 0x10, 23)}),
                   ("application", {"networkSecurityConfig": (0, 0x01, 0x7F0A0000)})]
        real = aegis_scan.decode_android_manifest
        aegis_scan.decode_android_manifest = lambda _b: decoded
        try:
            with tempfile.TemporaryDirectory() as tmp:
                zf = zipfile.ZipFile(_apk_with_manifest(Path(tmp), b"x"))
                found = aegis_scan._manifest_findings("app.apk", zf, zf.namelist())
                zf.close()
        finally:
            aegis_scan.decode_android_manifest = real
        self.assertEqual(found, [])

    def test_malformed_input_never_raises(self):
        import random
        rng = random.Random(1234)
        for name in ("debuggable_cleartext_true", "no_attributes_sdk28"):
            good = android_manifest(name)
            for _ in range(300):
                b = bytearray(good)
                if rng.random() < 0.5:
                    b = b[:rng.randrange(len(b))]
                for _ in range(rng.randrange(1, 6)):
                    if b:
                        b[rng.randrange(len(b))] = rng.randrange(256)
                result = aegis_scan.decode_android_manifest(bytes(b))
                self.assertTrue(result is None or isinstance(result, list))


class TestSignatureIsVerifiedOrSaidToBeUnverified(unittest.TestCase):
    """A signing block's PRESENCE was reported as if the signature had been checked."""

    def _scan(self, apk_name, verifier=None):
        """verifier: None hides apksigner; an exit code installs a stand-in that
        exits with it; "real" uses the installed apksigner."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / apk_name
            # Stored as .apk.bin: the repository's .gitignore rightly excludes *.apk.
            shutil.copy(ANDROID_FIXTURES / (apk_name + ".bin"), apk)
            if verifier == "real":
                return {f.title for f in aegis_scan.scan_mobile_package(root, apk)}
            if verifier is None:
                with _NoApksigner():
                    return {f.title for f in aegis_scan.scan_mobile_package(root, apk)}
            bin_dir = root / "bin"
            bin_dir.mkdir()
            tool = bin_dir / "apksigner"
            tool.write_text("#!/bin/sh\necho 'DOES NOT VERIFY' >&2\nexit %d\n" % verifier)
            tool.chmod(0o755)
            old = os.environ.get("PATH", "")
            os.environ["PATH"] = str(bin_dir) + os.pathsep + old
            try:
                return {f.title for f in aegis_scan.scan_mobile_package(root, apk)}
            finally:
                os.environ["PATH"] = old

    UNVERIFIED = "Package Signature Not Cryptographically Verified"
    FAILS = "Package Signature Does Not Verify"

    def test_without_a_verifier_the_signature_is_an_unknown(self):
        titles = self._scan("signed.apk")
        self.assertIn(self.UNVERIFIED, titles)
        self.assertNotIn(self.FAILS, titles)

    @unittest.skipIf(os.name == "nt", "stand-in verifier is a shell script")
    def test_a_verifier_that_passes_clears_it(self):
        titles = self._scan("signed.apk", 0)
        self.assertNotIn(self.UNVERIFIED, titles)
        self.assertNotIn(self.FAILS, titles)

    @unittest.skipIf(os.name == "nt", "stand-in verifier is a shell script")
    def test_a_verifier_that_fails_is_high(self):
        titles = self._scan("tampered.apk", 1)
        self.assertIn(self.FAILS, titles)

    def test_an_unsigned_package_is_still_unsigned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = _apk_with_manifest(root, android_manifest("cleartext_false"))
            with _NoApksigner():
                titles = {f.title for f in aegis_scan.scan_mobile_package(root, apk)}
        self.assertIn("Mobile Package Appears Unsigned", titles)
        self.assertNotIn(self.UNVERIFIED, titles)

    @unittest.skipUnless(shutil.which("apksigner"), "apksigner is not installed")
    def test_against_the_real_apksigner(self):
        self.assertFalse({self.UNVERIFIED, self.FAILS} & self._scan("signed.apk", "real"))
        self.assertIn(self.FAILS, self._scan("tampered.apk", "real"))
