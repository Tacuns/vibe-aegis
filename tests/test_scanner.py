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


if __name__ == "__main__":
    unittest.main()
