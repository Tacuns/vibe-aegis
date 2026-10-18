import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import aegis_scan  # noqa: E402


class TestVibeAegisScanner(unittest.TestCase):
    def test_detects_security_and_uiux_flaws(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. Create package.json
            (root / "package.json").write_text(
                json.dumps({
                    "dependencies": {
                        "next": "15.0.0",
                        "@supabase/supabase-js": "2.45.0",
                        "stripe": "16.0.0",
                        "tailwindcss": "3.4.0",
                        "openai": "4.60.0"
                    }
                }),
                encoding="utf-8",
            )
            # 2. Create a vulnerable SQL migration without RLS
            (root / "schema.sql").write_text(
                "CREATE TABLE public.Customer_orders (id uuid primary key, amount int);\n",
                encoding="utf-8",
            )
            # 3. Create an unprotected API route with client-trusted price & LLM call without max_tokens
            api_dir = root / "app" / "api" / "checkout"
            api_dir.mkdir(parents=True)
            (api_dir / "route.ts").write_text(
                '''
                export async function POST(req: Request) {
                  const body = await req.json();
                  const session = await stripe.checkout.sessions.create({
                    line_items: [{ price_data: { unit_amount: body.price } }]
                  });
                  const aiRes = await openai.chat.completions.create({ model: "gpt-4o", messages: [] });
                  return Response.json(session);
                }
                ''',
                encoding="utf-8",
            )
            # 4. Create a UI component with dead link, missing alt, missing disabled submit, and exposed secret
            comp_dir = root / "components"
            comp_dir.mkdir(parents=True)
            (comp_dir / "CheckoutForm.tsx").write_text(
                '''
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
                ''',
                encoding="utf-8",
            )

            stack = aegis_scan.detect_tech_stack(root)
            self.assertIn("next", stack["frameworks"])
            self.assertIn("@supabase/supabase-js", stack["databases_and_baas"])

            findings, count = aegis_scan.scan_repository(root)
            self.assertGreaterEqual(count, 3)
            rule_ids = {f.rule_id for f in findings}
            # Verify both Security and UI/UX rules fired
            self.assertIn("SEC-01", rule_ids)
            self.assertIn("SEC-02", rule_ids)
            self.assertIn("SEC-03", rule_ids)
            self.assertIn("SEC-05", rule_ids)
            self.assertIn("SEC-12", rule_ids)
            self.assertIn("UX-01", rule_ids)
            self.assertIn("UX-02", rule_ids)
            self.assertIn("UX-03", rule_ids)
            self.assertIn("UX-05", rule_ids)
            self.assertIn("UX-07", rule_ids)
            self.assertIn("UX-08", rule_ids)
            self.assertIn("UX-10", rule_ids)

            score, verdict = aegis_scan.compute_readiness_score(findings)
            self.assertLess(score, 50)
            self.assertTrue(verdict.startswith("BLOCKED"))


if __name__ == "__main__":
    unittest.main()
