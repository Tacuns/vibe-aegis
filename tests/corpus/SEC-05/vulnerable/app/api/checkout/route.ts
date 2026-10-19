export async function POST(req: Request) {
  const session = await auth();
  const body = await req.json();
  return stripe.checkout.sessions.create({ line_items: [{ price_data: { currency: 'usd', unit_amount: body.amount } }] });
}
