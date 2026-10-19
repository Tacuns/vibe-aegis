export async function POST(req: Request) {
  const session = await auth();
  const { planId } = await req.json();
  const plan = await db.plan.findUniqueOrThrow({ where: { id: planId } });
  return stripe.checkout.sessions.create({ line_items: [{ price: plan.stripePriceId, quantity: 1 }] });
}
