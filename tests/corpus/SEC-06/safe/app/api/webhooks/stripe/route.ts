import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const raw = await req.text();
  const event = stripe.webhooks.constructEvent(raw, req.headers.get('stripe-signature')!, process.env.STRIPE_WEBHOOK_SECRET!);
  if (event.type === 'checkout.session.completed') await grantAccess(event.data.object);
  return new Response('ok');
}
