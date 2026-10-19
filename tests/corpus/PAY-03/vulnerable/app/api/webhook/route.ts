import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === 'checkout.session.completed') await activate(event.data.object.customer);
  return new Response('ok');
}
