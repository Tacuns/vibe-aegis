export async function POST(req: Request) {
  const session = await auth();
  const body = await req.json();
  return razorpay.orders.create({ amount: body.amount, currency: 'INR' });
}
