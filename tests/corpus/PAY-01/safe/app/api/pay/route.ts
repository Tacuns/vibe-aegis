export async function POST(req: Request) {
  const session = await auth();
  const { sku } = await req.json();
  const product = await db.product.findUniqueOrThrow({ where: { sku } });
  return razorpay.orders.create({ amount: product.pricePaise, currency: 'INR' });
}
