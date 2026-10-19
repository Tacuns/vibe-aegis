export async function POST(req: Request) {
  const session = await auth();
  const body = await req.json();
  return Response.json(await db.order.findFirst({ where: { id: body.id, userId: session.user.id } }));
}
