export async function DELETE(req: Request) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  const { id } = await req.json();
  await db.post.delete({ where: { id, authorId: session.user.id } });
  return Response.json({ ok: true });
}
