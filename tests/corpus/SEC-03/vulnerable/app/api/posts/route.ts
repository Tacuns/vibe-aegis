export async function DELETE(req: Request) {
  const { id } = await req.json();
  await db.post.delete({ where: { id, authorId: 'x' } });
  return Response.json({ ok: true });
}
