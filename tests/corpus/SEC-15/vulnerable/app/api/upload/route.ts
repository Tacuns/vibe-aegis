export async function POST(req: Request) {
  const session = await auth();
  const form = await req.formData();
  const file = form.get('file') as File;
  await storage.put(file.name, file);
  return Response.json({ ok: true });
}
