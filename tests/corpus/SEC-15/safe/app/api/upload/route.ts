const MAX_FILE = 5 * 1024 * 1024;
const ALLOWED_TYPES = ['image/png', 'image/jpeg'];
export async function POST(req: Request) {
  const session = await auth();
  const form = await req.formData();
  const file = form.get('file') as File;
  if (file.size > MAX_FILE || !ALLOWED_TYPES.includes(file.type)) return new Response(null, { status: 400 });
  await storage.put(file.name, file);
  return Response.json({ ok: true });
}
