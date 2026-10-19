export async function POST(req: Request) {
  const { email, password } = await req.json();
  return Response.json(await signIn(email, password));
}
