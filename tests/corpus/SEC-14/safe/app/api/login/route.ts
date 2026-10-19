const ratelimit = new Ratelimit({ limiter: Ratelimit.slidingWindow(5, '1 m') });
export async function POST(req: Request) {
  const { email, password } = await req.json();
  const { success } = await ratelimit.limit(email);
  if (!success) return new Response(null, { status: 429 });
  return Response.json(await signIn(email, password));
}
