const ALLOWED = new Set(['api.example.com']);
export async function GET(req) {
  const session = await auth();
  const url = new URL(String(req.query.url));
  if (!ALLOWED.has(url.hostname)) return new Response(null, { status: 400 });
  return fetch(url, { signal: AbortSignal.timeout(5000) });
}
