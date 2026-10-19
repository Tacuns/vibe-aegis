export async function GET(req) {
  const session = await auth();
  const id = req.query.id;
  return fetch(`https://api.example.com/items/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(5000) });
}
