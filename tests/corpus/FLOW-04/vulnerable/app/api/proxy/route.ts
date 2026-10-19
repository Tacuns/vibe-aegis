export async function GET(req) {
  const session = await auth();
  const target = req.query.target;
  return fetch(target, { signal: AbortSignal.timeout(5000) });
}
