export async function GET(req) {
  const session = await auth();
  return fetch(req.query.url);
}
