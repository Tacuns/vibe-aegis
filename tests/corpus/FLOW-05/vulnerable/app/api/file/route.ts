export async function GET(req) {
  const session = await auth();
  const name = req.query.name;
  return readFileSync(path.join(UPLOADS, name));
}
