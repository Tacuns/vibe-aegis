export async function GET(req) {
  const session = await auth();
  const name = req.query.name;
  return db.query('SELECT * FROM t WHERE name = $1', [name]);
}
