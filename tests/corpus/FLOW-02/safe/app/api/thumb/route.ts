export async function GET(req) {
  const session = await auth();
  const file = req.query.file;
  execFileSync('convert', [file, 'out.png']);
}
