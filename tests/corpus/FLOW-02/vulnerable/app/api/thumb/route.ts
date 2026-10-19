export async function GET(req) {
  const session = await auth();
  const file = req.query.file;
  execSync('convert ' + file + ' out.png');
}
