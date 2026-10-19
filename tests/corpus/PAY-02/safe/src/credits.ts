export async function spend(userId: string) {
  const rows = await sql`UPDATE wallets SET credits = credits - 1 WHERE user_id = ${userId} AND credits >= 1`;
  if (rows.count === 0) throw new Error('insufficient credits');
}
