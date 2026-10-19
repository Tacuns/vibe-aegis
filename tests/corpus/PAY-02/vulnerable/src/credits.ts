export async function spend(userId: string) {
  const w = await db.wallet.findUnique({ where: { userId } });
  await db.wallet.update({ where: { userId }, data: { credits: w.credits - 1 } });
}
