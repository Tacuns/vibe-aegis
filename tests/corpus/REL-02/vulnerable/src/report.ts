export async function totals(ids: string[]) {
  const out = [];
  for (const id of ids) {
    out.push(await prisma.order.findUnique({ where: { id } }));
  }
  return out;
}
