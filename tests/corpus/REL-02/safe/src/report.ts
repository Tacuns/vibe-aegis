export async function totals(ids: string[]) {
  return prisma.order.findMany({ where: { id: { in: ids } } });
}
