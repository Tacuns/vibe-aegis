export const users = (cursor?: string) => prisma.user.findMany({ take: 50, ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}) });
