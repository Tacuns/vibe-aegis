export const allUsers = () => prisma.user.findMany();
