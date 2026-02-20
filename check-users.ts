
import { PrismaClient } from '@prisma/client';

async function main() {
  const prisma = new PrismaClient();
  try {
    const users = await prisma.user.findMany({
      take: 10,
      select: { id: true, email: true, role: true }
    });
    console.log('--- Users in app-auth ---');
    console.log(JSON.stringify(users, null, 2));

    const customers = await prisma.customer.findMany({
      take: 10,
      select: { id: true, email: true }
    });
    console.log('--- Customers in app-auth ---');
    console.log(JSON.stringify(customers, null, 2));
  } catch (error) {
    console.error('Error querying database:', error);
  } finally {
    await prisma.$disconnect();
  }
}

main();
