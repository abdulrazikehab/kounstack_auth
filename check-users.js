const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function checkUsers() {
  try {
    const count = await prisma.user.count();
    console.log('Total users:', count);
    
    const users = await prisma.user.findMany({
      take: 5,
      select: { email: true, createdAt: true }
    });
    console.log('Recent users:', users);
  } catch (error) {
    console.error('Database error:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

checkUsers();
