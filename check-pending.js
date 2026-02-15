require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function checkPending() {
  const pending = await prisma.passwordReset.findMany({
    where: {
      code: { startsWith: 'SIGNUP_' },
      used: false,
    },
    orderBy: { createdAt: 'desc' },
    take: 5
  });
  
  console.log('Last 5 pending signups:');
  pending.forEach(p => {
    console.log(`Email: ${p.email}, Code: ${p.code}, Created: ${p.createdAt}`);
    try {
      if (p.signupData) {
        const data = JSON.parse(p.signupData);
        console.log(`  StoreName: ${data.storeName}, Name: ${data.name}`);
      }
    } catch (e) {
      console.log(`  Failed to parse signupData`);
    }
  });
}

checkPending()
  .catch(e => console.error(e))
  .finally(() => prisma.$disconnect());
