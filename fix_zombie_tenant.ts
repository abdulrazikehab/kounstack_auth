
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function checkAndFixTenant() {
  try {
    console.log('Checking for tenant with subdomain "saeaa" in Auth DB...');
    const tenant = await prisma.tenant.findUnique({
      where: { subdomain: 'saeaa' },
    });
    
    if (tenant) {
      console.log('✅ Tenant found in Auth DB:', tenant);
      console.log('Deleting zombie tenant to allow recreation...');
      
      // Delete user-tenant links first
      await prisma.userTenant.deleteMany({
        where: { tenantId: tenant.id }
      });
      console.log('Deleted user-tenant links.');

      // Delete tenant
      await prisma.tenant.delete({
        where: { id: tenant.id }
      });
      console.log('✅ Deleted tenant form Auth DB. You can now recreate it.');
      
    } else {
      console.log('❌ Tenant "saeaa" NOT FOUND in Auth DB');
    }
    
  } catch (e) {
    console.error('Error:', e);
  } finally {
    await prisma.$disconnect();
  }
}

checkAndFixTenant();
