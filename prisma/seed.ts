import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

// For Prisma v5, PrismaClient reads DATABASE_URL from .env automatically.
const prisma = new PrismaClient();

async function main() {
  // Hash passwords server-side before storing to prevent plaintext exposure.
  // bcrypt is used for secure hashing with salt to resist rainbow table attacks.
  const hashedPassword = await bcrypt.hash('password123', 10);

  // Create admin user with elevated role.
  await prisma.user.upsert({
    where: { email: 'admin@penguwave.io' },
    update: {},
    create: {
      email: 'admin@penguwave.io',
      passwordHash: hashedPassword,
      role: 'admin',
    },
  });

  // Create analyst user with standard role.
  await prisma.user.upsert({
    where: { email: 'analyst@penguwave.io' },
    update: {},
    create: {
      email: 'analyst@penguwave.io',
      passwordHash: hashedPassword,
      role: 'analyst',
    },
  });

  // Create viewer user for testing read-only RBAC restrictions.
  await prisma.user.upsert({
    where: { email: 'viewer@penguwave.io' },
    update: {},
    create: {
      email: 'viewer@penguwave.io',
      passwordHash: hashedPassword,
      role: 'viewer',
    },
  });

  console.log('Database seeded with users: admin, analyst, viewer');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
