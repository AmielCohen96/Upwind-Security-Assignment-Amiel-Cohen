import { PrismaClient } from '@prisma/client';

// Single shared instance for the entire process.
// Multiple `new PrismaClient()` calls open separate connection pools to the same
// SQLite file, which causes write-lock contention. A singleton avoids this.
const prisma = new PrismaClient();

export default prisma;
