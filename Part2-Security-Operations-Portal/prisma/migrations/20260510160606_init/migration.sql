-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'analyst',
    "status" TEXT NOT NULL DEFAULT 'active'
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
