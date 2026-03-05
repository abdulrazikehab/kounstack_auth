-- Add emailVerified column to users table (fixes Prisma "column does not exist" in production).
-- Auth DB is MySQL: TINYINT(1) = boolean (0 false, 1 true).
-- If the column already exists, this will fail; run once or add IF NOT EXISTS logic per your MySQL version.
ALTER TABLE `users` ADD COLUMN `emailVerified` TINYINT(1) NOT NULL DEFAULT 0;
