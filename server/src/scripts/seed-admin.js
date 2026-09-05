/**
 * Bootstrap admin from environment variables (ADMIN_EMAIL / ADMIN_PASSWORD /
 * ADMIN_NAME in server/.env). Idempotent: skips if an admin already exists.
 * Usage: npm run seed  (from server/)
 */
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const env = require('../config/env');
const User = require('../models/User');
const { connectDB } = require('../config/db');

async function seedAdmin() {
  await connectDB();
  const { ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_NAME } = process.env;

  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.error('[seed] Set ADMIN_EMAIL and ADMIN_PASSWORD in server/.env first.');
    process.exit(1);
  }
  if (ADMIN_PASSWORD.length < 12) {
    console.error('[seed] ADMIN_PASSWORD must be at least 12 characters.');
    process.exit(1);
  }

  const existing = await User.findOne({ role: 'admin' });
  if (existing) {
    console.log(`[seed] Admin already exists (${existing.email}) — nothing to do.`);
  } else {
    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    const user = await User.create({
      email: ADMIN_EMAIL.toLowerCase().trim(),
      passwordHash,
      name: ADMIN_NAME || 'Platform Admin',
      role: 'admin',
    });
    console.log(`[seed] Created admin: ${user.email}`);
  }
  await mongoose.connection.close();
}

seedAdmin().catch((err) => {
  console.error('[seed] failed:', err.message);
  process.exit(1);
});
