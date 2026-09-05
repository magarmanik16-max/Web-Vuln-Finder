const mongoose = require('mongoose');
const env = require('./config/env');
const { connectDB } = require('./config/db');
const { buildApp } = require('./app');
const scanManager = require('./services/scanManager');

async function main() {
  await connectDB();
  await scanManager.recoverOrphans(); // scans from a previous process cannot still be running
  const app = buildApp();
  const server = app.listen(env.port, env.host, () => {
    console.log(`[api] listening on http://${env.host}:${env.port} (${env.nodeEnv})`);
  });

  const shutdown = async (signal) => {
    console.log(`\n[api] ${signal} received, shutting down`);
    server.close();
    await mongoose.connection.close().catch(() => {});
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('[api] failed to start:', err.message);
  process.exit(1);
});
