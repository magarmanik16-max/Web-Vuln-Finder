const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

function fail(message) {
  // Fail loudly at boot — the platform must never run with unknown security config.
  console.error(`[config] FATAL: ${message}`);
  process.exit(1);
}

const nodeEnv = process.env.NODE_ENV || 'development';

const env = {
  nodeEnv,
  port: parseInt(process.env.PORT || '5000', 10),
  mongoUri: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/webvulnapp',
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '8h',
  clientOrigins: (process.env.CLIENT_ORIGIN || 'http://localhost:5173')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
};

// Secrets only from the environment. A missing secret stops development too —
// silently generating one would hide misconfiguration from the operator.
if (!process.env.JWT_SECRET) fail('JWT_SECRET is not set. Copy server/.env.example to server/.env and generate a real secret.');
if (env.nodeEnv === 'production' && process.env.JWT_SECRET.length < 48) {
  fail('JWT_SECRET must be >= 48 chars in production.');
}

module.exports = env;
