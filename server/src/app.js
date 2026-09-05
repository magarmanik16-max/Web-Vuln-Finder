const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const env = require('./config/env');
const { generalLimiter, authLimiter } = require('./middleware/rateLimit');
const { notFound, errorHandler } = require('./middleware/errorHandler');
const mongoose = require('mongoose');

const authRoutes = require('./routes/auth.routes');
const targetsRoutes = require('./routes/targets.routes');
const scansRoutes = require('./routes/scans.routes');
const findingsRoutes = require('./routes/findings.routes');
const reportsRoutes = require('./routes/reports.routes');

function buildApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1); // correct req.ip behind the Vite dev proxy / reverse proxy

  // --- security middleware ---
  app.use(helmet()); // sane secure headers (HSTS, no-sniff, frameguard, CSP defaults)
  app.use(
    cors({
      origin(origin, cb) {
        // Allowed origins get CORS headers; anything else gets NO headers
        // (browsers then block the response) — never an error/500.
        if (!origin || env.clientOrigins.includes(origin)) return cb(null, true);
        cb(null, false);
      },
      methods: ['GET', 'POST'],
      credentials: false,
      maxAge: 600,
    })
  );
  app.use(express.json({ limit: '100kb' }));
  app.use(generalLimiter);

  // --- health (public, used by tooling & smoke tests) ---
  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      service: 'webvulnapp-api',
      mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      time: new Date().toISOString(),
    });
  });

  // --- API surface ---
  app.use('/api/auth', authLimiter, authRoutes);
  app.use('/api/targets', targetsRoutes);
  app.use('/api/scans', scansRoutes);
  app.use('/api/findings', findingsRoutes);
  app.use('/api/reports', reportsRoutes);

  app.use(notFound);
  app.use(errorHandler);
  return app;
}

module.exports = { buildApp };
