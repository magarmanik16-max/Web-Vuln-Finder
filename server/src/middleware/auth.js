const jwt = require('jsonwebtoken');
const env = require('../config/env');
const User = require('../models/User');
const { isRevoked } = require('../security/tokenDenylist');

function extractBearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : null;
}

async function requireAuth(req, res, next) {
  try {
    const token = extractBearer(req);
    if (!token) return res.status(401).json({ error: 'Authentication required' });

    let payload;
    try {
      payload = jwt.verify(token, env.jwtSecret);
    } catch {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    if (payload.type !== 'access' || isRevoked(payload.jti)) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const user = await User.findById(payload.sub);
    if (!user || !user.active) return res.status(401).json({ error: 'Account not available' });

    req.user = user;
    req.tokenPayload = payload;
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Parses the Bearer token if present and populates req.user, but never
 * rejects. Used by routes whose behavior depends on whether a valid user is
 * attached (e.g. first-user bootstrap registration).
 */
async function softAuth(req, _res, next) {
  try {
    const token = extractBearer(req);
    if (!token) return next();
    let payload;
    try {
      payload = jwt.verify(token, env.jwtSecret);
    } catch {
      return next();
    }
    if (payload.type === 'access' && !isRevoked(payload.jti)) {
      const user = await User.findById(payload.sub);
      if (user && user.active) req.user = user;
    }
    next();
  } catch (err) {
    next(err);
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient role' });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole, softAuth, extractBearer };
