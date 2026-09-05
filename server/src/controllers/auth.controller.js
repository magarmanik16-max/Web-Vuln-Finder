const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const env = require('../config/env');
const { logAudit } = require('../utils/audit');
const { revoke } = require('../security/tokenDenylist');

const DUMMY_HASH = '$2a$12$C6UzMDM.H6dfI/f/IKcEe.WvJ8sJcVLGVGGRIvbTQ0zMB0y5z7MmO'; // never matches user input semantics; constant-time-ish user enumeration defense

function signAccessToken(user) {
  return jwt.sign({ sub: user._id.toString(), role: user.role, type: 'access', jti: crypto.randomUUID() }, env.jwtSecret, {
    expiresIn: env.jwtExpiresIn,
  });
}

/**
 * Registration is gated: the very first account bootstraps the platform as
 * admin; afterwards only an existing admin may create accounts.
 */
async function register(req, res, next) {
  try {
    const { email, password, name, role } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
    if (typeof password !== 'string' || password.length < 12) {
      return res.status(400).json({ error: 'password must be at least 12 characters' });
    }
    if (role && !User.ROLES.includes(role)) return res.status(400).json({ error: 'invalid role' });

    const existing = await User.countDocuments();
    const isFirstUser = existing === 0;

    if (!isFirstUser) {
      if (!req.user) return res.status(401).json({ error: 'Authentication required' });
      if (req.user.role !== 'admin') return res.status(403).json({ error: 'Only admins can create accounts' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({
      email,
      passwordHash,
      name: name || '',
      role: isFirstUser ? 'admin' : role || 'analyst',
    });

    await logAudit({
      actor: req.user || user,
      action: 'auth.register',
      result: 'success',
      details: { createdEmail: user.email, role: user.role, bootstrap: isFirstUser },
      req,
    });
    res.status(201).json({ user: user.toJSON(), bootstrap: isFirstUser });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ error: 'Email already registered' });
    next(err);
  }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string' || !email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    const ok = user && user.active ? await user.comparePassword(password) : await bcrypt.compare(password, DUMMY_HASH);

    if (!ok) {
      await logAudit({
        actor: user || null,
        action: 'auth.login',
        result: 'failure',
        details: { email: String(email).slice(0, 120) },
        req,
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = signAccessToken(user);
    await logAudit({ actor: user, action: 'auth.login', result: 'success', req });
    res.json({ token, user: user.toJSON() });
  } catch (err) {
    next(err);
  }
}

async function logout(req, res, next) {
  try {
    const { exp, jti } = req.tokenPayload || {};
    revoke(jti, exp);
    await logAudit({ actor: req.user, action: 'auth.logout', result: 'success', req });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
}

async function me(req, res) {
  res.json({ user: req.user.toJSON() });
}

module.exports = { register, login, logout, me };
