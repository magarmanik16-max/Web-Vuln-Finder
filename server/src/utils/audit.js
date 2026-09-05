const AuditLog = require('../models/AuditLog');

const SECRET_KEY_PATTERNS = /password|secret|token|authorization|credential|jwt/i;

/** Shallow sanitization: secret-ish keys never enter the audit trail. */
function sanitize(details) {
  if (!details || typeof details !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(details)) {
    if (SECRET_KEY_PATTERNS.test(k)) {
      out[k] = '[redacted]';
    } else if (v !== null && typeof v === 'object') {
      out[k] = '[object]';
    } else if (typeof v !== 'undefined') {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Fire-and-forget audit write. Audit failures are logged but never break the
 * request that is being audited.
 */
async function logAudit({ actor, action, targetId = null, scanId = null, result = 'success', details = {}, req }) {
  try {
    await AuditLog.create({
      actor: actor ? actor._id || actor : null,
      actorEmail: (actor && actor.email) || '',
      action,
      targetId,
      scanId,
      result,
      ip: req && req.ip ? String(req.ip) : '',
      userAgent: req && req.headers ? String(req.headers['user-agent'] || '').slice(0, 200) : '',
      details: sanitize(details),
    });
  } catch (err) {
    console.error('[audit] write failed:', err.message);
  }
}

module.exports = { logAudit, sanitize };
