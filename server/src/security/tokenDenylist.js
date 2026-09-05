/**
 * JWT denylist for logout. In-memory (per process) with TTL sweep — adequate
 * for the Phase 1 single-node deployment; a Redis/persisted store is a Phase 4
 * hardening item (documented in docs/PHASE1.md).
 */
const denylist = new Map(); // jti -> expiry epoch ms

function revoke(jti, expEpochSec) {
  if (!jti) return;
  denylist.set(jti, (expEpochSec || Math.floor(Date.now() / 1000) + 3600) * 1000);
}

function isRevoked(jti) {
  if (!jti) return false;
  const exp = denylist.get(jti);
  if (exp === undefined) return false;
  if (exp <= Date.now()) {
    denylist.delete(jti);
    return false;
  }
  return true;
}

// periodic sweep so the map cannot grow unbounded
setInterval(() => {
  const now = Date.now();
  for (const [jti, exp] of denylist) if (exp <= now) denylist.delete(jti);
}, 10 * 60 * 1000).unref();

module.exports = { revoke, isRevoked };
