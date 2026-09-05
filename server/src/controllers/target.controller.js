const { AUTHORIZED_TARGETS, toPublicTarget } = require('../config/targets');

/**
 * Targets are immutable configuration, not database rows. The API exposes
 * exactly these two entries — the frontend has no mechanism to add or
 * input any other target.
 */
async function listTargets(req, res) {
  res.json({ targets: AUTHORIZED_TARGETS.map(toPublicTarget) });
}

module.exports = { listTargets };
