const Finding = require('../models/Finding');
const { resolveTarget } = require('../config/targets');

async function listFindings(req, res, next) {
  try {
    const filter = {};
    if (req.query.scanId && req.query.scanId.match(/^[a-f\d]{24}$/i)) filter.scan = req.query.scanId;
    if (req.query.targetId) {
      if (!resolveTarget(req.query.targetId)) return res.status(400).json({ error: 'Unknown targetId' });
      filter.targetId = req.query.targetId;
    }
    if (req.query.severity && Finding.SEVERITIES.includes(req.query.severity)) filter.severity = req.query.severity;
    if (req.query.status && Finding.STATUSES.includes(req.query.status)) filter.status = req.query.status;

    const limit = Math.min(parseInt(req.query.limit || '100', 10) || 100, 500);
    const findings = await Finding.find(filter).sort({ createdAt: -1 }).limit(limit);
    res.json({ findings });
  } catch (err) {
    next(err);
  }
}

async function getFinding(req, res, next) {
  try {
    const finding = await Finding.findById(req.params.id);
    if (!finding) return res.status(404).json({ error: 'Finding not found' });
    res.json({ finding });
  } catch (err) {
    next(err);
  }
}

module.exports = { listFindings, getFinding };
