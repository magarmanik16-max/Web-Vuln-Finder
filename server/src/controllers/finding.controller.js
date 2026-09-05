const Finding = require('../models/Finding');

async function listFindings(req, res, next) {
  try {
    const filter = {};
    if (req.query.scanId && req.query.scanId.match(/^[a-f\d]{24}$/i)) filter.scan = req.query.scanId;
    if (req.query.target) {
      // matches legacy targetId (STATIC_TARGET / DYNAMIC_TARGET) or a target host
      const v = String(req.query.target).slice(0, 200).toLowerCase();
      filter.$or = [{ targetId: v }, { targetHost: v }];
    }
    if (req.query.severity && Finding.SEVERITIES.includes(req.query.severity)) filter.severity = req.query.severity;
    if (req.query.confidence && Finding.CONFIDENCES.includes(req.query.confidence)) filter.confidence = req.query.confidence;
    if (req.query.category && /^[\w-]{1,40}$/.test(req.query.category)) filter.category = req.query.category;
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
    if (!/^[a-f\d]{24}$/i.test(req.params.id)) return res.status(400).json({ error: 'Invalid finding id' });
    const finding = await Finding.findById(req.params.id).populate('scan', 'status targetId');
    if (!finding) return res.status(404).json({ error: 'Finding not found' });
    res.json({ finding });
  } catch (err) {
    next(err);
  }
}

module.exports = { listFindings, getFinding };
