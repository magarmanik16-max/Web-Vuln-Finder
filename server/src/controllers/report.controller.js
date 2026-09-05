const Report = require('../models/Report');

// Generation arrives in a later phase; Phase 1 establishes the read-only list
// so the dashboard/report flow has a stable API surface.
async function listReports(req, res, next) {
  try {
    const filter = {};
    if (req.query.scanId && req.query.scanId.match(/^[a-f\d]{24}$/i)) filter.scan = req.query.scanId;
    const reports = await Report.find(filter).sort({ createdAt: -1 }).limit(100);
    res.json({ reports });
  } catch (err) {
    next(err);
  }
}

module.exports = { listReports };
