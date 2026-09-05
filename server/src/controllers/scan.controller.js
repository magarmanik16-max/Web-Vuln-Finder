const Scan = require('../models/Scan');
const { resolveTarget, TARGET_IDS } = require('../config/targets');
const { logAudit } = require('../utils/audit');

async function createScan(req, res, next) {
  try {
    const { targetId } = req.body || {};
    const target = resolveTarget(targetId);

    if (!target) {
      // The client tried to name a target that is not on the immutable allowlist.
      await logAudit({
        actor: req.user,
        action: 'scan.target.rejected',
        result: 'denied',
        details: { requestedTargetId: typeof targetId === 'string' ? targetId.slice(0, 120) : String(targetId).slice(0, 120), allowed: TARGET_IDS },
        req,
      });
      return res.status(400).json({ error: 'Unknown targetId. Authorized targets only.', allowedTargetIds: TARGET_IDS });
    }

    const scan = await Scan.create({ targetId: target.id, requestedBy: req.user._id, status: 'queued' });
    await logAudit({ actor: req.user, action: 'scan.create', targetId: target.id, scanId: scan._id, details: { status: scan.status }, req });
    res.status(201).json({ scan: await scan.populate('requestedBy', 'email role') });
  } catch (err) {
    next(err);
  }
}

async function listScans(req, res, next) {
  try {
    const filter = {};
    if (req.query.targetId) {
      if (!resolveTarget(req.query.targetId)) return res.status(400).json({ error: 'Unknown targetId', allowedTargetIds: TARGET_IDS });
      filter.targetId = req.query.targetId;
    }
    if (req.query.status && Scan.STATUSES.includes(req.query.status)) filter.status = req.query.status;

    const limit = Math.min(parseInt(req.query.limit || '50', 10) || 50, 200);
    const scans = await Scan.find(filter).sort({ createdAt: -1 }).limit(limit).populate('requestedBy', 'email role');
    res.json({ scans });
  } catch (err) {
    next(err);
  }
}

async function getScan(req, res, next) {
  try {
    const scan = await Scan.findById(req.params.id).populate('requestedBy', 'email role');
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    res.json({ scan });
  } catch (err) {
    next(err);
  }
}

async function cancelScan(req, res, next) {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (!['queued', 'running'].includes(scan.status)) {
      return res.status(409).json({ error: `Scan in status '${scan.status}' cannot be cancelled` });
    }
    scan.status = 'cancelled';
    scan.finishedAt = new Date();
    await scan.save();
    await logAudit({ actor: req.user, action: 'scan.cancel', targetId: scan.targetId, scanId: scan._id, req });
    res.json({ scan });
  } catch (err) {
    next(err);
  }
}

module.exports = { createScan, listScans, getScan, cancelScan };
