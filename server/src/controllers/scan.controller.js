const Scan = require('../models/Scan');
const { authorizeTarget, legacyTargetUrl } = require('../config/targets');
const { logAudit } = require('../utils/audit');
const scanManager = require('../services/scanManager');

// Max scans one user may have queued/running at once — arbitrary public
// targets raise the abuse surface, so per-user concurrency is now enforced.
const MAX_ACTIVE_SCANS_PER_USER = 2;

/**
 * Create a scan for a user-supplied PUBLIC HTTPS target.
 * Body: { url: "https://example.com" } (legacy { targetId } still accepted).
 * The URL is fully validated server-side (structural + DNS) BEFORE the scan
 * is created or the scanner process is launched.
 */
async function createScan(req, res, next) {
  try {
    const { url, targetId } = req.body || {};

    let target;
    if (url) {
      try {
        target = await authorizeTarget(url); // structural + DNS validation
      } catch (err) {
        await logAudit({
          actor: req.user,
          action: 'scan.target.rejected',
          result: 'denied',
          details: { requestedTarget: String(url).slice(0, 200), reason: err.code || 'invalid' },
          req,
        });
        // Deliberately terse: do not expose validation internals that could assist abuse.
        return res.status(400).json({
          error: 'Target rejected. Only public HTTPS origins (no ports, no credentials, resolvable to global IPs) can be scanned.',
        });
      }
    } else if (targetId) {
      // Backward compatibility: legacy allowlist IDs map to their URLs and go
      // through the exact same validation.
      const mapped = legacyTargetUrl(targetId);
      if (!mapped) {
        return res.status(400).json({ error: 'Unknown targetId. Submit { url: "https://…" } instead.' });
      }
      target = await authorizeTarget(mapped);
    } else {
      return res.status(400).json({ error: 'A target URL is required: { "url": "https://example.com" }' });
    }

    // Abuse control: bounded global concurrency (FIFO) + per-user active cap.
    if (scanManager.activeCount() >= 20) {
      return res.status(429).json({ error: 'Too many scans pending. Try again later.' });
    }
    const activeForUser = await Scan.countDocuments({
      requestedBy: req.user._id,
      status: { $in: ['queued', 'running'] },
    });
    if (activeForUser >= MAX_ACTIVE_SCANS_PER_USER) {
      return res.status(429).json({ error: `You already have ${activeForUser} scan(s) queued or running. Wait for one to finish.` });
    }

    const scan = await Scan.create({
      targetUrl: target.url,
      targetHost: target.host,
      targetId: null,
      requestedBy: req.user._id,
      status: 'queued',
    });
    scanManager.enqueue(scan); // re-validates the target before spawning the scanner
    await logAudit({ actor: req.user, action: 'scan.create', targetId: target.host, scanId: scan._id, details: { status: scan.status, targetUrl: target.url }, req });
    res.status(201).json({ scan: await scan.populate('requestedBy', 'email role') });
  } catch (err) {
    next(err);
  }
}

async function listScans(req, res, next) {
  try {
    const filter = {};
    if (req.query.targetId) filter.targetId = String(req.query.targetId).slice(0, 120);
    if (req.query.host) filter.targetHost = String(req.query.host).slice(0, 200).toLowerCase();
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
    if (!/^[a-f\d]{24}$/i.test(req.params.id)) return res.status(400).json({ error: 'Invalid scan id' });
    const scan = await Scan.findById(req.params.id).populate('requestedBy', 'email role');
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    res.json({ scan });
  } catch (err) {
    next(err);
  }
}

async function cancelScan(req, res, next) {
  try {
    if (!/^[a-f\d]{24}$/i.test(req.params.id)) return res.status(400).json({ error: 'Invalid scan id' });
    const scan = await Scan.findById(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (!['queued', 'running'].includes(scan.status)) {
      return res.status(409).json({ error: `Scan in status '${scan.status}' cannot be cancelled` });
    }

    const prevState = await scanManager.cancel(scan._id); // SIGTERM -> scanner flushes partial findings
    await logAudit({ actor: req.user, action: 'scan.cancel', targetId: scan.targetHost || scan.targetId, scanId: scan._id, details: { prevState }, req });

    const fresh = await Scan.findById(scan._id).populate('requestedBy', 'email role');
    res.json({ scan: fresh, cancelling: prevState === 'running' });
  } catch (err) {
    next(err);
  }
}

module.exports = { createScan, listScans, getScan, cancelScan, MAX_ACTIVE_SCANS_PER_USER };
