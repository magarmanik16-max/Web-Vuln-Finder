/**
 * Scan Manager (Phase 3) — Node ↔ Python orchestration.
 *
 * Responsibilities (SCANNER.md §2 / PLATFORM.md §2):
 *   validate target (already enforced by the controller + allowlist),
 *   create scan doc, launch the Python scanner, track the process, receive
 *   structured output, store findings, update scan status/progress,
 *   handle failure, support cancellation (partial findings preserved).
 *
 * Security properties:
 *   - Child process is spawned with an ARGUMENT ARRAY and `shell: false` —
 *     no shell string is ever constructed. The only arguments are:
 *       the interpreter, the fixed module name, the validated target ID
 *       (enum member), the server-generated scan id and an output path the
 *       server generated. No user-controlled string reaches the command line.
 *   - Concurrency is capped (SCAN_CONCURRENCY, default 2) with an internal
 *     FIFO queue, so bursts of API requests cannot start uncontrolled scans.
 *   - Scanner runs in its own process; Express is never blocked.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

const Scan = require('../models/Scan');
const Finding = require('../models/Finding');
const { logAudit } = require('../utils/audit');

// __dirname = server/src/services → three levels up is the repository root.
const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const SCAN_DATA_DIR = process.env.SCAN_DATA_DIR || path.join(REPO_ROOT, '.data', 'scans');
const SCANNER_CWD = process.env.SCANNER_CWD || path.join(REPO_ROOT, 'scanner');
const SCANNER_PYTHON = process.env.SCANNER_PYTHON || 'python3';
const SCANNER_ARGS = (process.env.SCANNER_ARGS || '-m scanner.main')
  .split(' ')
  .map((s) => s.trim())
  .filter(Boolean);
const MAX_CONCURRENT = Math.max(1, parseInt(process.env.SCAN_CONCURRENCY || '2', 10) || 2);
const CANCEL_GRACE_MS = 10_000;
const MAX_FINDINGS_PER_SCAN = 2000;

/** scanId -> child process. Also drives the concurrency cap. */
const running = new Map();
const pendingQueue = [];

function ensureDirs() {
  fs.mkdirSync(SCAN_DATA_DIR, { recursive: true });
}

/** On boot: scans from a previous process can no longer be running. */
async function recoverOrphans() {
  ensureDirs();
  const res = await Scan.updateMany(
    { status: { $in: ['queued', 'running'] } },
    { $set: { status: 'failed', error: 'interrupted by server restart', finishedAt: new Date() } }
  );
  if (res.modifiedCount > 0) console.log(`[scanManager] marked ${res.modifiedCount} orphaned scan(s) as failed`);
}

function isRunning(scanId) {
  return running.has(String(scanId));
}

function activeCount() {
  return running.size + pendingQueue.length;
}

/**
 * Enqueue a created scan. Starts immediately if below the concurrency cap,
 * otherwise the scan stays `queued` and starts when a slot frees up.
 */
function enqueue(scanDoc) {
  if (running.size < MAX_CONCURRENT) {
    _launch(scanDoc);
  } else {
    pendingQueue.push(String(scanDoc._id));
  }
}

function _launch(scanDoc) {
  const scanId = String(scanDoc._id);
  ensureDirs(); // in case recoverOrphans was not called (e.g. tests)
  const outputPath = path.join(SCAN_DATA_DIR, `${scanId}.json`);

  const args = [
    ...SCANNER_ARGS,
    '--target-id', scanDoc.targetId, // enum-validated by the controller — never a URL
    '--scan-id', scanId,             // server-generated ObjectId
    '--output', outputPath,          // server-generated path
  ];

  const child = spawn(SCANNER_PYTHON, args, {
    cwd: SCANNER_CWD,
    shell: false, // never construct shell strings
    stdio: ['ignore', 'pipe', 'pipe'],
    env: process.env, // explicit: inherits interpreter env incl. test overrides
  });
  running.set(scanId, { child, outputPath, stdout: '' });

  child.stdout.on('data', (d) => {
    const entry = running.get(scanId);
    if (entry) entry.stdout += d.toString();
  });

  // The scanner emits `PROGRESS {json}` lines on stderr for live tracking.
  child.stderr.on('data', (d) => {
    for (const line of d.toString().split('\n')) {
      if (!line.startsWith('PROGRESS ')) continue;
      try {
        _applyProgress(scanId, JSON.parse(line.slice('PROGRESS '.length)));
      } catch {
        /* malformed progress line — ignore */
      }
    }
  });

  child.on('error', async (err) => {
    await _finalize(scanId, { status: 'failed', error: `spawn failed: ${err.message}` });
  });

  child.on('exit', async (code, signal) => {
    const status = code === 0 ? 'completed' : code === 4 ? 'cancelled' : 'failed';
    await _finalize(scanId, {
      status,
      error: status === 'failed' ? `scanner exited with code ${code}${signal ? ` (${signal})` : ''}` : '',
    });
  });

  _setFields(scanId, {
    status: 'running',
    startedAt: new Date(),
    error: '',
    'progress.currentModule': 'authorization',
    'progress.modules': _moduleStates(['authorization'], [], []),
  });
}

function _moduleStates(done, runningNow, all = Scan.CHECK_MODULES) {
  const states = {};
  for (const m of all) states[m] = runningNow.includes(m) ? 'running' : done.includes(m) ? 'done' : 'pending';
  return states;
}

async function _applyProgress(scanId, p) {
  const entry = running.get(scanId);
  if (!entry) return;
  const update = {};
  const stage = p.stage || '';
  if (stage === 'check_started') {
    update['progress.currentModule'] = p.name || '';
  } else if (stage) {
    update['progress.currentModule'] = stage;
  }
  if (typeof p.requests === 'number') update['progress.requests'] = p.requests;
  if (typeof p.pages === 'number') update['progress.pages'] = p.pages;
  if (typeof p.endpoints === 'number') update['progress.endpoints'] = p.endpoints;
  if (Array.isArray(p.modules_done) || Array.isArray(p.modules_running)) {
    const doc = await Scan.findById(scanId).select('progress.modules').lean();
    const prev = (doc && doc.progress && doc.progress.modules) || {};
    const done = p.modules_done || Object.keys(prev).filter((k) => prev[k] === 'done');
    const run = p.modules_running || [];
    update['progress.modules'] = _moduleStates(done, run);
  }
  await _setFields(scanId, update).catch(() => {});
}

async function _setFields(scanId, update) {
  return Scan.updateOne({ _id: scanId }, { $set: update }).exec();
}

/** Parse the final scanner output and persist results. */
async function _finalize(scanId, { status, error }) {
  const entry = running.get(scanId);
  if (!entry) return; // already finalized
  running.delete(scanId);

  const scan = await Scan.findById(scanId);
  if (!scan) return;

  // A scan cancelled while queued never started; keep its state consistent.
  let report = null;
  try {
    if (fs.existsSync(entry.outputPath)) {
      report = JSON.parse(fs.readFileSync(entry.outputPath, 'utf8'));
    } else if (entry.stdout.trim().startsWith('{')) {
      report = JSON.parse(entry.stdout);
    }
  } catch (e) {
    report = null;
    error = error || `unparseable scanner output: ${e.message}`;
  }

  if (report && report.status === 'cancelled') status = 'cancelled';
  // A zero exit code with unusable output is still a failure — results cannot be trusted.
  if (!report && status === 'completed') status = 'failed';

  if (report && Array.isArray(report.findings)) {
    await _storeFindings(scan, report.findings.slice(0, MAX_FINDINGS_PER_SCAN));
  }

  // Update scan summary from the report statistics / stored findings.
  if (report && report.statistics) {
    const bySeverity = report.statistics.findings_by_severity || {};
    scan.summary = {
      critical: bySeverity.critical || 0,
      high: bySeverity.high || 0,
      medium: bySeverity.medium || 0,
      low: bySeverity.low || 0,
      info: (bySeverity.info || 0) + (bySeverity.informational || 0),
    };
    scan.progress = {
      ...scan.progress.toObject ? scan.progress.toObject() : scan.progress,
      requests: report.statistics.requests_made ?? scan.progress.requests,
      pages: report.statistics.pages_crawled ?? scan.progress.pages,
      endpoints: report.statistics.endpoints ?? scan.progress.endpoints,
    };
  } else {
    const counts = await Finding.aggregate([{ $match: { scan: scan._id } }, { $group: { _id: '$severity', n: { $sum: 1 } } }]);
    const map = Object.fromEntries(counts.map((c) => [c._id, c.n]));
    scan.summary = { critical: map.critical || 0, high: map.high || 0, medium: map.medium || 0, low: map.low || 0, info: map.info || 0 };
  }

  scan.status = status;
  scan.error = error || '';
  scan.finishedAt = new Date();
  scan.durationMs = scan.startedAt ? scan.finishedAt - scan.startedAt : 0;
  await scan.save();

  await logAudit({
    actor: scan.requestedBy,
    action: `scan.${status}`,
    targetId: scan.targetId,
    scanId: scan._id,
    result: status === 'completed' ? 'success' : status === 'cancelled' ? 'success' : 'failure',
    details: { durationMs: scan.durationMs, findings: report ? report.findings.length : 0 },
  });

  // clean up the output file only on success
  if (status === 'completed') {
    try {
      fs.unlinkSync(entry.outputPath);
    } catch {}
  }

  // start the next queued scan, if any
  const nextId = pendingQueue.shift();
  if (nextId) {
    const next = await Scan.findById(nextId);
    if (next && next.status === 'queued') _launch(next);
  }
}

async function _storeFindings(scan, findings) {
  if (findings.length === 0) return;
  const docs = findings.map((f) => ({
    scan: scan._id,
    targetId: scan.targetId,
    severity: f.severity || 'info',
    confidence: f.confidence || 'low',
    category: f.category || 'unknown',
    title: (f.title || 'Untitled finding').slice(0, 300),
    description: f.description || '',
    url: f.url || '',
    method: f.method || '',
    parameter: f.parameter || '',
    cwe: f.cwe || '',
    owasp: f.owasp || '',
    impact: f.impact || '',
    remediation: f.remediation || '',
    scannerModule: f.scanner_module || f.module || '',
    evidence: f.evidence && typeof f.evidence === 'object' ? f.evidence : {},
    detectedAt: f.timestamp ? new Date(f.timestamp) : new Date(),
  }));
  await Finding.insertMany(docs, { ordered: false });
}

/**
 * Cancel a scan. Running scans get SIGTERM (the Python scanner then flushes a
 * cancelled report including partial findings); a 10s grace precedes SIGKILL.
 * Returns the pre-cancel status or null if the scan was not found.
 */
async function cancel(scanId) {
  const scan = await Scan.findById(scanId);
  if (!scan) return null;
  if (!['queued', 'running'].includes(scan.status)) return scan.status;

  const entry = running.get(String(scanId));
  if (!entry) {
    // queued but not started yet
    const idx = pendingQueue.indexOf(String(scanId));
    if (idx >= 0) pendingQueue.splice(idx, 1);
    scan.status = 'cancelled';
    scan.finishedAt = new Date();
    scan.durationMs = 0;
    await scan.save();
    await logAudit({ actor: scan.requestedBy, action: 'scan.cancelled', targetId: scan.targetId, scanId: scan._id, details: { whileQueued: true } });
    return 'queued';
  }

  entry.child.kill('SIGTERM');
  entry.killTimer = setTimeout(() => {
    if (running.has(String(scanId))) entry.child.kill('SIGKILL');
  }, CANCEL_GRACE_MS);
  return 'running';
}

module.exports = {
  enqueue,
  cancel,
  recoverOrphans,
  isRunning,
  activeCount,
  MAX_CONCURRENT,
  SCAN_DATA_DIR,
};
