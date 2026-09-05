const mongoose = require('mongoose');
const { TARGET_IDS } = require('../config/targets');

const SCAN_STATUSES = ['queued', 'running', 'completed', 'failed', 'cancelled'];
const CHECK_MODULES = ['authorization', 'connectivity', 'crawl', 'headers', 'tls', 'cookies', 'cors', 'methods', 'disclosure', 'xss', 'sqli', 'csrf'];

const scanSchema = new mongoose.Schema(
  {
    // Always an ID from the immutable allowlist — never a URL.
    targetId: { type: String, enum: TARGET_IDS, required: true },
    requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: SCAN_STATUSES, default: 'queued', index: true },
    summary: {
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      info: { type: Number, default: 0 },
    },
    // Live integration fields (Phase 3) — populated by the Scan Manager.
    progress: {
      currentModule: { type: String, default: '' },
      modules: { type: mongoose.Schema.Types.Mixed, default: {} }, // name -> pending|running|done
      requests: { type: Number, default: 0 },
      pages: { type: Number, default: 0 },
      endpoints: { type: Number, default: 0 },
    },
    startedAt: { type: Date },
    finishedAt: { type: Date },
    durationMs: { type: Number, default: 0 },
    error: { type: String, default: '' },
  },
  { timestamps: true }
);

scanSchema.index({ createdAt: -1 });
scanSchema.index({ status: 1, createdAt: -1 });

const Scan = mongoose.model('Scan', scanSchema);
Scan.STATUSES = SCAN_STATUSES;
Scan.CHECK_MODULES = CHECK_MODULES;
module.exports = Scan;
