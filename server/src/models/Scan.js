const mongoose = require('mongoose');
const { TARGET_IDS } = require('../config/targets');

const SCAN_STATUSES = ['queued', 'running', 'completed', 'failed', 'cancelled'];

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
    startedAt: { type: Date },
    finishedAt: { type: Date },
    error: { type: String, default: '' },
  },
  { timestamps: true }
);

scanSchema.index({ createdAt: -1 });

const Scan = mongoose.model('Scan', scanSchema);
Scan.STATUSES = SCAN_STATUSES;
module.exports = Scan;
