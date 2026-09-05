const mongoose = require('mongoose');
const { TARGET_IDS } = require('../config/targets');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'informational'];
const FINDING_STATUSES = ['open', 'in_review', 'false_positive', 'resolved'];
const CONFIDENCES = ['low', 'medium', 'high'];

const findingSchema = new mongoose.Schema(
  {
    scan: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', required: true, index: true },
    targetId: { type: String, enum: TARGET_IDS, required: true },
    severity: { type: String, enum: SEVERITIES, required: true, index: true },
    confidence: { type: String, enum: CONFIDENCES, default: 'low', index: true },
    // Phase 2 scanner contract fields — stored verbatim from scanner JSON.
    category: { type: String, required: true, index: true }, // e.g. headers, tls, xss, sqli
    title: { type: String, required: true, maxlength: 300 },
    description: { type: String, default: '' },
    url: { type: String, default: '' }, // affected URL on the authorized target
    method: { type: String, default: '' },
    parameter: { type: String, default: '' },
    cwe: { type: String, default: '' },
    owasp: { type: String, default: '' },
    impact: { type: String, default: '' },
    remediation: { type: String, default: '' },
    scannerModule: { type: String, default: '' },
    evidence: { type: mongoose.Schema.Types.Mixed, default: {} },
    location: { type: String, default: '' }, // legacy alias (Phase 1 shape)
    status: { type: String, enum: FINDING_STATUSES, default: 'open', index: true },
    detectedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// Normalize scanner "informational" to the Phase 1 enum value "info" on write.
findingSchema.pre('validate', function normalizeSeverity(next) {
  if (this.severity === 'informational') this.severity = 'info';
  next();
});

const Finding = mongoose.model('Finding', findingSchema);
Finding.SEVERITIES = SEVERITIES;
Finding.STATUSES = FINDING_STATUSES;
Finding.CONFIDENCES = CONFIDENCES;
module.exports = Finding;
