const mongoose = require('mongoose');
const { TARGET_IDS } = require('../config/targets');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const FINDING_STATUSES = ['open', 'in_review', 'false_positive', 'resolved'];

const findingSchema = new mongoose.Schema(
  {
    scan: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', required: true, index: true },
    targetId: { type: String, enum: TARGET_IDS, required: true },
    severity: { type: String, enum: SEVERITIES, required: true, index: true },
    // Phase 2 scanner will populate these; the shape is fixed now so the
    // dashboard/report pipeline can be built against a stable contract.
    category: { type: String, required: true }, // e.g. xss, sqli, headers, tls
    title: { type: String, required: true, maxlength: 200 },
    description: { type: String, default: '' },
    location: { type: String, default: '' }, // path/endpoint on the authorized target
    evidence: { type: String, default: '' },
    status: { type: String, enum: FINDING_STATUSES, default: 'open', index: true },
  },
  { timestamps: true }
);

const Finding = mongoose.model('Finding', findingSchema);
Finding.SEVERITIES = SEVERITIES;
Finding.STATUSES = FINDING_STATUSES;
module.exports = Finding;
