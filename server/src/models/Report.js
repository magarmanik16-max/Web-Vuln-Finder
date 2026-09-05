const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema(
  {
    scan: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', required: true, index: true },
    generatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    format: { type: String, enum: ['pdf', 'html'], default: 'pdf' },
    status: { type: String, enum: ['pending', 'generating', 'ready', 'failed'], default: 'pending' },
    // Storage key for the generated artifact (Phase 4 implements generation).
    fileKey: { type: String, default: '' },
    error: { type: String, default: '' },
  },
  { timestamps: true }
);

const Report = mongoose.model('Report', reportSchema);
module.exports = Report;
