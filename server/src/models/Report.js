const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema(
  {
    scan: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', required: true, index: true },
    generatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    format: { type: String, enum: ['pdf', 'html'], default: 'pdf' },
    status: { type: String, enum: ['pending', 'generating', 'ready', 'failed'], default: 'pending', index: true },
    // Storage key for the generated artifact, relative to the reports dir.
    fileKey: { type: String, default: '' },
    // Structured report content, built strictly from stored scan + findings.
    sections: { type: mongoose.Schema.Types.Mixed, default: {} },
    error: { type: String, default: '' },
  },
  { timestamps: true }
);

const Report = mongoose.model('Report', reportSchema);
module.exports = Report;
