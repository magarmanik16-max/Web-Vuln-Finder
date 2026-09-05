const mongoose = require('mongoose');

const AUDIT_RESULTS = ['success', 'failure', 'denied'];

const auditLogSchema = new mongoose.Schema(
  {
    actor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    actorEmail: { type: String, default: '' },
    action: { type: String, required: true }, // e.g. auth.login.success, scan.create, scan.target.rejected
    targetId: { type: String, default: null },
    scanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', default: null },
    result: { type: String, enum: AUDIT_RESULTS, default: 'success' },
    ip: { type: String, default: '' },
    userAgent: { type: String, default: '' },
    details: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ actor: 1, createdAt: -1 });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);
AuditLog.RESULTS = AUDIT_RESULTS;
module.exports = AuditLog;
