const mongoose = require('mongoose');
const Report = require('../models/Report');
const Scan = require('../models/Scan');
const { buildSections, renderPdf, safeReportPath } = require('../services/reportService');
const { logAudit } = require('../utils/audit');

/**
 * Reports are generated from stored scan results only (§11 data integrity).
 */
async function generateReport(req, res, next) {
  try {
    const { scanId, format } = req.body || {};
    if (!scanId || !/^[a-f\d]{24}$/i.test(scanId)) {
      return res.status(400).json({ error: 'scanId is required' });
    }
    const fmt = format === 'html' ? 'html' : 'pdf';

    const scan = await Scan.findById(scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (!['completed', 'cancelled'].includes(scan.status)) {
      return res.status(409).json({ error: `Scan in status '${scan.status}' cannot be reported yet` });
    }

    const report = await Report.create({ scan: scan._id, generatedBy: req.user._id, format: fmt, status: 'generating' });
    try {
      report.sections = await buildSections(scan._id, req.user);
      if (fmt === 'pdf') {
        const filePath = await renderPdf(report);
        report.fileKey = require('path').basename(filePath);
      }
      report.status = 'ready';
      await report.save();
      await logAudit({ actor: req.user, action: 'report.generate', targetId: scan.targetId, scanId: scan._id, details: { reportId: String(report._id), format: fmt }, req });
      res.status(201).json({ report });
    } catch (err) {
      report.status = 'failed';
      report.error = err.message;
      await report.save();
      res.status(500).json({ error: `Report generation failed: ${err.message}` });
    }
  } catch (err) {
    next(err);
  }
}

async function listReports(req, res, next) {
  try {
    const filter = {};
    if (req.query.scanId && req.query.scanId.match(/^[a-f\d]{24}$/i)) filter.scan = req.query.scanId;
    const reports = await Report.find(filter).sort({ createdAt: -1 }).limit(100).populate('scan', 'targetId status');
    res.json({ reports });
  } catch (err) {
    next(err);
  }
}

async function getReport(req, res, next) {
  try {
    if (!/^[a-f\d]{24}$/i.test(req.params.id)) return res.status(400).json({ error: 'Invalid report id' });
    const report = await Report.findById(req.params.id).populate('scan', 'targetId status');
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json({ report });
  } catch (err) {
    next(err);
  }
}

async function downloadPdf(req, res, next) {
  try {
    if (!/^[a-f\d]{24}$/i.test(req.params.id)) return res.status(400).json({ error: 'Invalid report id' });
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    if (report.format !== 'pdf' || report.status !== 'ready' || !report.fileKey) {
      return res.status(409).json({ error: 'PDF is not available for this report' });
    }
    const filePath = safeReportPath(report.fileKey); // basename + dir confinement
    if (!require('fs').existsSync(filePath)) return res.status(404).json({ error: 'Report file missing' });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="assessment-report-${report._id}.pdf"`);
    require('fs').createReadStream(filePath).pipe(res);
  } catch (err) {
    next(err);
  }
}

module.exports = { generateReport, listReports, getReport, downloadPdf };
