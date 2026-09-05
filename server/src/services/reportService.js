/**
 * Report service (Phase 3) — builds reports strictly from stored scan data.
 *
 * Data integrity (PLATFORM.md §11): sections are derived ONLY from the
 * persisted Scan + Finding documents. No finding, evidence, severity or
 * statistic is ever fabricated; methodology/limitations are fixed descriptive
 * text about how the platform works, not result claims.
 */

const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');

const Scan = require('../models/Scan');
const Finding = require('../models/Finding');
const { resolveTarget, toPublicTarget } = require('../config/targets');

const REPORTS_DIR = process.env.REPORTS_DIR || path.join(__dirname, '..', '..', '.data', 'reports');

const METHODOLOGY = [
  'The assessment used the platform\'s authorized Python scanning engine against the allowlisted target only.',
  'Reconnaissance: same-origin crawling with conservative limits (depth, page and request caps, rate limiting).',
  'Passive analysis: security headers, TLS certificate properties, cookie flags, information disclosure indicators.',
  'Active-but-safe probes: CORS origin reflection, HTTP method behavior (PUT/DELETE only against random non-existent probe paths), TRACE echo markers.',
  'Input reflection checks: unique harmless markers injected into discovered GET parameters; reflection context classification only — no breakout payloads.',
  'Injection heuristics: minimal single-quote error probes and boolean differentials on discovered GET parameters; no enumeration, extraction or destructive testing.',
  'Every redirect hop and every DNS answer was re-validated against the target allowlist (SSRF protections).',
];

const LIMITATIONS = [
  'The scanner performs non-destructive testing only; it does not exploit, dump, extract or modify anything.',
  'Crawling is bounded by conservative limits, so unlinked or JS-rendered endpoints may not have been assessed.',
  'XSS results reflect reflection evidence, not confirmed exploitation; breakout payloads are never sent.',
  'SQL injection results are heuristic (error signatures / boolean differentials) and require manual verification.',
  'Findings depend on the responses observed during the scan window; the application may change over time.',
  'Authentication-protected areas were not assessed (no credentials were supplied to the scanner).',
];

function _counts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return counts;
}

function _total(counts) {
  return Object.values(counts).reduce((a, b) => a + b, 0);
}

function _highestSeverity(counts) {
  for (const s of ['critical', 'high', 'medium', 'low', 'info']) if (counts[s] > 0) return s;
  return 'none';
}

/** Build the full report content from persisted data only. */
async function buildSections(scanId, user) {
  const scan = await Scan.findById(scanId).populate('requestedBy', 'email name');
  if (!scan) {
    const err = new Error('Scan not found');
    err.statusCode = 404;
    throw err;
  }
  const target = resolveTarget(scan.targetId);
  const findings = await Finding.find({ scan: scan._id }).sort({ severity: 1, createdAt: -1 }).lean();

  const counts = _counts(findings);
  const durationMin = scan.durationMs ? (scan.durationMs / 60000).toFixed(1) : '0';

  const executiveSummary = [
    `A ${scan.status === 'completed' ? 'completed' : scan.status} security assessment of ${target ? target.label : scan.targetId} ` +
      `identified ${_total(counts)} finding(s): ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low and ${counts.info} informational.`,
    counts.critical > 0 || counts.high > 0
      ? 'Critical/high findings should be triaged and remediated as a priority.'
      : 'No critical or high-severity issues were identified; lower-severity hardening opportunities are listed in the findings section.',
    'All results below originate from the stored scan output of this assessment; nothing has been added, edited or inferred.',
  ];

  const remediation = findings
    .filter((f) => f.remediation)
    .map((f) => ({ title: f.title, severity: f.severity, remediation: f.remediation }));

  return {
    generatedAt: new Date().toISOString(),
    generatedFor: user ? user.email : '',
    executiveSummary,
    scope: {
      ...toPublicTarget(target || { id: scan.targetId, host: scan.targetId, type: 'unknown', description: '', authorizedUrl: '' }),
      assessmentType: 'Automated non-destructive vulnerability assessment',
    },
    methodology: METHODOLOGY,
    riskSummary: {
      counts,
      total: _total(counts),
      highestSeverity: _highestSeverity(counts),
      scan: {
        id: String(scan._id),
        status: scan.status,
        startedAt: scan.startedAt,
        finishedAt: scan.finishedAt,
        durationMs: scan.durationMs,
        durationMinutes: durationMin,
        requests: scan.progress ? scan.progress.requests : 0,
        pages: scan.progress ? scan.progress.pages : 0,
        endpoints: scan.progress ? scan.progress.endpoints : 0,
        error: scan.error || '',
      },
    },
    findings: findings.map((f) => ({
      title: f.title,
      severity: f.severity,
      confidence: f.confidence,
      category: f.category,
      url: f.url,
      method: f.method,
      parameter: f.parameter,
      cwe: f.cwe,
      owasp: f.owasp,
      description: f.description,
      impact: f.impact,
      remediation: f.remediation,
      evidence: f.evidence,
    })),
    remediation,
    limitations: LIMITATIONS,
    assessmentTimestamp: scan.startedAt ? new Date(scan.startedAt).toISOString() : '',
  };
}

function _pdfSafe(text) {
  return String(text == null ? '' : text).replace(/[\u2018\u2019]/g, "'").replace(/[\u201C\u201D]/g, '"').replace(/—/g, '-');
}

/** Render sections into a clean professional PDF. Returns the file path. */
function renderPdf(report) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const filePath = path.join(REPORTS_DIR, `${report._id}.pdf`);
  const doc = new PDFDocument({ margin: 54, size: 'A4' });
  const stream = fs.createWriteStream(filePath);
  doc.pipe(stream);

  const s = report.sections;
  const H1 = (t) => doc.moveDown(0.6).fontSize(18).fillColor('#111').text(_pdfSafe(t)).moveDown(0.3);
  const H2 = (t) => doc.moveDown(0.5).fontSize(13).fillColor('#1a1a1a').text(_pdfSafe(t)).moveDown(0.2);
  const P = (t, opts = {}) => doc.fontSize(9.5).fillColor('#333').text(_pdfSafe(t), { lineGap: 2, ...opts });
  const BULLET = (t) => doc.fontSize(9.5).fillColor('#333').text(_pdfSafe(t), { indent: 14, bullet: true, lineGap: 2 });

  H1('Web Vulnerability Assessment Report');
  P(`Target: ${s.scope.label} (${s.scope.type}) — ${s.scope.authorizedUrl}`);
  P(`Scan ID: ${s.riskSummary.scan.id} · Status: ${s.riskSummary.scan.status}`);
  P(`Assessment timestamp: ${s.assessmentTimestamp} · Generated: ${s.generatedAt}`);
  P(`Prepared for: ${s.generatedFor || 'platform operator'}`);

  H2('1. Executive Summary');
  s.executiveSummary.forEach((p) => P(p));

  H2('2. Assessment Scope');
  P(`Target ID: ${s.scope.id}`);
  P(`Authorized origin: ${s.scope.authorizedUrl}`);
  P(`Type: ${s.scope.type}`);
  P(s.scope.description || s.scope.assessmentType);

  H2('3. Methodology');
  s.methodology.forEach((m) => BULLET(m));

  H2('4. Risk Summary');
  const c = s.riskSummary.counts;
  P(`Total findings: ${s.riskSummary.total} (highest severity: ${s.riskSummary.highestSeverity})`);
  P(`Critical: ${c.critical} · High: ${c.high} · Medium: ${c.medium} · Low: ${c.low} · Informational: ${c.info}`);
  P(`Scan activity: ${s.riskSummary.scan.requests} HTTP requests, ${s.riskSummary.scan.pages} page(s), ${s.riskSummary.scan.endpoints} parameterized/API endpoint(s), duration ${s.riskSummary.scan.durationMinutes} min.`);

  H2('5. Findings');
  if (s.findings.length === 0) {
    P('No findings were recorded for this scan.');
  }
  s.findings.forEach((f, i) => {
    doc.moveDown(0.3).fontSize(11).fillColor('#111').text(`${i + 1}. [${_pdfSafe(f.severity.toUpperCase())}] ${_pdfSafe(f.title)}`);
    P(`Severity: ${f.severity} · Confidence: ${f.confidence} · Category: ${f.category}${f.cwe ? ' · ' + f.cwe : ''}${f.owasp ? ' · ' + f.owasp : ''}`);
    if (f.url) P(`URL: ${f.url}${f.method ? ' (' + f.method + ')' : ''}${f.parameter ? ' · Parameter: ' + f.parameter : ''}`);
    if (f.description) P(f.description);
    if (f.impact) P(`Impact: ${f.impact}`);
    if (f.remediation) P(`Remediation: ${f.remediation}`);
    const evidence = typeof f.evidence === 'object' ? JSON.stringify(f.evidence) : String(f.evidence || '');
    if (evidence && evidence !== '{}') P(`Evidence: ${evidence.slice(0, 600)}`, { color: '#555' });
  });

  H2('6. Remediation Priorities');
  if (s.remediation.length === 0) P('No remediation actions required.');
  s.remediation.forEach((r) => BULLET(`[${r.severity}] ${r.title}: ${r.remediation}`));

  H2('7. Limitations');
  s.limitations.forEach((l) => BULLET(l));

  doc.end();
  return new Promise((resolve, reject) => {
    stream.on('finish', () => resolve(filePath));
    stream.on('error', reject);
  });
}

function safeReportPath(fileKey) {
  const resolved = path.resolve(REPORTS_DIR, path.basename(fileKey));
  if (!resolved.startsWith(path.resolve(REPORTS_DIR))) throw new Error('invalid report path');
  return resolved;
}

module.exports = { buildSections, renderPdf, safeReportPath, REPORTS_DIR };
