/**
 * Phase 3 integration tests: Node -> Python (stub) -> JSON -> MongoDB flow.
 *
 * The real Scan Manager spawns a REAL child process (`python3 -m stub_scanner`
 * from tests/fixtures) — same spawn path as production, no network involved.
 * Covers: launch, progress tracking, findings storage, status transitions,
 * cancellation with partial findings, failure handling, reports + PDF,
 * findings filters (§15 API testing).
 */
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-only-secret-do-not-use-in-production-0123456789';
process.env.MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/webvulnapp_test';
process.env.SCANNER_PYTHON = 'python3';
process.env.SCANNER_ARGS = '-m stub_scanner';
process.env.SCANNER_CWD = __dirname + '/fixtures';
process.env.SCAN_DATA_DIR = __dirname + '/../../.data/test-scans';
process.env.REPORTS_DIR = __dirname + '/../../.data/test-reports';
process.env.SCAN_CONCURRENCY = '2';
delete process.env.STUB_MODE;

const request = require('supertest');
const mongoose = require('mongoose');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { buildApp } = require('../src/app');
const User = require('../src/models/User');
const Scan = require('../src/models/Scan');
const Finding = require('../src/models/Finding');
const Report = require('../src/models/Report');
const AuditLog = require('../src/models/AuditLog');

let app;
let token;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitFor(fn, timeoutMs = 20000, interval = 250) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const v = await fn();
    if (v) return v;
    await sleep(interval);
  }
  throw new Error('waitFor timed out');
}

async function createAndLogin(email) {
  await User.create({ email, role: 'admin', passwordHash: await bcrypt.hash('password-123456', 10) });
  const res = await request(app).post('/api/auth/login').send({ email, password: 'password-123456' });
  return res.body.token;
}

beforeAll(async () => {
  fs.rmSync(process.env.SCAN_DATA_DIR, { recursive: true, force: true });
  fs.rmSync(process.env.REPORTS_DIR, { recursive: true, force: true });
  await mongoose.connect(process.env.MONGODB_URI);
  await Promise.all([User.deleteMany({}), Scan.deleteMany({}), Finding.deleteMany({}), Report.deleteMany({}), AuditLog.deleteMany({})]);
  app = buildApp();
  token = await createAndLogin('admin@test.local');
});

afterAll(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
});

async function startScan(targetId = 'STATIC_TARGET') {
  const res = await request(app).post('/api/scans').set('Authorization', `Bearer ${token}`).send({ targetId });
  expect(res.status).toBe(201);
  return res.body.scan._id;
}

describe('scan lifecycle via real child process', () => {
  test('completed scan: findings stored, status/summary/progress populated', async () => {
    process.env.STUB_MODE = 'ok';
    const scanId = await startScan();

    const finished = await waitFor(async () => {
      const r = await request(app).get(`/api/scans/${scanId}`).set('Authorization', `Bearer ${token}`);
      return ['completed', 'failed'].includes(r.body.scan.status) ? r.body.scan : null;
    });
    expect(finished.status).toBe('completed');
    expect(finished.summary.high).toBe(1);
    expect(finished.summary.info).toBe(1);
    expect(finished.progress.requests).toBe(8);
    expect(finished.progress.pages).toBe(2);
    expect(finished.progress.endpoints).toBe(3);
    expect(finished.durationMs).toBeGreaterThanOrEqual(0);
    expect(finished.startedAt).toBeTruthy();
    expect(finished.finishedAt).toBeTruthy();

    const findings = await request(app).get(`/api/findings?scanId=${scanId}`).set('Authorization', `Bearer ${token}`);
    expect(findings.body.findings).toHaveLength(2);
    const f = findings.body.findings[0];
    for (const field of ['title', 'severity', 'confidence', 'category', 'url', 'method', 'cwe', 'owasp', 'impact', 'remediation', 'evidence', 'scannerModule']) {
      expect(f[field]).toBeDefined();
    }
    // scanner severity "informational" normalized to Phase 1 enum "info"
    const severities = findings.body.findings.map((x) => x.severity).sort();
    expect(severities).toEqual(['high', 'info']);

    // completion audit entry written
    const audit = await AuditLog.findOne({ action: 'scan.completed', scanId });
    expect(audit).toBeTruthy();
  });

  test('progress endpoint exposes module checklist states', async () => {
    process.env.STUB_MODE = 'cancelled';
    const scanId = await startScan();
    const running = await waitFor(async () => {
      const r = await request(app).get(`/api/scans/${scanId}`).set('Authorization', `Bearer ${token}`);
      return r.body.scan.status === 'running' ? r.body.scan : null;
    });
    expect(running.progress.currentModule).toBeTruthy();

    // cancel while running -> partial findings preserved
    const cancel = await request(app).post(`/api/scans/${scanId}/cancel`).set('Authorization', `Bearer ${token}`);
    expect(cancel.status).toBe(200);

    const cancelled = await waitFor(async () => {
      const r = await request(app).get(`/api/scans/${scanId}`).set('Authorization', `Bearer ${token}`);
      return ['cancelled', 'failed'].includes(r.body.scan.status) ? r.body.scan : null;
    });
    expect(cancelled.status).toBe('cancelled');
    const partial = await request(app).get(`/api/findings?scanId=${scanId}`).set('Authorization', `Bearer ${token}`);
    expect(partial.body.findings).toHaveLength(1); // partial finding preserved (§6)
    delete process.env.STUB_MODE;
  }, 30000);

  test('scanner failure -> status failed with error', async () => {
    process.env.STUB_MODE = 'fail';
    const scanId = await startScan();
    const failed = await waitFor(async () => {
      const r = await request(app).get(`/api/scans/${scanId}`).set('Authorization', `Bearer ${token}`);
      return r.body.scan.status === 'failed' ? r.body.scan : null;
    });
    expect(failed.error).toMatch(/exit/i);
    delete process.env.STUB_MODE;
  });

  test('unparseable scanner output -> status failed with error', async () => {
    process.env.STUB_MODE = 'garbage';
    const scanId = await startScan();
    const failed = await waitFor(async () => {
      const r = await request(app).get(`/api/scans/${scanId}`).set('Authorization', `Bearer ${token}`);
      return r.body.scan.status === 'failed' ? r.body.scan : null;
    });
    expect(failed.error).toMatch(/unparseable|exit/i);
    delete process.env.STUB_MODE;
  });

  test('cancel of nonexistent scan -> 404', async () => {
    const res = await request(app).post(`/api/scans/${'a'.repeat(24)}/cancel`).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });
});

describe('findings API filters (§9)', () => {
  beforeAll(async () => {
    process.env.STUB_MODE = 'ok';
    const scanId = await startScan('DYNAMIC_TARGET');
    await waitFor(async () => {
      const r = await request(app).get(`/api/scans/${scanId}`).set('Authorization', `Bearer ${token}`);
      return ['completed', 'failed'].includes(r.body.scan.status);
    });
    delete process.env.STUB_MODE;
  });

  test('filter by severity', async () => {
    const res = await request(app).get('/api/findings?severity=high').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.findings.length).toBeGreaterThanOrEqual(1);
    expect(res.body.findings.every((f) => f.severity === 'high')).toBe(true);
  });

  test('filter by target', async () => {
    const res = await request(app).get('/api/findings?targetId=DYNAMIC_TARGET').set('Authorization', `Bearer ${token}`);
    expect(res.body.findings.length).toBeGreaterThanOrEqual(1);
    expect(res.body.findings.every((f) => f.targetId === 'DYNAMIC_TARGET')).toBe(true);
  });

  test('filter by category and confidence', async () => {
    const res = await request(app).get('/api/findings?category=headers&confidence=high').set('Authorization', `Bearer ${token}`);
    expect(res.body.findings.length).toBeGreaterThanOrEqual(1);
    expect(res.body.findings.every((f) => f.category === 'headers' && f.confidence === 'high')).toBe(true);
  });

  test('finding detail includes full contract', async () => {
    const list = await request(app).get('/api/findings').set('Authorization', `Bearer ${token}`);
    const id = list.body.findings[0]._id;
    const detail = await request(app).get(`/api/findings/${id}`).set('Authorization', `Bearer ${token}`);
    expect(detail.status).toBe(200);
    const f = detail.body.finding;
    for (const field of ['title', 'severity', 'confidence', 'url', 'parameter', 'description', 'evidence', 'impact', 'remediation', 'cwe', 'owasp']) {
      expect(f).toHaveProperty(field);
    }
  });

  test('invalid finding id -> 400', async () => {
    const res = await request(app).get('/api/findings/not-an-id').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
  });
});

describe('reports (§10-§12): generated from stored data only', () => {
  let completedScanId;

  beforeAll(async () => {
    process.env.STUB_MODE = 'ok';
    completedScanId = await startScan();
    await waitFor(async () => {
      const r = await request(app).get(`/api/scans/${completedScanId}`).set('Authorization', `Bearer ${token}`);
      return ['completed', 'failed'].includes(r.body.scan.status);
    });
    delete process.env.STUB_MODE;
  });

  test('generate report for a completed scan -> ready with sections', async () => {
    const res = await request(app).post('/api/reports').set('Authorization', `Bearer ${token}`).send({ scanId: completedScanId });
    expect(res.status).toBe(201);
    const report = res.body.report;
    expect(report.status).toBe('ready');
    const s = report.sections;
    for (const section of ['executiveSummary', 'scope', 'methodology', 'riskSummary', 'findings', 'remediation', 'limitations', 'assessmentTimestamp']) {
      expect(s[section]).toBeDefined();
    }
    // data integrity: findings count matches stored findings exactly
    const stored = await request(app).get(`/api/findings?scanId=${completedScanId}`).set('Authorization', `Bearer ${token}`);
    expect(s.findings).toHaveLength(stored.body.findings.length);
    expect(s.riskSummary.counts.high).toBe(stored.body.findings.filter((f) => f.severity === 'high').length);
    expect(s.scope.authorizedUrl).toBe('https://manikmagar.com.np');
  });

  test('report for running/queued scan -> 409', async () => {
    const scan = await Scan.create({ targetId: 'STATIC_TARGET', requestedBy: new mongoose.Types.ObjectId(), status: 'running' });
    const res = await request(app).post('/api/reports').set('Authorization', `Bearer ${token}`).send({ scanId: String(scan._id) });
    expect(res.status).toBe(409);
  });

  test('report for unknown scan -> 404', async () => {
    const res = await request(app).post('/api/reports').set('Authorization', `Bearer ${token}`).send({ scanId: 'a'.repeat(24) });
    expect(res.status).toBe(404);
  });

  test('PDF download returns a real PDF', async () => {
    const created = await request(app).post('/api/reports').set('Authorization', `Bearer ${token}`).send({ scanId: completedScanId });
    const reportId = created.body.report._id;
    const res = await request(app).get(`/api/reports/${reportId}/pdf`).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/pdf/);
    expect(res.body.length).toBeGreaterThan(1000);
    expect(res.body.slice(0, 5).toString()).toBe('%PDF-');
  });

  test('report list + detail + auth + path traversal guard', async () => {
    const list = await request(app).get('/api/reports').set('Authorization', `Bearer ${token}`);
    expect(list.status).toBe(200);
    expect(list.body.reports.length).toBeGreaterThanOrEqual(1);

    const id = list.body.reports[0]._id;
    expect((await request(app).get(`/api/reports/${id}`).set('Authorization', `Bearer ${token}`)).status).toBe(200);
    expect((await request(app).get('/api/reports')).status).toBe(401);
    expect((await request(app).get('/api/reports/..%2F..%2Fsecret.pdf/pdf').set('Authorization', `Bearer ${token}`)).status).toBe(400);
  });
});
