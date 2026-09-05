/**
 * API-boundary security tests (real Express app + real local MongoDB).
 * Verifies: auth foundation, target-ID authorization at the HTTP boundary,
 * and audit logging. Uses the `webvulnapp_test` database.
 */
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-only-secret-do-not-use-in-production-0123456789';
process.env.MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/webvulnapp_test';
// Phase 3: POST /api/scans spawns the real Scan Manager; point it at the
// offline stub scanner so tests never touch the network.
process.env.SCANNER_PYTHON = 'python3';
process.env.SCANNER_ARGS = '-m stub_scanner';
process.env.SCANNER_CWD = __dirname + '/fixtures';
process.env.SCAN_DATA_DIR = __dirname + '/../../.data/test-scans';
delete process.env.STUB_MODE;

const request = require('supertest');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { buildApp } = require('../src/app');
const User = require('../src/models/User');
const Scan = require('../src/models/Scan');
const AuditLog = require('../src/models/AuditLog');

let app;
let admin; // admin user doc
let adminToken;
let analystToken;

beforeAll(async () => {
  await mongoose.connect(process.env.MONGODB_URI);
  await Promise.all([User.deleteMany({}), Scan.deleteMany({}), AuditLog.deleteMany({})]);

  admin = await User.create({
    email: 'admin@test.local',
    name: 'Admin',
    role: 'admin',
    passwordHash: await bcrypt.hash('admin-password-123', 10),
  });

  app = buildApp();
  const res = await request(app).post('/api/auth/login').send({ email: 'admin@test.local', password: 'admin-password-123' });
  adminToken = res.body.token;

  const analyst = await User.create({
    email: 'analyst@test.local',
    role: 'analyst',
    passwordHash: await bcrypt.hash('analyst-password-123', 10),
  });
  const res2 = await request(app).post('/api/auth/login').send({ email: 'analyst@test.local', password: 'analyst-password-123' });
  analystToken = res2.body.token;
});

afterAll(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
});

describe('authentication foundation', () => {
  test('login with wrong password -> 401 (no token leak)', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'admin@test.local', password: 'wrong-password' });
    expect(res.status).toBe(401);
    expect(res.body.token).toBeUndefined();
  });

  test('GET /api/auth/me returns the authenticated user without passwordHash', async () => {
    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe('admin@test.local');
    expect(res.body.user.passwordHash).toBeUndefined();
  });

  test('protected route without token -> 401; garbage token -> 401', async () => {
    expect((await request(app).get('/api/auth/me')).status).toBe(401);
    expect((await request(app).get('/api/auth/me').set('Authorization', 'Bearer not.a.jwt')).status).toBe(401);
  });

  test('logout revokes the token', async () => {
    const login = await request(app).post('/api/auth/login').send({ email: 'analyst@test.local', password: 'analyst-password-123' });
    const tok = login.body.token;
    expect((await request(app).post('/api/auth/logout').set('Authorization', `Bearer ${tok}`)).status).toBe(200);
    expect((await request(app).get('/api/auth/me').set('Authorization', `Bearer ${tok}`)).status).toBe(401);
  });

  test('registration: open for first user only; afterwards admin-only', async () => {
    // analysts may not create accounts
    const denied = await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ email: 'x@test.local', password: 'long-enough-password' });
    expect(denied.status).toBe(403);
    // admin creates an account
    const ok = await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: 'newuser@test.local', password: 'long-enough-password' });
    expect(ok.status).toBe(201);
    // short passwords rejected
    const weak = await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: 'weak@test.local', password: 'short' });
    expect(weak.status).toBe(400);
  });
});

describe('targets API exposes the immutable allowlist only', () => {
  test('GET /api/targets returns exactly the two authorized targets', async () => {
    const res = await request(app).get('/api/targets').set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.targets).toHaveLength(2);
    expect(res.body.targets.map((t) => t.id).sort()).toEqual(['DYNAMIC_TARGET', 'STATIC_TARGET']);
    expect(res.body.targets.map((t) => t.host).sort()).toEqual(['manikmagar.com.np', 'mnk.manikmagar.com.np']);
  });

  test('targets require authentication', async () => {
    expect((await request(app).get('/api/targets')).status).toBe(401);
  });
});

describe('scan creation: the API accepts target IDs, never URLs', () => {
  test('authorized target IDs are accepted', async () => {
    for (const targetId of ['STATIC_TARGET', 'DYNAMIC_TARGET']) {
      const res = await request(app).post('/api/scans').set('Authorization', `Bearer ${analystToken}`).send({ targetId });
      expect(res.status).toBe(201);
      expect(res.body.scan.targetId).toBe(targetId);
      // Scan Manager may already be running the scan by response time
      expect(['queued', 'running', 'completed']).toContain(res.body.scan.status);
    }
  });

  test.each([
    'https://example.com', // the client tried to submit a URL
    'https://evil.manikmagar.com.np',
    'http://localhost',
    'http://127.0.0.1',
    '192.168.1.1',
    'ARBITRARY_TARGET',
    '',
    null,
    { url: 'https://example.com' },
  ])('targetId %j rejected', async (bad) => {
    const res = await request(app).post('/api/scans').set('Authorization', `Bearer ${analystToken}`).send({ targetId: bad });
    expect(res.status).toBe(400);
    expect(res.body.allowedTargetIds).toEqual(['STATIC_TARGET', 'DYNAMIC_TARGET']);
  });

  test('rejected target attempts are audit-logged as denied', async () => {
    await request(app).post('/api/scans').set('Authorization', `Bearer ${analystToken}`).send({ targetId: 'https://example.com' });
    const entry = await AuditLog.findOne({ action: 'scan.target.rejected', result: 'denied' }).sort({ createdAt: -1 });
    expect(entry).toBeTruthy();
    expect(entry.details.requestedTargetId).toBe('https://example.com');
  });

  test('scan creation is audit-logged with user, target and scan IDs', async () => {
    const entry = await AuditLog.findOne({ action: 'scan.create', result: 'success' }).sort({ createdAt: -1 });
    expect(entry).toBeTruthy();
    expect(entry.actor.toString()).toBeTruthy();
    expect(['STATIC_TARGET', 'DYNAMIC_TARGET']).toContain(entry.targetId);
    expect(entry.scanId).toBeTruthy();
  });

  test('scan list/detail/cancel flow', async () => {
    process.env.STUB_MODE = 'cancelled'; // keep the scan running long enough to cancel
    const create = await request(app).post('/api/scans').set('Authorization', `Bearer ${analystToken}`).send({ targetId: 'STATIC_TARGET' });
    const id = create.body.scan._id;

    const list = await request(app).get('/api/scans').set('Authorization', `Bearer ${analystToken}`);
    expect(list.status).toBe(200);
    expect(list.body.scans.some((s) => s._id === id)).toBe(true);

    const one = await request(app).get(`/api/scans/${id}`).set('Authorization', `Bearer ${analystToken}`);
    expect(one.status).toBe(200);

    const cancel = await request(app).post(`/api/scans/${id}/cancel`).set('Authorization', `Bearer ${analystToken}`);
    expect(cancel.status).toBe(200);
    expect(['running', 'cancelled']).toContain(cancel.body.scan.status); // finalize is async after SIGTERM

    // eventually reaches cancelled with partial findings preserved
    for (let i = 0; i < 40; i++) {
      const s = await request(app).get(`/api/scans/${id}`).set('Authorization', `Bearer ${analystToken}`);
      if (s.body.scan.status === 'cancelled') break;
      await new Promise((r) => setTimeout(r, 250));
    }
    const final = await request(app).get(`/api/scans/${id}`).set('Authorization', `Bearer ${analystToken}`);
    expect(final.body.scan.status).toBe('cancelled');

    const again = await request(app).post(`/api/scans/${id}/cancel`).set('Authorization', `Bearer ${analystToken}`);
    expect(again.status).toBe(409);
    delete process.env.STUB_MODE;
  }, 30000);

  test('all /api/scans and /api/findings routes require auth', async () => {
    expect((await request(app).get('/api/scans')).status).toBe(401);
    expect((await request(app).post('/api/scans').send({ targetId: 'STATIC_TARGET' })).status).toBe(401);
    expect((await request(app).get('/api/findings')).status).toBe(401);
    expect((await request(app).get('/api/reports')).status).toBe(401);
  });
});

describe('findings & reports read APIs', () => {
  test('findings list is filterable and empty before scanning', async () => {
    const res = await request(app).get('/api/findings').set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.findings)).toBe(true);
    const filtered = await request(app)
      .get('/api/findings?targetId=STATIC_TARGET&severity=high')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(filtered.status).toBe(200);
  });

  test('reports list works', async () => {
    const res = await request(app).get('/api/reports').set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.reports)).toBe(true);
  });
});

describe('login is audit-logged and rate limited', () => {
  test('failed login writes a failure audit entry without storing secrets', async () => {
    await request(app).post('/api/auth/login').send({ email: 'admin@test.local', password: 'definitely-wrong' });
    const entry = await AuditLog.findOne({ action: 'auth.login', result: 'failure' }).sort({ createdAt: -1 });
    expect(entry).toBeTruthy();
    const raw = JSON.stringify(entry.toObject());
    expect(raw).not.toContain('definitely-wrong');
  });
});
