/**
 * Phase 4 hardening tests: CORS behavior, JWT expiry, adversarial target IDs,
 * scan concurrency/queue abuse, orphan recovery, rate limiting.
 */
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-only-secret-do-not-use-in-production-0123456789';
process.env.MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/webvulnapp_test_hard';
process.env.SCANNER_PYTHON = 'python3';
process.env.SCANNER_ARGS = '-m stub_scanner';
process.env.SCANNER_CWD = __dirname + '/fixtures';
process.env.SCAN_DATA_DIR = __dirname + '/../../.data/test-scans';
process.env.SCAN_CONCURRENCY = '1'; // deterministic queue assertions
delete process.env.STUB_MODE;

const request = require('supertest');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { buildApp } = require('../src/app');
const urlGuard = require('../src/security/urlGuard');

let dnsSpy;
beforeAll(() => {
  dnsSpy = jest.spyOn(urlGuard, 'validateTargetUrl').mockImplementation(async (u) => urlGuard.normalizeTargetUrl(u));
});
afterAll(() => dnsSpy.mockRestore());
const User = require('../src/models/User');
const Scan = require('../src/models/Scan');
const AuditLog = require('../src/models/AuditLog');
const scanManager = require('../src/services/scanManager');
const env = require('../src/config/env');

let app;
let token;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
async function waitFor(fn, timeoutMs = 25000, interval = 250) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const v = await fn();
    if (v) return v;
    await sleep(interval);
  }
  throw new Error('waitFor timed out');
}

beforeAll(async () => {
  await mongoose.connect(process.env.MONGODB_URI);
  await Promise.all([User.deleteMany({}), Scan.deleteMany({}), AuditLog.deleteMany({})]);
  await User.create({ email: 'admin@test.local', role: 'admin', passwordHash: await bcrypt.hash('password-123456', 10) });
  app = buildApp();
  token = (await request(app).post('/api/auth/login').send({ email: 'admin@test.local', password: 'password-123456' })).body.token;
});

afterAll(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
});

describe('CORS policy (§2/§14)', () => {
  test('allowed origin receives CORS headers', async () => {
    const res = await request(app).get('/api/health').set('Origin', 'http://localhost:5173');
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:5173');
  });

  test('disallowed origin gets NO CORS headers and is not a 500', async () => {
    const res = await request(app).get('/api/health').set('Origin', 'https://evil.com');
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('no-origin requests (API clients) work without CORS headers', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('JWT/session handling (§2)', () => {
  test('expired token is rejected', async () => {
    const expired = jwt.sign({ sub: 'x', role: 'admin', type: 'access', jti: 'j1' }, env.jwtSecret, { expiresIn: '1s' });
    await sleep(1600);
    const res = await request(app).get('/api/targets').set('Authorization', `Bearer ${expired}`);
    expect(res.status).toBe(401);
  });

  test('token signed with a different secret is rejected', async () => {
    const forged = jwt.sign({ sub: 'x', role: 'admin', type: 'access', jti: 'j2' }, 'attacker-secret-attacker-secret-attacker-secret', { expiresIn: '1h' });
    const res = await request(app).get('/api/targets').set('Authorization', `Bearer ${forged}`);
    expect(res.status).toBe(401);
  });

  test('HS256 is the only accepted algorithm family', async () => {
    // jsonwebtoken rejects 'none' when algorithms are pinned; verify a
    // mismatched-alg token fails instead of verifying against the secret.
    const forged = jwt.sign({ sub: 'x', role: 'admin', type: 'access', jti: 'j3' }, env.jwtSecret, { algorithm: 'HS512', expiresIn: '1h' });
    const res = await request(app).get('/api/targets').set('Authorization', `Bearer ${forged}`);
    expect(res.status).toBe(401);
  });
});

describe('adversarial URLs at the API boundary (§3/§14)', () => {
  // Genuinely unsafe: rejected by the structural gate before any DNS/network.
  test.each([
    'https://manikmagar.com.np:8443',
    'https://2130706433', // decimal 127.0.0.1
    'https://[::ffff:7f00:1]', // abbreviated IPv4-mapped loopback
    'https://[::ffff:127.0.0.1]',
    'http://manikmagar.com.np',
    'http://localhost',
    'https://localhost',
    'https://127.0.0.1',
    'https://192.168.1.1',
    'https://169.254.169.254',
    'https://user:password@example.com',
  ])('%j is an unsafe target -> 400', async (bad) => {
    const res = await request(app).post('/api/scans').set('Authorization', `Bearer ${token}`).send({ url: bad });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/rejected|public HTTPS/i);
  });

  // Public but suspicious-looking names: accepted by the policy (they ARE
  // public origins the user explicitly submitted); the DNS stage and the
  // origin-scoped crawler remain the boundaries. 429 = accepted but the
  // per-user scan cap was hit.
  test.each([
    'https://manikmagar.com.np\t.evil.com', // WHATWG strips tabs -> public name
    'https://evil.com\\@manikmagar.com.np', // host is evil.com (public)
    'https://xn--mnikmagar-n1a.com.np', // punycode name
    'https://manikmagar.com.np.evil.com', // lookalike suffix (public)
  ])('%j is a public origin -> accepted (201) or capped (429)', async (bad) => {
    const res = await request(app).post('/api/scans').set('Authorization', `Bearer ${token}`).send({ url: bad });
    expect([201, 429]).toContain(res.status);
  });

  afterAll(async () => Scan.deleteMany({}));
});

describe('scan concurrency & queue abuse (§18)', () => {
  test('scans above the concurrency cap stay queued and start FIFO', async () => {
    // clean slate: earlier tests may have left scans draining
    await Scan.deleteMany({});
    for (let i = 0; i < 40 && scanManager.activeCount() > 0; i++) await sleep(250);
    process.env.STUB_MODE = 'cancelled'; // sleeps until SIGTERM — deterministic
    const a = await request(app).post('/api/scans').set('Authorization', `Bearer ${token}`).send({ url: 'https://stub-a.example.test/' });
    const b = await request(app).post('/api/scans').set('Authorization', `Bearer ${token}`).send({ url: 'https://stub-b.example.test/' });
    const idA = a.body.scan._id;
    const idB = b.body.scan._id;

    await waitFor(async () => (await Scan.findById(idA)).status === 'running');
    expect((await Scan.findById(idB)).status).toBe('queued'); // cap = 1

    await scanManager.cancel(idA); // SIGTERM -> finalize -> queue advances
    await waitFor(async () => (await Scan.findById(idB)).status === 'running');

    await scanManager.cancel(idB);
    await waitFor(async () => ['cancelled', 'completed'].includes((await Scan.findById(idB)).status));
    delete process.env.STUB_MODE;
  }, 40000);
});

describe('orphan recovery (§10)', () => {
  test('queued/running scans from a dead process are marked failed on boot', async () => {
    await Scan.create({ targetId: 'STATIC_TARGET', requestedBy: new mongoose.Types.ObjectId(), status: 'queued' });
    await Scan.create({ targetId: 'DYNAMIC_TARGET', requestedBy: new mongoose.Types.ObjectId(), status: 'running', startedAt: new Date() });
    await scanManager.recoverOrphans();
    const orphans = await Scan.countDocuments({ status: { $in: ['queued', 'running'] } });
    expect(orphans).toBe(0);
    const failed = await Scan.countDocuments({ status: 'failed', error: /interrupted/ });
    expect(failed).toBeGreaterThanOrEqual(2);
  });
});

describe('rate limiting (§14)', () => {
  test('auth endpoint throttles brute-force attempts', async () => {
    let throttled = false;
    for (let i = 0; i < 25; i++) {
      const res = await request(app).post('/api/auth/login').send({ email: 'nobody@test.local', password: 'wrong-wrong-wrong' });
      if (res.status === 429) {
        throttled = true;
        break;
      }
    }
    expect(throttled).toBe(true);
  }, 30000);
});
