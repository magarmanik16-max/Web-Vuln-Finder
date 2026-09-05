/**
 * End-to-end smoke test against a RUNNING stack (mongod + API on :5000 +
 * client on :5173). Uses only Node builtins.
 *
 *   node tests/smoke.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const API = process.env.API_URL || 'http://localhost:5173/api'; // via Vite proxy, like the real frontend

function loadEnv() {
  const p = path.join(__dirname, '..', 'server', '.env');
  return Object.fromEntries(
    fs
      .readFileSync(p, 'utf8')
      .split('\n')
      .filter((l) => l.includes('='))
      .map((l) => [l.slice(0, l.indexOf('=')).trim(), l.slice(l.indexOf('=') + 1).trim()])
  );
}

const env = loadEnv();
let failures = 0;

async function check(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failures++;
    console.error(`  ✗ ${name}: ${e.message}`);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

(async () => {
  console.log(`Smoke-testing API at ${API}\n`);

  await check('health reports connected MongoDB', async () => {
    const r = await fetch(`${API}/health`);
    const b = await r.json();
    assert(b.ok && b.mongo === 'connected', JSON.stringify(b));
  });

  let token = '';
  await check('login works (seeded admin)', async () => {
    const r = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: env.ADMIN_EMAIL, password: env.ADMIN_PASSWORD }),
    });
    const b = await r.json();
    assert(r.ok && b.token, `status ${r.status}`);
    token = b.token;
  });

  await check('wrong password rejected (401)', async () => {
    const r = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: env.ADMIN_EMAIL, password: 'wrong' }),
    });
    assert(r.status === 401, `status ${r.status}`);
  });

  await check('/api/targets describes the safety policy', async () => {
    const r = await fetch(`${API}/targets`, { headers: { Authorization: `Bearer ${token}` } });
    const b = await r.json();
    assert(b.policy && /public HTTPS/i.test(b.policy.statement), JSON.stringify(b).slice(0, 120));
  });

  await check('scan for a public HTTPS target accepted', async () => {
    const r = await fetch(`${API}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ url: 'https://example.com' }),
    });
    assert(r.status === 201, `status ${r.status}`);
  });

  for (const bad of ['http://example.com', 'http://localhost', 'https://127.0.0.1', 'https://example.com:8443', 'https://user:pass@example.com']) {
    await check(`scan for unsafe "${bad}" rejected (400)`, async () => {
      const r = await fetch(`${API}/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ url: bad }),
      });
      assert(r.status === 400, `status ${r.status}`);
    });
  }

  await check('unauthenticated request rejected (401)', async () => {
    const r = await fetch(`${API}/targets`);
    assert(r.status === 401, `status ${r.status}`);
  });

  console.log(failures === 0 ? '\nALL SMOKE CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})();
