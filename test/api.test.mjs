// Integration tests: the server runs in-process against a temp data dir,
// exercising the real protocol the way the browser client speaks it.
import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lilsecret-test-'));
process.env.DATA_DIR = dataDir;
process.env.PORT = '0';
process.env.STORAGE_KEY = crypto.randomBytes(32).toString('hex');

const { server, buckets } = await import('../server.js');
if (!server.listening) await new Promise((r) => server.once('listening', r));
const BASE = 'http://127.0.0.1:' + server.address().port;

// Every test starts with a clean rate-limit slate so counts are exact and
// tests stay order-independent.
beforeEach(() => buckets.clear());

after(() => {
  server.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

/* ---------- client-protocol helpers (mirror public/app.js) ---------- */

const hexOf = (b) => Buffer.from(b).toString('hex');
const sha256Hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

function derive(secret, salt) {
  const bits = crypto.pbkdf2Sync(secret, salt, 310000, 64, 'sha256');
  return { keyMaterial: bits.subarray(0, 32), verifier: hexOf(bits.subarray(32)) };
}

const PLAINTEXT = 'hello **world** — top secret';

async function createDrop({ secret = '123456', codeMode = 'auto', afterOpenMin = 0, unopenedMin = 60, raw = {} } = {}) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const linkKey = crypto.randomBytes(16);
  const { keyMaterial, verifier } = derive(secret, salt);
  const key = crypto.hkdfSync('sha256', Buffer.concat([keyMaterial, linkKey]), salt, 'lilsecret-enc-v1', 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key), iv);
  const pt = JSON.stringify({ v: 1, notes: [{ title: 't', body: PLAINTEXT }] });
  const ct = Buffer.concat([cipher.update(pt, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  const res = await fetch(BASE + '/api/drops', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      ct: ct.toString('base64'), iv: iv.toString('base64'), salt: salt.toString('base64'),
      verifierHash: sha256Hex(verifier), codeMode, noteCount: 1, afterOpenMin, unopenedMin,
      ...raw,
    }),
  });
  const data = await res.json();
  return { status: res.status, id: data.id, verifier, key, ctB64: ct.toString('base64') };
}

async function unlock(id, verifier) {
  const res = await fetch(`${BASE}/api/drops/${id}/unlock`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ verifier }),
  });
  return { status: res.status, data: await res.json() };
}

async function meta(id) {
  const res = await fetch(`${BASE}/api/drops/${id}`);
  return { status: res.status, data: await res.json() };
}

async function burn(id, burnToken, reason) {
  const res = await fetch(`${BASE}/api/drops/${id}/burn`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ burnToken, reason }),
  });
  return { status: res.status, data: await res.json() };
}

/* ---------- the drop lifecycle ---------- */

test('happy path: seal → meta → unlock → decrypt → link is dead', async () => {
  const d = await createDrop();
  assert.equal(d.status, 201);

  const m = await meta(d.id);
  assert.equal(m.status, 200);
  assert.equal(m.data.codeMode, 'auto');
  assert.equal(m.data.noteCount, 1);
  assert.equal(m.data.triesLeft, 3);
  assert.ok(m.data.salt);

  const u = await unlock(d.id, d.verifier);
  assert.equal(u.status, 200);
  assert.ok(u.data.ct && u.data.iv && u.data.burnToken);

  const ctBuf = Buffer.from(u.data.ct, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(d.key), Buffer.from(u.data.iv, 'base64'));
  decipher.setAuthTag(ctBuf.subarray(ctBuf.length - 16));
  const out = JSON.parse(Buffer.concat([decipher.update(ctBuf.subarray(0, ctBuf.length - 16)), decipher.final()]).toString('utf8'));
  assert.equal(out.notes[0].body, PLAINTEXT);

  assert.equal((await meta(d.id)).data.reason, 'used');
  assert.equal((await unlock(d.id, d.verifier)).data.reason, 'used');
});

test('burn bookkeeping: valid token records the reason, invalid does not', async () => {
  const d = await createDrop();
  const u = await unlock(d.id, d.verifier);

  const bad = await burn(d.id, 'f'.repeat(32), 'manual');
  assert.equal(bad.status, 200); // never leaks whether the token matched
  assert.equal((await meta(d.id)).data.reason, 'used');

  const badReason = await burn(d.id, u.data.burnToken, 'revoked');
  assert.equal(badReason.status, 200);
  assert.equal((await meta(d.id)).data.reason, 'used');

  await burn(d.id, u.data.burnToken, 'manual');
  assert.equal((await meta(d.id)).data.reason, 'manual');
});

test('timer reason is also accepted', async () => {
  const d = await createDrop({ afterOpenMin: 5 });
  const u = await unlock(d.id, d.verifier);
  await burn(d.id, u.data.burnToken, 'timer');
  assert.equal((await meta(d.id)).data.reason, 'timer');
});

test('three wrong codes self-destruct the drop', async () => {
  const d = await createDrop();
  const w1 = await unlock(d.id, 'a'.repeat(64));
  assert.equal(w1.status, 403);
  assert.equal(w1.data.triesLeft, 2);
  const w2 = await unlock(d.id, 'b'.repeat(64));
  assert.equal(w2.data.triesLeft, 1);
  const w3 = await unlock(d.id, 'c'.repeat(64));
  assert.equal(w3.status, 410);
  assert.equal(w3.data.reason, 'tries');
  // even the correct verifier is too late now
  assert.equal((await unlock(d.id, d.verifier)).data.reason, 'tries');
});

test('passphrase mode round-trips', async () => {
  const d = await createDrop({ secret: 'olive & thunder', codeMode: 'pass' });
  const m = await meta(d.id);
  assert.equal(m.data.codeMode, 'pass');
  const wrong = derive('wrong horse', Buffer.from(m.data.salt, 'base64'));
  assert.equal((await unlock(d.id, wrong.verifier)).status, 403);
  const right = derive('olive & thunder', Buffer.from(m.data.salt, 'base64'));
  assert.equal((await unlock(d.id, right.verifier)).status, 200);
});

test('unopened drops expire on schedule', async () => {
  const d = await createDrop();
  const db = new DatabaseSync(path.join(dataDir, 'lilsecret.db'));
  const twoHoursAgo = Date.now() - 2 * 3600 * 1000;
  db.prepare('UPDATE drops SET created_at = ?, expires_at = ? WHERE id = ?')
    .run(twoHoursAgo, twoHoursAgo + 3600 * 1000, d.id);
  db.close();
  const m = await meta(d.id);
  assert.equal(m.status, 410);
  assert.equal(m.data.reason, 'unopened');
  assert.equal((await unlock(d.id, d.verifier)).status, 410);
});

/* ---------- validation ---------- */

test('policy values outside the allowed sets are rejected', async () => {
  assert.equal((await createDrop({ afterOpenMin: 3 })).status, 400);
  assert.equal((await createDrop({ unopenedMin: 999 })).status, 400);
  assert.equal((await createDrop({ raw: { noteCount: 0 } })).status, 400);
  assert.equal((await createDrop({ raw: { noteCount: 21 } })).status, 400);
  assert.equal((await createDrop({ raw: { codeMode: 'psychic' } })).status, 400);
  assert.equal((await createDrop({ raw: { verifierHash: 'zz' } })).status, 400);
});

test('malformed unlock verifier is rejected without burning a try', async () => {
  const d = await createDrop();
  const res = await fetch(`${BASE}/api/drops/${d.id}/unlock`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ verifier: 'not-hex' }),
  });
  assert.equal(res.status, 400);
  assert.equal((await meta(d.id)).data.triesLeft, 3);
});

test('unknown ids and malformed ids', async () => {
  const m = await meta('nosuchdrop12');
  assert.equal(m.status, 410);
  assert.equal(m.data.reason, 'missing');
  const res = await fetch(BASE + '/api/drops/UPPERCASE-ID');
  assert.equal(res.status, 404);
});

/* ---------- at-rest sealing ---------- */

test('database bytes reveal neither plaintext nor stored ciphertext', async () => {
  const d = await createDrop(); // stays sealed
  const files = ['lilsecret.db', 'lilsecret.db-wal']
    .map((f) => path.join(dataDir, f))
    .filter((f) => fs.existsSync(f));
  const blob = Buffer.concat(files.map((f) => fs.readFileSync(f)));
  const hay = blob.toString('latin1');
  assert.ok(!hay.includes(PLAINTEXT), 'plaintext leaked into DB');
  assert.ok(!hay.includes(d.ctB64.slice(0, 48)), 'client ciphertext stored unsealed');
  assert.ok(!hay.includes('verifierHash'), 'record JSON stored unsealed');
});

/* ---------- static serving and headers ---------- */

test('index, gate paths, healthz, and 404s', async () => {
  const home = await fetch(BASE + '/');
  assert.equal(home.status, 200);
  assert.match(home.headers.get('content-type'), /text\/html/);
  assert.ok(home.headers.get('content-security-policy').includes("default-src 'none'"));
  assert.equal(home.headers.get('x-frame-options'), null);
  assert.ok(
    home.headers
      .get('content-security-policy')
      .includes("frame-ancestors 'self' https://norik.io https://*.norik.io")
  );
  assert.equal(home.headers.get('referrer-policy'), 'no-referrer');

  const gate = await fetch(BASE + '/d/abcdefgh2345');
  assert.equal(gate.status, 200);
  assert.equal(gate.headers.get('cache-control'), 'no-store');

  assert.equal((await fetch(BASE + '/healthz')).status, 200);
  assert.equal((await fetch(BASE + '/server.js')).status, 404);
  assert.equal((await fetch(BASE + '/..%2Fserver.js')).status, 404);
  assert.equal((await fetch(BASE + '/', { method: 'POST' })).status, 405);
});

/* ---------- rate limiting ---------- */

test('unlock attempts are rate limited to 15/min per IP', async () => {
  const statuses = [];
  for (let i = 0; i < 20; i++) {
    const r = await unlock('zzzzzzzzzzzz', 'd'.repeat(64));
    statuses.push(r.status);
  }
  assert.equal(statuses.filter((s) => s === 410).length, 15);
  assert.equal(statuses.filter((s) => s === 429).length, 5);
});

