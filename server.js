// lilsecret API + static server. Zero npm dependencies.
//
// Two layers of encryption, two different threat models:
//   1. Note content is sealed on the sender's device (AES-256-GCM, key
//      derived from the code + a link fragment the server never sees).
//      The server cannot read notes, period.
//   2. Every stored record is sealed again server-side with STORAGE_KEY
//      before touching SQLite, so a leaked database or volume snapshot
//      reveals nothing — not even policies or attempt counts — without the
//      key, which lives in a Kubernetes Secret, not on the volume.
//
// The server's one privileged job is refereeing unlock attempts so a drop
// self-destructs after too many wrong codes.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const PORT = Number(
  process.argv.includes('--port')
    ? process.argv[process.argv.indexOf('--port') + 1]
    : process.env.PORT || 8080
);

const MAX_BODY = 1_048_576; // 1 MiB ciphertext budget per drop
const ID_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
const ATTEMPTS = 3;
const AFTER_OPEN_MIN = [0, 1, 5, 10, 15, 30];
const UNOPENED_MIN = [60, 120, 480, 1440, 2880];
const TOMBSTONE_DAYS = 30;

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- at-rest sealing ----------

function loadStorageKey() {
  const hex = process.env.STORAGE_KEY;
  if (hex) {
    if (!/^[0-9a-f]{64}$/.test(hex)) {
      console.error('STORAGE_KEY must be 64 hex chars (32 bytes). Generate one: openssl rand -hex 32');
      process.exit(1);
    }
    return Buffer.from(hex, 'hex');
  }
  // Dev fallback: a key file beside the database. Fine on a laptop; in
  // production STORAGE_KEY should come from a secret manager so the key
  // never sits on the same volume as the data.
  const keyFile = path.join(DATA_DIR, '.storage-key');
  try {
    return Buffer.from(fs.readFileSync(keyFile, 'utf8').trim(), 'hex');
  } catch {
    const key = crypto.randomBytes(32);
    fs.writeFileSync(keyFile, key.toString('hex'), { mode: 0o600 });
    console.warn('No STORAGE_KEY set — generated a dev key at ' + keyFile);
    return key;
  }
}
const STORAGE_KEY = loadStorageKey();

function sealRecord(obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', STORAGE_KEY, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

function unsealRecord(buf) {
  const b = Buffer.from(buf);
  const decipher = crypto.createDecipheriv('aes-256-gcm', STORAGE_KEY, b.subarray(0, 12));
  decipher.setAuthTag(b.subarray(12, 28));
  return JSON.parse(Buffer.concat([decipher.update(b.subarray(28)), decipher.final()]).toString('utf8'));
}

// ---------- store: one SQLite file, sealed record blobs ----------
// Clear columns are only what the sweeper needs to index: timestamps.
// Everything with meaning lives inside the sealed blob.

const db = new DatabaseSync(path.join(DATA_DIR, 'lilsecret.db'));
db.exec('PRAGMA journal_mode=WAL');
db.exec(`CREATE TABLE IF NOT EXISTS drops (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  opened_at INTEGER,
  wiped_at INTEGER,
  record BLOB NOT NULL
) STRICT`);

const stmtInsert = db.prepare('INSERT INTO drops (id, created_at, expires_at, opened_at, wiped_at, record) VALUES (?, ?, ?, ?, ?, ?)');
const stmtGet = db.prepare('SELECT * FROM drops WHERE id = ?');
const stmtUpdate = db.prepare('UPDATE drops SET expires_at = ?, opened_at = ?, wiped_at = ?, record = ? WHERE id = ?');
const stmtExpired = db.prepare('SELECT id FROM drops WHERE wiped_at IS NULL AND opened_at IS NULL AND expires_at < ?');
const stmtDead = db.prepare('DELETE FROM drops WHERE COALESCE(wiped_at, opened_at) < ?');

function readDrop(id) {
  if (!/^[a-z0-9]{8,20}$/.test(id)) return null;
  const row = stmtGet.get(id);
  if (!row) return null;
  try {
    const rec = unsealRecord(row.record);
    return { id: row.id, createdAt: Number(row.created_at), openedAt: row.opened_at && Number(row.opened_at), ...rec };
  } catch {
    return null; // wrong STORAGE_KEY or corrupt row — treat as missing
  }
}

function saveDrop(drop) {
  const { id, createdAt, openedAt, ...rec } = drop;
  const expiresAt = rec.status === 'sealed' ? createdAt + rec.unopenedMin * 60000 : null;
  const wipedAt = rec.wipedAt || null;
  const sealed = sealRecord(rec);
  if (stmtGet.get(id)) stmtUpdate.run(expiresAt, openedAt || null, wipedAt, sealed, id);
  else stmtInsert.run(id, createdAt, expiresAt, openedAt || null, wipedAt, sealed);
}

function genId() {
  const bytes = crypto.randomBytes(12);
  let s = '';
  for (const b of bytes) s += ID_ALPHABET[b % ID_ALPHABET.length];
  return s;
}

// Wipe the payload but keep a tombstone so revisits get an honest answer
// ("already used" vs "expired unread" vs "self-destructed").
function wipe(drop, status, reason) {
  drop.status = status;
  drop.reason = reason;
  drop.wipedAt = Date.now();
  if (drop.burnToken) {
    drop.burnTokenSha = sha256Hex(drop.burnToken);
    delete drop.burnToken;
  }
  delete drop.ct;
  delete drop.iv;
  delete drop.salt;
  delete drop.verifierHash;
  saveDrop(drop);
}

// Lazy expiry: a sealed drop past its unopened deadline is ash no matter
// when the sweeper last ran.
function fresh(drop) {
  if (drop && drop.status === 'sealed' && Date.now() > drop.createdAt + drop.unopenedMin * 60000) {
    wipe(drop, 'expired', 'unopened');
  }
  return drop;
}

function sweep() {
  try {
    for (const row of stmtExpired.all(Date.now())) {
      const drop = readDrop(row.id);
      if (drop) fresh(drop);
    }
    stmtDead.run(Date.now() - TOMBSTONE_DAYS * 86_400_000);
  } catch (e) {
    console.error('sweep failed:', e.message);
  }
}
setInterval(sweep, 60_000).unref();

// ---------- helpers ----------

function json(res, status, body) {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': buf.length,
    'cache-control': 'no-store',
  });
  res.end(buf);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('too_large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('bad_json'));
      }
    });
    req.on('error', reject);
  });
}

function isB64(s, maxLen) {
  return typeof s === 'string' && s.length > 0 && s.length <= maxLen && /^[A-Za-z0-9+/=]+$/.test(s);
}

function isHex(s, len) {
  return typeof s === 'string' && s.length === len && /^[0-9a-f]+$/.test(s);
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function timingSafeEq(aHex, bHex) {
  const a = Buffer.from(aHex, 'hex');
  const b = Buffer.from(bHex, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Minimal per-IP rate limit — enough to blunt enumeration and code-guess
// scripts without a dependency.
const buckets = new Map();
function rateLimited(req, scope, limit) {
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?';
  const key = scope + ':' + ip;
  const now = Date.now();
  const recent = (buckets.get(key) || []).filter((t) => now - t < 60_000);
  recent.push(now);
  buckets.set(key, recent);
  if (buckets.size > 10_000) buckets.clear();
  return recent.length > limit;
}

function goneReason(drop) {
  if (!drop) return 'missing';
  if (drop.status === 'opened') return 'used';
  return drop.reason || 'missing';
}

// ---------- API ----------

async function handleApi(req, res, url) {
  let m;

  if (req.method === 'POST' && url.pathname === '/api/drops') {
    if (rateLimited(req, 'create', 20)) return json(res, 429, { error: 'slow_down' });
    let body;
    try {
      body = await readBody(req);
    } catch (e) {
      return json(res, e.message === 'too_large' ? 413 : 400, { error: e.message });
    }
    const { ct, iv, salt, verifierHash, codeMode, noteCount, afterOpenMin, unopenedMin } = body;
    if (
      !isB64(ct, 1_400_000) || !isB64(iv, 32) || !isB64(salt, 64) ||
      !isHex(verifierHash, 64) ||
      (codeMode !== 'auto' && codeMode !== 'pass') ||
      !Number.isInteger(noteCount) || noteCount < 1 || noteCount > 20 ||
      !AFTER_OPEN_MIN.includes(afterOpenMin) || !UNOPENED_MIN.includes(unopenedMin)
    ) {
      return json(res, 400, { error: 'bad_drop' });
    }
    const drop = {
      id: genId(), createdAt: Date.now(),
      v: 1, status: 'sealed', reason: null,
      ct, iv, salt,
      // Already sha256(verifier) as sent by the client — the database never
      // holds the preimage an unlock challenge must present.
      verifierHash,
      codeMode, noteCount, afterOpenMin, unopenedMin,
      tries: 0,
      burnToken: crypto.randomBytes(16).toString('hex'),
    };
    saveDrop(drop);
    return json(res, 201, { id: drop.id });
  }

  if ((m = url.pathname.match(/^\/api\/drops\/([a-z0-9]{8,20})$/)) && req.method === 'GET') {
    const drop = fresh(readDrop(m[1]));
    if (!drop || drop.status !== 'sealed') return json(res, 410, { status: 'gone', reason: goneReason(drop) });
    return json(res, 200, {
      status: 'sealed',
      // The KDF salt is needed client-side to compute the unlock verifier;
      // it is not a secret (without ciphertext it enables nothing).
      salt: drop.salt,
      codeMode: drop.codeMode,
      noteCount: drop.noteCount,
      createdAt: drop.createdAt,
      afterOpenMin: drop.afterOpenMin,
      unopenedMin: drop.unopenedMin,
      triesLeft: ATTEMPTS - (drop.tries || 0),
      attempts: ATTEMPTS,
    });
  }

  if ((m = url.pathname.match(/^\/api\/drops\/([a-z0-9]{8,20})\/unlock$/)) && req.method === 'POST') {
    if (rateLimited(req, 'unlock', 15)) return json(res, 429, { error: 'slow_down' });
    const drop = fresh(readDrop(m[1]));
    if (!drop || drop.status !== 'sealed') return json(res, 410, { status: 'gone', reason: goneReason(drop) });
    let body;
    try {
      body = await readBody(req);
    } catch (e) {
      return json(res, 400, { error: e.message });
    }
    if (!isHex(body.verifier, 64)) return json(res, 400, { error: 'bad_verifier' });

    if (timingSafeEq(sha256Hex(body.verifier), drop.verifierHash)) {
      const payload = {
        ct: drop.ct, iv: drop.iv, salt: drop.salt,
        afterOpenMin: drop.afterOpenMin,
        burnToken: drop.burnToken,
      };
      drop.openedAt = Date.now();
      wipe(drop, 'opened', null); // payload leaves the server exactly once
      return json(res, 200, payload);
    }

    drop.tries = (drop.tries || 0) + 1;
    if (drop.tries >= ATTEMPTS) {
      wipe(drop, 'burned', 'tries');
      return json(res, 410, { status: 'gone', reason: 'tries' });
    }
    saveDrop(drop);
    return json(res, 403, { error: 'wrong_code', triesLeft: ATTEMPTS - drop.tries });
  }

  // Post-read bookkeeping: lets a revisit say "burned by hand" / "window
  // closed" instead of the generic "already used". Requires the burn token
  // that only a successful unlock hands out.
  if ((m = url.pathname.match(/^\/api\/drops\/([a-z0-9]{8,20})\/burn$/)) && req.method === 'POST') {
    let body;
    try {
      body = await readBody(req);
    } catch (e) {
      return json(res, 400, { error: e.message });
    }
    const drop = readDrop(m[1]);
    if (
      drop && drop.status === 'opened' && drop.burnTokenSha &&
      isHex(body.burnToken || '', 32) &&
      timingSafeEq(sha256Hex(body.burnToken), drop.burnTokenSha) &&
      (body.reason === 'manual' || body.reason === 'timer')
    ) {
      drop.status = 'burned';
      drop.reason = body.reason;
      delete drop.burnTokenSha;
      saveDrop(drop);
    }
    return json(res, 200, { ok: true }); // never leak whether the token matched
  }

  return json(res, 404, { error: 'not_found' });
}

// ---------- static ----------

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function serveFile(res, file, cache) {
  let buf;
  try {
    buf = fs.readFileSync(file);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' });
    return res.end('not found');
  }
  res.writeHead(200, {
    'content-type': MIME[path.extname(file)] || 'application/octet-stream',
    'content-length': buf.length,
    'cache-control': cache,
  });
  res.end(buf);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');

  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader(
    'content-security-policy',
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
  );

  if (url.pathname.startsWith('/api/')) {
    handleApi(req, res, url).catch(() => json(res, 500, { error: 'internal' }));
    return;
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { allow: 'GET, HEAD' });
    return res.end();
  }

  if (url.pathname === '/healthz') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    return res.end('ok');
  }

  // Recipient links are real paths so the key fragment in the URL hash
  // never fights the sender's hash routes; the SPA takes it from there.
  // no-store: a shared machine's cache must never hold a gate page.
  if (url.pathname === '/' || /^\/d\/[a-z0-9]{8,20}$/.test(url.pathname)) {
    return serveFile(res, path.join(PUBLIC_DIR, 'index.html'), 'no-store');
  }

  const file = path.normalize(path.join(PUBLIC_DIR, url.pathname));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    return res.end('not found');
  }
  serveFile(res, file, 'no-cache');
});

server.listen(PORT, () => {
  console.log(`lilsecret listening on :${server.address().port} — data in ${DATA_DIR}`);
});

// For the test suite: lets node:test import the running server in-process
// (real coverage, no child processes), reset rate-limit state between
// tests, and close the server when done.
export { server, buckets };
