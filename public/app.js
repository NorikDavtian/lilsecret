// lilsecret frontend. No framework, no dependencies.
//
// Crypto model: a drop is sealed on this device with AES-256-GCM. The key is
// derived (PBKDF2 310k + HKDF) from BOTH the code/passphrase AND a random
// link-key that travels only in the URL fragment — which browsers never send
// to servers. The server stores ciphertext plus a hashed verifier so it can
// referee wrong-code attempts; it can decrypt nothing.

'use strict';

/* ---------- tiny DOM helper ---------- */

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(c));
  }
  return el;
}
const app = document.getElementById('app');

/* ---------- state ---------- */

function newNote() {
  return { id: Math.random().toString(36).slice(2, 9), title: '', body: '' };
}

const S = {
  view: 'landing',
  draft: { notes: [newNote()] },
  seal: { codeMode: 'auto', passphrase: '', afterOpenMin: 0, unopenedMin: 60 },
  handoff: null, // { link, code, codeMode, afterOpenMin, unopenedMin }
  gate: null,    // { id, meta, error, input, missingKey }
  reveal: null,  // { notes, burnsAt, burnToken, id, raw:Set, afterOpenMin }
  gone: 'missing',
};

/* ---------- crypto ---------- */

const enc = new TextEncoder();
const PBKDF2_ITERS = 310000;

function rand(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
function b64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
function unb64(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
function b64url(bytes) {
  return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64url(s) {
  return unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
}
function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function kdfBits(secret, salt) {
  const km = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' }, km, 512
  );
  return new Uint8Array(bits); // [0..32) = key material, [32..64) = verifier material
}

async function dropKey(keyMaterial, linkKey, salt) {
  const ikm = new Uint8Array([...keyMaterial, ...linkKey]);
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('lilsecret-enc-v1') },
    k, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function sha256HexOf(str) {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(str))));
}

function genCode() {
  const r = new Uint32Array(1);
  crypto.getRandomValues(r);
  return String(r[0] % 1000000).padStart(6, '0');
}

/* ---------- formatting (ported from the design) ---------- */

function fmtClock(ms) {
  const s = Math.max(0, Math.ceil(ms / 1000));
  const m = Math.floor(s / 60);
  const x = s % 60;
  return (m < 10 ? '0' : '') + m + ':' + (x < 10 ? '0' : '') + x;
}
function fmtDate(ts) {
  return new Date(ts).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function fmtSpan(ms) {
  if (ms <= 0) return 'now';
  const m = Math.ceil(ms / 60000);
  if (m < 60) return m + 'm';
  const hh = Math.ceil(m / 60);
  if (hh < 24) return hh + 'h';
  return Math.ceil(hh / 24) + 'd';
}
function fuseWord(min) {
  return min === 1 ? '1 minute' : min + ' minutes';
}
function policyShort(d) {
  const fuse = d.afterOpenMin > 0
    ? d.afterOpenMin + '-minute fuse after opening'
    : 'burns on open';
  return fuse + ' · shelf life ' + fmtSpan(d.unopenedMin * 60000);
}

/* ---------- markdown: escape-first, safe subset (ported) ---------- */

function mdEsc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function mdInline(s) {
  return s
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/\*([^*]+)\*/g, '<i>$1</i>')
    .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer noopener">$1</a>');
}
function mdToHtml(src) {
  const esc = mdEsc(src || '');
  const fences = [];
  const guarded = esc.replace(/```([\s\S]*?)```/g, (m2, code) => {
    fences.push(code.replace(/^\n|\n$/g, ''));
    return '\u0000' + (fences.length - 1) + '\u0000';
  });
  const lines = guarded.split('\n');
  let html = '', inUl = false, para = [];
  const flush = () => { if (para.length) { html += '<p>' + mdInline(para.join('<br>')) + '</p>'; para = []; } };
  const closeUl = () => { if (inUl) { html += '</ul>'; inUl = false; } };
  for (const l of lines) {
    const t = l.trim();
    if (!t) { flush(); closeUl(); continue; }
    if (t.charCodeAt(0) === 0) {
      flush(); closeUl();
      const i = parseInt(t.slice(1), 10);
      html += '<pre>' + (fences[i] || '') + '</pre>';
      continue;
    }
    const hd = t.match(/^(#{1,4})\s+(.*)/);
    if (hd) { flush(); closeUl(); const n = hd[1].length; html += `<h${n}>` + mdInline(hd[2]) + `</h${n}>`; continue; }
    if (/^[-*]\s+/.test(t)) {
      flush();
      if (!inUl) { html += '<ul>'; inUl = true; }
      html += '<li>' + mdInline(t.replace(/^[-*]\s+/, '')) + '</li>';
      continue;
    }
    if (/^(---|\*\*\*)$/.test(t)) { flush(); closeUl(); html += '<hr>'; continue; }
    if (t.indexOf('&gt;') === 0) { flush(); closeUl(); html += '<blockquote>' + mdInline(t.replace(/^&gt;\s?/, '')) + '</blockquote>'; continue; }
    para.push(t);
  }
  flush(); closeUl();
  const div = h('div', { class: 'md' });
  div.innerHTML = html; // safe: every character of user input was escaped above
  return div;
}

/* ---------- toast / copy ---------- */

let toastTimer;
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 2200);
}
function copyText(text, msg) {
  const done = () => toast(msg || 'Copied.');
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, done);
  else done();
}

/* ---------- API ---------- */

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

/* ---------- landing canvas (ported fingerprint waves) ---------- */

let fpRaf = 0;
function startCanvas(c) {
  cancelAnimationFrame(fpRaf);
  const R = Math.random;
  const waves = Array.from({ length: 5 }, () => ({
    a: 5 + R() * 15, kx: 0.0035 + R() * 0.009, ky: 0.006 + R() * 0.018,
    ph: R() * Math.PI * 2, sp: (0.12 + R() * 0.3) * (R() < 0.5 ? -1 : 1),
  }));
  const dash = [3.5 + R() * 5, 3.5 + R() * 4];
  const t0 = performance.now();
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const draw = () => {
    if (!c.isConnected) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = c.clientWidth, hh = c.clientHeight;
    if (w && hh && (c.width !== Math.round(w * dpr) || c.height !== Math.round(hh * dpr))) {
      c.width = Math.round(w * dpr);
      c.height = Math.round(hh * dpr);
    }
    const ctx = c.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, hh);
    const t = reduce ? 0 : (performance.now() - t0) / 1000;
    ctx.lineWidth = 1.1;
    ctx.lineCap = 'round';
    ctx.strokeStyle = 'rgba(228,228,233,0.13)';
    ctx.setLineDash(dash);
    let row = 0;
    for (let y0 = -24; y0 < hh + 24; y0 += 9) {
      row++;
      ctx.lineDashOffset = (row * 7.3) % 13 + t * 2.2 * (row % 2 ? 1 : -1);
      ctx.beginPath();
      for (let x = -12; x <= w + 12; x += 6) {
        let y = y0;
        for (const wv of waves) y += wv.a * Math.sin(x * wv.kx + y0 * wv.ky + wv.ph + t * wv.sp);
        if (x === -12) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.stroke();
    }
    if (!reduce) fpRaf = requestAnimationFrame(draw);
  };
  draw();
}

/* ---------- screens ---------- */

function screenLanding() {
  const canvas = h('canvas', { class: 'land-canvas' });
  requestAnimationFrame(() => startCanvas(canvas));
  const sub = h('p', { class: 'land-sub' });
  sub.append(
    'Share credentials, keys, and ',
    h('span', { class: 'redact', text: 'confessions' }),
    ' as sealed drops — never in plaintext. The recipient gets one link and a one-time code. Wrong code three times, or one read, and it’s ash.'
  );
  const card = (n, t, d) => h('div', { class: 'land-card' },
    h('div', { class: 'n', text: n }), h('div', { class: 't', text: t }), h('div', { class: 'd', text: d }));
  return h('div', { class: 'land' },
    canvas,
    h('div', { class: 'land-inner' },
      h('div', { class: 'kicker', text: 'ENCRYPTED NOTE SHARING · SELF-DESTRUCTS ON OPEN' }),
      h('h1', { text: 'Some things should only be read once.' }),
      sub,
      h('div', { class: 'land-cta' },
        h('button', { class: 'btn-bone', onclick: () => nav('#/new'), text: 'Draft a drop' })),
      h('div', { class: 'land-cards' },
        card('01 · SEAL', 'Sealed on your device', 'Notes are encrypted in your browser before anything leaves it. The server only ever holds scrambled bytes.'),
        card('02 · RELAY', 'Two channels, two halves', 'The link is half the key. The code is the other half. Send them separately — no one in the middle ever holds both.'),
        card('03 · BURN', 'Ash by design', 'Three wrong codes, an expired shelf life, or a single read — the drop erases itself for good. Erased, not archived.')),
      h('div', { class: 'how' },
        h('div', { class: 'kicker', text: 'HOW IT WORKS' }),
        h('h2', { class: 'serif-h', text: 'Built to forget.' }),
        h('div', { class: 'how-rows' },
          h('div', { class: 'how-row' },
            h('div', { class: 't', text: 'Sealed before it leaves' }),
            h('div', { class: 'd', text: 'Your notes are locked on your device before anything is sent. What travels — and what sits on our server — is scrambled beyond reading. We couldn’t peek if we wanted to.' })),
          h('div', { class: 'how-row' },
            h('div', { class: 't', text: 'Two halves of one key' }),
            h('div', { class: 'd', text: 'The link carries half of the key. The code you relay carries the other half. The server holds neither — only someone with both halves can open the drop. That’s why you send them separately.' })),
          h('div', { class: 'how-row' },
            h('div', { class: 't', text: 'It really is gone' }),
            h('div', { class: 'd', text: 'One read, three wrong codes, or time running out — the notes are erased on the spot, not archived. All that remains is a marker that says how it burned.' }))),
        h('p', { class: 'how-foot' },
          'No accounts. No analytics. ',
          h('a', { href: 'https://github.com/NorikDavtian/lilsecret', target: '_blank', rel: 'noreferrer noopener' }, 'Open source'),
          ' — the curious can read exactly how the sealing works.'))));
}

function screenCompose() {
  const list = h('div', {});
  S.draft.notes.forEach((note, i) => {
    const gutter = h('div', { class: 'gutter' });
    const syncGutter = () => {
      const n = note.body.split('\n').length;
      gutter.replaceChildren(...Array.from({ length: n }, (_, j) => h('div', { text: String(j + 1) })));
    };
    syncGutter();
    const ta = h('textarea', {
      class: 'note-ta', spellcheck: 'false',
      rows: String(Math.max(7, note.body.split('\n').length + 1)),
      placeholder: 'The secret itself. Markdown works — # heading, **bold**, code fences.',
      oninput: (e) => {
        note.body = e.target.value;
        e.target.rows = Math.max(7, note.body.split('\n').length + 1);
        syncGutter();
      },
    });
    ta.value = note.body;
    const title = h('input', {
      class: 'note-title', autocomplete: 'off',
      placeholder: 'title — e.g. prod-db.env',
      oninput: (e) => { note.title = e.target.value; },
    });
    title.value = note.title;
    list.append(h('div', { class: 'note-card' },
      h('div', { class: 'note-head' },
        h('span', { class: 'note-num', text: String(i + 1).padStart(2, '0') }),
        title,
        h('button', {
          class: 'note-x', title: 'Remove note',
          onclick: () => {
            const rest = S.draft.notes.filter((x) => x.id !== note.id);
            S.draft.notes = rest.length ? rest : [newNote()];
            render();
          },
        }, '✕')),
      h('div', { class: 'note-grid' }, gutter, ta)));
  });
  const count = S.draft.notes.length;
  return h('div', { class: 'wrap-880 screen' },
    h('div', { class: 'kicker', text: 'STEP 1 / 3 · DRAFT' }),
    h('h2', { class: 'serif-h h2-34', text: 'What goes in the drop?' }),
    h('p', { class: 'step-sub', text: 'Plain text or markdown. Nothing below ever travels unsealed.' }),
    list,
    h('button', {
      class: 'add-note',
      onclick: () => { S.draft.notes.push(newNote()); render(); },
      text: '+ ADD ANOTHER NOTE',
    }),
    h('div', { class: 'compose-foot' },
      h('span', { class: 'count-label', text: count + (count === 1 ? ' NOTE' : ' NOTES') + ' IN THIS DROP' }),
      h('div', { class: 'spacer' }),
      h('button', {
        class: 'btn-bone',
        onclick: () => {
          if (draftHasContent()) nav('#/seal');
          else toast('Write something first.');
        },
      }, 'Continue to seal →')));
}

function draftHasContent() {
  return S.draft.notes.some((n) => n.title.trim() || n.body.trim());
}

function screenSeal() {
  const seal = S.seal;
  const keyCard = (mode, t, d) => h('div', {
    class: 'key-card' + (seal.codeMode === mode ? ' on' : ''),
    onclick: () => { seal.codeMode = mode; render(); },
  }, h('div', { class: 't', text: t }), h('div', { class: 'd', text: d }));

  const chips = (pairs, key) => h('div', { class: 'chip-row' },
    pairs.map(([v, label]) => h('button', {
      class: 'chip' + (seal[key] === v ? ' on' : ''),
      onclick: () => { seal[key] = v; render(); },
      text: label,
    })));

  const passInput = seal.codeMode === 'pass'
    ? h('input', {
        class: 'pass-input', type: 'text', autocomplete: 'off',
        placeholder: "the passphrase — 4+ characters, exactly as they'll type it",
        oninput: (e) => { seal.passphrase = e.target.value; },
      })
    : null;
  if (passInput) passInput.value = seal.passphrase;

  return h('div', { class: 'wrap-720 screen' },
    h('div', { class: 'kicker', text: 'STEP 2 / 3 · SEAL' }),
    h('h2', { class: 'serif-h h2-34', text: 'Set the burn conditions.' }),
    h('p', { class: 'step-sub', text: 'Every link is single-use no matter what you pick below.' }),
    h('div', { class: 'label', style: 'margin-bottom:10px', text: 'THE KEY' }),
    h('div', { class: 'key-cards' },
      keyCard('auto', 'Auto 6-digit code', 'We cut a random code. You relay it — ideally not in the same channel as the link.'),
      keyCard('pass', 'Your own passphrase', 'Something the recipient already knows. It never gets stored — anywhere.')),
    passInput,
    h('div', { class: 'label', style: 'margin:28px 0 10px', text: 'DESTRUCTION — BOTH TIMERS ALWAYS RUN' }),
    h('div', { class: 'burn-panel' },
      h('div', { class: 't', text: 'Burn after reading' }),
      h('div', { class: 'd', text: "How long they can read once it's open. Immediately means one sitting — leave, and it's ash." }),
      chips([[0, 'IMMEDIATELY'], [1, '1 MIN'], [5, '5 MIN'], [10, '10 MIN'], [15, '15 MIN'], [30, '30 MIN']], 'afterOpenMin')),
    h('div', { class: 'burn-panel' },
      h('div', { class: 't', text: 'Expire if unopened' }),
      h('div', { class: 'd', text: 'Never opened in time? It shreds itself, unread.' }),
      chips([[60, '1 HOUR'], [120, '2 HOURS'], [480, '8 HOURS'], [1440, '24 HOURS'], [2880, '48 HOURS']], 'unopenedMin')),
    h('div', { class: 'seal-note' },
      "THE RECIPIENT ALWAYS GETS A BURN BUTTON — THAT ONE'S NOT OPTIONAL.", h('br'),
      'WRONG CODE 3 TIMES → THE DROP SELF-DESTRUCTS.'),
    h('div', { class: 'seal-foot' },
      h('button', { class: 'btn-ghost', onclick: () => nav('#/new') }, '← Back to draft'),
      h('div', { class: 'spacer' }),
      h('button', { class: 'btn-bone', onclick: sealNow }, 'Seal the drop')));
}

function screenSealing() {
  return h('div', { class: 'sealing' },
    h('div', { text: '▸ ENCRYPTING NOTES — AES-256-GCM' }),
    h('div', { style: 'animation-delay:0.25s', text: '▸ CUTTING SINGLE-USE LINK' }),
    h('div', { style: 'animation-delay:0.5s' }, '▸ SCRUBBING FINGERPRINTS ', h('span', { class: 'blink', text: '▎' })));
}

async function sealNow() {
  const seal = S.seal;
  const notes = S.draft.notes
    .filter((n) => n.title.trim() || n.body.trim())
    .map((n) => ({ title: n.title.trim(), body: n.body }));
  if (!notes.length) return toast('Write something first.');
  if (seal.codeMode === 'pass' && seal.passphrase.trim().length < 4) {
    return toast('Passphrase needs at least 4 characters.');
  }
  S.view = 'sealing';
  render();
  const started = Date.now();
  try {
    const code = seal.codeMode === 'auto' ? genCode() : seal.passphrase;
    const salt = rand(16);
    const linkKey = rand(16);
    const iv = rand(12);
    const bits = await kdfBits(code, salt);
    const key = await dropKey(bits.slice(0, 32), linkKey, salt);
    const ctBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify({ v: 1, notes }))
    );
    const verifier = hex(bits.slice(32));
    const { status, data } = await api('POST', '/api/drops', {
      ct: b64(new Uint8Array(ctBuf)), iv: b64(iv), salt: b64(salt),
      verifierHash: await sha256HexOf(verifier),
      codeMode: seal.codeMode, noteCount: notes.length,
      afterOpenMin: seal.afterOpenMin, unopenedMin: seal.unopenedMin,
    });
    if (status !== 201) throw new Error(data.error || 'seal_failed');
    await new Promise((r) => setTimeout(r, Math.max(0, 1400 - (Date.now() - started))));
    S.handoff = {
      link: location.origin + '/d/' + data.id + '#' + b64url(linkKey),
      code: seal.codeMode === 'auto' ? code : null,
      codeMode: seal.codeMode,
      afterOpenMin: seal.afterOpenMin,
      unopenedMin: seal.unopenedMin,
    };
    S.draft = { notes: [newNote()] };
    seal.passphrase = '';
    S.view = 'handoff';
    render();
  } catch (e) {
    S.view = 'seal';
    render();
    toast('Sealing failed — ' + (e.message === 'slow_down' ? 'too many drops too fast. Give it a minute.' : 'try again.'));
  }
}

function screenHandoff() {
  const hf = S.handoff;
  if (!hf) { S.view = 'landing'; return screenLanding(); }
  const policyLine = [
    hf.afterOpenMin > 0
      ? 'It burns ' + fuseWord(hf.afterOpenMin) + ' after they open it.'
      : 'It burns the moment they open it.',
    'Unopened, it shreds itself in ' + fmtSpan(hf.unopenedMin * 60000) + '.',
  ].join(' ');
  return h('div', { class: 'wrap-680 screen' },
    h('div', { class: 'kicker', text: 'STEP 3 / 3 · RELAY' }),
    h('h2', { class: 'serif-h h2-34', text: 'Sealed. Handle with care.' }),
    h('p', { class: 'step-sub' }, policyLine + ' The link works exactly once.'),
    h('div', { class: 'linkbox' },
      h('div', { class: 'label', text: 'SHARE LINK · SINGLE USE' }),
      h('div', { class: 'linkbox-row' },
        h('div', { class: 'linkbox-val', text: hf.link }),
        h('button', { class: 'pill-btn', onclick: () => copyText(hf.link, 'Link copied.'), text: 'COPY' }))),
    hf.codeMode === 'auto'
      ? h('div', { class: 'code-panel' },
          h('div', { class: 'label', text: 'ONE-TIME CODE — SHOWN ONCE' }),
          h('div', { class: 'code-row' },
            h('span', { class: 'code-digits', text: hf.code.split('').join(' ') }),
            h('button', {
              class: 'btn-ghost', style: 'padding:7px 13px;font-size:12px',
              onclick: () => copyText(hf.code, 'Code copied — relay it apart from the link.'),
            }, 'Copy code')),
          h('div', { class: 'code-note', text: "Relay it through a different channel than the link. It isn't stored — we can't show it again." }))
      : h('div', { class: 'pass-panel' },
          h('div', { class: 'label', text: 'YOUR PASSPHRASE IS THE KEY' }),
          h('div', { class: 'd', text: 'We never stored it. The recipient needs it exactly as you typed it — relay it your own way.' })),
    h('div', { class: 'handoff-actions' },
      h('button', { class: 'btn-ghost', onclick: () => { location.href = hf.link; } }, 'Simulate the recipient →'),
      h('button', { class: 'btn-ghost dimmer', onclick: () => nav('#/'), text: 'Done' })));
}

/* ---------- recipient flow ---------- */

async function enterGate(id) {
  const frag = location.hash.slice(1);
  S.gate = { id, meta: null, error: '', missingKey: !frag };
  S.view = 'gate';
  render();
  const { status, data } = await api('GET', '/api/drops/' + id);
  if (status !== 200) {
    S.view = 'gone';
    S.gone = data.reason || 'missing';
  } else {
    S.gate.meta = data;
  }
  render();
}

async function unlock() {
  const g = S.gate;
  if (!g || !g.meta) return;
  if (g.missingKey) return toast('This link is missing its key fragment — ask the sender to re-copy the full link.');
  const input = (g.input || '').trim();
  if (!input) return toast(g.meta.codeMode === 'auto' ? 'Enter the 6-digit code.' : 'Enter the passphrase.');
  const btn = document.getElementById('unlockBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Unlocking…'; }
  try {
    const salt = unb64(g.meta.salt);
    const bits = await kdfBits(input, salt);
    const verifier = hex(bits.slice(32));
    const { status, data } = await api('POST', '/api/drops/' + g.id + '/unlock', { verifier });
    if (status === 200) {
      let payload;
      try {
        const linkKey = unb64url(location.hash.slice(1));
        const key = await dropKey(bits.slice(0, 32), linkKey, salt);
        const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(data.iv) }, key, unb64(data.ct));
        payload = JSON.parse(new TextDecoder().decode(buf));
      } catch {
        S.view = 'gone';
        S.gone = 'keylost';
        return render();
      }
      S.reveal = {
        id: g.id,
        notes: payload.notes || [],
        burnToken: data.burnToken,
        afterOpenMin: data.afterOpenMin,
        burnsAt: data.afterOpenMin > 0 ? Date.now() + data.afterOpenMin * 60000 : null,
        raw: new Set(),
      };
      S.view = 'reveal';
      render();
    } else if (status === 403 && data.error === 'wrong_code') {
      g.error = 'Wrong code. ' + data.triesLeft + (data.triesLeft === 1 ? ' try' : ' tries') + ' left before it burns.';
      g.input = '';
      g.meta.triesLeft = data.triesLeft;
      render();
    } else if (status === 410) {
      S.view = 'gone';
      S.gone = data.reason || 'missing';
      render();
    } else if (status === 429) {
      toast('Too many attempts too fast. Give it a minute.');
      if (btn) { btn.disabled = false; btn.textContent = 'Unlock'; }
    } else {
      toast('Something went wrong — try again.');
      if (btn) { btn.disabled = false; btn.textContent = 'Unlock'; }
    }
  } catch {
    toast('Something went wrong — try again.');
    if (btn) { btn.disabled = false; btn.textContent = 'Unlock'; }
  }
}

function screenGate() {
  const g = S.gate;
  const meta = g.meta;
  const isCode = !meta || meta.codeMode === 'auto';
  const input = h('input', Object.assign(
    {
      class: 'gate-input ' + (isCode ? 'code' : 'pass'),
      oninput: (e) => {
        let v = e.target.value;
        if (isCode) v = v.replace(/\D/g, '').slice(0, 6);
        e.target.value = v;
        g.input = v;
      },
      onkeydown: (e) => { if (e.key === 'Enter') unlock(); },
    },
    isCode
      ? { inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: '••••••' }
      : { type: 'password', placeholder: 'the passphrase you were given' }
  ));
  input.value = g.input || '';
  requestAnimationFrame(() => input.focus());
  const attempts = meta ? meta.attempts : 3;
  const left = meta ? meta.triesLeft : 3;
  return h('div', { class: 'gate screen' },
    h('div', { class: 'kicker', text: 'SEALED DROP · ' + g.id }),
    h('h2', { class: 'serif-h', text: 'Someone left you a secret.' }),
    h('div', { class: 'gate-meta', text: meta
      ? meta.noteCount + (meta.noteCount === 1 ? ' note' : ' notes') + ' · sealed ' + fmtDate(meta.createdAt) + ' · ' + policyShort(meta)
      : 'checking the drop…' }),
    input,
    g.missingKey ? h('div', { class: 'gate-err', text: 'This link is incomplete — its key fragment is missing. Ask the sender to copy the whole link.' }) : null,
    g.error ? h('div', { class: 'gate-err', text: g.error }) : null,
    h('div', { class: 'gate-tries', text: left === attempts
      ? 'You have ' + attempts + ' tries. On the last mistake, it burns.'
      : left + (left === 1 ? ' try' : ' tries') + ' left before it burns.' }),
    h('div', {}, h('button', { class: 'btn-bone', id: 'unlockBtn', onclick: unlock }, 'Unlock')));
}

async function burn(reason) {
  const r = S.reveal;
  if (!r) return;
  S.reveal = null;
  S.view = 'gone';
  S.gone = reason;
  render();
  api('POST', '/api/drops/' + r.id + '/burn', { burnToken: r.burnToken, reason }).catch(() => {});
}

function screenReveal() {
  const r = S.reveal;
  if (!r) { S.view = 'landing'; return screenLanding(); }
  const notesEls = r.notes.map((n, i) => {
    const isRaw = r.raw.has(i);
    return h('div', { class: 'rv-note' },
      h('div', { class: 'rv-note-head' },
        h('span', { class: 'note-num', text: String(i + 1).padStart(2, '0') }),
        h('span', { class: 'rv-note-title', text: n.title || 'untitled' }),
        h('button', {
          class: 'pill-btn',
          onclick: () => { isRaw ? r.raw.delete(i) : r.raw.add(i); render(); },
          text: isRaw ? 'RENDERED' : 'RAW',
        }),
        h('button', { class: 'pill-btn', onclick: () => copyText(n.body, 'Note copied.'), text: 'COPY' })),
      h('div', { class: 'rv-body' },
        isRaw ? h('pre', { class: 'rv-raw', text: n.body }) : mdToHtml(n.body)));
  });
  const remain = r.burnsAt ? r.burnsAt - Date.now() : 0;
  return h('div', { class: 'wrap-760 screen' },
    h('div', { class: 'rv-head' },
      h('div', { class: 'rv-kicker', text: 'DECRYPTED · FOR YOUR EYES ONLY' }),
      h('div', { class: 'spacer' }),
      r.burnsAt ? h('span', {
        class: 'timer-chip' + (remain > 60000 ? '' : ' hot'),
        id: 'burnTimer',
        text: 'BURNS IN ' + fmtClock(remain),
      }) : null),
    h('p', { class: 'rv-policy', text: r.burnsAt
      ? 'The reading window is open — when the timer ends, everything below burns. Done early? Burn it yourself.'
      : 'This link died the moment you opened it. Copy what you need, then burn it.' }),
    notesEls,
    h('div', { class: 'rv-burn' },
      h('button', { class: 'btn-danger', onclick: () => burn('manual') }, "I've read it — burn everything")));
}

setInterval(() => {
  const r = S.reveal;
  if (S.view !== 'reveal' || !r || !r.burnsAt) return;
  const remain = r.burnsAt - Date.now();
  if (remain <= 0) return void burn('timer');
  const chipEl = document.getElementById('burnTimer');
  if (chipEl) {
    chipEl.textContent = 'BURNS IN ' + fmtClock(remain);
    chipEl.className = 'timer-chip' + (remain > 60000 ? '' : ' hot');
  }
}, 1000);

const GONE = {
  tries: ['SELF-DESTRUCT COMPLETE', 'Too many wrong codes. Ash.', 'The notes shredded themselves after 3 failed attempts. Nothing can bring them back. If this wasn’t you — someone else has your link.'],
  timer: ['THE WINDOW CLOSED', 'Time’s up. The pages are ash.', 'The reading window ran out and the drop burned itself, exactly as instructed.'],
  manual: ['BURNED BY HAND', 'Read once, burned once.', 'This drop was destroyed after reading. Exactly as designed.'],
  used: ['LINK ALREADY USED', 'This drop was already opened.', 'Links die after one use. If that wasn’t you, tell the sender — fast.'],
  unopened: ['EXPIRED UNREAD', 'It shredded itself, unopened.', 'The shelf life ran out before anyone opened this drop.'],
  keylost: ['KEY FRAGMENT MISMATCH', 'The link couldn’t decrypt it.', 'The code was right, but the link’s key fragment wasn’t — and the drop burned on opening, as drops do. Ask the sender to cut a fresh one and copy the whole link.'],
  missing: ['NO SUCH DROP', 'Nothing buried here.', 'This link doesn’t match any drop. It may have been scrubbed from existence — or it never existed at all.'],
};

function screenGone() {
  const g = GONE[S.gone] || GONE.missing;
  return h('div', { class: 'gone' },
    h('div', { class: 'gone-kicker', text: g[0] }),
    h('h2', { class: 'serif-h', text: g[1] }),
    h('p', { text: g[2] }),
    h('button', { class: 'btn-ghost', onclick: () => nav('#/new'), text: 'Draft your own drop' }));
}

/* ---------- routing / render ---------- */

const SCREENS = {
  landing: screenLanding, compose: screenCompose, seal: screenSeal,
  sealing: screenSealing, handoff: screenHandoff, gate: screenGate,
  reveal: screenReveal, gone: screenGone,
};

function render() {
  cancelAnimationFrame(fpRaf);
  app.replaceChildren(SCREENS[S.view]());
  window.scrollTo(0, 0);
}

const gateMatch = location.pathname.match(/^\/d\/([a-z0-9]{8,20})$/);
const onGatePage = !!gateMatch;

function nav(hash) {
  if (onGatePage) {
    // Recipient page: the fragment is the key, not a route — leave for home.
    location.href = '/' + (hash === '#/' ? '' : hash);
    return;
  }
  if (location.hash === hash) route();
  else location.hash = hash;
}

function route() {
  if (onGatePage) return; // gate page never hash-routes
  const hash = location.hash;
  if (hash === '#/new') S.view = 'compose';
  else if (hash === '#/seal') S.view = draftHasContent() ? 'seal' : 'compose';
  else S.view = 'landing';
  render();
}

document.getElementById('brandHome').addEventListener('click', () => nav('#/'));
document.getElementById('hdrNew').addEventListener('click', () => nav('#/new'));
window.addEventListener('hashchange', () => route());

if (onGatePage) enterGate(gateMatch[1]);
else route();
