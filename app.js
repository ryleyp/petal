/* Petal — private period & patch tracker
 * All data is encrypted with the user's passcode (PBKDF2-HMAC-SHA-256 + AES-GCM) and stored
 * only in this browser. Nothing is ever sent anywhere. */
'use strict';

const APP_VERSION = 'v39'; // shown in Settings so updates are easy to confirm

/* ============================================================ Crypto ===== */
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = {
  enc: (buf) => {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
  },
  dec: (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0)),
};

const PBKDF2_ITER = 600000; // current OWASP recommendation for PBKDF2-HMAC-SHA-256
const MAX_UNLOCK_ATTEMPTS = 10;
const LOCKOUT_MS = 5 * 60 * 1000;
const LOCKOUT_KEY = 'petal.unlockLockout';

async function deriveKey(passcode, salt, iterations = PBKDF2_ITER) {
  const base = await crypto.subtle.importKey('raw', enc.encode(passcode), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptState(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64.enc(iv), ct: b64.enc(ct) };
}

async function decryptState(key, iv, ct) {
  const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(iv) }, key, b64.dec(ct));
  return JSON.parse(dec.decode(buf));
}

/* ============================================================ Storage ===== */
const VAULT = 'petal.vault';
const hasVault = () => !!localStorage.getItem(VAULT);
function readVault() { try { return JSON.parse(localStorage.getItem(VAULT)); } catch { return null; } }
function writeVault(v) { localStorage.setItem(VAULT, JSON.stringify(v)); mirrorToFile(); }

/* ---- Native (Capacitor) durable + iCloud-synced copy ----
 * In the native app, localStorage in WKWebView is durable (no Safari 7-day wipe).
 * We ALSO mirror the encrypted vault to a file in the app's Documents folder. With
 * the iCloud capability enabled in Xcode, that file is carried by iCloud — and because
 * it's encrypted with the user's passcode, iCloud/Apple can't read it. */
const Cap = (typeof window !== 'undefined') && window.Capacitor;
const isNative = !!(Cap && Cap.isNativePlatform && Cap.isNativePlatform());
const FS = () => Cap && Cap.Plugins && Cap.Plugins.Filesystem;
const VAULT_FILE = 'petal-vault.json';

async function mirrorToFile() {
  if (!isNative || !FS()) return;
  try {
    const data = localStorage.getItem(VAULT);
    if (data) await FS().writeFile({ path: VAULT_FILE, data, directory: 'DOCUMENTS', encoding: 'utf8' });
  } catch (e) { /* non-fatal: localStorage remains the source of truth */ }
}
// On a fresh device with no local vault, restore the encrypted file if iCloud delivered one.
async function restoreFromFileIfNeeded() {
  if (!isNative || !FS() || hasVault()) return;
  try {
    const res = await FS().readFile({ path: VAULT_FILE, directory: 'DOCUMENTS', encoding: 'utf8' });
    if (res && res.data) localStorage.setItem(VAULT, res.data);
  } catch (e) { /* no backup file yet */ }
}

let KEY = null;      // CryptoKey for the session
let SALT = null;     // Uint8Array
let ITER = PBKDF2_ITER;
let state = null;    // decrypted app state

function defaultState() {
  return {
    version: 2,
    settings: { cycleLen: 28, lutealLen: 14, onPatch: true, patchStart: null,
      reminderTime: '09:00', edgeCheckReminder: true, backupReminder: true,
      patchDayOfWeek: null, lastBackup: null,
      patchesLeft: null, patchExpiry: null, customSymptoms: [], doctorQuestions: [] },
    periods: [],                 // [{ start:'YYYY-MM-DD', end:'YYYY-MM-DD'|null }]
    logs: {},                    // { 'YYYY-MM-DD': { flow, bleedType, symptoms:[], tags:[], notes } }
    patchActions: [],            // [{ date:'YYYY-MM-DD', action:'apply'|'remove'|'detached', site }]
    appointments: [],            // [{ id, date:'YYYY-MM-DD', label, type:'appointment'|'refill' }]
    tests: [],                   // [{ id, date:'YYYY-MM-DD', result:'negative'|'faint'|'positive'|'invalid', note }]
  };
}

async function saveState() {
  if (!KEY) return;
  invalidatePeriods();
  const { iv, ct } = await encryptState(KEY, state);
  writeVault({ v: 2, salt: b64.enc(SALT), iter: ITER, iv, ct });
}

/* ============================================================ Dates ======= */
const DAY = 86400000;
const pad = (n) => String(n).padStart(2, '0');
const iso = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const parseISO = (s) => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };
const today = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d; };
const todayISO = () => iso(today());
const addDays = (d, n) => { const x = new Date(d); x.setDate(x.getDate() + n); return x; };
const daysBetween = (a, b) => Math.round((parseISO(b) - parseISO(a)) / DAY);
const fmtDate = (s, opts) => parseISO(s).toLocaleDateString(undefined, opts || { weekday: 'short', month: 'short', day: 'numeric' });

/* ============================================================ DOM utils === */
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden');
  t.style.opacity = '1';
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.classList.add('hidden'), 300); }, 1900);
}
// toast with a 6-second Undo button — mis-taps shouldn't need calendar surgery
function toastUndo(msg, undoFn) {
  const t = $('#toast');
  t.innerHTML = `${escapeHtml(msg)} <button class="toast-undo" type="button">Undo</button>`;
  t.classList.remove('hidden'); t.style.opacity = '1';
  t.querySelector('.toast-undo').addEventListener('click', () => {
    clearTimeout(toast._t);
    t.style.opacity = '0'; setTimeout(() => t.classList.add('hidden'), 300);
    undoFn();
  });
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.classList.add('hidden'), 300); }, 6000);
}

const SYMPTOMS = ['Cramps', 'Headache', 'Bloating', 'Tender breasts', 'Acne', 'Fatigue',
  'Mood swings', 'Anxiety', 'Irritability', 'Stress', 'Poor sleep', 'Nausea',
  'Back pain', 'Cravings', 'Low energy', 'High energy', 'Clots', 'Brown discharge'];

// Zafemy-approved patch areas, split left/right so rotation stats are useful.
// Per labeling: never on breasts, cut/irritated skin, or the exact previous location.
const SITES = [
  'Left upper outer arm', 'Right upper outer arm',
  'Left abdomen', 'Right abdomen',
  'Left buttock', 'Right buttock',
  'Left upper back', 'Right upper back',
];

// Private log tags (sex / EC / tests) — stored only in the encrypted day log
const INTIMACY = [
  ['sex-protected', 'Protected sex'],
  ['sex-unprotected', 'Unprotected sex'],
  ['ec', 'EC taken'],
  ['test-neg', 'Test: negative'],
  ['test-pos', 'Test: positive'],
];

/* Flow strength as a cute droplet whose size + colour grows with intensity. */
const FLOWS = [['', 'None'], ['spotting', 'Spotting'], ['light', 'Light'], ['medium', 'Medium'], ['heavy', 'Heavy']];
function dropletIcon(color, scale, outline) {
  const t = `translate(12 12) scale(${scale}) translate(-12 -12)`;
  const d = 'M12 4c2.7 3.3 4.6 5.7 4.6 8.1a4.6 4.6 0 0 1-9.2 0C7.4 9.7 9.3 7.3 12 4z';
  const shape = outline
    ? `<path d="${d}" fill="none" stroke="currentColor" stroke-width="2" transform="${t}"/>`
    : `<path d="${d}" fill="currentColor" transform="${t}"/>`;
  return `<svg class="seg-ic" viewBox="0 0 24 24" style="color:${color}" aria-hidden="true">${shape}</svg>`;
}
const FLOW_ICONS = {
  '': dropletIcon('var(--muted)', 0.8, true),
  spotting: dropletIcon('#ffb3c8', 0.5, false),
  light: dropletIcon('#ff85a6', 0.72, false),
  medium: dropletIcon('#ff5d7e', 0.9, false),
  heavy: dropletIcon('#e23b5a', 1.05, false),
};
function flowSegHTML(currentVal) {
  return FLOWS.map(([v, l]) =>
    `<button data-val="${v}" class="${(currentVal || '') === v ? 'on' : ''}">${FLOW_ICONS[v]}<span>${l}</span></button>`).join('');
}

/* Tiny inline icons so the whole UI shares one soft, rounded look (no emoji). */
const IC_PATHS = {
  check: '<circle cx="12" cy="12" r="9" fill="currentColor"/><path d="M7.8 12.4l2.6 2.6 5.6-5.7" fill="none" stroke="#1b1430" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>',
  warn: '<path d="M12 3.2c.8 0 1.5.4 1.9 1.1l7 12.3a2.2 2.2 0 0 1-1.9 3.3H5a2.2 2.2 0 0 1-1.9-3.3l7-12.3c.4-.7 1.1-1.1 1.9-1.1z" fill="currentColor"/><rect x="10.9" y="8.2" width="2.2" height="5.6" rx="1.1" fill="#1b1430"/><circle cx="12" cy="16.4" r="1.3" fill="#1b1430"/>',
  clock: '<circle cx="12" cy="12" r="9" fill="currentColor"/><path d="M12 7.4V12l3.2 2" fill="none" stroke="#1b1430" stroke-width="2.2" stroke-linecap="round"/>',
  bandage: '<g transform="rotate(-40 12 12)"><rect x="3" y="8.4" width="18" height="7.2" rx="3.6" fill="currentColor"/><g fill="#1b1430" opacity=".55"><circle cx="9.4" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="14.6" cy="12" r="1"/></g></g>',
  moon: '<path d="M15.6 3.2A9 9 0 1 0 21 14.6 7 7 0 0 1 15.6 3.2z" fill="currentColor"/>',
  drop: '<path d="M12 3.4c3 3.7 5.2 6.4 5.2 9.1a5.2 5.2 0 0 1-10.4 0c0-2.7 2.2-5.4 5.2-9.1z" fill="currentColor"/>',
  calendar: '<rect x="3.5" y="5" width="17" height="15.5" rx="4" fill="currentColor"/><rect x="7" y="2.6" width="2.4" height="4.6" rx="1.2" fill="currentColor"/><rect x="14.6" y="2.6" width="2.4" height="4.6" rx="1.2" fill="currentColor"/><circle cx="9" cy="13" r="1.4" fill="#1b1430"/><circle cx="12.5" cy="13" r="1.4" fill="#1b1430"/><circle cx="9" cy="16.4" r="1.4" fill="#1b1430"/>',
  backup: '<circle cx="12" cy="12" r="9" fill="currentColor"/><path d="M12 7.2v6M9.4 11l2.6 2.6L14.6 11M8.4 16.2h7.2" fill="none" stroke="#1b1430" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  sparkle: '<path d="M12 3l1.8 5.4L19 10l-5.2 1.7L12 17l-1.8-5.3L5 10l5.2-1.6z" fill="currentColor"/>',
};
function ic(name, color, cls = 'a-ic') {
  return `<svg class="${cls} ic-${name}" viewBox="0 0 24 24" style="color:${color}" aria-hidden="true">${IC_PATHS[name]}</svg>`;
}

/* ============================================================ Lock flow === */
const lockEl = $('#lock'), appEl = $('#app');

function showLock(setup) {
  lockEl.classList.remove('hidden');
  appEl.classList.add('hidden');
  $('#pass1').value = ''; $('#pass2').value = '';
  $('#lockError').textContent = '';
  if (setup) {
    $('#lockSub').textContent = 'Create a passcode to protect your data';
    $('#pass2').classList.remove('hidden');
    $('#lockBtn').textContent = 'Create';
    $('#lockNote').classList.remove('hidden');
    $('#resetAll').classList.add('hidden');
  } else {
    $('#lockSub').textContent = 'Enter your passcode to unlock';
    $('#pass2').classList.add('hidden');
    $('#lockBtn').textContent = 'Unlock';
    $('#lockNote').classList.add('hidden');
    $('#resetAll').classList.remove('hidden');
  }
  setTimeout(() => $('#pass1').focus(), 100);
}

function lockoutState() {
  try {
    const s = JSON.parse(localStorage.getItem(LOCKOUT_KEY) || '{}');
    if (s.until && Date.now() < s.until) return s;
  } catch {}
  localStorage.removeItem(LOCKOUT_KEY);
  return { count: 0, until: 0 };
}
function noteUnlockFailure() {
  const s = lockoutState();
  const count = (s.count || 0) + 1;
  const until = count >= MAX_UNLOCK_ATTEMPTS ? Date.now() + LOCKOUT_MS : 0;
  localStorage.setItem(LOCKOUT_KEY, JSON.stringify({ count, until }));
  return { count, until };
}
function clearUnlockFailures() {
  localStorage.removeItem(LOCKOUT_KEY);
}

$('#lockForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const p1 = $('#pass1').value;
  const err = $('#lockError');
  err.textContent = '';
  const lockout = lockoutState();
  if (lockout.until) {
    const mins = Math.ceil((lockout.until - Date.now()) / 60000);
    err.textContent = `Too many tries. Wait ${mins} minute${mins === 1 ? '' : 's'} and try again.`;
    return;
  }

  if (!hasVault()) {
    // setup
    const p2 = $('#pass2').value;
    if (p1 !== p2) { err.textContent = 'Passcodes do not match.'; return; }
    SALT = crypto.getRandomValues(new Uint8Array(16));
    ITER = PBKDF2_ITER;
    KEY = await deriveKey(p1, SALT, ITER);
    state = defaultState();
    await saveState();
    openApp();
    return;
  }

  // unlock
  const vault = readVault();
  try {
    SALT = b64.dec(vault.salt);
    ITER = vault.iter || 250000;
    const key = await deriveKey(p1, SALT, ITER);
    state = await decryptState(key, vault.iv, vault.ct);
    KEY = key;
    const migrated = migrate();
    clearUnlockFailures();
    if (ITER < PBKDF2_ITER) {
      ITER = PBKDF2_ITER;
      KEY = await deriveKey(p1, SALT, ITER);
      await saveState();
    } else if (migrated) {
      await saveState();
    }
    openApp();
  } catch {
    const failed = noteUnlockFailure();
    err.textContent = 'Incorrect passcode.';
    if (failed.until) err.textContent += ' Too many tries; Petal is paused for 5 minutes.';
    $('#pass1').value = '';
  }
});

$('#resetAll').addEventListener('click', () => {
  if (confirm('Erase ALL data and start over? This cannot be undone.')) {
    localStorage.removeItem(VAULT); location.reload();
  }
});

function migrate() {
  const d = defaultState();
  let changed = false;
  state.settings = Object.assign({}, d.settings, state.settings || {});
  state.periods = state.periods || [];
  state.logs = state.logs || {};
  for (const log of Object.values(state.logs)) {
    if (log && log.flow && !log.bleedType) { log.bleedType = 'withdrawal'; changed = true; }
  }
  state.patchActions = state.patchActions || [];
  state.appointments = state.appointments || [];
  state.tests = state.tests || [];
  return changed;
}

function openApp() {
  invalidatePeriods();
  lockEl.classList.add('hidden');
  appEl.classList.remove('hidden');
  hydrateSettings();
  buildSymptomChips();
  $('#flowSeg').innerHTML = flowSegHTML(''); // build the flow control with droplet icons
  $('#versionLabel').textContent = 'Petal ' + APP_VERSION;
  renderAll();
  requestNotifyPermission();
  scheduleReminderTimer();
}

/* lock on tab hide for privacy */
let hideTimer = null;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    hideTimer = setTimeout(() => location.reload(), 5 * 60 * 1000); // relock after 5 min
  } else if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
});
$('#lockNow').addEventListener('click', () => location.reload());

/* ============================================================ Periods ===== */
/* Periods are DERIVED from the bleeding you log day-by-day. One pipeline:
 *   - a bleeding day = any day with flow logged (a "Period started" marker also
 *     counts as a bleeding day, and legacy start–end ranges count day-by-day);
 *   - consecutive bleeding days form one episode, across month boundaries
 *     (May 25 → Jun 8 is ONE period) — any bleed-free calendar day ends it;
 *   - an episode is a period if it has real (non-spotting) flow, OR you
 *     explicitly marked "Period started" in it (so a spotting-day start counts);
 *     spotting-only or all-breakthrough episodes without a marker are
 *     breakthrough bleeding, not periods.
 * There is no "period ended" anywhere — the end is always implied by the gap. */
let _periodsCache = null;
function invalidatePeriods() { _periodsCache = null; }

function bleedDayMap() {
  const map = new Map(); // date -> { flow, bt, marker }
  for (const [d, l] of Object.entries(state.logs)) {
    if (l.flow) map.set(d, { flow: l.flow, bt: l.bleedType || '', marker: false });
  }
  // manual entries: start markers; legacy {start,end} ranges count as bleeding days
  for (const m of (state.periods || [])) {
    if (!m.start) continue;
    const end = m.end && m.end >= m.start ? m.end : m.start;
    let d = parseISO(m.start), guard = 0;
    const e = parseISO(end);
    while (d <= e && guard++ < 60) {
      const ds = iso(d);
      const cur = map.get(ds) || { flow: '', bt: '', marker: false };
      if (ds === m.start) cur.marker = true;
      map.set(ds, cur);
      d = addDays(d, 1);
    }
  }
  return map;
}

function bleedEpisodes() {
  const days = [...bleedDayMap().entries()]
    .map(([d, v]) => ({ d, ...v }))
    .sort((a, b) => a.d.localeCompare(b.d));
  const eps = [];
  for (const day of days) {
    const cur = eps[eps.length - 1];
    if (cur && daysBetween(cur.end, day.d) === 1) {
      cur.end = day.d; cur.days.push(day);
    } else {
      eps.push({ start: day.d, end: day.d, days: [day] });
    }
  }
  return eps;
}

// Does a bleeding episode count as a period / withdrawal bleed (vs breakthrough)?
// Assumption: ANY logged bleed is a withdrawal bleed unless you explicitly tag it
// breakthrough. So an episode counts unless every one of its bleeding days is
// tagged breakthrough (a "Period started" marker always counts).
function isPeriodEpisode(e) {
  if (e.days.some((x) => x.marker)) return true;
  return e.days.some((x) => x.flow && x.bt !== 'breakthrough');
}

function derivedPeriods() {
  return bleedEpisodes()
    .filter(isPeriodEpisode)
    .map((e) => ({ start: e.start, end: e.end, ongoing: e.end === todayISO(), derived: true }));
}

function sortedPeriods() {
  if (!_periodsCache) _periodsCache = derivedPeriods();
  return _periodsCache;
}

function hasStartMarker(dateStr) {
  return (state.periods || []).some((p) => p.start === dateStr);
}
function startPeriod(dateStr) {
  dateStr = dateStr || todayISO();
  if (hasStartMarker(dateStr)) { toast('Already marked'); return; }
  state.periods.push({ start: dateStr });
  saveState(); renderAll();
  toastUndo('Period start marked', () => unmarkStart(dateStr));
}
function unmarkStart(dateStr) {
  // only removes simple markers; legacy start–end ranges are left alone
  state.periods = (state.periods || []).filter((p) => !(p.start === dateStr && (!p.end || p.end === p.start)));
  saveState(); renderAll(); toast('Start mark removed');
}

/* cycle stats from logged period starts */
function cycleStats() {
  const ps = sortedPeriods().filter((p) => p.start);
  const lengths = [];
  for (let i = 1; i < ps.length; i++) {
    const len = daysBetween(ps[i - 1].start, ps[i].start);
    if (len >= 18 && len <= 60) lengths.push(len);
  }
  // exclude the still-ongoing episode; allow long bleeds (e.g. a 15-day May 25 → Jun 8 period)
  const periodLens = ps.filter((p) => p.end && !p.ongoing).map((p) => daysBetween(p.start, p.end) + 1).filter((n) => n >= 1 && n <= 20);
  const avg = (arr, fb) => (arr.length ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : fb);
  return {
    count: ps.length,
    avgCycle: avg(lengths, state.settings.cycleLen),
    avgPeriod: avg(periodLens, null),
    lengths,
    lastStart: ps.length ? ps[ps.length - 1].start : null,
  };
}

function bleedTypeStats() {
  const out = { withdrawalDays: 0, breakthroughDays: 0, withdrawalEpisodes: 0, breakthroughEpisodes: 0 };
  for (const [, log] of Object.entries(state.logs)) {
    if (!log || !log.flow) continue;
    if (log.bleedType === 'breakthrough') out.breakthroughDays++;
    else out.withdrawalDays++;
  }
  for (const ep of bleedEpisodes()) {
    if (isPeriodEpisode(ep)) out.withdrawalEpisodes++;
    else out.breakthroughEpisodes++;
  }
  return out;
}

function hasWithdrawalBleed(from, to) {
  return Object.keys(state.logs).some((d) => {
    const log = state.logs[d];
    return d >= from && d <= to && log && log.flow && log.bleedType !== 'breakthrough';
  });
}

// Honest caption for how much data backs a prediction.
function predictionConfidence() {
  const n = cycleStats().lengths.length;
  if (!n) return 'based on your starting cycle length — log periods to personalize';
  return `based on ${n} logged cycle${n === 1 ? '' : 's'}`;
}

/* predicted next period start (natural cycle) */
function predictNextPeriod() {
  const s = cycleStats();
  if (!s.lastStart) return null;
  let next = addDays(parseISO(s.lastStart), s.avgCycle);
  // roll forward if we're well past it (no recent logging), but keep up to 5 days of "late" visible
  const cutoff = addDays(today(), -5);
  while (next < cutoff) next = addDays(next, s.avgCycle);
  return iso(next);
}

/* ============================================================ Patch ======= */
const PATCH_CYCLE = 28;

/* The effective start of the CURRENT 28-day cycle, derived from what was actually
 * logged — not just the manual "first patch" date. Per combined-patch guidance,
 * the cycle re-anchors when:
 *   - a new patch goes on after a remove/detach (day 1 of a new cycle), or
 *   - a weekly change is ≥48h late (≥9-day gap): that patch starts a NEW cycle.
 * On-time or <48h-late changes keep the existing change day. */
// All the dates at which a fresh 28-day cycle began (chronological): the manual
// first-patch date, plus any apply that restarted the cycle (new patch after a
// remove/detach, or a ≥48h-late weekly change).
/* Nudge a derived anchor onto the weekday you've told Petal your changes really
 * land on. Without this, one application logged a day late moves the anchor for
 * good — every predicted date shifts with it, and nothing in the app undoes it. */
function snapToChangeDay(dateStr) {
  const target = state.settings.patchDayOfWeek;
  if (target == null) return dateStr;
  const d = parseISO(dateStr);
  const delta = ((d.getDay() - target + 3 + 7) % 7) - 3;         // nearest occurrence, -3..+3
  let snapped = addDays(d, -delta);
  if (iso(snapped) > todayISO()) snapped = addDays(snapped, -7); // never anchor in the future
  return iso(snapped);
}
// `raw` gives what the logs alone imply, before any change-day correction —
// used to show you what Petal had inferred and by how much it was off.
function cycleAnchors(raw) {
  const anchors = [];
  if (state.settings.patchStart) anchors.push(state.settings.patchStart);
  let prev = null;
  for (const a of sortedActions()) {
    if (a.action === 'apply') {
      if (!anchors.length) anchors.push(a.date);
      else if (prev && prev.action === 'remove') anchors.push(a.date);
      // a fallen-off patch re-applied within 24h keeps the original change day;
      // off ≥24h means a fresh 4-week cycle starts here
      else if (prev && prev.action === 'detached' && daysBetween(prev.date, a.date) >= 2) anchors.push(a.date);
      else if (prev && prev.action === 'apply' && daysBetween(prev.date, a.date) >= 9) anchors.push(a.date);
    }
    prev = a;
  }
  const list = raw ? anchors : anchors.map(snapToChangeDay);
  return [...new Set(list)].sort((x, y) => x.localeCompare(y));
}
// The current cycle's start (for today / upcoming schedule).
function cycleAnchor() { const a = cycleAnchors(); return a.length ? a[a.length - 1] : null; }
// The anchor in effect on a given date (so history stays correct across re-anchors).
function anchorFor(dateStr) {
  let best = null;
  for (const an of cycleAnchors()) { if (an <= dateStr) best = an; else break; }
  return best;
}

// returns 0-based day within the 28-day patch cycle, or null
function patchCycleDay(dateStr) {
  const p = anchorFor(dateStr);
  if (!p) return null;
  const diff = daysBetween(p, dateStr);
  if (diff < 0) return null;
  return ((diff % PATCH_CYCLE) + PATCH_CYCLE) % PATCH_CYCLE;
}
const isPatchFree = (day) => day !== null && day >= 21 && day <= 27;
const isPatchOn = (day) => day !== null && day >= 0 && day <= 20;

const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
// The weekday your patch changes currently land on, from your real cycle anchor.
function patchChangeWeekday() {
  const a = cycleAnchor();
  return a ? parseISO(a).getDay() : null;
}

// What the logs alone imply your change day is, before any correction.
function derivedChangeWeekday() {
  const raw = cycleAnchors(true);
  return raw.length ? parseISO(raw[raw.length - 1]).getDay() : null;
}

/* What setting a change day does to the schedule: Petal lines its cycle up with
 * the weekday you name, moving at most 3 days in whichever direction is nearer. */
function changeDayCorrection() {
  const target = state.settings.patchDayOfWeek;
  if (target == null) return null;
  const raw = cycleAnchors(true);
  if (!raw.length) return null;
  const before = raw[raw.length - 1];
  const after = cycleAnchor();
  const moved = daysBetween(before, after); // negative = earlier, positive = later
  return { target, derived: parseISO(before).getDay(), before, after, moved };
}

// upcoming patch events for `weeks` weeks (anchored to logged reality)
function patchEvents(weeks = 12) {
  const p = cycleAnchor();
  if (!p) return [];
  const start = parseISO(p);
  const horizon = addDays(today(), weeks * 7);
  const events = [];
  let cycle = 0;
  while (true) {
    const base = addDays(start, cycle * PATCH_CYCLE);
    const items = [
      { off: 0, type: 'apply', label: 'Apply new patch (week 1)' },
      { off: 7, type: 'change', label: 'Change patch (week 2)' },
      { off: 14, type: 'change', label: 'Change patch (week 3)' },
      { off: 21, type: 'remove', label: 'Remove patch — patch-free week begins' },
    ];
    for (const it of items) {
      const d = addDays(base, it.off);
      if (d > horizon) { return events; }
      if (d >= addDays(today(), -1)) events.push({ date: iso(d), type: it.type, label: it.label });
    }
    cycle++;
    if (cycle > weeks) return events; // safety
  }
}

/* When does the current patch supply run out? Every upcoming application
 * (new-cycle apply or weekly change) consumes one patch. */
function refillStatus() {
  const left = state.settings.patchesLeft;
  if (left == null || !state.settings.onPatch || !cycleAnchor()) return null;
  const uses = patchEvents(26).filter((e) => e.type === 'apply' || e.type === 'change');
  if (!uses.length) return null;
  if (left === 0) return { level: 'risk', left, outDate: uses[0].date, daysTo: daysBetween(todayISO(), uses[0].date) };
  if (left >= uses.length) return { level: 'ok', left, outDate: null, daysTo: null };
  const outDate = uses[left].date; // the first application you can't cover
  const daysTo = daysBetween(todayISO(), outDate);
  return { level: daysTo <= 7 ? 'risk' : (daysTo <= 21 ? 'caution' : 'ok'), left, outDate, daysTo };
}

// which patch number a given apply-date corresponds to within the ideal cycle
// cycle day 0-6 -> patch 1, 7-13 -> patch 2, 14-20 -> patch 3, 21-27 -> a late new-cycle start
function patchNumberFor(dateStr) {
  const cd = patchCycleDay(dateStr);
  if (cd === null) return null;
  if (cd >= 21) return 1;        // applied during what should be the patch-free week = starting a new cycle late
  return Math.floor(cd / 7) + 1; // 1,2,3
}

function sortedActions() {
  return [...(state.patchActions || [])].sort((a, b) => a.date.localeCompare(b.date));
}
function recordPatchAction(action, dateStr) {
  dateStr = dateStr || todayISO();
  state.patchActions = state.patchActions || [];
  // de-dupe same action same day
  if (!state.patchActions.some((a) => a.date === dateStr && a.action === action)) {
    state.patchActions.push({ date: dateStr, action });
  }
}

function currentPatchWear() {
  const acts = sortedActions();
  const lastApply = [...acts].reverse().find((a) => a.action === 'apply');
  const lastOff = [...acts].reverse().find((a) => a.action === 'remove' || a.action === 'detached');
  const patchOn = !!(lastApply && (!lastOff || lastApply.date >= lastOff.date));
  if (patchOn) {
    const daysOn = daysBetween(lastApply.date, todayISO());
    return {
      patchOn,
      applyDate: lastApply.date,
      site: lastApply.site || null,
      daysOn,
      dueDate: iso(addDays(parseISO(lastApply.date), 7)),
    };
  }
  if (lastOff) {
    return {
      patchOn: false,
      offDate: lastOff.date,
      offAction: lastOff.action,
      daysOff: daysBetween(lastOff.date, todayISO()),
      dueDate: iso(addDays(parseISO(lastOff.date), 7)),
    };
  }
  return { patchOn: false };
}

function siteStats() {
  const applies = sortedActions().filter((a) => a.action === 'apply');
  const sited = applies.filter((a) => a.site);
  const counts = Object.fromEntries(SITES.map((s) => [s, 0]));
  for (const a of sited) counts[a.site] = (counts[a.site] || 0) + 1;
  // only genuinely consecutive applications can be a same-site repeat — an
  // application with no placement in between means we simply don't know
  let sameRepeats = 0, prev = null, recentRepeat = null;
  for (const a of applies) {
    if (prev && prev.site && a.site && prev.site === a.site) { sameRepeats++; recentRepeat = a.site; }
    prev = a;
  }
  const lastSite = prev ? (prev.site || null) : null;
  const next = SITES
    .filter((s) => s !== lastSite)
    .sort((a, b) => (counts[a] - counts[b]) || a.localeCompare(b));
  return {
    applies: applies.length,
    sited: sited.length,
    counts,
    sameRepeats,
    recentRepeat,
    lastSite,
    nextSites: next.slice(0, 3),
    missing: applies.length - sited.length,
  };
}

/* Timing stats read off the coverage timeline. `sinceISO` optionally limits the
 * counts to recent history so an old one-off doesn't flag forever. */
function patchTimingStats(sinceISO) {
  const spans = patchSpans().filter((s) => !sinceISO || s.from >= sinceISO);
  // wear time only from patches we actually saw come off — never from an inferred end
  const wear = spans.filter((s) => !s.inferred).map((s) => daysBetween(s.from, s.toExclusive));
  // a weekly change is two patches back to back with no hormone-free time between
  const weeklyGaps = [];
  for (let i = 0; i + 1 < spans.length; i++) {
    if (spans[i + 1].from === spans[i].toExclusive) weeklyGaps.push(daysBetween(spans[i].from, spans[i + 1].from));
  }
  // completed patch-free intervals: only deliberate removals count — a fall-off is
  // an incident, and a patch left on past its grace is a late change, not an interval
  const offGaps = hormoneFreeGaps()
    .filter((g) => g.resumed && g.cause === 'remove' && (!sinceISO || g.from >= sinceISO))
    .map((g) => g.days);
  const avg = (arr) => arr.length ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length * 10) / 10 : null;
  const hist = patchHistory().filter((e) => !sinceISO || e.date >= sinceISO);
  return {
    avgWear: avg(wear),
    wearCount: wear.length,
    longWear: wear.filter((n) => n > 7).length,
    avgPatchFree: avg(offGaps),
    maxPatchFree: offGaps.length ? Math.max(...offGaps) : null,
    lateChanges: hist.filter((e) => e.kind === 'late').length,
    riskEvents: hist.filter((e) => e.status === 'risk').length,
    weeklyOffDay: weeklyGaps.filter((n) => n !== 7).length,
  };
}

function patchAssistant() {
  if (!state.settings.onPatch || !cycleAnchor()) return null;
  const a = assessPatch();
  const wear = currentPatchWear();
  const rotation = siteStats();
  const evs = patchEvents(4);
  const next = evs.find((e) => daysBetween(todayISO(), e.date) >= 0);
  const lines = [];
  if (wear.patchOn) {
    const site = wear.site ? ` on ${wear.site.toLowerCase()}` : '';
    lines.push(`${ic('bandage', 'var(--patch)', 'i-ic')} Current sticker: <b>${wear.daysOn} day${wear.daysOn === 1 ? '' : 's'} worn</b>${site}.`);
    if (!wear.site) lines.push(`${ic('sparkle', 'var(--muted)', 'i-ic')} Add its placement from the Calendar so rotation stats stay complete.`);
  } else if (wear.offDate) {
    lines.push(`${ic('moon', 'var(--patchfree)', 'i-ic')} Patch-free: <b>${wear.daysOff} day${wear.daysOff === 1 ? '' : 's'}</b> since ${fmtDate(wear.offDate)}.`);
  }
  if (next) {
    const d = daysBetween(todayISO(), next.date);
    lines.push(`${ic('calendar', 'var(--patchfree)', 'i-ic')} Next: <b>${next.label}</b> ${d === 0 ? 'today' : d === 1 ? 'tomorrow' : `in ${d} days`}.`);
  }
  if (rotation.nextSites.length) {
    lines.push(`${ic('sparkle', 'var(--ok)', 'i-ic')} Rotation pick: <b>${rotation.nextSites[0].toLowerCase()}</b>${rotation.nextSites[1] ? ` or ${rotation.nextSites[1].toLowerCase()}` : ''}.`);
  }
  return {
    level: a ? a.level : 'ok',
    title: a ? a.title : 'Patch assistant',
    message: a ? a.message : 'Your schedule is ready.',
    lines,
  };
}

function patternFlags() {
  const flags = [];
  const a = assessPatch();
  if (a && a.level !== 'ok') flags.push({ level: a.level, icon: a.level === 'risk' ? 'warn' : 'clock', color: a.level === 'risk' ? 'var(--accent)' : 'var(--patch)', text: `<b>${a.title}.</b> ${a.message}` });
  const ss = siteStats();
  if (ss.sameRepeats) flags.push({ level: 'caution', icon: 'warn', color: 'var(--patch)', text: `<b>${ss.sameRepeats}</b> consecutive same-site repeat${ss.sameRepeats === 1 ? '' : 's'} logged${ss.recentRepeat ? `, most recently ${ss.recentRepeat.toLowerCase()}` : ''}.` });
  if (ss.missing && ss.applies >= 2) flags.push({ level: 'info', icon: 'sparkle', color: 'var(--muted)', text: `<b>${ss.missing}</b> application${ss.missing === 1 ? '' : 's'} missing placement, so rotation and fall-off stats are incomplete.` });
  // flags describe your current habits, so they age out — a one-off from a year
  // ago shouldn't sit on the screen as a permanent red mark
  const FLAG_WINDOW = 180;
  const since = iso(addDays(today(), -FLAG_WINDOW));
  const recently = 'in the last 6 months';
  const timing = patchTimingStats(since);
  if (timing.maxPatchFree && timing.maxPatchFree > 7) flags.push({ level: 'risk', icon: 'warn', color: 'var(--accent)', text: `Longest patch-free interval ${recently}: <b>${timing.maxPatchFree} days</b>, over the 7-day limit.` });
  if (timing.weeklyOffDay >= 2) flags.push({ level: 'caution', icon: 'clock', color: 'var(--patch)', text: `<b>${timing.weeklyOffDay}</b> weekly changes ${recently} landed off the 7-day rhythm. Your change day may need a reset.` });
  const det = sortedActions().filter((x) => x.action === 'detached' && x.date >= since);
  if (det.length >= 2) flags.push({ level: 'caution', icon: 'warn', color: 'var(--patch)', text: `<b>${det.length}</b> fall-offs ${recently}. Placement, lotion, sweat, friction, and waistbands are worth watching.` });
  const recentBreakthrough = Object.entries(state.logs).filter(([d, l]) =>
    d >= iso(addDays(today(), -60)) && l.flow && l.bleedType === 'breakthrough').length;
  if (recentBreakthrough >= 4) flags.push({ level: 'info', icon: 'drop', color: 'var(--period)', text: `<b>${recentBreakthrough}</b> breakthrough bleeding days logged in the last 60 days.` });
  const lastBackup = state.settings.lastBackup;
  if (state.settings.backupReminder !== false && (!lastBackup || daysBetween(lastBackup, todayISO()) >= 30)) {
    flags.push({ level: 'info', icon: 'backup', color: 'var(--fertile)', text: `Encrypted backup is ${lastBackup ? `${daysBetween(lastBackup, todayISO())} days old` : 'not exported yet'}.` });
  }
  return flags;
}

/* ---- Honest "what changes when I'm off-schedule" engine ----
 * The contraceptive patch (combined estrogen+progestin) prevents pregnancy mainly by
 * SUPPRESSING OVULATION. The one thing that restores the risk of ovulation is a
 * hormone-free stretch longer than 7 days. So:
 *   - leaving a patch ON a bit long, or removing the 3rd patch late = SAFE direction
 *     (you just stay on hormones longer; withdrawal week is shorter/delayed).
 *   - a LATE weekly change (gap building up) or a LONG patch-free week = the risky direction.
 * These rules follow the common combined-patch guidance (e.g. Xulane/Evra). Brands differ
 * slightly (Twirla), so the app always tells you to confirm with your leaflet/pharmacist. */
const GUIDE_DISCLAIMER =
  'This follows standard combined-patch guidance. Brands differ — confirm with your patch leaflet or a pharmacist. Emergency contraception is most effective the sooner it is taken (within 3–5 days).';

// Hypothetical/explicit guidance for a single off-schedule event.
// kind: 'change-late' | 'newcycle-late' | 'left-on-late' | 'detached'
// hoursLate: how late vs. when it should have happened (for change/newcycle/detached)
function lateGuidance(kind, hoursLate) {
  const days = hoursLate != null ? Math.floor(hoursLate / 24) : 0;
  if (kind === 'left-on-late') {
    return {
      level: 'ok',
      title: 'Still protected',
      message: 'Leaving a patch on past its change day keeps hormones in your system, so you stay protected. '
        + 'Remove it now and start your next cycle on your normal change day — your patch-free week will just be a bit shorter. No backup needed.',
    };
  }
  if (kind === 'detached') {
    if (hoursLate != null && hoursLate < 24) {
      return { level: 'ok', title: 'Still protected',
        message: 'Off for less than 24 hours: reapply the same patch if it still sticks, or apply a new one. Keep your usual change day. No backup needed.' };
    }
    return { level: 'risk', title: 'Protection may be reduced',
      message: 'Off for 24 hours or more (or unsure how long): apply a NEW patch now and treat today as day 1 of a new 4-week cycle (new change day). '
        + 'Use non-hormonal backup (e.g. condoms) for 7 days. If you had unprotected sex recently, ask about emergency contraception.' };
  }
  if (kind === 'newcycle-late') {
    // applying the first patch of a new cycle late = the hormone-free interval ran long
    return { level: 'risk', title: 'Hormone-free week ran long — ovulation risk',
      message: `Your patch-free time stretched past 7 days${days ? ` (about ${days} day${days === 1 ? '' : 's'} over)` : ''}. `
        + 'This is the highest-risk patch mistake because ovulation can resume. Apply a new patch now — today becomes your new change day. '
        + 'Use backup for 7 days. If you had unprotected sex during the extended gap, ask about emergency contraception promptly.' };
  }
  // change-late (a weekly change in week 2 or 3)
  if (hoursLate < 48) {
    return { level: 'ok', title: 'Still protected',
      message: `Less than 48 hours late on a weekly change keeps you protected. Apply the new patch now and keep your usual change day. No backup needed.` };
  }
  return { level: 'risk', title: 'Protection may be reduced',
    message: `48 hours or more late on a weekly change${days ? ` (about ${days} days)` : ''}. Apply a new patch now and start a NEW 4-week cycle from today (new change day). `
      + 'Use backup for 7 days. If you had unprotected sex in the last few days, ask about emergency contraception.' };
}

// Assess the user's CURRENT real situation from logged patch actions.
function assessPatch() {
  if (!state.settings.onPatch || !state.settings.patchStart) return null;
  const acts = sortedActions();
  const tISO = todayISO();
  const lastApply = [...acts].reverse().find((a) => a.action === 'apply');
  const lastRemove = [...acts].reverse().find((a) => a.action === 'remove' || a.action === 'detached');

  // Is a patch currently on? (an apply with no later remove/detach)
  const patchOn = lastApply && (!lastRemove || lastApply.date >= lastRemove.date);

  if (patchOn) {
    const daysOn = daysBetween(lastApply.date, tISO);
    // Prefer counting real applications since the cycle anchor; fall back to date-bucketing.
    const anchor = cycleAnchor();
    const applies = anchor ? acts.filter((x) => x.action === 'apply' && x.date >= anchor && x.date <= lastApply.date).length : 0;
    const num = applies ? Math.min(3, applies) : patchNumberFor(lastApply.date);
    if (num === 3) {
      // 3rd patch: due to be REMOVED at +7 (start patch-free week)
      if (daysOn < 7) return { level: 'ok', title: `Patch 3 of 3 on`, message: `Remove in ${7 - daysOn} day${7 - daysOn === 1 ? '' : 's'} to begin your patch-free week.` };
      if (daysOn === 7) return { level: 'caution', title: 'Time to start your patch-free week', message: 'Remove the patch today.' };
      return Object.assign(lateGuidance('left-on-late'), { num, daysOn });
    }
    // patch 1 or 2: due to be CHANGED at +7
    if (daysOn < 7) return { level: 'ok', title: `Patch ${num} of 3 on`, message: `Change in ${7 - daysOn} day${7 - daysOn === 1 ? '' : 's'}.` };
    if (daysOn === 7) return { level: 'caution', title: 'Patch change due today', message: 'Apply a fresh patch today.' };
    return Object.assign(lateGuidance('change-late', (daysOn - 7) * 24), { daysOn, num });
  }

  // No patch on. A fall-off is urgent; a removal starts the normal patch-free week.
  if (lastRemove && lastRemove.action === 'detached') {
    const daysOff = daysBetween(lastRemove.date, tISO);
    if (daysOff <= 1) return { level: 'caution', title: 'Patch fell off — act now',
      message: 'Re-apply it if it still sticks well, or put on a new patch. Within 24 hours you stay protected and keep your usual change day.' };
    return Object.assign(lateGuidance('detached', daysOff * 24), { daysOff });
  }
  if (lastRemove) {
    const daysFree = daysBetween(lastRemove.date, tISO);
    if (daysFree < 7) return { level: 'ok', title: 'Patch-free week', message: `Apply your next patch in ${7 - daysFree} day${7 - daysFree === 1 ? '' : 's'}.` };
    if (daysFree === 7) return { level: 'caution', title: 'Time for a new patch', message: 'Apply the first patch of your new cycle today.' };
    return Object.assign(lateGuidance('newcycle-late', (daysFree - 7) * 24), { daysFree });
  }
  return null;
}

/* Walk the logged patch actions and rate each one on time / late, from the real
 * gaps between events (the 7-day rule) — never self-labeled. Returns newest first. */
function patchHistory() {
  const acts = sortedActions();
  const spans = patchSpans();
  const out = [];
  let prevApply = null;
  for (const a of acts) {
    // kind: how this event compares to the 7-day rhythm ('start' events aren't rated)
    let status = 'ok', note = '', kind = 'start', delta = null, hfGap = null;
    if (a.action === 'detached') {
      status = 'caution'; note = 'Patch fell off'; kind = 'incident';
    } else if (a.action === 'remove') {
      const gap = prevApply ? daysBetween(prevApply.date, a.date) : null;
      if (gap === null) { note = 'Removed'; }
      else {
        delta = gap - 7; kind = delta === 0 ? 'ontime' : (delta < 0 ? 'early' : 'late');
        if (gap <= 7) { status = 'ok'; note = gap === 7 ? 'Removed on time (7d worn)' : `Removed ${-delta}d early`; }
        else { status = 'ok'; note = `Removed ${delta}d late — still protected`; }
      }
    } else { // apply — rate it on the hormone-free time immediately before it, so a
             // scheduled patch-free week is never mistaken for a very late change
      const prevSpan = spans.filter((s) => s.toExclusive <= a.date).pop();
      const free = prevSpan ? daysBetween(prevSpan.toExclusive, a.date) : null;
      if (!prevApply || free === null) { status = 'ok'; note = 'Cycle start'; }
      else if (free === 0) { // straight swap, no hormone-free time in between
        const gap = daysBetween(prevApply.date, a.date);
        delta = gap - 7; kind = delta === 0 ? 'ontime' : (delta < 0 ? 'early' : 'late');
        if (gap <= 7) { status = 'ok'; note = gap === 7 ? 'Changed on time' : `Changed ${-delta}d early`; }
        else if (gap < 9) { status = 'caution'; note = `Changed ${delta}d late (<48h) — still protected`; }
        else { status = 'risk'; note = `Changed ${delta}d late (≥48h) — protection reduced, new cycle from here`; }
      } else if (prevSpan.endReason === 'detached') { // re-apply after a fall-off
        kind = 'incident'; hfGap = free;
        if (free <= 1) { status = 'ok'; note = 'Re-applied within 24h — still protected'; }
        else { status = 'risk'; note = `Off ~${free}d before a new patch — new cycle from here, 7-day backup advised`; }
      } else if (prevSpan.endReason === 'expired') {
        // the previous patch ran past its wear grace, so this change was ≥48h late
        const gap = daysBetween(prevApply.date, a.date);
        delta = gap - 7; kind = 'late'; hfGap = free; status = 'risk';
        note = `Changed ${delta}d late (≥48h) — protection reduced, new cycle from here`;
      } else { // a patch-free stretch then a new cycle
        hfGap = free; delta = free - 7; kind = delta === 0 ? 'ontime' : (delta < 0 ? 'early' : 'late');
        if (free <= 7) { status = 'ok'; note = free === 7 ? 'New patch on time' : `New patch ${-delta}d early`; }
        else { status = 'risk'; note = `Hormone-free ${free}d (>7) — ovulation risk`; }
      }
    }
    out.push({ date: a.date, action: a.action, site: a.site || null, status, note, kind, delta, hfGap });
    if (a.action === 'apply') prevApply = a;
  }
  return out.reverse();
}

/* ---- Hormone coverage timeline ----
 * Everything about protection is derived from one question: on a given day, was
 * there patch hormone in your system? A patch covers you from the day it goes on
 * until the day it comes off. When a removal was never logged we infer the end
 * rather than assuming the worst:
 *   - the 3rd patch of a cycle is designed to come off at day 7, so we assume it
 *     did (its patch-free week is the method working, not a missed change);
 *   - any other patch keeps working through 8 days of wear (7 scheduled + the
 *     under-48h grace the label allows) or until the next patch goes on.
 * MAX_WEAR is deliberately the label's grace limit, not a guess. */
const MAX_WEAR = 8;

/* One span per applied patch, in order. `inferred` marks a span whose end we
 * reasoned out rather than read from a log — those are fine for judging
 * protection but must never be presented as measured wear time. */
function patchSpans() {
  const acts = sortedActions();
  const tISO = todayISO();
  const spans = [];
  for (let i = 0; i < acts.length; i++) {
    const a = acts[i];
    if (a.action !== 'apply') continue;
    const rest = acts.slice(i + 1);
    // a removal on the same date belongs to the patch being replaced, not this one
    const close = rest.find((x) => (x.action === 'remove' || x.action === 'detached') && x.date > a.date);
    const nextApply = rest.find((x) => x.action === 'apply' && x.date > a.date);
    let endExclusive, endReason; // endExclusive = the first day with no hormone from this patch
    let inferred = false;
    if (close && (!nextApply || close.date <= nextApply.date)) {
      endExclusive = close.date;
      endReason = close.action; // 'remove' (deliberate) | 'detached' (fell off)
    } else {
      // never logged coming off — infer from the schedule instead of guessing a lapse
      const scheduledLast = patchNumberFor(a.date) === 3; // comes off at +7 by design
      const worn = iso(addDays(parseISO(a.date), scheduledLast ? 7 : MAX_WEAR));
      const replaced = nextApply && nextApply.date < worn;
      endExclusive = replaced ? nextApply.date : worn;
      endReason = replaced ? 'replaced' : (scheduledLast ? 'remove' : 'expired');
      inferred = !replaced; // a following apply is real evidence the old patch came off
    }
    // a patch still on today is covering you today
    if (endExclusive > tISO) { endExclusive = iso(addDays(today(), 1)); endReason = 'ongoing'; inferred = true; }
    spans.push({ from: a.date, toExclusive: endExclusive, endReason, inferred });
  }
  return spans.sort((x, y) => x.from.localeCompare(y.from));
}

/* Patch spans merged into continuous covered stretches — the coverage timeline. */
function coverageSpans() {
  const spans = patchSpans();
  const merged = [];
  for (const s of spans) {
    const last = merged[merged.length - 1];
    if (last && s.from <= last.toExclusive) {
      if (s.toExclusive >= last.toExclusive) { last.toExclusive = s.toExclusive; last.endReason = s.endReason; }
    } else merged.push({ ...s });
  }
  return merged;
}
// Was a patch on this day? (the question the "unprotected sex" alert should really ask)
const isCovered = (d) => coverageSpans().some((s) => d >= s.from && d < s.toExclusive);

/* Stretches with no patch hormone at all, and what caused each one. */
function hormoneFreeGaps() {
  const spans = coverageSpans();
  const gaps = [];
  for (let i = 0; i < spans.length; i++) {
    const from = spans[i].toExclusive;                                  // first uncovered day
    const next = spans[i + 1];
    const toExclusive = next ? next.from : iso(addDays(today(), 1));    // an open gap runs through today
    if (toExclusive <= from) continue;
    gaps.push({ from, toExclusive, days: daysBetween(from, toExclusive),
      cause: spans[i].endReason, resumed: next ? next.from : null });
  }
  return gaps;
}

/* Date ranges when protection was plausibly reduced. Read off the coverage
 * timeline, so a scheduled patch-free week — the method working as designed —
 * is never mistaken for a missed change. Each window runs until 7 days after
 * the patch goes back on (the standard back-up period). */
const RISK_CAUSE = {
  gap: 'hormone-free stretch longer than 7 days',
  detached: 'patch off 24h or more after falling off',
  expired: 'weekly change 48h or more late',
};
function riskWindows() {
  const ws = [];
  for (const g of hormoneFreeGaps()) {
    let firstRisk = null, cause = null;
    if (g.cause === 'detached') {
      // label: back on within 24h keeps you protected; longer needs 7 days of back-up
      if (g.days >= 2) { firstRisk = iso(addDays(parseISO(g.from), 1)); cause = 'detached'; }
    } else if (g.cause === 'expired') {
      // a patch worn past its grace limit stops being reliable from that day on
      firstRisk = g.from; cause = 'expired';
    }
    // the universal rule, whatever the cause: more than 7 days with no hormones
    if (!firstRisk && g.days > 7) { firstRisk = iso(addDays(parseISO(g.from), 7)); cause = 'gap'; }
    if (!firstRisk) continue;
    const to = iso(addDays(g.resumed ? parseISO(g.resumed) : today(), 7));
    if (to >= firstRisk) ws.push({ from: firstRisk, to, cause, open: !g.resumed });
  }
  return ws;
}
const inRiskWindow = (d) => riskWindows().some((w) => d >= w.from && d <= w.to);

/* Were you protected by the method on this day? Being mid patch-free week counts:
 * those 7 days are hormone-free by design and ovulation stays suppressed. Since
 * riskWindows() now captures every real lapse, "protected" is simply: on the
 * patch, inside your logged patch history, and not in a risk window. */
function isProtectedDay(d) {
  if (!state.settings.onPatch) return false;
  const firstApply = sortedActions().find((a) => a.action === 'apply');
  if (!firstApply || d < firstApply.date) return false;
  return !inRiskWindow(d);
}

// Emergency contraception logged on, or within 5 days after, a given day.
function ecLoggedFor(dateStr) {
  return Object.keys(state.logs)
    .filter((d) => (state.logs[d].tags || []).includes('ec') && d >= dateStr && daysBetween(dateStr, d) <= 5)
    .sort()[0] || null;
}

// Cross-reference risk windows against logged unprotected sex. Factual, date-based —
// never a fabricated probability.
function riskCrossref() {
  const windows = riskWindows();
  const hits = [];
  for (const w of windows) {
    let d = parseISO(w.from);
    const end = parseISO(w.to);
    while (d <= end) {
      const ds = iso(d);
      const log = state.logs[ds];
      if (log && log.tags && log.tags.includes('sex-unprotected')) hits.push(ds);
      d = addDays(d, 1);
    }
  }
  return { windows, hits: [...new Set(hits)] };
}

/* ---- Cycle phase, pregnancy check & bleeding health ---- */

// consecutive bleeding days ending today (0 if not bleeding today)
function bleedDayNumber() {
  let n = 0, d = today();
  while (state.logs[iso(d)] && state.logs[iso(d)].flow) { n++; d = addDays(d, -1); }
  return n;
}

/* Where you are right now. On the patch the honest phases are hormone vs
 * withdrawal (ovulation is suppressed, so follicular/luteal don't apply);
 * off the patch we estimate the classic phases from your average cycle. */
function phaseInfo() {
  const tISO = todayISO();
  const s = cycleStats();
  const bleedDay = bleedDayNumber();
  if (state.settings.onPatch && cycleAnchor()) {
    const cd = patchCycleDay(tISO);
    if (cd === null) return null;
    const week = Math.floor(cd / 7) + 1;
    return {
      mode: 'patch', cycleDay: cd + 1, cycleLen: 28, bleedDay,
      label: isPatchFree(cd) ? 'Withdrawal phase' : 'Hormone phase',
      detail: isPatchFree(cd)
        ? `patch-free week — hormone levels drop, which triggers the withdrawal bleed`
        : `patch week ${week} — steady hormones, ovulation suppressed`,
    };
  }
  if (!s.lastStart) return null;
  const cycleDay = daysBetween(s.lastStart, tISO) + 1;
  const ovulDay = s.avgCycle - (state.settings.lutealLen || 14);
  let label, detail;
  if (bleedDay) { label = 'Menstrual'; detail = `bleeding day ${bleedDay}`; }
  else if (cycleDay > s.avgCycle) { label = 'Late'; detail = `${cycleDay - s.avgCycle} day${cycleDay - s.avgCycle === 1 ? '' : 's'} past your average cycle`; }
  else if (cycleDay === ovulDay) { label = 'Ovulation (estimated)'; detail = 'peak fertility'; }
  else if (cycleDay >= ovulDay - 5 && cycleDay < ovulDay) { label = 'Fertile window'; detail = 'conception is most likely in these days'; }
  else if (cycleDay < ovulDay - 5) { label = 'Follicular'; detail = 'body prepares an egg; fertility is lower but not zero'; }
  else { label = 'Luteal'; detail = 'after estimated ovulation, heading toward your next period'; }
  return { mode: 'natural', cycleDay, cycleLen: s.avgCycle, bleedDay, label, detail };
}

/* All patch-cycle starts (anchors + each 28-day repeat up to today). */
function allCycleStarts() {
  const anchors = cycleAnchors();
  if (!anchors.length) return [];
  const starts = [];
  const t = today();
  for (let i = 0; i < anchors.length; i++) {
    const bound = i + 1 < anchors.length ? parseISO(anchors[i + 1]) : addDays(t, 1);
    let d = parseISO(anchors[i]), guard = 0;
    while (d < bound && d <= t && guard++ < 40) { starts.push(iso(d)); d = addDays(d, PATCH_CYCLE); }
  }
  return starts;
}

/* ---- Pregnancy test tracker ---- */
const TEST_RESULTS = [
  ['negative', 'Negative'],
  ['faint', 'Faint line'],
  ['positive', 'Positive'],
  ['invalid', 'Invalid'],
];
const TEST_LABELS = Object.fromEntries(TEST_RESULTS);
const TEST_META = {
  negative: ['check', 'var(--ok)'],
  faint: ['clock', 'var(--patch)'],
  positive: ['warn', 'var(--accent)'],
  invalid: ['warn', 'var(--muted)'],
};

/* One unified list: dedicated tracker entries plus the quick test-pos/test-neg
 * chips from the daily private log (skipping days the tracker already covers). */
function allPregnancyTests() {
  const list = (state.tests || []).map((t) => ({ ...t, source: 'test' }));
  for (const [d, log] of Object.entries(state.logs)) {
    for (const [tagName, result] of [['test-pos', 'positive'], ['test-neg', 'negative']]) {
      if ((log.tags || []).includes(tagName) && !list.some((t) => t.date === d && t.result === result)) {
        list.push({ id: `log:${d}:${result}`, date: d, result, note: '', source: 'log' });
      }
    }
  }
  return list.sort((a, b) => a.date.localeCompare(b.date));
}
function latestTest(result) {
  const l = allPregnancyTests().filter((t) => t.result === result);
  return l.length ? l[l.length - 1] : null;
}
function testsOn(dateStr) {
  return allPregnancyTests().filter((t) => t.date === dateStr);
}
/* Where in the cycle a test was taken — the context a clinician asks about. */
function testContext(dateStr) {
  if (state.settings.onPatch && cycleAnchor()) {
    const cd = patchCycleDay(dateStr);
    if (cd === null) return '';
    return isPatchFree(cd) ? `patch-free day ${cd - 20}` : `patch day ${cd + 1}`;
  }
  const starts = sortedPeriods().map((p) => p.start).filter((s) => s <= dateStr);
  if (!starts.length) return '';
  return `cycle day ${daysBetween(starts[starts.length - 1], dateStr) + 1}`;
}

/* Honest pregnancy assessment from timing — dates and label guidance, never a
 * made-up probability. Levels: none | info | test. */
function pregnancyCheck() {
  const tISO = todayISO();
  const lines = [];
  let level = 'none';
  const bump = (l) => { if (l === 'test' || (l === 'info' && level === 'none')) level = l; };

  // a recent logged positive test outranks everything
  const pos = latestTest('positive');
  if (pos && daysBetween(pos.date, tISO) <= 60) {
    const negAfter = latestTest('negative');
    return { level: 'test', lines: [
      `You logged a <b>positive pregnancy test</b> (${fmtDate(pos.date)}). Please talk to a clinician about next steps.`,
      ...(negAfter && negAfter.date > pos.date
        ? [`You've since logged a negative (${fmtDate(negAfter.date)}) — mixed results are still worth confirming with a clinician.`]
        : []),
    ] };
  }
  const rc = riskCrossref();
  const recentUnprotected = rc.hits.some((h) => daysBetween(h, tISO) <= 35);

  if (state.settings.onPatch && cycleAnchor()) {
    // check recent patch-free windows for a withdrawal bleed
    const firstData = [...Object.keys(state.logs), ...((state.patchActions || []).map((a) => a.date))].sort()[0] || tISO;
    const windows = allCycleStarts()
      .map((s) => ({ from: iso(addDays(parseISO(s), 20)), to: iso(addDays(parseISO(s), 29)), start: s }))
      .filter((w) => w.to >= firstData) // keep windows that overlap your logged history
      .filter((w) => w.from <= tISO)
      .filter((w) => w.to < tISO || hasWithdrawalBleed(w.from, tISO)); // current window counts once bleeding appears
    const recent = windows.slice(-3).reverse();
    let missed = 0;
    for (const w of recent) {
      const bled = hasWithdrawalBleed(w.from, w.to);
      if (!bled) missed++; else break;
    }
    const riskThatCycle = recent[0] && riskWindows().some((rw) => rw.from <= iso(addDays(parseISO(recent[0].start), 28)) && rw.to >= recent[0].start);
    if (!recent.length) {
      lines.push('Not enough completed patch-free weeks logged yet to check your bleed timing.');
    } else if (missed >= 2) {
      bump('test');
      lines.push(`<b>No withdrawal bleed in your last ${missed} patch-free weeks.</b> The patch label advises taking a <b>pregnancy test</b> when two bleeds in a row are missed.`);
    } else if (missed === 1 && (riskThatCycle || recentUnprotected)) {
      bump('test');
      lines.push(`<b>You skipped your last withdrawal bleed after a cycle with possible reduced protection.</b> Take a <b>pregnancy test</b> to be sure.`);
    } else if (missed === 1) {
      bump('info');
      lines.push(`No bleed showed up in your last patch-free week. With consistent use this can be normal — bleeds on the patch are often light or occasionally absent. If it happens twice in a row, test.`);
    } else {
      lines.push(`Your withdrawal bleeds are arriving when expected — <b>no pregnancy signals from your timing</b>. Just what you want to see.`);
    }
    if (recentUnprotected && missed === 0) {
      bump('info');
      lines.push(`You logged unprotected sex during a reduced-protection window recently — your next patch-free week's bleed is the checkpoint to watch.`);
    }
  } else {
    const s = cycleStats();
    if (!s.lastStart) return { level: 'none', lines: ['Log a period or two and Petal can check your timing.'] };
    const late = daysBetween(s.lastStart, tISO) + 1 - s.avgCycle;
    if (late >= 7 || (late >= 5 && recentUnprotected)) {
      bump('test');
      lines.push(`<b>Your period is ${late} days past your ${s.avgCycle}-day average.</b> That's the point where a <b>pregnancy test</b> gives a reliable answer.`);
    } else if (late >= 1) {
      bump('info');
      lines.push(`You're ${late} day${late === 1 ? '' : 's'} past your average — a few days of drift is common (stress, travel, illness). Test if it reaches a week.`);
    } else {
      lines.push(`Your timing looks on track — <b>no pregnancy signals</b>. Just what you want to see.`);
    }
  }

  // logged tests refine the timing signal
  const faint = latestTest('faint');
  const neg = latestTest('negative');
  if (faint && daysBetween(faint.date, tISO) <= 10 && (!neg || neg.date <= faint.date)) {
    bump('test');
    lines.unshift(`You logged a <b>faint-line test</b> (${fmtDate(faint.date)}) — a faint line usually still means positive. Retest in 2–3 days with first-morning urine, or ask a clinician for a blood test.`);
  } else if (level === 'test' && neg && daysBetween(neg.date, tISO) <= 7) {
    level = 'info';
    lines.push(`You logged a <b>negative test</b> ${fmtDate(neg.date)} — <b>good news</b>. A test taken early can miss, so if there's still no bleed a week after that test, take one more to be sure.`);
  }
  return { level, lines };
}

/* Gentle, factual bleeding-health flags — never diagnoses. */
function bleedingHealth() {
  const lines = [];
  const ps = sortedPeriods();
  const last = ps[ps.length - 1];
  if (last) {
    const len = daysBetween(last.start, last.end || last.start) + 1;
    if (len >= 8) lines.push(`Your ${last.ongoing ? 'current' : 'last'} bleed ${last.ongoing ? 'has lasted' : 'lasted'} <b>${len} days</b>${last.ongoing ? ' so far' : ''} — bleeds over 7–8 days are worth mentioning to a clinician, especially if heavy.`);
  }
  // breakthrough bleeding recurring across several recent patch cycles
  if (state.settings.onPatch) {
    const starts = allCycleStarts().slice(-4);
    let cyclesWithBt = 0;
    for (const st of starts) {
      const end = iso(addDays(parseISO(st), 20)); // hormone weeks only
      if (Object.keys(state.logs).some((d) => d >= st && d <= end && state.logs[d].flow &&
        (state.logs[d].bleedType === 'breakthrough' || state.logs[d].flow === 'spotting'))) cyclesWithBt++;
    }
    if (cyclesWithBt >= 3) lines.push(`You've had breakthrough bleeding/spotting during the patch weeks in <b>${cyclesWithBt} recent cycles</b>. Common in early patch use, but if it persists it's worth a clinician chat — sometimes it also follows late changes.`);
  }
  return lines;
}

/* When to expect the next withdrawal bleed: next scheduled removal + your own
 * typical removal→bleed delay (default 2 days until enough cycles are logged). */
function nextBleedPrediction() {
  if (!state.settings.onPatch || !cycleAnchor()) return null;
  const cd = patchCycleDay(todayISO());
  if (cd === null) return null;
  const bt = bleedTimingInsight();
  const offset = bt ? bt.avg : 2;
  // most recent removal point (this cycle's day 21, past or upcoming)
  const removal = cd >= 21 ? addDays(today(), -(cd - 21)) : addDays(today(), 21 - cd);
  const expected = addDays(removal, offset);
  // if this patch-free window already has a withdrawal bleed, nothing is overdue
  if (cd >= 21 && hasWithdrawalBleed(iso(removal), todayISO())) return null;
  return { expected: iso(expected), removal: iso(removal), offset, personalized: !!bt,
    overdue: cd >= 21 && iso(expected) < todayISO() };
}

/* Are bleeds getting shorter or longer over time? Compares older vs recent halves. */
function bleedLengthTrend() {
  const lens = sortedPeriods().filter((p) => !p.ongoing)
    .map((p) => daysBetween(p.start, p.end || p.start) + 1)
    .filter((n) => n >= 1 && n <= 20);
  if (lens.length < 4) return null;
  const half = Math.floor(lens.length / 2);
  const avg = (a) => a.reduce((x, y) => x + y, 0) / a.length;
  const early = avg(lens.slice(0, half)), late = avg(lens.slice(-half));
  const diff = late - early;
  if (Math.abs(diff) < 1.5) return { dir: 'steady', early, late, n: lens.length };
  return { dir: diff < 0 ? 'shorter' : 'longer', early: Math.round(early * 10) / 10, late: Math.round(late * 10) / 10, n: lens.length };
}

/* Which placements do fall-offs happen from? (site comes from the apply before) */
function detachmentPatterns() {
  const acts = sortedActions();
  const det = acts.filter((a) => a.action === 'detached');
  if (det.length < 2) return null;
  const bySite = {};
  let sited = 0;
  for (const d of det) {
    // the patch that fell off is the one applied most recently — never search past it
    // for an older placement, or we blame a site that wasn't even being worn
    const apply = [...acts].reverse().find((a) => a.action === 'apply' && a.date <= d.date);
    if (apply && apply.site) { bySite[apply.site] = (bySite[apply.site] || 0) + 1; sited++; }
  }
  if (!sited) return { total: det.length, top: null };
  const [topSite, topCount] = Object.entries(bySite).sort((a, b) => b[1] - a[1])[0];
  return { total: det.length, sited, topSite, topCount };
}

/* Adherence stats across everything logged in the calendar. */
function patchAdherence() {
  const hist = patchHistory(); // newest first
  const rated = hist.filter((e) => e.kind === 'ontime' || e.kind === 'early' || e.kind === 'late');
  if (!rated.length) return null;
  const count = (k) => rated.filter((e) => e.kind === k).length;
  const risks = hist.filter((e) => e.status === 'risk').length;
  let streak = 0; // consecutive rated events (newest first) without reduced protection
  for (const e of rated) { if (e.status === 'risk') break; streak++; }
  const hfGaps = hist.filter((e) => e.hfGap != null).map((e) => e.hfGap);
  return {
    rated: rated.length,
    ontime: count('ontime'),
    early: count('early'),
    late: count('late'),
    risks,
    streak,
    protectedRate: Math.round(100 * (rated.length - rated.filter((e) => e.status === 'risk').length) / rated.length),
    maxHF: hfGaps.length ? Math.max(...hfGaps) : null,
  };
}

function zafemyStickerInsights() {
  const acts = sortedActions();
  const applies = acts.filter((a) => a.action === 'apply');
  const detaches = acts.filter((a) => a.action === 'detached');
  const timing = patchTimingStats();
  const sited = applies.filter((a) => a.site);
  const siteCounts = {};
  for (const a of sited) siteCounts[a.site] = (siteCounts[a.site] || 0) + 1;
  const topSite = Object.entries(siteCounts).sort((a, b) => b[1] - a[1])[0] || null;
  const changeDayCounts = {};
  for (const a of applies) {
    const day = parseISO(a.date).toLocaleDateString(undefined, { weekday: 'long' });
    changeDayCounts[day] = (changeDayCounts[day] || 0) + 1;
  }
  const topChangeDay = Object.entries(changeDayCounts).sort((a, b) => b[1] - a[1])[0] || null;
  let sameSiteRepeats = 0;
  let lastSited = null;
  let mostRecentRepeat = null;
  for (const a of applies) {
    if (!a.site) continue;
    if (lastSited && lastSited.site === a.site) {
      sameSiteRepeats++;
      mostRecentRepeat = a.site;
    }
    lastSited = a;
  }
  const lastApply = [...acts].reverse().find((a) => a.action === 'apply');
  const lastOff = [...acts].reverse().find((a) => a.action === 'remove' || a.action === 'detached');
  const patchOn = lastApply && (!lastOff || lastApply.date >= lastOff.date);
  const lines = [];
  if (!applies.length) {
    lines.push(`${ic('bandage', 'var(--patch)', 'i-ic')} Log each Zafemy application and placement to unlock timing, rotation, and fall-off insights.`);
  } else if (patchOn) {
    const daysOn = daysBetween(lastApply.date, todayISO());
    const site = lastApply.site ? ` on ${lastApply.site.toLowerCase()}` : '';
    if (daysOn < 7) lines.push(`${ic('clock', 'var(--patch)', 'i-ic')} Current sticker has been on <b>${daysOn} day${daysOn === 1 ? '' : 's'}</b>${site}; change it in <b>${7 - daysOn}</b> day${7 - daysOn === 1 ? '' : 's'}.`);
    else if (daysOn === 7) lines.push(`${ic('clock', 'var(--patch)', 'i-ic')} Current sticker reaches <b>7 days today</b>${site}; this is your change/removal checkpoint.`);
    else lines.push(`${ic('warn', 'var(--accent)', 'i-ic')} Current sticker has been on <b>${daysOn} days</b>${site}. Zafemy is designed around a weekly Patch Change Day, so log the change/removal when it happens.`);
  } else if (lastOff) {
    const daysOff = daysBetween(lastOff.date, todayISO());
    lines.push(`${ic('moon', 'var(--patchfree)', 'i-ic')} You have been patch-free for <b>${daysOff} day${daysOff === 1 ? '' : 's'}</b>. Zafemy should not have more than a 7-day patch-free interval between cycles.`);
  }
  if (topChangeDay && applies.length >= 2) {
    const offDay = applies.length - topChangeDay[1];
    lines.push(`${ic('calendar', 'var(--patchfree)', 'i-ic')} Your logged Patch Change Day is usually <b>${topChangeDay[0]}</b>${offDay ? `; <b>${offDay}</b> application${offDay === 1 ? '' : 's'} landed on another weekday.` : ', with every logged application on that weekday.'}`);
  }
  if (timing.avgWear) {
    lines.push(`${ic('clock', 'var(--patch)', 'i-ic')} Average logged wear time is <b>${timing.avgWear} days</b>${timing.longWear ? `, with <b>${timing.longWear}</b> sticker${timing.longWear === 1 ? '' : 's'} worn over 7 days` : ', right around the weekly rhythm'}.`);
  }
  if (timing.avgPatchFree) {
    lines.push(`${ic('moon', 'var(--patchfree)', 'i-ic')} Average patch-free interval is <b>${timing.avgPatchFree} days</b>${timing.maxPatchFree > 7 ? `; longest was <b>${timing.maxPatchFree} days</b>, above the 7-day limit` : ', within the 7-day limit so far'}.`);
  }
  if (applies.length && sited.length < applies.length) {
    const missing = applies.length - sited.length;
    lines.push(`${ic('sparkle', 'var(--muted)', 'i-ic')} <b>${missing}</b> application${missing === 1 ? '' : 's'} ${missing === 1 ? 'is' : 'are'} missing placement, so rotation stats are incomplete.`);
  }
  if (sameSiteRepeats) {
    lines.push(`${ic('warn', 'var(--patch)', 'i-ic')} Same-site repeat${sameSiteRepeats === 1 ? '' : 's'} logged: <b>${sameSiteRepeats}</b>${mostRecentRepeat ? `, most recently ${mostRecentRepeat.toLowerCase()}` : ''}. Zafemy labeling says not to use the same location as the previous sticker.`);
  } else if (sited.length >= 2) {
    lines.push(`${ic('check', 'var(--ok)', 'i-ic')} No consecutive same-site repeats in your logged placements.`);
  }
  if (topSite && sited.length >= 3) {
    lines.push(`${ic('bandage', 'var(--patch)', 'i-ic')} Most-used placement: <b>${topSite[0].toLowerCase()}</b> (${topSite[1]} of ${sited.length}). Rotate toward a less-used approved area next time.`);
  }
  const dp = detachmentPatterns();
  if (dp && dp.topSite) {
    lines.push(`${ic('warn', 'var(--accent)', 'i-ic')} Fall-off pattern: <b>${dp.topCount} of ${dp.sited}</b> sited fall-offs were from <b>${dp.topSite.toLowerCase()}</b>. Friction, lotion, sweat, and waistbands are worth watching there.`);
  } else if (detaches.length) {
    lines.push(`${ic('warn', 'var(--muted)', 'i-ic')} <b>${detaches.length}</b> fall-off${detaches.length === 1 ? '' : 's'} logged. Add placement each time so Petal can spot where the sticker does not hold.`);
  }
  lines.push(`${ic('check', 'var(--ok)', 'i-ic')} Zafemy basics: one sticker at a time, clean/dry skin, avoid breasts/cut/irritated skin, press firmly for 10 seconds, and check the edges daily.`);
  return {
    stats: [
      ['Applied', applies.length],
      ['Placements', sited.length],
      ['Avg wear', timing.avgWear ? `${timing.avgWear}d` : '—'],
      ['Fall-offs', detaches.length],
    ],
    lines,
  };
}

// Which quarter of the 28-day patch cycle a date falls in, or null off-patch.
function cyclePosition(dateStr) {
  const cd = patchCycleDay(dateStr);
  if (cd === null) return null;
  if (isPatchFree(cd)) return 'free';
  return 'week' + (Math.floor(cd / 7) + 1);
}
const WINDOW_LABEL = { week1: 'Week 1', week2: 'Week 2', week3: 'Week 3', free: 'the patch-free week' };

/* Symptom clustering from calendar logs, broken down by position in the 28-day
 * patch cycle. A symptom "clusters" in a window only when there's real signal:
 * ≥3 logs AND ≥50% of them land in one window (each window is ~25% of the
 * cycle, so 50%+ is a genuine pattern, not noise). We only make that one claim
 * per symptom — no overfitting into vague trend lines. */
function symptomTrends() {
  const entries = Object.entries(state.logs).filter(([, l]) => l.symptoms && l.symptoms.length);
  if (!entries.length) return null;
  const counts = {};
  for (const [d, l] of entries) {
    const pos = cyclePosition(d);
    for (const s of l.symptoms) {
      counts[s] = counts[s] || { total: 0, week1: 0, week2: 0, week3: 0, free: 0 };
      counts[s].total++;
      if (pos) counts[s][pos]++;
    }
  }
  return Object.entries(counts).map(([sym, c]) => {
    let dominant = null, share = 0;
    for (const w of ['week1', 'week2', 'week3', 'free']) {
      const s = c.total ? c[w] / c.total : 0;
      if (s > share) { share = s; dominant = w; }
    }
    const clusters = c.total >= 3 && share >= 0.5;
    return { sym, ...c, clusters, dominant: clusters ? dominant : null, dominantLabel: clusters ? WINDOW_LABEL[dominant] : null, share };
  }).sort((a, b) => b.total - a.total);
}

/* "You typically begin bleeding N days after removing your patch" — averaged
 * across cycles where a period start follows a logged removal within 10 days. */
function bleedTimingInsight() {
  // read removals off the coverage timeline, so this still works for people who
  // take the patch off without logging it (the end of a patch-3 span is a removal)
  const removals = patchSpans().filter((s) => s.endReason === 'remove').map((s) => s.toExclusive);
  if (!removals.length) return null;
  const deltas = [];
  for (const p of sortedPeriods()) {
    const cand = removals.filter((r) => { const d = daysBetween(r, p.start); return d >= 0 && d <= 10; });
    if (cand.length) deltas.push(daysBetween(cand[cand.length - 1], p.start));
  }
  if (deltas.length < 2) return null;
  return { avg: Math.round(deltas.reduce((a, b) => a + b, 0) / deltas.length), n: deltas.length };
}

/* ============================================================ Day info ==== */
function dayInfo(dateStr) {
  const info = { period: false, predicted: false, fertile: false, ovul: false,
    patch: false, patchfree: false, note: false, flow: '' };
  const log = state.logs[dateStr];
  if (log) { info.note = !!(log.notes || (log.symptoms && log.symptoms.length)); info.flow = log.flow || ''; }

  // periods (derived from logged bleeding, plus manual fallback entries)
  for (const p of sortedPeriods()) {
    if (dateStr >= p.start && dateStr <= (p.end || p.start)) { info.period = true; break; }
  }
  if (info.flow) info.period = true;

  // patch overlay
  if (state.settings.patchStart) {
    const cd = patchCycleDay(dateStr);
    if (isPatchOn(cd)) info.patch = true;
    if (isPatchFree(cd)) info.patchfree = true;
  }

  // predictions (only show future, and only natural-cycle ovulation if not on patch)
  const np = predictNextPeriod();
  if (np && !info.period) {
    const s = cycleStats();
    // predicted period window (avgPeriod days)
    const plen = s.avgPeriod || 5;
    for (let i = 0; i < plen; i++) {
      if (dateStr === iso(addDays(parseISO(np), i))) info.predicted = true;
    }
    if (!state.settings.onPatch) {
      const ovul = addDays(parseISO(np), -state.settings.lutealLen);
      const ovulISO = iso(ovul);
      if (dateStr === ovulISO) info.ovul = true;
      for (let i = 1; i <= 5; i++) {
        if (dateStr === iso(addDays(ovul, -i))) info.fertile = true;
      }
    }
  }
  return info;
}

/* ============================================================ Render ====== */
function renderAll() {
  renderToday();
  renderPatchAssistant();
  renderCalendar();
  renderPatch();
  renderInsights();
  renderPregnancyTests();
  renderAppointments();
  renderDoctorQuestions();
  renderBackupHealth();
}

/* ---- Cycle ring (Clue-style) ---- */
function polar(cx, cy, r, a) { const rad = (a - 90) * Math.PI / 180; return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)]; }
function ringArc(r, a0, a1, color, w, opacity = 1) {
  if (a1 <= a0) return '';
  const [x0, y0] = polar(50, 50, r, a0), [x1, y1] = polar(50, 50, r, a1);
  const large = (a1 - a0) > 180 ? 1 : 0;
  return `<path class="arc" pathLength="100" d="M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}" stroke="${color}" stroke-width="${w}" fill="none" stroke-linecap="round"${opacity !== 1 ? ` stroke-opacity="${opacity}"` : ''}/>`;
}
const RING_DEFS = `<defs>
  <linearGradient id="gAmber" gradientUnits="userSpaceOnUse" x1="14" y1="8" x2="86" y2="92">
    <stop offset="0" stop-color="#ffe49a"/><stop offset="1" stop-color="#ff9d2e"/></linearGradient>
  <linearGradient id="gPurple" gradientUnits="userSpaceOnUse" x1="14" y1="8" x2="86" y2="92">
    <stop offset="0" stop-color="#cdbef8"/><stop offset="1" stop-color="#8a7bbf"/></linearGradient>
  <linearGradient id="gPink" gradientUnits="userSpaceOnUse" x1="14" y1="8" x2="86" y2="92">
    <stop offset="0" stop-color="#ffa6c6"/><stop offset="1" stop-color="#ff5d8f"/></linearGradient>
  <linearGradient id="gGreen" gradientUnits="userSpaceOnUse" x1="14" y1="8" x2="86" y2="92">
    <stop offset="0" stop-color="#84e8cd"/><stop offset="1" stop-color="#43c6a8"/></linearGradient>
  <linearGradient id="gLav" gradientUnits="userSpaceOnUse" x1="14" y1="8" x2="86" y2="92">
    <stop offset="0" stop-color="#cdbef8"/><stop offset="1" stop-color="#8b6bff"/></linearGradient>
  <radialGradient id="gCenterGlow">
    <stop offset="0.55" stop-color="#8b6bff" stop-opacity="0"/>
    <stop offset="1" stop-color="#8b6bff" stop-opacity="0.16"/></radialGradient>
  <filter id="ringDepth" x="-25%" y="-25%" width="150%" height="150%">
    <feDropShadow dx="0" dy="0.9" stdDeviation="0.9" flood-color="#000" flood-opacity="0.3"/></filter>
  <filter id="arcGlow" x="-30%" y="-30%" width="160%" height="160%">
    <feGaussianBlur stdDeviation="1.8"/></filter>
  <filter id="markerGlow" x="-150%" y="-150%" width="400%" height="400%">
    <feDropShadow dx="0" dy="0" stdDeviation="1.8" flood-color="#ff5d8f" flood-opacity="0.8"/></filter>
  <filter id="ovulGlow" x="-150%" y="-150%" width="400%" height="400%">
    <feDropShadow dx="0" dy="0" stdDeviation="1.6" flood-color="#4aa8ff" flood-opacity="0.85"/></filter>
</defs>`;
function drawCycleRing() {
  const el = $('#cycleRing'); if (!el) return;
  const r = 44, w = 5, tISO = todayISO();
  const TRACK = '#352a5c';
  let total, cd, arcs = '', glow = '', extra = '';
  const patchMode = state.settings.onPatch && state.settings.patchStart;

  if (patchMode) {
    total = 28;
    cd = patchCycleDay(tISO); if (cd === null) cd = 0;
    const step = 360 / total, g = 1.8;
    const prog = (cd + 0.5) * step; // the lived part of the cycle, up to the today marker
    for (const [s, e, grad] of [[0, 7, 'gAmber'], [7, 14, 'gAmber'], [14, 21, 'gAmber'], [21, 28, 'gPurple']]) {
      const a0 = s * step + g, a1 = e * step - g;
      const pa = Math.min(a1, Math.max(a0, prog));
      if (pa < a1) arcs += ringArc(r, pa, a1, `url(#${grad})`, w, 0.26); // still ahead — dimmed
      if (pa > a0) {                                                     // lived — full colour + soft halo
        arcs += ringArc(r, a0, pa, `url(#${grad})`, w);
        glow += ringArc(r, a0, pa, `url(#${grad})`, w + 1.6, 0.55);
      }
    }
  } else {
    const s = cycleStats();
    total = s.avgCycle || state.settings.cycleLen || 28; // data-driven average when available
    const step = 360 / total;
    const raw = s.lastStart ? daysBetween(s.lastStart, tISO) : null;
    cd = raw === null ? null : ((raw % total) + total) % total;
    // lavender shimmer under the zones so elapsed progress reads at a glance
    if (cd !== null && cd > 0) {
      arcs += ringArc(r, 0.8, (cd + 0.5) * step, 'url(#gLav)', w, 0.35);
      glow += ringArc(r, 0.8, (cd + 0.5) * step, 'url(#gLav)', w + 1.4, 0.4);
    }
    const plen = s.avgPeriod || 5;
    arcs += ringArc(r, 1, plen * step - 1, 'url(#gPink)', w);              // period
    const ovD = total - (state.settings.lutealLen || 14);
    arcs += ringArc(r, (ovD - 5) * step + 1, ovD * step - 1, 'url(#gGreen)', w); // fertile
    const [ox, oy] = polar(50, 50, r, (ovD + 0.5) * step);
    extra += `<g filter="url(#ovulGlow)"><circle cx="${ox.toFixed(2)}" cy="${oy.toFixed(2)}" r="2.8" fill="#2fa3ff"/>` +
             `<circle cx="${ox.toFixed(2)}" cy="${oy.toFixed(2)}" r="1.2" fill="#fff"/></g>`;
  }

  // day ticks on an inner orbit — one dot per day, the lived ones shine
  let ticks = '';
  {
    const stepT = 360 / total;
    for (let i = 0; i < total; i++) {
      const boundary = patchMode && i % 7 === 0; // patch-change days stand out a little
      const [tx, ty] = polar(50, 50, 38, (i + 0.5) * stepT);
      const lived = cd !== null && i <= cd;
      ticks += `<circle cx="${tx.toFixed(2)}" cy="${ty.toFixed(2)}" r="${boundary ? 1.05 : 0.55}" fill="${lived ? '#cfc2f4' : '#463a76'}"/>`;
    }
  }

  // glowing today marker with a gentle pulse (hidden when reduced motion is on)
  let marker = '';
  if (cd !== null) {
    const [mx, my] = polar(50, 50, r, (cd + 0.5) * (360 / total));
    marker = `<circle class="today-pulse" cx="${mx.toFixed(2)}" cy="${my.toFixed(2)}" r="5.2" fill="none" stroke="#ff8bb0" stroke-width="1"/>` +
      `<g filter="url(#markerGlow)">` +
      `<circle cx="${mx.toFixed(2)}" cy="${my.toFixed(2)}" r="3.4" fill="#fff"/>` +
      `<circle cx="${mx.toFixed(2)}" cy="${my.toFixed(2)}" r="3.4" fill="none" stroke="#ff5d8f" stroke-width="1.5"/>` +
      `<circle cx="${mx.toFixed(2)}" cy="${my.toFixed(2)}" r="1.15" fill="#ff5d8f"/></g>`;
  }
  el.innerHTML = `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" style="overflow:visible">${RING_DEFS}
    <circle cx="50" cy="50" r="34" fill="url(#gCenterGlow)"/>
    <circle cx="50" cy="50" r="${r}" stroke="${TRACK}" stroke-width="${w}" fill="none" opacity="0.5"/>
    ${ticks}
    <g filter="url(#arcGlow)" opacity="0.6">${glow}</g>
    <g filter="url(#ringDepth)">${arcs}</g>${extra}${marker}</svg>`;
}

/* ---- Today ---- */
// A warm daily check-in line — makes opening the app a small ritual. Context-aware
// and honest (never fake reassurance when something needs attention), and stable
// within a day so it doesn't flicker on every render.
function checkinGreeting() {
  const h = new Date().getHours();
  const kicker = h < 5 ? 'Late night' : h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : h < 21 ? 'Good evening' : 'Winding down';
  const a = state.settings.onPatch ? assessPatch() : null;
  const cd = patchCycleDay(todayISO());
  // deterministic pick-of-the-day so it feels fresh but doesn't jump around
  const seed = Number(todayISO().replaceAll('-', '')) % 997;
  const pick = (arr) => arr[seed % arr.length];
  let line;
  if (a && a.level === 'risk') line = 'Let’s sort your patch out together — details below.';
  else if (a && a.level === 'caution') line = 'One small patch task for you today.';
  else if (cd !== null && isPatchFree(cd)) line = pick(['Patch-free week — a little rest for your skin.', 'Patch-free week — you’re still covered.', 'Rest week. Nothing to change today.']);
  else if (state.settings.onPatch && cd !== null) line = pick(['Your patch is quietly doing its job.', 'All covered — nothing to do today.', 'Steady as ever. You’ve got this.', 'You showed up today. That’s the whole game.']);
  else line = pick(['Here whenever you want to log something.', 'A gentle check-in — how are you today?']);
  return { kicker, line };
}

function renderToday() {
  const tISO = todayISO();
  $('#todayDate').textContent = fmtDate(tISO, { weekday: 'long', month: 'long', day: 'numeric' });
  const g = checkinGreeting();
  $('#checkin').innerHTML = `<div class="checkin-kicker">${g.kicker} ✨</div><div class="checkin-line">${g.line}</div>`;
  drawCycleRing();

  // hero: one glance, one fact — a big number in the ring center
  const np = predictNextPeriod();
  const cd = patchCycleDay(tISO);
  const setHero = (kicker, big, cap, sub, words) => {
    $('#heroKicker').textContent = kicker;
    const hb = $('#heroBig');
    hb.textContent = big;
    hb.classList.toggle('words', !!words || String(big).length > 3);
    $('#heroCap').textContent = cap;
    $('#heroSub').textContent = sub;
  };
  const dayWord = (n) => `day${n === 1 ? '' : 's'}`;
  if (state.settings.onPatch && cd !== null) {
    // where the patch currently on your skin is placed (if logged)
    const acts = sortedActions();
    const lastApply = [...acts].reverse().find((x) => x.action === 'apply');
    const lastOff = [...acts].reverse().find((x) => x.action === 'remove' || x.action === 'detached');
    const wornSite = lastApply && (!lastOff || lastApply.date >= lastOff.date) && lastApply.site
      ? ` · on ${lastApply.site.toLowerCase()}` : '';
    if (isPatchFree(cd)) {
      const back = 28 - cd;
      setHero('Patch-free week', back, `${dayWord(back)} until new patch`,
        `Day ${cd + 1} of 28 · a withdrawal bleed is normal this week`);
    } else {
      const week = Math.floor(cd / 7) + 1;
      const left = week === 3 ? 21 - cd : 7 - (cd % 7);
      setHero(`Patch week ${week}`, left,
        `${dayWord(left)} until ${week === 3 ? 'removal' : 'patch change'}`,
        `Day ${cd + 1} of 28${wornSite}`);
    }
  } else if (np) {
    const dleft = daysBetween(tISO, np);
    const s = cycleStats();
    const cyc = s.lastStart ? daysBetween(s.lastStart, tISO) + 1 : null;
    const sub = (cyc ? `Cycle day ${cyc} · ` : '') + predictionConfidence();
    if (dleft > 0) setHero('Next period', dleft, `${dayWord(dleft)} away · ${fmtDate(np)}`, sub);
    else if (dleft === 0) setHero('Next period', 'Today', 'expected — log it when it starts', sub, true);
    else setHero('Period', -dleft, `${dayWord(-dleft)} late · log it when it starts`, sub);
  } else {
    setHero('Welcome', 'Hello', 'let’s get set up', 'Log a period or set your patch schedule.', true);
  }

  renderAlerts();

  // today's log fields
  const log = state.logs[tISO] || { flow: '', bleedType: '', symptoms: [], tags: [], notes: '' };
  $$('#flowSeg button').forEach((b) => b.classList.toggle('on', (b.dataset.val || '') === (log.flow || '')));
  $('#bleedTypeRow').classList.toggle('inactive', !log.flow);
  const btVal = log.bleedType === 'breakthrough' ? 'breakthrough' : 'withdrawal';
  $$('#bleedTypeSeg button').forEach((b) => b.classList.toggle('on', b.dataset.val === btVal));
  $$('#symptomChips .chip').forEach((c) => c.classList.toggle('on', (log.symptoms || []).includes(c.dataset.sym)));
  $$('#intimacyChips .chip').forEach((c) => c.classList.toggle('on', (log.tags || []).includes(c.dataset.tag)));
  $('#todayNotes').value = log.notes || '';
  // auto-expand sections that already hold today's data so nothing is invisible
  if (log.symptoms?.length) { $('#symptomWrap').classList.remove('chips-collapsed'); $('#symptomToggle').textContent = 'Show less'; }
  if (log.tags?.length) { $('#intimacyChips').classList.remove('hidden'); $('#intimacyToggle').textContent = 'Hide'; }
}

function renderPatchAssistant() {
  const el = $('#patchAssistantCard');
  if (!el) return;
  const pa = patchAssistant();
  if (!pa) { el.classList.add('hidden'); el.innerHTML = ''; return; }
  el.classList.remove('hidden');
  const m = LEVEL_META[pa.level] || LEVEL_META.ok;
  el.innerHTML = `
    <div class="card-head"><h2>${m.icon()} Patch change assistant</h2></div>
    <div class="guidance ${pa.level}">
      <h3>${escapeHtml(pa.title)}</h3>
      <div>${pa.message}</div>
      ${pa.level === 'risk' ? `<div class="disc">${GUIDE_DISCLAIMER}</div>` : ''}
    </div>
    ${pa.lines.map((l) => `<div class="insight-line">${l}</div>`).join('')}
    <button class="btn btn-ghost full btn-ic" data-open-calendar>${ic('calendar', 'var(--patchfree)', 'b-ic')}Log from Calendar</button>`;
  el.querySelector('[data-open-calendar]').addEventListener('click', () => {
    const tab = document.querySelector('.tab[data-view="calendar"]');
    if (tab) tab.click();
  });
}

const LEVEL_META = {
  ok: { cls: 'ok', icon: () => ic('check', 'var(--ok)') },
  caution: { cls: 'due', icon: () => ic('clock', 'var(--patch)') },
  risk: { cls: 'due', icon: () => ic('warn', 'var(--accent)') },
};
function renderAlerts() {
  const box = $('#alerts'); box.innerHTML = '';
  const tISO = todayISO();

  // primary: honest assessment of the real patch situation
  const a = assessPatch();
  if (a) {
    const m = LEVEL_META[a.level] || LEVEL_META.ok;
    box.insertAdjacentHTML('beforeend',
      `<div class="alert ${m.cls}">${m.icon()}<div><b>${a.title}.</b> ${a.message}` +
      (a.level === 'risk' ? `<div class="muted small" style="margin-top:6px">${GUIDE_DISCLAIMER}</div>` : '') +
      `</div></div>`);
  } else if (state.settings.onPatch && state.settings.patchStart) {
    // schedule-based reminder when there are no logged actions yet
    const evs = patchEvents(2);
    const todayEv = evs.find((e) => e.date === tISO);
    const tomEv = evs.find((e) => e.date === iso(addDays(today(), 1)));
    if (todayEv) box.insertAdjacentHTML('beforeend',
      `<div class="alert due">${ic('bandage', 'var(--patch)')}<div><b>Patch task today:</b> ${todayEv.label}.</div></div>`);
    else if (tomEv) box.insertAdjacentHTML('beforeend',
      `<div class="alert">${ic('clock', 'var(--patch)')}<div><b>Tomorrow:</b> ${tomEv.label}.</div></div>`);
  }

  // late period (natural cycle only)
  const np = predictNextPeriod();
  if (np && !state.settings.onPatch) {
    const dleft = daysBetween(tISO, np);
    if (dleft <= -2) box.insertAdjacentHTML('beforeend',
      `<div class="alert">${ic('calendar', 'var(--patchfree)')}<div>Your period is ${-dleft} days later than predicted.</div></div>`);
  }

  // prescription/box expiration
  if (state.settings.patchExpiry) {
    const dExp = daysBetween(tISO, state.settings.patchExpiry);
    if (dExp <= 30) {
      box.insertAdjacentHTML('beforeend',
        `<div class="alert${dExp <= 7 ? ' due' : ''}">${ic(dExp <= 7 ? 'warn' : 'clock', dExp <= 7 ? 'var(--accent)' : 'var(--patch)')}<div>${dExp < 0
          ? `<b>Your patch prescription expired ${fmtDate(state.settings.patchExpiry)}.</b> Check with your pharmacy before using it.`
          : `<b>Expires ${fmtDate(state.settings.patchExpiry)}</b> (${dExp} day${dExp === 1 ? '' : 's'}) — plan a refill.`}</div></div>`);
    }
  }

  // refill warning — an empty box is how late applications happen
  const rf = refillStatus();
  if (rf && rf.level !== 'ok') {
    const msg = rf.left === 0
      ? `<b>You're out of patches.</b> Your next application is ${fmtDate(rf.outDate)} — refill your prescription now.`
      : `<b>${rf.left} patch${rf.left === 1 ? '' : 'es'} left.</b> You'll run out around ${fmtDate(rf.outDate)} — refill before then.`;
    box.insertAdjacentHTML('beforeend',
      `<div class="alert ${rf.level === 'risk' ? 'due' : ''}">${ic(rf.level === 'risk' ? 'warn' : 'clock', rf.level === 'risk' ? 'var(--accent)' : 'var(--patch)')}<div>${msg}</div></div>`);
  }

  // upcoming appointments / refills (next 2 days)
  for (const ap of (state.appointments || [])) {
    const dleft = daysBetween(tISO, ap.date);
    if (dleft >= 0 && dleft <= 2) {
      box.insertAdjacentHTML('beforeend',
        `<div class="alert">${ic('calendar', 'var(--ovul)')}<div><b>${dleft === 0 ? 'Today' : dleft === 1 ? 'Tomorrow' : 'In 2 days'}:</b> ${escapeHtml(ap.label)}.</div></div>`);
    }
  }

  // unprotected sex logged during a reduced-protection window (recent = actionable)
  const rc = riskCrossref();
  const recentHit = rc.hits.find((h) => daysBetween(h, tISO) <= 5 && daysBetween(h, tISO) >= 0);
  if (recentHit) {
    // being inside a window is not the same as having had no patch on — say which
    const covered = isCovered(recentHit);
    const why = rc.windows.find((w) => recentHit >= w.from && recentHit <= w.to);
    box.insertAdjacentHTML('beforeend',
      `<div class="alert due">${ic('warn', 'var(--accent)')}<div><b>Unprotected sex logged ${fmtDate(recentHit)}${covered
        ? ' — your patch was on, but it was still inside a back-up period.'
        : ' — you had no patch hormone cover that day.'}</b>
      ${covered
        ? `Your patch timing shows a ${why ? RISK_CAUSE[why.cause] : 'recent gap'}, and the label advises 7 days of back-up after that before the patch is fully reliable again.`
        : `This came from a ${why ? RISK_CAUSE[why.cause] : 'gap in your logged patch timing'}.`}
      ${(() => {
        const ec = ecLoggedFor(recentHit);
        return ec
          ? `You logged <b>emergency contraception on ${fmtDate(ec)}</b> — that's the timely step covered here. EC only covers sex that already happened, so keep using back-up until your patch is reliable again.`
          : `Emergency contraception is most effective the sooner it's taken (within 3–5 days). A pharmacist can help today, no appointment needed.`;
      })()}
      <div class="muted small" style="margin-top:6px">${GUIDE_DISCLAIMER}</div></div></div>`);
  } else {
    // logged unprotected sex while fully covered — the common case, and worth saying plainly
    const lastSex = Object.keys(state.logs)
      .filter((d) => (state.logs[d].tags || []).includes('sex-unprotected') && d <= tISO && daysBetween(d, tISO) <= 5)
      .sort().pop();
    if (lastSex && isProtectedDay(lastSex)) {
      const cd = patchCycleDay(lastSex);
      const where = isCovered(lastSex) ? 'Your patch was on and on schedule'
        : (isPatchFree(cd) ? 'You were in your scheduled patch-free week' : 'Your patch timing was on schedule');
      box.insertAdjacentHTML('beforeend',
        `<div class="alert ok">${ic('check', 'var(--ok)')}<div>${where} on ${fmtDate(lastSex)} — <b>you were covered for pregnancy</b> that day.</div></div>`);
    }
  }

  // pregnancy-timing signal (only when it's test-worthy — no noise)
  const preg = pregnancyCheck();
  if (preg.level === 'test') {
    box.insertAdjacentHTML('beforeend',
      `<div class="alert due">${ic('warn', 'var(--accent)')}<div>${preg.lines[0]} <span class="muted small">Details in Insights.</span></div></div>`);
  }

  // prolonged ongoing bleed
  {
    const last = sortedPeriods().slice(-1)[0];
    if (last && last.ongoing && daysBetween(last.start, last.end) + 1 >= 8) {
      box.insertAdjacentHTML('beforeend',
        `<div class="alert">${ic('drop', 'var(--period)')}<div>You've been bleeding <b>${daysBetween(last.start, last.end) + 1} days</b> — bleeds over 7–8 days are worth mentioning to a clinician, especially if heavy.</div></div>`);
    }
  }

  // streak encouragement — your logged changes, working for you
  const adh = patchAdherence();
  if (adh && adh.streak >= 3 && (!a || a.level === 'ok')) {
    box.insertAdjacentHTML('beforeend',
      `<div class="alert ok">${ic('sparkle', 'var(--patch)')}<div><b>${adh.streak} changes in a row</b> with protection maintained.</div></div>`);
  }

  // gentle backup reminder so a year of data survives iOS storage eviction
  maybeBackupReminder(box);

  // urgent alerts always sort to the top so the cap can never hide them
  [...box.querySelectorAll('.alert.due')].reverse().forEach((el) => box.prepend(el));

  // keep the Today screen calm: max 4 alerts visible, the rest one tap away
  const all = [...box.querySelectorAll('.alert')];
  if (all.length > 4) {
    all.slice(4).forEach((el) => el.classList.add('overflow-hidden'));
    const more = document.createElement('button');
    more.className = 'alerts-more'; more.type = 'button';
    more.textContent = `Show ${all.length - 4} more`;
    more.addEventListener('click', () => {
      all.forEach((el) => el.classList.remove('overflow-hidden'));
      more.remove();
    });
    box.appendChild(more);
  }
}

function maybeBackupReminder(box) {
  if (state.settings.backupReminder === false) return;
  const last = state.settings.lastBackup;
  const stale = !last || daysBetween(last, todayISO()) >= 30;
  if (stale && (state.periods.length || (state.patchActions && state.patchActions.length))) {
    box.insertAdjacentHTML('beforeend',
      `<div class="alert">${ic('backup', 'var(--fertile)')}<div>Back up your data so it can't be lost — Settings → Export encrypted backup, then save it to iCloud Drive.</div></div>`);
  }
}

$('#saveToday').addEventListener('click', () => {
  const tISO = todayISO();
  const flow = ($('#flowSeg button.on') || {}).dataset?.val ?? '';
  const bleedType = flow ? (($('#bleedTypeSeg button.on') || {}).dataset?.val ?? 'withdrawal') : '';
  const symptoms = $$('#symptomChips .chip.on').map((c) => c.dataset.sym);
  const tags = $$('#intimacyChips .chip.on').map((c) => c.dataset.tag);
  const notes = $('#todayNotes').value.trim();
  const prevLog = state.logs[tISO] ? JSON.parse(JSON.stringify(state.logs[tISO])) : undefined;
  if (!flow && !symptoms.length && !tags.length && !notes) { delete state.logs[tISO]; }
  else state.logs[tISO] = { flow, bleedType, symptoms, tags, notes };
  // periods are derived from consecutive bleeding days — no manual entry needed
  saveState(); renderAll();
  toastUndo('Saved', () => {
    if (prevLog === undefined) delete state.logs[tISO]; else state.logs[tISO] = prevLog;
    saveState(); renderAll(); toast('Restored');
  });
});

$('#flowSeg').addEventListener('click', (e) => {
  const b = e.target.closest('button'); if (!b) return;
  $$('#flowSeg button').forEach((x) => x.classList.toggle('on', x === b));
  $('#bleedTypeRow').classList.toggle('inactive', !b.dataset.val);
});
$('#bleedTypeSeg').addEventListener('click', (e) => {
  const b = e.target.closest('button'); if (!b) return;
  $$('#bleedTypeSeg button').forEach((x) => x.classList.toggle('on', x === b));
});

function allSymptoms() {
  return SYMPTOMS.concat(state.settings.customSymptoms || []);
}
function buildSymptomChips() {
  const box = $('#symptomChips'); box.innerHTML = '';
  allSymptoms().forEach((s) => {
    const c = document.createElement('button');
    c.className = 'chip'; c.dataset.sym = s; c.textContent = s; c.type = 'button';
    c.addEventListener('click', () => c.classList.toggle('on'));
    box.appendChild(c);
  });
  buildIntimacyChips();
  // "+" chip: add your own; typing an existing custom one offers to remove it
  const add = document.createElement('button');
  add.className = 'chip chip-add'; add.textContent = '+ Add'; add.type = 'button';
  add.addEventListener('click', () => {
    const name = (prompt('Track your own symptom or tag (e.g. “Migraine aura”, “Skipped coffee”):') || '').trim();
    if (!name) return;
    const customs = state.settings.customSymptoms || [];
    const existing = customs.find((c) => c.toLowerCase() === name.toLowerCase());
    if (existing) {
      if (confirm(`“${existing}” already exists. Remove it from your chips? (Past logs keep it.)`)) {
        state.settings.customSymptoms = customs.filter((c) => c !== existing);
        saveState(); buildSymptomChips(); renderToday(); toast('Tag removed');
      }
      return;
    }
    if (SYMPTOMS.some((c) => c.toLowerCase() === name.toLowerCase())) { toast('That one’s already built in'); return; }
    customs.push(name.slice(0, 24));
    state.settings.customSymptoms = customs;
    saveState(); buildSymptomChips(); renderToday(); toast('Tag added');
  });
  box.appendChild(add);
}
function buildIntimacyChips() {
  const box = $('#intimacyChips'); if (!box) return;
  box.innerHTML = '';
  INTIMACY.forEach(([tag, label]) => {
    const c = document.createElement('button');
    c.className = 'chip'; c.dataset.tag = tag; c.textContent = label; c.type = 'button';
    c.addEventListener('click', () => c.classList.toggle('on'));
    box.appendChild(c);
  });
}

/* Collapsed-by-default sections keep the Today screen calm (and the private
 * log away from shoulder-surfers) — one tap opens them. */
$('#symptomToggle').addEventListener('click', () => {
  const wrap = $('#symptomWrap');
  const collapsed = wrap.classList.toggle('chips-collapsed');
  $('#symptomToggle').textContent = collapsed ? 'Show all' : 'Show less';
});
$('#intimacyToggle').addEventListener('click', () => {
  const chips = $('#intimacyChips');
  const nowHidden = chips.classList.toggle('hidden');
  $('#intimacyToggle').textContent = nowHidden ? 'Show — sex, EC & tests' : 'Hide';
});

// quick actions
$$('.quick-actions').forEach((row) => row.addEventListener('click', (e) => {
  const b = e.target.closest('.qa'); if (!b) return;
  const q = b.dataset.quick;
  if (q === 'period-start') startPeriod();
  if (q === 'patch-applied') applyPatchToday();
  if (q === 'patch-removed') removePatchToday();
  if (q === 'patch-detached') logPatchActionOn(todayISO(), 'detached');
}));

function applyPatchToday() { logPatchActionOn(todayISO(), 'apply'); }
function removePatchToday() { logPatchActionOn(todayISO(), 'remove'); }

// Log a patch apply/remove for any date (today or retroactive).
function logPatchActionOn(ds, action) {
  // If there's no schedule yet, the first applied patch anchors the cycle.
  if (action === 'apply' && !state.settings.patchStart) {
    state.settings.patchStart = ds;
    state.settings.onPatch = true;
  }
  const before = (state.patchActions || []).length;
  recordPatchAction(action, ds);
  const isNew = state.patchActions.length > before;
  // each newly-logged application uses one patch from the box
  if (action === 'apply' && isNew && state.settings.patchesLeft != null) {
    state.settings.patchesLeft = Math.max(0, state.settings.patchesLeft - 1);
  }
  saveState(); hydrateSettings(); renderAll();
  const a = assessPatch();
  const fallback = action === 'apply' ? 'Patch applied' : (action === 'detached' ? 'Fall-off logged — reapply or replace ASAP' : 'Patch removed');
  const msg = (a && a.level !== 'ok') ? a.title : fallback;
  if (isNew) {
    toastUndo(msg, () => {
      document.querySelector('.site-modal')?.remove();
      unlogPatchActionOn(ds, action);
      if (!$('#dayDetail').classList.contains('hidden')) showDayDetail(ds);
    });
  } else toast(msg);
  if (action === 'apply' && isNew) promptSiteFor(ds);
}

/* ---- Placement & rotation ---- */
function siteOf(dateStr) {
  const a = (state.patchActions || []).find((x) => x.date === dateStr && x.action === 'apply');
  return a ? a.site || null : null;
}
function lastSiteBefore(dateStr) {
  const prior = sortedActions().filter((a) => a.action === 'apply' && a.site && a.date < dateStr);
  return prior.length ? prior[prior.length - 1].site : null;
}
function setSite(dateStr, site) {
  const a = (state.patchActions || []).find((x) => x.date === dateStr && x.action === 'apply');
  if (!a) return;
  a.site = site || undefined;
  saveState(); renderAll();
  if (!$('#dayDetail').classList.contains('hidden')) showDayDetail(dateStr);
}
// Small overlay asking where the patch went, with a same-spot rotation warning.
function promptSiteFor(ds) {
  document.querySelector('.site-modal')?.remove();
  const prevSite = lastSiteBefore(ds);
  const cur = siteOf(ds);
  const m = document.createElement('div');
  m.className = 'site-modal';
  m.innerHTML = `<div class="site-sheet">
    <h3>Where did this patch go?</h3>
    <p class="muted small">Rotate sites each week to avoid skin irritation. Never on the breasts.</p>
    <div class="site-grid">${SITES.map((s) =>
      `<button class="btn btn-ghost${cur === s ? ' on-site' : ''}" data-site="${s}">${s}${prevSite === s ? ' ⟲' : ''}</button>`).join('')}
    </div>
    <div id="siteWarn" class="muted small" style="min-height:18px;margin-top:8px"></div>
    <button class="link-btn" data-site="">Skip</button>
  </div>`;
  m.addEventListener('click', (e) => {
    const b = e.target.closest('[data-site]');
    if (!b && e.target === m) { m.remove(); return; } // tap outside closes
    if (!b) return;
    const site = b.dataset.site;
    if (site && site === prevSite && !b.dataset.confirmed) {
      b.dataset.confirmed = '1';
      m.querySelector('#siteWarn').innerHTML =
        `<span style="color:var(--patch)">Same spot as your last patch — the leaflet says to use a different site. Tap again to log it anyway.</span>`;
      return;
    }
    if (site) { setSite(ds, site); toast(`Placement saved: ${site.toLowerCase()}`); }
    m.remove();
  });
  document.body.appendChild(m);
}
// Remove logged patch action(s) on a given date (to fix a mistake).
function unlogPatchActionOn(ds, action) {
  const before = (state.patchActions || []).length;
  state.patchActions = (state.patchActions || []).filter((a) => !(a.date === ds && a.action === action));
  // undoing a logged application puts the patch back in the box
  if (action === 'apply' && state.patchActions.length < before && state.settings.patchesLeft != null) {
    state.settings.patchesLeft += 1;
  }
  saveState(); renderAll(); toast('Removed log');
}
function patchActionsOn(ds) { return (state.patchActions || []).filter((a) => a.date === ds); }

function logBleedingRange(from) {
  const to = prompt('Last bleeding day (YYYY-MM-DD):', from);
  if (!to) return;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(to) || to < from) { toast('End must be a valid date on/after the start'); return; }
  if (daysBetween(from, to) > 20) { toast('That range is over 20 days — enter it in smaller chunks'); return; }
  const written = [];
  let d = parseISO(from);
  const e = parseISO(to);
  while (d <= e) {
    const ds = iso(d);
    const log = state.logs[ds] || { flow: '', bleedType: '', symptoms: [], tags: [], notes: '' };
    if (!log.flow) { log.flow = 'medium'; log.bleedType = 'withdrawal'; state.logs[ds] = log; written.push(ds); }
    d = addDays(d, 1);
  }
  if (!written.length) { toast('Those days already have flow logged'); return; }
  saveState(); renderAll(); showDayDetail(from);
  toastUndo(`Logged ${written.length} bleeding day${written.length === 1 ? '' : 's'}`, () => {
    for (const ds of written) {
      const log = state.logs[ds];
      if (!log) continue;
      log.flow = ''; log.bleedType = '';
      if (!log.symptoms?.length && !log.tags?.length && !log.notes) delete state.logs[ds];
    }
    saveState(); renderAll(); showDayDetail(from); toast('Range undone');
  });
}

/* ---- Calendar ---- */
let calCursor = today();
function renderCalendar() {
  const y = calCursor.getFullYear(), m = calCursor.getMonth();
  $('#calTitle').textContent = calCursor.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
  const grid = $('#calGrid'); grid.innerHTML = '';
  const first = new Date(y, m, 1);
  const startPad = first.getDay();
  const dim = new Date(y, m + 1, 0).getDate();
  const tISO = todayISO();
  for (let i = 0; i < startPad; i++) grid.insertAdjacentHTML('beforeend', '<div class="cal-cell empty"></div>');
  for (let d = 1; d <= dim; d++) {
    const ds = `${y}-${pad(m + 1)}-${pad(d)}`;
    const info = dayInfo(ds);
    const cls = ['cal-cell'];
    if (ds === tISO) cls.push('today');
    if (info.period) cls.push('period-bg');
    else if (info.patchfree) cls.push('patchfree-bg');
    const marks = [];
    // logged patch actions first (your real history), shown as ringed dots
    const acts = patchActionsOn(ds);
    if (acts.some((a) => a.action === 'apply')) marks.push('act-apply');
    if (acts.some((a) => a.action === 'remove' || a.action === 'detached')) marks.push('act-remove');
    if (info.period) marks.push('period');
    if (info.predicted) marks.push('predicted');
    if (info.fertile) marks.push('fertile');
    if (info.ovul) marks.push('ovul');
    if (info.patch) marks.push('patch');
    if (info.patchfree) marks.push('patchfree');
    if (info.note && !info.period) marks.push('note');
    if ((state.appointments || []).some((a) => a.date === ds)) marks.push('appt');
    if (testsOn(ds).length) marks.unshift('test');
    const dots = marks.slice(0, 4).map((c) => `<span class="mark ${c}"></span>`).join('');
    const cell = document.createElement('div');
    cell.className = cls.join(' ');
    cell.dataset.date = ds;
    cell.innerHTML = `<span>${d}</span><span class="marks">${dots}</span>`;
    cell.addEventListener('click', () => showDayDetail(ds));
    grid.appendChild(cell);
  }
}
$('#calPrev').addEventListener('click', () => { calCursor = new Date(calCursor.getFullYear(), calCursor.getMonth() - 1, 1); renderCalendar(); $('#dayDetail').classList.add('hidden'); });
$('#calNext').addEventListener('click', () => { calCursor = new Date(calCursor.getFullYear(), calCursor.getMonth() + 1, 1); renderCalendar(); $('#dayDetail').classList.add('hidden'); });

function showDayDetail(ds) {
  $$('#calGrid .cal-cell').forEach((c) => c.classList.toggle('sel', c.dataset.date === ds));
  const info = dayInfo(ds);
  const log = state.logs[ds] || {};
  const tag = (cls, label) => `<span class="d-tag"><i class="dot ${cls}"></i>${label}</span>`;
  const tags = [];
  if (info.period) tags.push(tag('period', 'Period'));
  if (info.predicted) tags.push(tag('predicted', 'Predicted period'));
  if (info.ovul) tags.push(tag('ovul', 'Predicted ovulation'));
  if (info.fertile) tags.push(tag('fertile', 'Fertile window'));
  if (info.patch) tags.push(tag('patch', 'Patch on'));
  if (info.patchfree) tags.push(tag('patchfree', 'Patch-free'));
  const acts = patchActionsOn(ds);
  const appliedHere = acts.some((a) => a.action === 'apply');
  const removedHere = acts.some((a) => a.action === 'remove');
  const detachedHere = acts.some((a) => a.action === 'detached');
  if (appliedHere) tags.push(tag('act-apply', 'Applied (logged)'));
  if (removedHere) tags.push(tag('act-remove', 'Removed (logged)'));
  if (detachedHere) tags.push(tag('act-remove', 'Fell off (logged)'));
  for (const t of testsOn(ds)) tags.push(tag('test', `Test: ${TEST_LABELS[t.result].toLowerCase()}`));
  const box = $('#dayDetail'); box.classList.remove('hidden');
  box.innerHTML = `
    <div class="card-head"><h2>${fmtDate(ds, { weekday: 'long', month: 'long', day: 'numeric' })}</h2></div>
    <p class="muted small d-tags">${tags.join('') || 'Nothing logged'}</p>
    <div class="log-row"><label>Flow strength</label>
      <div class="seg" id="dFlow">${flowSegHTML(log.flow || '')}</div>
    </div>
    <div class="log-row${log.flow ? '' : ' inactive'}" id="dBleedTypeRow"><label>Bleeding type <span class="muted" style="font-weight:400">— counts as your period unless marked breakthrough</span></label>
      <div class="seg" id="dBleedType">
        <button data-val="withdrawal" class="${log.bleedType === 'breakthrough' ? '' : 'on'}">Withdrawal</button>
        <button data-val="breakthrough" class="${log.bleedType === 'breakthrough' ? 'on' : ''}">Breakthrough</button>
      </div>
    </div>
    <div class="log-row"><label>Symptoms</label>
      <div class="chips" id="dSymptoms">${allSymptoms().map((s) =>
        `<button class="chip${(log.symptoms || []).includes(s) ? ' on' : ''}" data-sym="${escapeHtml(s)}" type="button">${escapeHtml(s)}</button>`).join('')}</div>
    </div>
    <div class="log-row"><label>Private log</label>
      <div class="chips" id="dTags">${INTIMACY.map(([t, l]) =>
        `<button class="chip${(log.tags || []).includes(t) ? ' on' : ''}" data-tag="${t}" type="button">${l}</button>`).join('')}</div>
    </div>
    <div class="log-row"><label>Notes</label>
      <textarea id="dNotes" rows="2" placeholder="Notes for this day…">${log.notes ? escapeHtml(log.notes) : ''}</textarea>
    </div>
    <button class="btn btn-primary full" data-act="save">Save this day</button>
    <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
      <button class="btn btn-ghost btn-ic" data-act="ps" style="flex:1">${hasStartMarker(ds)
        ? '✕ Unmark period start'
        : ic('drop', 'var(--period)', 'b-ic') + 'Period started this day'}</button>
      <button class="btn btn-ghost btn-ic" data-act="range" style="flex:1">${ic('calendar', 'var(--period)', 'b-ic')}Log bleeding range</button>
    </div>
    <p class="muted small" style="margin:8px 0 0">A period's end is implied automatically — it's the
      last bleeding day you log before a gap. Use the mark above if day 1 was only spotting.</p>
    <div class="log-row" style="margin-top:8px"><label>Patch (log for this day)</label>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-ghost btn-ic" data-act="${appliedHere ? 'unapply' : 'apply'}" style="flex:1">${appliedHere ? '✕ Undo applied' : ic('bandage', 'var(--patch)', 'b-ic') + 'Applied patch'}</button>
        <button class="btn btn-ghost btn-ic" data-act="${removedHere ? 'unremove' : 'remove'}" style="flex:1">${removedHere ? '✕ Undo removed' : ic('moon', 'var(--patchfree)', 'b-ic') + 'Removed patch'}</button>
        <button class="btn btn-ghost btn-ic" data-act="${detachedHere ? 'undetach' : 'detach'}" style="flex:1">${detachedHere ? '✕ Undo fell off' : ic('warn', 'var(--muted)', 'b-ic') + 'Fell off'}</button>
      </div>
      ${appliedHere ? `<button class="link-btn" data-act="site" style="margin-top:8px">Placement: ${siteOf(ds) ? siteOf(ds).toLowerCase() : 'not set'} — change</button>` : ''}
    </div>`;
  box.querySelector('#dFlow').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    box.querySelectorAll('#dFlow button').forEach((x) => x.classList.toggle('on', x === b));
    box.querySelector('#dBleedTypeRow').classList.toggle('inactive', !b.dataset.val);
  });
  box.querySelector('#dBleedType').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    box.querySelectorAll('#dBleedType button').forEach((x) => x.classList.toggle('on', x === b));
  });
  box.querySelector('#dSymptoms').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    b.classList.toggle('on');
  });
  box.querySelector('#dTags').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    b.classList.toggle('on');
  });
  box.querySelector('[data-act="save"]').addEventListener('click', () => {
    const flow = (box.querySelector('#dFlow button.on') || {}).dataset?.val ?? '';
    const bleedType = flow ? ((box.querySelector('#dBleedType button.on') || {}).dataset?.val ?? 'withdrawal') : '';
    const notes = box.querySelector('#dNotes').value.trim();
    const symptoms = [...box.querySelectorAll('#dSymptoms .chip.on')].map((c) => c.dataset.sym);
    const tags = [...box.querySelectorAll('#dTags .chip.on')].map((c) => c.dataset.tag);
    if (!flow && !notes && !symptoms.length && !tags.length) delete state.logs[ds];
    else state.logs[ds] = { flow, bleedType, symptoms, tags, notes };
    // periods are derived from consecutive bleeding days — no manual entry needed
    saveState(); renderAll(); showDayDetail(ds); toast('Day saved');
  });
  box.querySelector('[data-act="ps"]').addEventListener('click', () => {
    if (hasStartMarker(ds)) unmarkStart(ds); else startPeriod(ds);
    showDayDetail(ds);
  });
  box.querySelector('[data-act="range"]').addEventListener('click', () => logBleedingRange(ds));
  box.querySelector('[data-act^="apply"],[data-act^="unapply"]').addEventListener('click', (e) => {
    const act = e.currentTarget.dataset.act;
    if (act === 'apply') logPatchActionOn(ds, 'apply'); else unlogPatchActionOn(ds, 'apply');
    showDayDetail(ds);
  });
  box.querySelector('[data-act^="remove"],[data-act^="unremove"]').addEventListener('click', (e) => {
    const act = e.currentTarget.dataset.act;
    if (act === 'remove') logPatchActionOn(ds, 'remove'); else unlogPatchActionOn(ds, 'remove');
    showDayDetail(ds);
  });
  box.querySelector('[data-act^="detach"],[data-act^="undetach"]').addEventListener('click', (e) => {
    const act = e.currentTarget.dataset.act;
    if (act === 'detach') logPatchActionOn(ds, 'detached'); else unlogPatchActionOn(ds, 'detached');
    showDayDetail(ds);
  });
  box.querySelector('[data-act="site"]')?.addEventListener('click', () => promptSiteFor(ds));
}
function escapeHtml(s) { return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

/* ---- Patch view ---- */
function renderPatch() {
  // live, honest status of the real situation
  const sc = $('#patchStatusCard');
  const a = assessPatch();
  if (a) {
    const m = LEVEL_META[a.level] || LEVEL_META.ok;
    sc.className = `status-card ${a.level}`;
    sc.innerHTML = `<h2 style="display:flex;align-items:center;gap:8px">${m.icon()}${a.title}</h2><p>${a.message}</p>` +
      (a.level === 'risk' ? `<p class="muted small" style="margin-top:8px">${GUIDE_DISCLAIMER}</p>` : '');
  } else {
    sc.className = '';
    sc.innerHTML = '';
  }
  $('#patchStart').value = state.settings.patchStart || '';
  $('#reminderTime').value = state.settings.reminderTime || '09:00';
  $('#edgeCheckReminder').checked = state.settings.edgeCheckReminder !== false;
  $('#backupReminder').checked = state.settings.backupReminder !== false;
  $('#patchesLeft').value = state.settings.patchesLeft ?? '';
  $('#patchExpiry').value = state.settings.patchExpiry || '';
  renderChangeDay();
  const box = $('#patchSchedule'); box.innerHTML = '';
  // be upfront when the schedule has re-anchored to logged reality
  const anchor = cycleAnchor();
  if (anchor && state.settings.patchStart && anchor !== state.settings.patchStart) {
    box.insertAdjacentHTML('beforeend',
      `<p class="muted small">${ic('calendar', 'var(--patchfree)', 'i-ic')} Schedule follows what you actually logged —
      your current cycle started <b>${fmtDate(anchor)}</b> (a logged patch restarted it). Reminders below and the
      calendar export use these real dates.</p>`);
  }
  const evs = patchEvents(10);
  if (!evs.length) { box.innerHTML = '<p class="muted small">Set your first-patch date above to see your schedule.</p>'; return; }
  const tISO = todayISO();
  evs.slice(0, 12).forEach((e) => {
    const dleft = daysBetween(tISO, e.date);
    let when = fmtDate(e.date);
    let cls = 'ev-date';
    if (dleft === 0) { when = 'Today'; cls = 'ev-due'; }
    else if (dleft === 1) { when = 'Tomorrow'; cls = 'ev-soon'; }
    else if (dleft > 1) when = `in ${dleft} days`;
    box.insertAdjacentHTML('beforeend',
      `<div class="ev"><span>${e.label}</span><span class="${cls}">${when}</span></div>`);
  });
}
$('#savePatch').addEventListener('click', () => {
  const v = $('#patchStart').value;
  state.settings.patchStart = v || null;
  state.settings.reminderTime = $('#reminderTime').value || '09:00';
  state.settings.edgeCheckReminder = $('#edgeCheckReminder').checked;
  state.settings.backupReminder = $('#backupReminder').checked;
  const pl = $('#patchesLeft').value.trim();
  state.settings.patchesLeft = pl === '' ? null : clampNum(pl, 0, 60, null);
  state.settings.patchExpiry = $('#patchExpiry').value || null;
  if (v) state.settings.onPatch = true;
  saveState(); hydrateSettings(); renderAll(); scheduleReminderTimer();
  toast('Patch schedule saved');
});

/* ---- Patch change day ---- */
function renderChangeDay() {
  const seg = $('#changeDaySeg'); if (!seg) return;
  const note = $('#changeDayNote');
  const currentWd = patchChangeWeekday();
  const selected = state.settings.patchDayOfWeek ?? currentWd;
  $$('#changeDaySeg button').forEach((b) => b.classList.toggle('on', Number(b.dataset.val) === selected));
  if (currentWd === null) {
    note.innerHTML = '<p class="muted small">Set your first-patch date above, then you can move your change day here.</p>';
    return;
  }
  const corr = changeDayCorrection();
  const derived = derivedChangeWeekday();
  if (!corr || corr.moved === 0) {
    note.innerHTML = `<p class="muted small">${ic('check', 'var(--ok)', 'i-ic')} Your changes land on
      <b>${WEEKDAYS[currentWd]}</b>${state.settings.patchDayOfWeek == null
        ? ', going by what you\'ve logged. If that\'s not your real change day, set it here and every reminder, prediction and calendar export will line up with it.'
        : ', matching what you set.'}</p>`;
    return;
  }
  const dir = corr.moved < 0 ? 'earlier' : 'later';
  note.innerHTML = `
    <div class="guidance ok" style="margin-top:8px">
      <h3>Schedule lined up to ${WEEKDAYS[corr.target]}</h3>
      <div>Your logs alone read as a <b>${WEEKDAYS[derived]}</b> change day, so Petal was ${Math.abs(corr.moved)}
      day${Math.abs(corr.moved) === 1 ? '' : 's'} out. Its cycle now starts <b>${fmtDate(corr.after)}</b>
      instead of ${fmtDate(corr.before)}, and reminders, the calendar, the ring and the .ics export all follow it.
      Nothing about the patch you're wearing changes — this only corrects what Petal believes.</div>
    </div>
    <p class="muted small">${corr.moved < 0
      ? `A single application logged a day late is enough to shift the whole schedule ${dir}; this pins it back.`
      : `This moves Petal's schedule ${Math.abs(corr.moved)} day${Math.abs(corr.moved) === 1 ? '' : 's'} <b>later</b>, which is right if ${WEEKDAYS[corr.target]} is genuinely the day you change on. If instead you want to <b>switch</b> to a new day, do it by changing early rather than late — a patch-free week stretched past 7 days is the one thing that can let ovulation resume.`}</p>`;
}
$('#changeDaySeg')?.addEventListener('click', (e) => {
  const b = e.target.closest('button'); if (!b) return;
  $$('#changeDaySeg button').forEach((x) => x.classList.toggle('on', x === b));
  state.settings.patchDayOfWeek = Number(b.dataset.val);
  saveState(); renderAll(); scheduleReminderTimer();
});

/* ---- Appointments & refills ---- */
function renderAppointments() {
  const box = $('#appointmentsList'); if (!box) return;
  const tISO = todayISO();
  const list = (state.appointments || []).slice().sort((a, b) => a.date.localeCompare(b.date));
  if (!list.length) { box.innerHTML = '<p class="muted small">No appointments or refills scheduled.</p>'; return; }
  box.innerHTML = list.map((a) => {
    const dleft = daysBetween(tISO, a.date);
    const when = dleft === 0 ? 'Today' : dleft === 1 ? 'Tomorrow' : dleft > 1 ? `in ${dleft} days` : fmtDate(a.date);
    return `<div class="h-item"><span>${a.type === 'refill' ? ic('backup', 'var(--fertile)', 'h-ic') : ic('calendar', 'var(--patchfree)', 'h-ic')} ${escapeHtml(a.label)}</span>
      <span class="${dleft <= 2 && dleft >= 0 ? '' : 'muted'}" style="display:flex;align-items:center;gap:8px">${when}
      <button class="link-btn" data-del="${a.id}" style="margin:0;font-size:12px">✕</button></span></div>`;
  }).join('');
  box.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', () => {
    state.appointments = state.appointments.filter((a) => a.id !== b.dataset.del);
    saveState(); renderAll();
  }));
}
$('#addAppointment')?.addEventListener('click', () => {
  const date = prompt('Date (YYYY-MM-DD):', todayISO());
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) { if (date !== null) toast('Use YYYY-MM-DD'); return; }
  const label = (prompt('What is it? (e.g. "Dr. Lee follow-up" or "Pharmacy refill")') || '').trim();
  if (!label) return;
  const type = /refill|pharmacy|prescription/i.test(label) ? 'refill' : 'appointment';
  state.appointments = state.appointments || [];
  state.appointments.push({ id: crypto.randomUUID(), date, label: label.slice(0, 60), type });
  saveState(); renderAll();
  toast('Added');
});

/* ---- Pregnancy test log ---- */
function renderPregnancyTests() {
  const box = $('#testHistory'); if (!box) return;
  const sum = $('#testSummary');
  const list = allPregnancyTests().slice().reverse(); // newest first
  if (!list.length) {
    sum.innerHTML = '';
    box.innerHTML = '<p class="muted small">No tests logged yet. Petal watches your bleed timing and suggests testing when it\'s warranted — log the result here either way, so the pregnancy check above can use it.</p>';
    return;
  }
  const FOLLOW_UP = {
    positive: 'Talk with a clinician to confirm and discuss next steps.',
    faint: 'A faint line usually still means positive — retest in 2–3 days with first-morning urine.',
    negative: 'Good news — not pregnant. If your bleed still hasn\'t arrived a week after this test, take one more to be sure.',
    invalid: 'An invalid test tells you nothing either way — retest with a fresh one.',
  };
  const last = list[0];
  const [lIcon, lColor] = TEST_META[last.result];
  const lBorder = last.result === 'positive' || last.result === 'faint'
    ? ' style="border-left:3px solid var(--accent)"'
    : last.result === 'negative' ? ' style="border-left:3px solid var(--ok)"' : '';
  sum.innerHTML = `<div class="insight-line"${lBorder}>${ic(lIcon, lColor, 'i-ic')} Last test: <b>${TEST_LABELS[last.result].toLowerCase()}</b> · ${fmtDate(last.date)}. ${FOLLOW_UP[last.result]}</div>` +
    (last.result === 'positive' || last.result === 'faint' ? `<p class="muted small" style="margin:6px 0 0">${GUIDE_DISCLAIMER}</p>` : '');
  box.innerHTML = list.slice(0, 20).map((t) => {
    const [icn, color] = TEST_META[t.result];
    const extras = [testContext(t.date), t.note ? escapeHtml(t.note) : '', t.source === 'log' ? 'from day log' : '']
      .filter(Boolean).join(' · ');
    return `<div class="h-item"><span>${ic(icn, color, 'h-ic')} <b>${TEST_LABELS[t.result]}</b> · ${fmtDate(t.date)}</span>
      <span class="muted" style="display:flex;align-items:center;gap:8px">${extras}${t.source === 'test'
        ? `<button class="link-btn" data-del-test="${t.id}" style="margin:0;font-size:12px">✕</button>` : ''}</span></div>`;
  }).join('');
  box.querySelectorAll('[data-del-test]').forEach((b) => b.addEventListener('click', () => {
    state.tests = (state.tests || []).filter((t) => t.id !== b.dataset.delTest);
    saveState(); renderAll(); toast('Test removed');
  }));
}
$('#addTest')?.addEventListener('click', () => {
  const nowOpen = !$('#testForm').classList.toggle('hidden');
  $('#addTest').textContent = nowOpen ? 'Cancel' : '+ Log a pregnancy test';
  if (nowOpen) {
    $('#testDate').value = todayISO();
    $('#testNote').value = '';
    $$('#testResultSeg button').forEach((b) => b.classList.remove('on'));
  }
});
$('#testResultSeg')?.addEventListener('click', (e) => {
  const b = e.target.closest('button'); if (!b) return;
  $$('#testResultSeg button').forEach((x) => x.classList.toggle('on', x === b));
});
$('#saveTest')?.addEventListener('click', () => {
  const date = $('#testDate').value;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) { toast('Pick the test date'); return; }
  if (date > todayISO()) { toast('That date is in the future'); return; }
  const result = ($('#testResultSeg button.on') || {}).dataset?.val;
  if (!result) { toast('Pick a result'); return; }
  const t = { id: crypto.randomUUID(), date, result, note: $('#testNote').value.trim().slice(0, 60) };
  state.tests = state.tests || [];
  state.tests.push(t);
  $('#testForm').classList.add('hidden');
  $('#addTest').textContent = '+ Log a pregnancy test';
  saveState(); renderAll();
  toastUndo('Test logged', () => {
    state.tests = state.tests.filter((x) => x.id !== t.id);
    saveState(); renderAll(); toast('Removed');
  });
});

/* ---- Doctor-visit questions ---- */
function renderDoctorQuestions() {
  const box = $('#doctorQuestions'); if (!box) return;
  const list = state.settings.doctorQuestions || [];
  if (!list.length) { box.innerHTML = '<p class="muted small">No questions saved yet.</p>'; return; }
  box.innerHTML = list.map((q, i) =>
    `<div class="h-item"><span>${escapeHtml(q)}</span><button class="link-btn" data-qi="${i}" style="margin:0;font-size:12px">✕</button></div>`).join('');
  box.querySelectorAll('[data-qi]').forEach((b) => b.addEventListener('click', () => {
    state.settings.doctorQuestions.splice(Number(b.dataset.qi), 1);
    saveState(); renderDoctorQuestions();
  }));
}
$('#addDoctorQuestion')?.addEventListener('click', () => {
  const q = (prompt('Question to bring up at your next appointment:') || '').trim();
  if (!q) return;
  state.settings.doctorQuestions = state.settings.doctorQuestions || [];
  state.settings.doctorQuestions.push(q.slice(0, 140));
  saveState(); renderDoctorQuestions();
});
$('#exportIcs').addEventListener('click', exportICS);

// "What if I'm off-schedule?" helper
const HELP_MAP = {
  change1: () => lateGuidance('change-late', 24),
  change2: () => lateGuidance('change-late', 60),
  newcycle: () => lateGuidance('newcycle-late', 24),
  lefton: () => lateGuidance('left-on-late'),
  detach1: () => lateGuidance('detached', 12),
  detach2: () => lateGuidance('detached', 30),
};
document.querySelector('.helper-btns').addEventListener('click', (e) => {
  const b = e.target.closest('[data-help]'); if (!b) return;
  const g = HELP_MAP[b.dataset.help](); if (!g) return;
  $('#helperResult').innerHTML =
    `<div class="guidance ${g.level}"><h3>${g.title}</h3><div>${g.message}</div>` +
    `<div class="disc">${GUIDE_DISCLAIMER}</div></div>`;
});

/* ---- Insights ---- */
function renderRotationMap() {
  const box = $('#rotationMap'); if (!box) return;
  const ss = siteStats();
  if (!ss.applies) {
    box.innerHTML = '<p class="muted small">Log a Zafemy application from the Calendar, then choose a placement to build your rotation map.</p>';
    return;
  }
  const max = Math.max(...Object.values(ss.counts), 1);
  const nextSet = new Set(ss.nextSites);
  box.innerHTML = `
    <div class="rotation-grid">
      ${SITES.map((site) => {
        const count = ss.counts[site] || 0;
        const cls = [site === ss.lastSite ? 'last' : '', nextSet.has(site) ? 'next' : ''].filter(Boolean).join(' ');
        return `<div class="site-tile ${cls}">
          <span>${site}</span>
          <b>${count}</b>
          <i style="width:${Math.max(8, Math.round(100 * count / max))}%"></i>
        </div>`;
      }).join('')}
    </div>
    <div class="insight-line">${ic('sparkle', 'var(--ok)', 'i-ic')} Suggested next area: <b>${ss.nextSites.length ? ss.nextSites[0].toLowerCase() : 'any approved area'}</b>${ss.lastSite ? `; avoid repeating <b>${ss.lastSite.toLowerCase()}</b> next.` : '.'}</div>
    ${ss.sameRepeats ? `<div class="insight-line">${ic('warn', 'var(--patch)', 'i-ic')} Same-site repeats logged: <b>${ss.sameRepeats}</b>.</div>` : ''}
    ${ss.missing ? `<p class="muted small">Missing placement on ${ss.missing} application${ss.missing === 1 ? '' : 's'}.</p>` : ''}`;
}

function renderPatternFlags() {
  const box = $('#patternFlags'); if (!box) return;
  const flags = patternFlags();
  if (!flags.length) {
    box.innerHTML = `<div class="insight-line">${ic('check', 'var(--ok)', 'i-ic')} No timing, rotation, backup, or bleeding pattern flags right now.</div>`;
    return;
  }
  box.innerHTML = flags.slice(0, 8).map((f) =>
    `<div class="insight-line${f.level === 'risk' ? ' flag-risk' : ''}">${ic(f.icon, f.color, 'i-ic')} ${f.text}</div>`).join('');
}

function renderInsights() {
  const s = cycleStats();
  const bts = bleedTypeStats();
  const box = $('#insights');
  box.innerHTML = `
    <div class="stat"><div class="big">${s.avgCycle}</div><div class="lbl">avg cycle (days)</div></div>
    <div class="stat"><div class="big">${s.avgPeriod || '—'}</div><div class="lbl">avg period (days)</div></div>
    <div class="stat"><div class="big">${s.count}</div><div class="lbl">cycles logged</div></div>
    <div class="stat"><div class="big">${variability(s.lengths)}</div><div class="lbl">regularity</div></div>
    <div class="stat"><div class="big">${bts.withdrawalDays}</div><div class="lbl">${state.settings.onPatch ? 'withdrawal bleed' : 'period'} days</div></div>
    <div class="stat"><div class="big">${bts.breakthroughDays}</div><div class="lbl">breakthrough days</div></div>`;

  // where you are in the cycle right now
  const pc = $('#phaseCard');
  const phase = phaseInfo();
  if (!phase) {
    pc.innerHTML = '<p class="muted small">Set your patch schedule or log a period and your current phase shows here.</p>';
  } else {
    pc.innerHTML = `
      <div class="insights" style="margin-bottom:10px">
        <div class="stat"><div class="big">${phase.cycleDay}</div><div class="lbl">day of ${phase.cycleLen}</div></div>
        <div class="stat"><div class="big" style="font-size:19px;line-height:1.2;padding-top:6px">${phase.label}</div><div class="lbl">current phase</div></div>
      </div>
      <div class="insight-line">${ic(phase.mode === 'patch' ? 'bandage' : 'sparkle', phase.mode === 'patch' ? 'var(--patch)' : 'var(--ovul)', 'i-ic')} ${phase.detail.charAt(0).toUpperCase() + phase.detail.slice(1)}.${phase.bleedDay ? ` Bleeding day <b>${phase.bleedDay}</b>.` : ''}</div>
      ${(() => {
        const nb = nextBleedPrediction();
        if (!nb) return '';
        return `<div class="insight-line">${ic('drop', 'var(--period)', 'i-ic')} Next withdrawal bleed expected around <b>${fmtDate(nb.expected)}</b>${nb.overdue ? ' — <b>hasn’t arrived yet</b>; the pregnancy check below is watching it' : ''} <span class="muted small">(removal ${fmtDate(nb.removal, { month: 'short', day: 'numeric' })} + ${nb.personalized ? `your usual ${nb.offset}-day delay` : `a typical ${nb.offset}-day delay`})</span>.</div>`;
      })()}
      ${phase.mode === 'patch' ? `<div class="insight-line muted small">On the patch there's no follicular/ovulation/luteal cycle — hormones stay steady, then drop in the patch-free week. That drop is what causes the withdrawal bleed.</div>` : `<div class="insight-line muted small">Phases estimated from your ${phase.cycleLen}-day average (${predictionConfidence()}).</div>`}`;
  }

  // pregnancy check — timing-based, factual
  const pg = $('#pregCheck');
  const preg = pregnancyCheck();
  const bh = bleedingHealth();
  const PREG_META = { none: ['check', 'var(--ok)'], info: ['clock', 'var(--patch)'], test: ['warn', 'var(--accent)'] };
  const [pIcon, pColor] = PREG_META[preg.level];
  const rcForCard = state.settings.onPatch ? riskCrossref() : null;
  const windowsDetail = rcForCard && rcForCard.windows.length
    ? `<details class="risk-windows-detail"><summary>${rcForCard.windows.length} reduced-protection window${rcForCard.windows.length === 1 ? '' : 's'} from your logged patch timing</summary>` +
      rcForCard.windows.map((w) => `<div class="insight-line small ${rcForCard.hits.some((h) => h >= w.from && h <= w.to) ? '' : 'muted'}">${fmtDate(w.from)} – ${fmtDate(w.to)} — ${RISK_CAUSE[w.cause] || 'gap in logged patch timing'}${w.open ? ', still open (no patch logged as applied since)' : ''}${rcForCard.hits.some((h) => h >= w.from && h <= w.to) ? '; unprotected sex logged' : ''}</div>`).join('') +
      `<p class="muted small">Scheduled patch-free weeks are not listed here — those are the method working normally, not a gap.</p>` +
      `</details>`
    : '';
  pg.innerHTML = preg.lines.map((l, i) =>
    `<div class="insight-line"${preg.level === 'test' && i === 0 ? ' style="border-left:3px solid var(--accent)"' : ''}>${i === 0 ? ic(pIcon, pColor, 'i-ic') + ' ' : ''}${l}</div>`).join('') +
    windowsDetail +
    (preg.level !== 'none' ? `<div class="insight-line muted small">Taken a test? Log it in the “Pregnancy tests” card below — Petal factors the result into this check.</div>` : '') +
    (preg.level === 'test' ? `<p class="muted small" style="margin-top:6px">${GUIDE_DISCLAIMER}</p>` : '') +
    bh.map((l) => `<div class="insight-line">${ic('drop', 'var(--period)', 'i-ic')} ${l}</div>`).join('') +
    (() => {
      const t = bleedLengthTrend();
      if (!t || t.dir === 'steady') return '';
      return `<div class="insight-line">${ic('sparkle', 'var(--fertile)', 'i-ic')} Your bleeds have gotten <b>${t.dir}</b> — from about ${t.early}d to ${t.late}d over your last ${t.n} cycles.</div>`;
    })() +
    (() => {
      const d = detachmentPatterns();
      if (!d) return '';
      if (!d.topSite) return `<div class="insight-line">${ic('warn', 'var(--muted)', 'i-ic')} You've logged ${d.total} patch fall-offs. Log the placement each time and Petal can tell you if one spot is the culprit.</div>`;
      return `<div class="insight-line">${ic('warn', 'var(--patch)', 'i-ic')} ${d.topCount} of your ${d.sited} sited fall-offs were on the <b>${d.topSite.toLowerCase()}</b> — consider rotating away from that spot.</div>`;
    })();

  // ovulation insight
  const ob = $('#ovulationInsight');
  if (state.settings.onPatch) {
    const np = predictNextPeriod();
    ob.innerHTML = `
      <div class="insight-line">${ic('bandage', 'var(--patch)', 'i-ic')} <b>You're using the combined patch.</b> It works mainly by
      <b>suppressing ovulation</b>, so while you wear it consistently you generally don't ovulate —
      there's no fertile window to predict.</div>
      <div class="insight-line">${ic('moon', 'var(--patchfree)', 'i-ic')} The bleeding in your <b>patch-free week</b> is a
      <b>withdrawal bleed</b>, not a true period. ${patchFreeNext()}</div>
      <div class="insight-line muted small">If you stop the patch, turn off “Currently using the patch”
      in Settings and Petal will estimate your fertile window from your logged cycles.</div>`;
  } else {
    const np = predictNextPeriod();
    if (np) {
      const ovul = iso(addDays(parseISO(np), -state.settings.lutealLen));
      const fStart = iso(addDays(parseISO(ovul), -5));
      ob.innerHTML = `
        <div class="insight-line">${ic('sparkle', 'var(--ovul)', 'i-ic')} Estimated <b>ovulation: ${fmtDate(ovul)}</b>
        (about ${state.settings.lutealLen} days before your next predicted period).</div>
        <div class="insight-line">${ic('drop', 'var(--fertile)', 'i-ic')} Most fertile window: <b>${fmtDate(fStart)} – ${fmtDate(ovul)}</b>.</div>
        <div class="insight-line muted small">Estimate ${predictionConfidence()}, using your average cycle and luteal
        phase — actual ovulation varies. Not a contraceptive method.</div>`;
    } else {
      ob.innerHTML = '<div class="insight-line muted">Log a couple of periods to estimate ovulation.</div>';
    }
  }

  // cycle comparison — each cycle as a bar aligned to day 1 (bleed in pink)
  const cc = $('#cycleCompare');
  const psAsc = sortedPeriods();
  if (psAsc.length < 2) {
    cc.innerHTML = '<p class="muted small">Log at least two periods and each cycle shows up here as a bar — regularity at a glance.</p>';
  } else {
    const cycles = [];
    for (let i = 0; i < psAsc.length; i++) {
      const startD = psAsc[i].start;
      const next = psAsc[i + 1];
      const len = next ? daysBetween(startD, next.start) : daysBetween(startD, todayISO()) + 1;
      const bleedRaw = psAsc[i].end ? daysBetween(startD, psAsc[i].end) + 1 : Math.min(len, 5);
      const bleed = Math.min(Math.max(bleedRaw, 1), len);
      // closed cycles under 15 days are noise (e.g. two bleed episodes close together);
      // the trailing in-progress cycle shows at any length
      if (next ? (len >= 15 && len <= 60) : (len >= 1 && len <= 60)) {
        cycles.push({ start: startD, len, bleed, ongoing: !next });
      }
    }
    const show = cycles.slice(-6).reverse(); // newest first
    const maxLen = Math.max(...show.map((c) => c.len), state.settings.cycleLen);
    cc.innerHTML = !show.length
      ? '<p class="muted small">Not enough consecutive-bleeding history yet — log flow day-by-day and cycles will appear here.</p>'
      : show.map((c) => `
      <div class="cyc-row">
        <span class="cyc-date">${fmtDate(c.start, { month: 'short', day: 'numeric' })}</span>
        <div class="cyc-track">
          <div class="cyc-fill${c.ongoing ? ' ongoing' : ''}" style="width:${Math.round(100 * c.len / maxLen)}%">
            <i class="cyc-bleed" style="width:${Math.round(100 * c.bleed / c.len)}%"></i>
          </div>
        </div>
        <span class="cyc-len">${c.len}d${c.ongoing ? '…' : ''}</span>
      </div>`).join('') +
      `<p class="muted small" style="margin:8px 0 0">Pink = bleeding days. Bars line up at day 1${state.settings.onPatch ? ' — on the patch these are withdrawal bleeds' : ''}.</p>` +
      (() => {
        const tr = bleedLengthTrend();
        if (!tr) return '';
        if (tr.dir === 'steady') return `<div class="insight-line muted small" style="margin-top:8px">Bleed length is steady across your ${tr.n} logged bleeds.</div>`;
        return `<div class="insight-line" style="margin-top:8px">${ic('drop', 'var(--period)', 'i-ic')} Your bleeds have gotten <b>${tr.dir}</b> — about ${tr.early} days early on vs ${tr.late} days recently.${tr.dir === 'longer' ? ' Gradual is common, but a sudden jump is worth mentioning to a clinician.' : ' Lighter, shorter bleeds are typical as your body settles on the patch.'}</div>`;
      })();
  }

  // symptom patterns from calendar logs — natural-language insight cards first,
  // then the raw per-symptom counts
  const st = $('#symptomTrends');
  const trends = symptomTrends();
	  if (!trends || !trends.length) {
	    st.innerHTML = '<p class="muted small">Log symptoms on the Today screen and patterns will show up here — like whether cramps cluster in your patch-free week.</p>';
	  } else {
    const clustered = trends.filter((t) => t.clusters);
    const cards = clustered.slice(0, 4).map((t) => {
      const verb = t.dominant === 'free' ? 'usually occur during' : (t.share >= 0.7 ? 'peak during' : 'tend to happen most in');
      return `<div class="insight-line">${ic(t.dominant === 'free' ? 'moon' : 'sparkle', t.dominant === 'free' ? 'var(--patchfree)' : 'var(--patch)', 'i-ic')} <b>${escapeHtml(t.sym)}</b> ${verb} <b>${t.dominantLabel}</b> (${t[t.dominant]} of ${t.total} logs).</div>`;
    }).join('');
    const bt = bleedTimingInsight();
    const btCard = bt ? `<div class="insight-line">${ic('drop', 'var(--period)', 'i-ic')} You typically start bleeding <b>${bt.avg} day${bt.avg === 1 ? '' : 's'}</b> after removing a patch (based on ${bt.n} cycles).</div>` : '';
    const rows = trends.slice(0, 8).map((t) =>
      `<div class="h-item"><span>${escapeHtml(t.sym)}</span><span class="${t.clusters ? '' : 'muted'}">${t.clusters
        ? `${ic('moon', 'var(--patchfree)', 'h-ic')} ${t.dominantLabel} (${t[t.dominant]} of ${t.total})`
        : `${t.total}×`}</span></div>`).join('');
    st.innerHTML = cards + btCard + `<div class="history" style="margin-top:${cards || btCard ? '10px' : '0'}">${rows}</div>` + (clustered.length
      ? `<p class="muted small" style="margin-top:8px">Patterns tied to the patch-free week are typical hormone-withdrawal effects. If they're rough, ask your clinician about options — some people shorten the patch-free interval under medical guidance.</p>`
	      : '');
	  }

  const zi = $('#zafemyInsights');
  const z = zafemyStickerInsights();
  zi.innerHTML = `
    <div class="insights" style="margin-bottom:10px">
      ${z.stats.map(([label, value]) => `<div class="stat"><div class="big">${value}</div><div class="lbl">${label}</div></div>`).join('')}
    </div>
    ${z.lines.map((l) => `<div class="insight-line">${l}</div>`).join('')}
    <p class="muted small" style="margin-top:8px">Based on your logged Zafemy sticker dates, placement sites, removals, and fall-offs.</p>`;

  renderRotationMap();
  renderPatternFlags();

	  // adherence — the honest scoreboard of everything logged in the calendar
	  const ad = $('#adherence');
  const adh = patchAdherence();
  if (!adh) {
    ad.innerHTML = '<p class="muted small">Log your patch changes (Today screen or any day on the Calendar) and Petal will rate each one on time, early, or late — and track your protection.</p>';
  } else {
    const hfNote = adh.maxHF == null ? ''
      : `<div class="insight-line ${adh.maxHF > 7 ? '' : 'muted'} small">${adh.maxHF > 7
          ? ic('warn', 'var(--accent)', 'i-ic') + ` Longest hormone-free gap so far: <b>${adh.maxHF} days</b> — over the 7-day limit. That gap is when ovulation can resume.`
          : ic('check', 'var(--ok)', 'i-ic') + ` Longest hormone-free gap so far: <b>${adh.maxHF} days</b> — within the 7-day limit.`}</div>`;
    ad.innerHTML = `
      <div class="insights" style="margin-bottom:10px">
        <div class="stat"><div class="big">${adh.ontime}</div><div class="lbl">on time</div></div>
        <div class="stat"><div class="big">${adh.early}</div><div class="lbl">early</div></div>
        <div class="stat"><div class="big" style="color:${adh.late ? 'var(--patch)' : 'var(--text)'}">${adh.late}</div><div class="lbl">late</div></div>
        <div class="stat"><div class="big" style="color:${adh.risks ? 'var(--accent)' : 'var(--ok)'}">${adh.risks}</div><div class="lbl">risk events</div></div>
      </div>
      <div class="insight-line">${adh.streak >= 2
        ? ic('sparkle', 'var(--patch)', 'i-ic') + ` <b>${adh.streak} changes in a row</b> with protection maintained — keep it up!`
        : ic('check', 'var(--ok)', 'i-ic') + ` Protection maintained on <b>${adh.protectedRate}%</b> of your logged changes.`}</div>
      ${hfNote}
      ${(() => {
        const dp = detachmentPatterns();
        if (!dp) return '';
        if (!dp.top && !dp.topSite) return `<div class="insight-line muted small">${dp.total} fall-offs logged — add placements when you apply and Petal can spot which sites don't hold.</div>`;
        return `<div class="insight-line">${ic('warn', 'var(--patch)', 'i-ic')} <b>${dp.topCount} of your ${dp.total} fall-offs</b> were <b>${dp.topSite.toLowerCase()}</b> placements — that spot may not hold well for you (lotion, waistbands, and friction are common culprits).</div>`;
      })()}`;
  }

  // patch history (on time / late, derived from logged dates)
  const ph = $('#patchHistory'); ph.innerHTML = '';
  const STATUS_META = {
    ok: () => ic('check', 'var(--ok)', 'h-ic'),
    caution: () => ic('clock', 'var(--patch)', 'h-ic'),
    risk: () => ic('warn', 'var(--accent)', 'h-ic'),
  };
  const STATUS_COLOR = { ok: 'var(--ok)', caution: 'var(--patch)', risk: 'var(--accent)' };
  const hist = patchHistory();
  if (!hist.length) {
    ph.innerHTML = '<p class="muted small">No patch actions logged yet. Tap a day on the Calendar to log when you applied or removed a patch.</p>';
  } else {
    hist.slice(0, 20).forEach((e) => {
      const verb = e.action === 'apply'
        ? ic('bandage', 'var(--patch)', 'h-ic') + ' Applied'
        : (e.action === 'detached' ? ic('bandage', 'var(--muted)', 'h-ic') + ' Fell off'
        : ic('moon', 'var(--patchfree)', 'h-ic') + ' Removed');
      const place = e.action === 'apply' && e.site ? ` · ${e.site}` : '';
      ph.insertAdjacentHTML('beforeend',
        `<div class="h-item"><span>${verb} · ${fmtDate(e.date)}${place}</span>` +
        `<span style="color:${STATUS_COLOR[e.status]}">${STATUS_META[e.status]()} ${e.note}</span></div>`);
    });
  }

  // period history
  const h = $('#history'); h.innerHTML = '';
  const ps = sortedPeriods().slice().reverse();
  if (!ps.length) { h.innerHTML = '<p class="muted small">No periods logged yet.</p>'; }
  ps.slice(0, 12).forEach((p) => {
    const len = daysBetween(p.start, p.end || p.start) + 1;
    h.insertAdjacentHTML('beforeend',
      `<div class="h-item"><span>${fmtDate(p.start)}${p.ongoing ? ' (ongoing)' : ' – ' + fmtDate(p.end)}</span>
       <span class="muted">${len}d${p.ongoing ? '…' : ''}</span></div>`);
  });
}
function variability(lengths) {
  if (lengths.length < 2) return '—';
  const max = Math.max(...lengths), min = Math.min(...lengths);
  const spread = max - min;
  return spread <= 3 ? 'Regular' : spread <= 7 ? 'Slightly irregular' : 'Irregular';
}
function patchFreeNext() {
  const anchor = cycleAnchor();
  if (!anchor) return '';
  const evs = [];
  const start = parseISO(anchor);
  for (let c = 0; c < 6; c++) {
    const d = addDays(start, c * 28 + 21);
    if (d >= today()) { evs.push(iso(d)); }
  }
  return evs.length ? `Next patch-free week starts <b>${fmtDate(evs[0])}</b>.` : '';
}

/* ---- Settings ---- */
function hydrateSettings() {
  $('#cycleLen').value = state.settings.cycleLen;
  $('#lutealLen').value = state.settings.lutealLen;
  $('#onPatch').checked = !!state.settings.onPatch;
  $('#patchStart').value = state.settings.patchStart || '';
  $('#reminderTime').value = state.settings.reminderTime || '09:00';
  $('#edgeCheckReminder').checked = state.settings.edgeCheckReminder !== false;
  $('#backupReminder').checked = state.settings.backupReminder !== false;
  $('#patchesLeft').value = state.settings.patchesLeft ?? '';
}
$('#saveSettings').addEventListener('click', () => {
  state.settings.cycleLen = clampNum($('#cycleLen').value, 20, 45, 28);
  state.settings.lutealLen = clampNum($('#lutealLen').value, 10, 16, 14);
  state.settings.onPatch = $('#onPatch').checked;
  saveState(); renderAll(); toast('Settings saved');
});
function clampNum(v, lo, hi, fb) { v = parseInt(v, 10); if (isNaN(v)) return fb; return Math.min(hi, Math.max(lo, v)); }

function renderBackupHealth() {
  const box = $('#backupHealth'); if (!box) return;
  const last = state.settings.lastBackup;
  const age = last ? daysBetween(last, todayISO()) : null;
  const vault = localStorage.getItem(VAULT) || '';
  const level = !last || age >= 30 ? 'caution' : 'ok';
  box.innerHTML = `
    <div class="backup-health ${level}">
      <div>${ic(level === 'ok' ? 'check' : 'backup', level === 'ok' ? 'var(--ok)' : 'var(--fertile)', 'i-ic')} <b>${level === 'ok' ? 'Backup current' : 'Backup recommended'}</b></div>
      <p class="muted small">${last ? `Last encrypted export: ${fmtDate(last)} (${age} day${age === 1 ? '' : 's'} ago).` : 'No encrypted export logged yet.'} Vault size: ${Math.max(1, Math.round(vault.length / 1024))} KB.</p>
    </div>`;
}

$('#changePass').addEventListener('click', async () => {
  const p1 = prompt('New passcode:'); if (p1 === null) return;
  const p2 = prompt('Confirm new passcode:'); if (p2 === null) return;
  if (p1 !== p2) { alert('Passcodes do not match.'); return; }
  SALT = crypto.getRandomValues(new Uint8Array(16));
  ITER = PBKDF2_ITER;
  KEY = await deriveKey(p1, SALT, ITER);
  await saveState();
  toast('Passcode changed');
});

$('#checkUpdates').addEventListener('click', checkForAppUpdate);

$('#exportData').addEventListener('click', () => {
  const blob = new Blob([localStorage.getItem(VAULT)], { type: 'application/json' });
  downloadBlob(blob, `petal-backup-${todayISO()}.json`);
  state.settings.lastBackup = todayISO();
  saveState();
  renderBackupHealth();
  toast('Encrypted backup exported');
});
$('#importData').addEventListener('change', (e) => {
  const file = e.target.files[0]; if (!file) return;
  const r = new FileReader();
  r.onload = () => {
    try {
      const v = JSON.parse(r.result);
      if (!v.salt || !v.ct) throw new Error('bad');
      if (!confirm('Replace current data with this backup? You will unlock it with that backup\'s passcode.')) return;
      writeVault(v); location.reload();
    } catch { alert('Not a valid Petal backup.'); }
  };
  r.readAsText(file);
});
/* Doctor's report — a clean, human-readable summary you can print or show at an
 * appointment. Generated entirely on-device; plainly NOT encrypted, so we say so. */
function buildDoctorReport() {
  const s = cycleStats();
  const adh = patchAdherence();
  const trends = symptomTrends() || [];
  const psDesc = sortedPeriods().slice().reverse().slice(0, 12);
  const hist = patchHistory().slice(0, 14);
  const rf = refillStatus();
  const rc = riskCrossref();
  const row = (a, b) => `<tr><td>${escapeHtml(String(a ?? ''))}</td><td>${escapeHtml(String(b ?? ''))}</td></tr>`;
  const bleedRows = Object.entries(state.logs).filter(([, l]) => l.bleedType)
    .reduce((acc, [, l]) => { acc[l.bleedType] = (acc[l.bleedType] || 0) + 1; return acc; }, {});
  const siteRows = sortedActions().filter((a) => a.action === 'apply' && a.site).slice(-8).reverse();
  const appts = (state.appointments || []).slice().sort((a, b) => a.date.localeCompare(b.date));
  const testRows = allPregnancyTests().slice(-10).reverse();
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Petal — cycle report</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;max-width:640px;margin:32px auto;padding:0 16px;color:#222;line-height:1.5}
h1{font-size:22px}h2{font-size:16px;margin-top:26px;border-bottom:1px solid #ddd;padding-bottom:4px}
table{border-collapse:collapse;width:100%;font-size:14px}td{padding:5px 8px;border-bottom:1px solid #eee}
.meta{color:#666;font-size:13px}.warn{color:#a33}
@media print{.no-print{display:none}}</style></head><body>
<h1>Cycle &amp; contraception report</h1>
<p class="meta">Generated ${new Date().toLocaleDateString()} from Petal (self-tracked data — accuracy depends on what was logged).</p>
<h2>Summary</h2><table>
${row('Contraception', state.settings.onPatch ? 'Combined hormonal patch (3 weeks on / 1 week patch-free)' : 'None recorded / natural cycle')}
${row('Average cycle length', `${s.avgCycle} days (${s.lengths.length} measured cycle${s.lengths.length === 1 ? '' : 's'})`)}
${row('Average bleed length', s.avgPeriod ? `${s.avgPeriod} days` : 'not enough data')}
${row('Regularity', variability(s.lengths))}
${adh ? row('Patch changes logged', `${adh.rated} rated — ${adh.ontime} on time, ${adh.early} early, ${adh.late} late; ${adh.risks} with possible reduced protection`) : ''}
${adh && adh.maxHF != null ? row('Longest hormone-free interval', `${adh.maxHF} days ${adh.maxHF > 7 ? '(exceeded the 7-day limit)' : '(within the 7-day limit)'}`) : ''}
${rf ? row('Patches on hand', `${rf.left}${rf.outDate ? ` — projected to run out ${fmtDate(rf.outDate)}` : ''}`) : ''}
${state.settings.patchExpiry ? row('Prescription/box expiration', fmtDate(state.settings.patchExpiry, { year: 'numeric', month: 'short', day: 'numeric' })) : ''}
</table>
<h2>Recent bleeds</h2><table>
${psDesc.map((p) => row(fmtDate(p.start, { year: 'numeric', month: 'short', day: 'numeric' }),
  p.ongoing ? `ongoing (${daysBetween(p.start, p.end) + 1} days so far)` : `${daysBetween(p.start, p.end || p.start) + 1} days (to ${fmtDate(p.end || p.start, { month: 'short', day: 'numeric' })})`)).join('') || row('—', 'none logged')}
</table>
${Object.keys(bleedRows).length ? `<h2>Bleeding type (self-reported)</h2><table>
${Object.entries(bleedRows).map(([k, v]) => row(k === 'withdrawal' ? 'Withdrawal bleed' : k === 'breakthrough' ? 'Breakthrough bleeding' : 'Unspecified', `${v}×`)).join('')}
</table>` : ''}
${hist.length ? `<h2>Recent patch events</h2><table>
${hist.map((e) => row(`${fmtDate(e.date, { year: 'numeric', month: 'short', day: 'numeric' })} — ${e.action}`, e.note)).join('')}
</table>` : ''}
${siteRows.length ? `<h2>Patch placement (rotation)</h2><table>
${siteRows.map((a) => row(fmtDate(a.date, { year: 'numeric', month: 'short', day: 'numeric' }), a.site)).join('')}
</table>` : ''}
${trends.length ? `<h2>Symptoms</h2><table>
${trends.slice(0, 10).map((t) => row(t.sym, `${t.total}× logged${t.clusters ? ` — mostly ${t.dominantLabel} (${t[t.dominant]} of ${t.total})` : ''}`)).join('')}
</table>` : ''}
${rc && rc.windows.length ? `<h2>Reduced-protection windows (from logged patch timing)</h2><table>
${rc.windows.map((w) => row(`${fmtDate(w.from, { month: 'short', day: 'numeric' })} – ${fmtDate(w.to, { month: 'short', day: 'numeric' })}`, rc.hits.some((h) => h >= w.from && h <= w.to) ? 'Unprotected sex logged in this window' : 'No unprotected sex logged')).join('')}
</table>` : ''}
${testRows.length ? `<h2>Pregnancy tests (self-reported)</h2><table>
${testRows.map((t) => row(`${fmtDate(t.date, { year: 'numeric', month: 'short', day: 'numeric' })}${testContext(t.date) ? ` (${testContext(t.date)})` : ''}`, `${TEST_LABELS[t.result]}${t.note ? ` — ${t.note}` : ''}`)).join('')}
</table>` : ''}
${appts.length ? `<h2>Appointments &amp; refills</h2><table>
${appts.map((a) => row(fmtDate(a.date, { year: 'numeric', month: 'short', day: 'numeric' }), a.label)).join('')}
</table>` : ''}
${(state.settings.doctorQuestions || []).length ? `<h2>Questions to discuss</h2><table>
${state.settings.doctorQuestions.map((q) => row('•', q)).join('')}
</table>` : ''}
<p class="meta warn">This file is not encrypted. Share it only with people you trust, and delete copies you no longer need.</p>
</body></html>`;
}
$('#exportReport').addEventListener('click', () => {
  if (!confirm('This creates a READABLE (unencrypted) summary for a clinician. Only share it with people you trust. Continue?')) return;
  downloadBlob(new Blob([buildDoctorReport()], { type: 'text/html' }), `petal-report-${todayISO()}.html`);
  toast('Report exported — open or AirDrop it');
});
$('#printReport').addEventListener('click', () => {
  if (!confirm('This opens a READABLE (unencrypted) summary for printing/saving as PDF. Continue?')) return;
  const win = window.open('', '_blank');
  if (!win) { toast('Allow pop-ups to preview the report'); return; }
  win.document.write(buildDoctorReport());
  win.document.close();
  setTimeout(() => { try { win.print(); } catch {} }, 300);
});

$('#eraseData').addEventListener('click', () => {
  if (confirm('Erase ALL data permanently? This cannot be undone.')) { localStorage.removeItem(VAULT); location.reload(); }
});

/* ============================================================ Tabs ======== */
$$('.tab').forEach((t) => t.addEventListener('click', () => {
  $$('.tab').forEach((x) => x.classList.toggle('active', x === t));
  const view = t.dataset.view;
  $$('.view').forEach((v) => v.classList.add('hidden'));
  $(`#view-${view}`).classList.remove('hidden');
  const v = $('#views'); if (v) v.scrollTop = 0;
}));

/* ============================================================ Reminders ==== */
async function requestNotifyPermission() {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'default') {
    try { await Notification.requestPermission(); } catch {}
  }
}
// Fire a notification for a patch task due today (best-effort, only while app/SW alive)
function reminderEventsForDate(dateStr) {
  const events = [];
  const task = patchEvents(26).find((e) => e.date === dateStr);
  if (task) events.push({ kind: 'patch', label: task.label });
  const wear = dateStr === todayISO() ? currentPatchWear() : null;
  const onForDate = dateStr === todayISO() ? wear.patchOn : isPatchOn(patchCycleDay(dateStr));
  if (state.settings.edgeCheckReminder !== false && onForDate && !task) {
    events.push({ kind: 'edge', label: 'Check Zafemy edges and placement' });
  }
  const lastBackup = state.settings.lastBackup;
  const backupDue = state.settings.backupReminder !== false
    && (!lastBackup || daysBetween(lastBackup, dateStr) >= 30);
  if (backupDue && dateStr === todayISO()) events.push({ kind: 'backup', label: 'Export encrypted Petal backup' });
  return events;
}

function fireTodayNotificationIfDue() {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const ev = reminderEventsForDate(todayISO())[0];
  if (!ev) return;
  const key = 'petal.notified.' + todayISO() + '.' + ev.kind;
  if (localStorage.getItem(key)) return;
  localStorage.setItem(key, '1');
  try { new Notification('Petal — patch reminder', { body: ev.label, icon: './icon-192.png', tag: 'patch' }); } catch {}
}
// schedule a timer to fire at the user's reminder time if the app stays open
function scheduleReminderTimer() {
  clearTimeout(scheduleReminderTimer._t);
  fireTodayNotificationIfDue();
  const [h, m] = (state.settings.reminderTime || '09:00').split(':').map(Number);
  const now = new Date();
  const target = new Date(); target.setHours(h, m, 0, 0);
  if (target <= now) target.setDate(target.getDate() + 1);
  const ms = Math.min(target - now, 2 ** 31 - 1);
  scheduleReminderTimer._t = setTimeout(() => { fireTodayNotificationIfDue(); scheduleReminderTimer(); }, ms);
}

/* ---- ICS export (reliable phone alarms) ---- */
function exportICS() {
  if (!state.settings.patchStart) { toast('Set your patch date first'); return; }
  const [h, m] = (state.settings.reminderTime || '09:00').split(':').map(Number);
  const evs = patchEvents(26); // ~6 months
  const lines = [
    'BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Petal//Patch Tracker//EN',
    'CALSCALE:GREGORIAN', 'METHOD:PUBLISH', 'X-WR-CALNAME:Petal Patch Reminders',
  ];
  const stamp = toICSStamp(new Date());
  evs.forEach((e, i) => {
    const dt = parseISO(e.date); dt.setHours(h, m, 0, 0);
    const end = new Date(dt.getTime() + 15 * 60000);
    lines.push('BEGIN:VEVENT');
    lines.push(`UID:petal-${e.date}-${i}@petal.local`);
    lines.push(`DTSTAMP:${stamp}`);
    lines.push(`DTSTART:${toICSStamp(dt)}`);
    lines.push(`DTEND:${toICSStamp(end)}`);
    lines.push(`SUMMARY:🩹 ${e.label}`);
    lines.push('DESCRIPTION:Petal birth-control patch reminder');
    lines.push('BEGIN:VALARM', 'ACTION:DISPLAY', 'DESCRIPTION:Patch reminder', 'TRIGGER:-PT0M', 'END:VALARM');
    lines.push('END:VEVENT');
  });
  if (state.settings.edgeCheckReminder !== false) {
    const taskDates = new Set(evs.map((e) => e.date));
    for (let i = 0; i < 84; i++) {
      const ds = iso(addDays(today(), i));
      if (taskDates.has(ds) || !isPatchOn(patchCycleDay(ds))) continue;
      const dt = parseISO(ds); dt.setHours(h, m, 0, 0);
      const end = new Date(dt.getTime() + 10 * 60000);
      lines.push('BEGIN:VEVENT');
      lines.push(`UID:petal-edge-${ds}@petal.local`);
      lines.push(`DTSTAMP:${stamp}`);
      lines.push(`DTSTART:${toICSStamp(dt)}`);
      lines.push(`DTEND:${toICSStamp(end)}`);
      lines.push('SUMMARY:Check Zafemy patch edges');
      lines.push('DESCRIPTION:Petal: make sure the patch is still stuck well and the edges are smooth');
      lines.push('BEGIN:VALARM', 'ACTION:DISPLAY', 'DESCRIPTION:Check patch edges', 'TRIGGER:-PT0M', 'END:VALARM');
      lines.push('END:VEVENT');
    }
  }
  // refill reminder ~5 days before the supply runs out
  const rf = refillStatus();
  if (rf && rf.outDate) {
    const remind = addDays(parseISO(rf.outDate), -5);
    const dt = remind < today() ? addDays(today(), 1) : remind;
    dt.setHours(h, m, 0, 0);
    const end = new Date(dt.getTime() + 15 * 60000);
    lines.push('BEGIN:VEVENT');
    lines.push(`UID:petal-refill-${rf.outDate}@petal.local`);
    lines.push(`DTSTAMP:${stamp}`);
    lines.push(`DTSTART:${toICSStamp(dt)}`);
    lines.push(`DTEND:${toICSStamp(end)}`);
    lines.push('SUMMARY:💊 Refill patch prescription');
    lines.push(`DESCRIPTION:Petal: your patch supply runs out around ${rf.outDate}`);
    lines.push('BEGIN:VALARM', 'ACTION:DISPLAY', 'DESCRIPTION:Refill reminder', 'TRIGGER:-PT0M', 'END:VALARM');
    lines.push('END:VEVENT');
  }
  if (state.settings.backupReminder !== false) {
    for (let i = 1; i <= 6; i++) {
      const dt = addDays(today(), i * 30);
      dt.setHours(h, m, 0, 0);
      const end = new Date(dt.getTime() + 15 * 60000);
      lines.push('BEGIN:VEVENT');
      lines.push(`UID:petal-backup-${iso(dt)}@petal.local`);
      lines.push(`DTSTAMP:${stamp}`);
      lines.push(`DTSTART:${toICSStamp(dt)}`);
      lines.push(`DTEND:${toICSStamp(end)}`);
      lines.push('SUMMARY:Export encrypted Petal backup');
      lines.push('DESCRIPTION:Petal: export an encrypted backup and save it to Files or iCloud Drive');
      lines.push('BEGIN:VALARM', 'ACTION:DISPLAY', 'DESCRIPTION:Export encrypted backup', 'TRIGGER:-PT0M', 'END:VALARM');
      lines.push('END:VEVENT');
    }
  }
  lines.push('END:VCALENDAR');
  const blob = new Blob([lines.join('\r\n')], { type: 'text/calendar' });
  downloadBlob(blob, 'petal-patch-reminders.ics');
  toast('Calendar file ready');
}
function toICSStamp(d) {
  return d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) + 'T' + pad(d.getHours()) + pad(d.getMinutes()) + '00';
}
function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ============================================================ Boot ======== */
let SW_REG = null;
let updateReloadPending = false;

function reloadForUpdateSoon() {
  updateReloadPending = true;
  setTimeout(() => { if (updateReloadPending) location.reload(); }, 1400);
}

async function preserveVaultBeforeUpdate() {
  try {
    if (KEY && state) await saveState();
    await mirrorToFile();
  } catch {}
}

async function applyWaitingUpdate(reg) {
  if (updateReloadPending) return;
  const worker = reg && (reg.waiting || reg.installing);
  toast('Saving encrypted data…');
  await preserveVaultBeforeUpdate();
  toast('Update ready — refreshing');
  updateReloadPending = true;
  if (worker) {
    try { worker.postMessage('skipWaiting'); } catch {}
  }
  reloadForUpdateSoon();
}

function watchInstallingUpdate(reg, worker) {
  if (!worker) return;
  worker.addEventListener('statechange', () => {
    if (worker.state === 'installed' || worker.state === 'activated') applyWaitingUpdate(reg);
  });
}

async function checkForAppUpdate() {
  const btn = $('#checkUpdates');
  if (isNative) { toast('Native app updates happen through the installed app'); return; }
  if (!('serviceWorker' in navigator)) { toast('Updates load when you refresh'); return; }
  try {
    if (btn) btn.disabled = true;
    toast('Checking for updates…');
    const reg = SW_REG || await navigator.serviceWorker.getRegistration('./') || await navigator.serviceWorker.register('./sw.js');
    SW_REG = reg;
    let found = false;
    const onUpdateFound = () => {
      found = true;
      watchInstallingUpdate(reg, reg.installing);
    };
    reg.addEventListener('updatefound', onUpdateFound, { once: true });
    await reg.update();
    if (reg.waiting) { applyWaitingUpdate(reg); return; }
    if (reg.installing) {
      found = true;
      watchInstallingUpdate(reg, reg.installing);
      toast('Update found — installing');
      return;
    }
    setTimeout(() => {
      if (!found && !reg.waiting && !reg.installing) toast('Petal is up to date');
    }, 900);
  } catch {
    toast('Could not check for updates');
  } finally {
    setTimeout(() => { if (btn) btn.disabled = false; }, 1200);
  }
}

navigator.serviceWorker?.addEventListener('controllerchange', () => {
  if (!updateReloadPending) return;
  updateReloadPending = false;
  location.reload();
});

// Service worker only helps the browser/PWA build; native uses bundled assets.
if ('serviceWorker' in navigator && !isNative) {
  navigator.serviceWorker.register('./sw.js').then((reg) => { SW_REG = reg; }).catch(() => {});
}
(async function boot() {
  await restoreFromFileIfNeeded();   // pull encrypted vault from iCloud on a fresh device
  showLock(!hasVault());
})();
