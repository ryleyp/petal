/* Petal — private period & patch tracker
 * All data is encrypted with the user's passcode (PBKDF2 + AES-GCM) and stored
 * only in this browser. Nothing is ever sent anywhere. */
'use strict';

/* ============================================================ Crypto ===== */
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  dec: (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0)),
};

const PBKDF2_ITER = 310000; // OWASP-aligned work factor; stored in vault for forward compat

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
      reminderTime: '09:00', patchDayOfWeek: null, lastBackup: null },
    periods: [],                 // [{ start:'YYYY-MM-DD', end:'YYYY-MM-DD'|null }]
    logs: {},                    // { 'YYYY-MM-DD': { flow, symptoms:[], notes } }
    patchActions: [],            // [{ date:'YYYY-MM-DD', action:'apply'|'remove'|'detached' }]
  };
}

async function saveState() {
  if (!KEY) return;
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

const SYMPTOMS = ['Cramps', 'Headache', 'Bloating', 'Tender breasts', 'Acne', 'Fatigue',
  'Mood swings', 'Nausea', 'Back pain', 'Cravings', 'Low energy', 'High energy'];

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

$('#lockForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const p1 = $('#pass1').value.trim();
  const err = $('#lockError');
  err.textContent = '';

  if (!hasVault()) {
    // setup
    const p2 = $('#pass2').value.trim();
    if (p1.length < 4) { err.textContent = 'Use at least 4 characters.'; return; }
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
    migrate();
    openApp();
  } catch {
    err.textContent = 'Incorrect passcode.';
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
  state.settings = Object.assign({}, d.settings, state.settings || {});
  state.periods = state.periods || [];
  state.logs = state.logs || {};
  state.patchActions = state.patchActions || [];
}

function openApp() {
  lockEl.classList.add('hidden');
  appEl.classList.remove('hidden');
  hydrateSettings();
  buildSymptomChips();
  $('#flowSeg').innerHTML = flowSegHTML(''); // build the flow control with droplet icons
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
function sortedPeriods() {
  return [...state.periods].sort((a, b) => a.start.localeCompare(b.start));
}
function openPeriod() {
  const ps = sortedPeriods();
  const last = ps[ps.length - 1];
  return last && !last.end ? last : null;
}
function startPeriod(dateStr) {
  dateStr = dateStr || todayISO();
  // avoid duplicate same-day start
  if (state.periods.some((p) => p.start === dateStr)) { toast('Already logged'); return; }
  const op = openPeriod();
  if (op && daysBetween(op.start, dateStr) <= 10) { toast('Period already in progress'); return; }
  state.periods.push({ start: dateStr, end: null });
  saveState(); renderAll(); toast('Period start logged 🩸');
}
function endPeriod(dateStr) {
  dateStr = dateStr || todayISO();
  const op = openPeriod();
  if (!op) { toast('No open period to end'); return; }
  op.end = dateStr;
  saveState(); renderAll(); toast('Period end logged ✅');
}

/* cycle stats from logged period starts */
function cycleStats() {
  const ps = sortedPeriods().filter((p) => p.start);
  const lengths = [];
  for (let i = 1; i < ps.length; i++) {
    const len = daysBetween(ps[i - 1].start, ps[i].start);
    if (len >= 18 && len <= 60) lengths.push(len);
  }
  const periodLens = ps.filter((p) => p.end).map((p) => daysBetween(p.start, p.end) + 1).filter((n) => n >= 1 && n <= 14);
  const avg = (arr, fb) => (arr.length ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : fb);
  return {
    count: ps.length,
    avgCycle: avg(lengths, state.settings.cycleLen),
    avgPeriod: avg(periodLens, null),
    lengths,
    lastStart: ps.length ? ps[ps.length - 1].start : null,
  };
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
// returns 0-based day within the 28-day patch cycle, or null
function patchCycleDay(dateStr) {
  const p = state.settings.patchStart;
  if (!p) return null;
  const diff = daysBetween(p, dateStr);
  if (diff < 0) return null;
  return ((diff % PATCH_CYCLE) + PATCH_CYCLE) % PATCH_CYCLE;
}
const isPatchFree = (day) => day !== null && day >= 21 && day <= 27;
const isPatchOn = (day) => day !== null && day >= 0 && day <= 20;

// upcoming patch events for `weeks` weeks
function patchEvents(weeks = 12) {
  const p = state.settings.patchStart;
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
    const num = patchNumberFor(lastApply.date);
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

  // No patch on -> patch-free interval. How long has it been hormone-free?
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
  const out = [];
  let prev = null;
  for (const a of acts) {
    let status = 'ok', note = '';
    if (a.action === 'detached') {
      const gap = prev ? daysBetween(prev.date, a.date) : 0;
      status = 'caution'; note = 'Patch fell off';
    } else if (a.action === 'remove') {
      const gap = prev && prev.action === 'apply' ? daysBetween(prev.date, a.date) : null;
      if (gap === null) { note = 'Removed'; }
      else if (gap <= 7) { status = 'ok'; note = gap === 7 ? 'Removed on time (7d worn)' : `Removed after ${gap}d`; }
      else { status = 'ok'; note = `Removed ${gap - 7}d late — still protected`; }
    } else { // apply
      if (!prev) { status = 'ok'; note = 'Cycle start'; }
      else if (prev.action === 'apply') { // weekly change
        const gap = daysBetween(prev.date, a.date);
        if (gap <= 7) { status = 'ok'; note = gap === 7 ? 'Changed on time' : `Changed early (${gap}d)`; }
        else if (gap < 9) { status = 'caution'; note = `Changed ${gap - 7}d late (<48h) — still protected`; }
        else { status = 'risk'; note = `Changed ${gap - 7}d late (≥48h) — protection reduced`; }
      } else { // apply after a remove/detach = start of a new cycle
        const gap = daysBetween(prev.date, a.date);
        if (gap <= 7) { status = 'ok'; note = gap === 7 ? 'New patch on time' : `Patch-free ${gap}d, new patch on`; }
        else { status = 'risk'; note = `Hormone-free ${gap}d (>7) — ovulation risk`; }
      }
    }
    out.push({ date: a.date, action: a.action, status, note });
    prev = a;
  }
  return out.reverse();
}

/* ============================================================ Day info ==== */
function dayInfo(dateStr) {
  const info = { period: false, predicted: false, fertile: false, ovul: false,
    patch: false, patchfree: false, note: false, flow: '' };
  const log = state.logs[dateStr];
  if (log) { info.note = !!(log.notes || (log.symptoms && log.symptoms.length)); info.flow = log.flow || ''; }

  // logged periods
  for (const p of state.periods) {
    const end = p.end || (p.start === dateStr ? p.start : iso(addDays(parseISO(p.start), 5)));
    if (dateStr >= p.start && dateStr <= (p.end || end) && p.end) { if (dateStr >= p.start && dateStr <= p.end) info.period = true; }
    if (!p.end && dateStr === p.start) info.period = true;
  }
  if (info.flow && info.flow !== '') info.period = true;

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
function renderAll() { renderToday(); renderCalendar(); renderPatch(); renderInsights(); }

/* ---- Cycle ring (Clue-style) ---- */
function polar(cx, cy, r, a) { const rad = (a - 90) * Math.PI / 180; return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)]; }
function ringArc(r, a0, a1, color, w, opacity = 1) {
  if (a1 <= a0) return '';
  const [x0, y0] = polar(50, 50, r, a0), [x1, y1] = polar(50, 50, r, a1);
  const large = (a1 - a0) > 180 ? 1 : 0;
  return `<path d="M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}" stroke="${color}" stroke-width="${w}" fill="none" stroke-linecap="round"${opacity !== 1 ? ` stroke-opacity="${opacity}"` : ''}/>`;
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
  <filter id="ringDepth" x="-25%" y="-25%" width="150%" height="150%">
    <feDropShadow dx="0" dy="1.1" stdDeviation="1.3" flood-color="#000" flood-opacity="0.35"/></filter>
  <filter id="markerGlow" x="-120%" y="-120%" width="340%" height="340%">
    <feDropShadow dx="0" dy="0" stdDeviation="2.4" flood-color="#ff5d8f" flood-opacity="0.75"/></filter>
</defs>`;
function drawCycleRing() {
  const el = $('#cycleRing'); if (!el) return;
  const r = 42, w = 9.5, tISO = todayISO();
  const TRACK = '#352a5c';
  let total, cd, arcs = '', extra = '';
  const patchMode = state.settings.onPatch && state.settings.patchStart;

  if (patchMode) {
    total = 28;
    cd = patchCycleDay(tISO); if (cd === null) cd = 0;
    const step = 360 / total, g = 2.6;
    const seg = (s, e, grad) => ringArc(r, s * step + g, e * step - g, `url(#${grad})`, w);
    arcs = seg(0, 7, 'gAmber') + seg(7, 14, 'gAmber') + seg(14, 21, 'gAmber') + seg(21, 28, 'gPurple');
    // softly dim the part of the cycle still ahead (a gentle progress feel)
    if (cd > 0 && cd < total) extra = ringArc(r, cd * step, 359.9, '#16102c', w + 0.4, 0.32);
  } else {
    const s = cycleStats();
    total = s.avgCycle || state.settings.cycleLen || 28; // data-driven average when available
    const step = 360 / total;
    const raw = s.lastStart ? daysBetween(s.lastStart, tISO) : null;
    cd = raw === null ? null : ((raw % total) + total) % total;
    const plen = s.avgPeriod || 5;
    arcs = ringArc(r, 1, plen * step - 1, 'url(#gPink)', w);              // period
    const ovD = total - (state.settings.lutealLen || 14);
    arcs += ringArc(r, (ovD - 5) * step + 1, ovD * step - 1, 'url(#gGreen)', w); // fertile
    const [ox, oy] = polar(50, 50, r, (ovD + 0.5) * step);
    extra += `<circle cx="${ox.toFixed(2)}" cy="${oy.toFixed(2)}" r="3.6" fill="#2fa3ff"/>` +
             `<circle cx="${ox.toFixed(2)}" cy="${oy.toFixed(2)}" r="1.5" fill="#fff"/>`;
  }

  // glowing today marker
  let marker = '';
  if (cd !== null) {
    const [mx, my] = polar(50, 50, r, (cd + 0.5) * (360 / total));
    marker = `<g filter="url(#markerGlow)">` +
      `<circle cx="${mx.toFixed(2)}" cy="${my.toFixed(2)}" r="5.6" fill="#fff"/>` +
      `<circle cx="${mx.toFixed(2)}" cy="${my.toFixed(2)}" r="5.6" fill="none" stroke="#ff5d8f" stroke-width="2.1"/></g>`;
  }
  el.innerHTML = `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">${RING_DEFS}
    <circle cx="50" cy="50" r="${r}" stroke="${TRACK}" stroke-width="${w}" fill="none" opacity="0.55"/>
    <g filter="url(#ringDepth)">${arcs}</g>${extra}${marker}</svg>`;
}

/* ---- Today ---- */
function renderToday() {
  const tISO = todayISO();
  $('#todayDate').textContent = fmtDate(tISO, { weekday: 'long', month: 'long', day: 'numeric' });
  drawCycleRing();

  // hero
  const heroDay = $('#heroDay'), heroLabel = $('#heroLabel'), heroSub = $('#heroSub');
  const np = predictNextPeriod();
  const cd = patchCycleDay(tISO);
  if (state.settings.onPatch && cd !== null) {
    const week = Math.floor(cd / 7) + 1;
    heroDay.textContent = `Patch cycle · day ${cd + 1} of 28`;
    if (isPatchFree(cd)) {
      const back = 28 - cd;
      heroLabel.textContent = 'Patch-free week 🌙';
      heroSub.textContent = `Withdrawal bleed expected. New patch in ${back} day${back === 1 ? '' : 's'}.`;
    } else {
      heroLabel.textContent = `Patch week ${week} 🩹`;
      const nextChange = 7 - (cd % 7);
      heroSub.textContent = cd >= 14
        ? `Remove patch in ${21 - cd} day${21 - cd === 1 ? '' : 's'}.`
        : `Change patch in ${nextChange} day${nextChange === 1 ? '' : 's'}.`;
    }
  } else if (np) {
    const dleft = daysBetween(tISO, np);
    heroDay.textContent = dleft >= 0 ? 'Next period' : 'Period';
    if (dleft > 1) { heroLabel.textContent = `In ${dleft} days`; heroSub.textContent = `Expected ${fmtDate(np)}`; }
    else if (dleft === 1) { heroLabel.textContent = 'Tomorrow'; heroSub.textContent = fmtDate(np); }
    else if (dleft === 0) { heroLabel.textContent = 'Expected today'; heroSub.textContent = ''; }
    else { heroLabel.textContent = `${-dleft} day${-dleft === 1 ? '' : 's'} late`; heroSub.textContent = 'Log it when it starts'; }
  } else {
    heroDay.textContent = 'Welcome 🌸';
    heroLabel.textContent = 'Start tracking';
    heroSub.textContent = 'Log a period or set your patch schedule.';
  }

  renderAlerts();

  // today's log fields
  const log = state.logs[tISO] || { flow: '', symptoms: [], notes: '' };
  $$('#flowSeg button').forEach((b) => b.classList.toggle('on', (b.dataset.val || '') === (log.flow || '')));
  $$('#symptomChips .chip').forEach((c) => c.classList.toggle('on', (log.symptoms || []).includes(c.dataset.sym)));
  $('#todayNotes').value = log.notes || '';
}

const LEVEL_META = {
  ok: { cls: 'ok', emoji: '✅' },
  caution: { cls: 'due', emoji: '⏰' },
  risk: { cls: 'due', emoji: '⚠️' },
};
function renderAlerts() {
  const box = $('#alerts'); box.innerHTML = '';
  const tISO = todayISO();

  // primary: honest assessment of the real patch situation
  const a = assessPatch();
  if (a) {
    const m = LEVEL_META[a.level] || LEVEL_META.ok;
    box.insertAdjacentHTML('beforeend',
      `<div class="alert ${m.cls}"><span class="a-emoji">${m.emoji}</span><div><b>${a.title}.</b> ${a.message}` +
      (a.level === 'risk' ? `<div class="muted small" style="margin-top:6px">${GUIDE_DISCLAIMER}</div>` : '') +
      `</div></div>`);
  } else if (state.settings.onPatch && state.settings.patchStart) {
    // schedule-based reminder when there are no logged actions yet
    const evs = patchEvents(2);
    const todayEv = evs.find((e) => e.date === tISO);
    const tomEv = evs.find((e) => e.date === iso(addDays(today(), 1)));
    if (todayEv) box.insertAdjacentHTML('beforeend',
      `<div class="alert due"><span class="a-emoji">🩹</span><div><b>Patch task today:</b> ${todayEv.label}.</div></div>`);
    else if (tomEv) box.insertAdjacentHTML('beforeend',
      `<div class="alert"><span class="a-emoji">⏰</span><div><b>Tomorrow:</b> ${tomEv.label}.</div></div>`);
  }

  // late period (natural cycle only)
  const np = predictNextPeriod();
  if (np && !state.settings.onPatch) {
    const dleft = daysBetween(tISO, np);
    if (dleft <= -2) box.insertAdjacentHTML('beforeend',
      `<div class="alert"><span class="a-emoji">📅</span><div>Your period is ${-dleft} days later than predicted.</div></div>`);
  }

  // gentle backup reminder so a year of data survives iOS storage eviction
  maybeBackupReminder(box);
}

function maybeBackupReminder(box) {
  const last = state.settings.lastBackup;
  const stale = !last || daysBetween(last, todayISO()) >= 30;
  if (stale && (state.periods.length || (state.patchActions && state.patchActions.length))) {
    box.insertAdjacentHTML('beforeend',
      `<div class="alert"><span class="a-emoji">💾</span><div>Back up your data so it can't be lost — Settings → Export encrypted backup, then save it to iCloud Drive.</div></div>`);
  }
}

$('#saveToday').addEventListener('click', () => {
  const tISO = todayISO();
  const flow = ($('#flowSeg button.on') || {}).dataset?.val ?? '';
  const symptoms = $$('#symptomChips .chip.on').map((c) => c.dataset.sym);
  const notes = $('#todayNotes').value.trim();
  if (!flow && !symptoms.length && !notes) { delete state.logs[tISO]; }
  else state.logs[tISO] = { flow, symptoms, notes };
  // auto-create period when flow logged and none open
  if (flow && flow !== 'spotting' && !openPeriod() && !state.periods.some((p) => p.start === tISO)) {
    state.periods.push({ start: tISO, end: null });
  }
  saveState(); renderAll(); toast('Saved');
});

$('#flowSeg').addEventListener('click', (e) => {
  const b = e.target.closest('button'); if (!b) return;
  $$('#flowSeg button').forEach((x) => x.classList.toggle('on', x === b));
});

function buildSymptomChips() {
  const box = $('#symptomChips'); box.innerHTML = '';
  SYMPTOMS.forEach((s) => {
    const c = document.createElement('button');
    c.className = 'chip'; c.dataset.sym = s; c.textContent = s; c.type = 'button';
    c.addEventListener('click', () => c.classList.toggle('on'));
    box.appendChild(c);
  });
}

// quick actions
$('.quick-actions').addEventListener('click', (e) => {
  const b = e.target.closest('.qa'); if (!b) return;
  const q = b.dataset.quick;
  if (q === 'period-start') startPeriod();
  if (q === 'period-end') endPeriod();
  if (q === 'patch-applied') applyPatchToday();
  if (q === 'patch-removed') removePatchToday();
});

function applyPatchToday() { logPatchActionOn(todayISO(), 'apply'); }
function removePatchToday() { logPatchActionOn(todayISO(), 'remove'); }

// Log a patch apply/remove for any date (today or retroactive).
function logPatchActionOn(ds, action) {
  // If there's no schedule yet, the first applied patch anchors the cycle.
  if (action === 'apply' && !state.settings.patchStart) {
    state.settings.patchStart = ds;
    state.settings.onPatch = true;
  }
  recordPatchAction(action, ds);
  saveState(); hydrateSettings(); renderAll();
  flashAssessment(action === 'apply' ? 'Patch applied 🩹' : 'Patch removed 🌙');
}
// Remove logged patch action(s) on a given date (to fix a mistake).
function unlogPatchActionOn(ds, action) {
  state.patchActions = (state.patchActions || []).filter((a) => !(a.date === ds && a.action === action));
  saveState(); renderAll(); toast('Removed log');
}
function patchActionsOn(ds) { return (state.patchActions || []).filter((a) => a.date === ds); }
// after a patch action, toast a short honest status if anything needs attention
function flashAssessment(fallback) {
  const a = assessPatch();
  if (a && a.level !== 'ok') toast(a.title);
  else toast(fallback);
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
  const tags = [];
  if (info.period) tags.push('🩸 Period');
  if (info.predicted) tags.push('• Predicted period');
  if (info.ovul) tags.push('🔵 Predicted ovulation');
  if (info.fertile) tags.push('🟢 Fertile window');
  if (info.patch) tags.push('🩹 Patch on');
  if (info.patchfree) tags.push('🌙 Patch-free');
  const acts = patchActionsOn(ds);
  const appliedHere = acts.some((a) => a.action === 'apply');
  const removedHere = acts.some((a) => a.action === 'remove' || a.action === 'detached');
  if (appliedHere) tags.push('🩹 Applied (logged)');
  if (removedHere) tags.push('🌙 Removed (logged)');
  const box = $('#dayDetail'); box.classList.remove('hidden');
  box.innerHTML = `
    <div class="card-head"><h2>${fmtDate(ds, { weekday: 'long', month: 'long', day: 'numeric' })}</h2></div>
    <p class="muted small">${tags.join(' &nbsp;·&nbsp; ') || 'Nothing logged'}</p>
    <div class="log-row"><label>Flow strength</label>
      <div class="seg" id="dFlow">${flowSegHTML(log.flow || '')}</div>
    </div>
    <div class="log-row"><label>Notes</label>
      <textarea id="dNotes" rows="2" placeholder="Notes for this day…">${log.notes ? escapeHtml(log.notes) : ''}</textarea>
    </div>
    <button class="btn btn-primary full" data-act="save">Save this day</button>
    <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
      <button class="btn btn-ghost" data-act="ps" style="flex:1">🩸 Period started</button>
      <button class="btn btn-ghost" data-act="pe" style="flex:1">✅ Period ended</button>
    </div>
    <div class="log-row" style="margin-top:8px"><label>Patch (log for this day)</label>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-ghost" data-act="${appliedHere ? 'unapply' : 'apply'}" style="flex:1">${appliedHere ? '✕ Undo applied' : '🩹 Applied patch'}</button>
        <button class="btn btn-ghost" data-act="${removedHere ? 'unremove' : 'remove'}" style="flex:1">${removedHere ? '✕ Undo removed' : '🌙 Removed patch'}</button>
      </div>
    </div>`;
  box.querySelector('#dFlow').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    box.querySelectorAll('#dFlow button').forEach((x) => x.classList.toggle('on', x === b));
  });
  box.querySelector('[data-act="save"]').addEventListener('click', () => {
    const flow = (box.querySelector('#dFlow button.on') || {}).dataset?.val ?? '';
    const notes = box.querySelector('#dNotes').value.trim();
    const prev = state.logs[ds] || {};
    if (!flow && !notes && !(prev.symptoms && prev.symptoms.length)) delete state.logs[ds];
    else state.logs[ds] = { flow, symptoms: prev.symptoms || [], notes };
    // logging real flow (not spotting) starts a period if none covers this day
    if (flow && flow !== 'spotting' && !state.periods.some((p) => ds >= p.start && ds <= (p.end || p.start))) {
      if (!state.periods.some((p) => p.start === ds)) state.periods.push({ start: ds, end: null });
    }
    saveState(); renderAll(); showDayDetail(ds); toast('Day saved');
  });
  box.querySelector('[data-act="ps"]').addEventListener('click', () => { startPeriod(ds); showDayDetail(ds); });
  box.querySelector('[data-act="pe"]').addEventListener('click', () => { endPeriod(ds); showDayDetail(ds); });
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
}
function escapeHtml(s) { return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

/* ---- Patch view ---- */
function renderPatch() {
  // live, honest status of the real situation
  const sc = $('#patchStatusCard');
  const a = assessPatch();
  if (a) {
    sc.className = `status-card ${a.level}`;
    sc.innerHTML = `<h2>${a.title}</h2><p>${a.message}</p>` +
      (a.level === 'risk' ? `<p class="muted small" style="margin-top:8px">${GUIDE_DISCLAIMER}</p>` : '');
  } else {
    sc.className = '';
    sc.innerHTML = '';
  }
  $('#patchStart').value = state.settings.patchStart || '';
  $('#reminderTime').value = state.settings.reminderTime || '09:00';
  const box = $('#patchSchedule'); box.innerHTML = '';
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
  if (v) state.settings.onPatch = true;
  saveState(); hydrateSettings(); renderAll(); scheduleReminderTimer();
  toast('Patch schedule saved 🩹');
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
function renderInsights() {
  const s = cycleStats();
  const box = $('#insights');
  box.innerHTML = `
    <div class="stat"><div class="big">${s.avgCycle}</div><div class="lbl">avg cycle (days)</div></div>
    <div class="stat"><div class="big">${s.avgPeriod || '—'}</div><div class="lbl">avg period (days)</div></div>
    <div class="stat"><div class="big">${s.count}</div><div class="lbl">cycles logged</div></div>
    <div class="stat"><div class="big">${variability(s.lengths)}</div><div class="lbl">regularity</div></div>`;

  // ovulation insight
  const ob = $('#ovulationInsight');
  if (state.settings.onPatch) {
    const np = predictNextPeriod();
    ob.innerHTML = `
      <div class="insight-line">🩹 <b>You're using the combined patch.</b> It works mainly by
      <b>suppressing ovulation</b>, so while you wear it consistently you generally don't ovulate —
      there's no fertile window to predict.</div>
      <div class="insight-line">🌙 The bleeding in your <b>patch-free week</b> is a
      <b>withdrawal bleed</b>, not a true period. ${patchFreeNext()}</div>
      <div class="insight-line muted small">If you stop the patch, turn off “Currently using the patch”
      in Settings and Petal will estimate your fertile window from your logged cycles.</div>`;
  } else {
    const np = predictNextPeriod();
    if (np) {
      const ovul = iso(addDays(parseISO(np), -state.settings.lutealLen));
      const fStart = iso(addDays(parseISO(ovul), -5));
      ob.innerHTML = `
        <div class="insight-line">🔵 Estimated <b>ovulation: ${fmtDate(ovul)}</b>
        (about ${state.settings.lutealLen} days before your next predicted period).</div>
        <div class="insight-line">🟢 Most fertile window: <b>${fmtDate(fStart)} – ${fmtDate(ovul)}</b>.</div>
        <div class="insight-line muted small">This is an estimate from your average cycle and luteal
        phase — actual ovulation varies. Not a contraceptive method.</div>`;
    } else {
      ob.innerHTML = '<div class="insight-line muted">Log a couple of periods to estimate ovulation.</div>';
    }
  }

  // patch history (on time / late, derived from logged dates)
  const ph = $('#patchHistory'); ph.innerHTML = '';
  const STATUS_ICON = { ok: '✅', caution: '⚠️', risk: '⚠️' };
  const STATUS_COLOR = { ok: 'var(--ok)', caution: 'var(--patch)', risk: 'var(--accent)' };
  const hist = patchHistory();
  if (!hist.length) {
    ph.innerHTML = '<p class="muted small">No patch actions logged yet. Tap a day on the Calendar to log when you applied or removed a patch.</p>';
  } else {
    hist.slice(0, 20).forEach((e) => {
      const verb = e.action === 'apply' ? '🩹 Applied' : (e.action === 'detached' ? '🩹 Fell off' : '🌙 Removed');
      ph.insertAdjacentHTML('beforeend',
        `<div class="h-item"><span>${verb} · ${fmtDate(e.date)}</span>` +
        `<span style="color:${STATUS_COLOR[e.status]}">${STATUS_ICON[e.status]} ${e.note}</span></div>`);
    });
  }

  // period history
  const h = $('#history'); h.innerHTML = '';
  const ps = sortedPeriods().slice().reverse();
  if (!ps.length) { h.innerHTML = '<p class="muted small">No periods logged yet.</p>'; }
  ps.slice(0, 12).forEach((p, i) => {
    const next = ps[i - 1]; // since reversed, previous in array is later in time
    const len = p.end ? daysBetween(p.start, p.end) + 1 : null;
    h.insertAdjacentHTML('beforeend',
      `<div class="h-item"><span>${fmtDate(p.start)}${p.end ? ' – ' + fmtDate(p.end) : ' (ongoing)'}</span>
       <span class="muted">${len ? len + 'd' : ''}</span></div>`);
  });
}
function variability(lengths) {
  if (lengths.length < 2) return '—';
  const max = Math.max(...lengths), min = Math.min(...lengths);
  const spread = max - min;
  return spread <= 3 ? 'Regular' : spread <= 7 ? 'Slightly irregular' : 'Irregular';
}
function patchFreeNext() {
  if (!state.settings.patchStart) return '';
  const evs = [];
  const start = parseISO(state.settings.patchStart);
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
}
$('#saveSettings').addEventListener('click', () => {
  state.settings.cycleLen = clampNum($('#cycleLen').value, 20, 45, 28);
  state.settings.lutealLen = clampNum($('#lutealLen').value, 10, 16, 14);
  state.settings.onPatch = $('#onPatch').checked;
  saveState(); renderAll(); toast('Settings saved');
});
function clampNum(v, lo, hi, fb) { v = parseInt(v, 10); if (isNaN(v)) return fb; return Math.min(hi, Math.max(lo, v)); }

$('#changePass').addEventListener('click', async () => {
  const p1 = prompt('New passcode (min 4 chars):'); if (p1 === null) return;
  if (p1.trim().length < 4) { alert('Too short.'); return; }
  const p2 = prompt('Confirm new passcode:'); if (p2 === null) return;
  if (p1 !== p2) { alert('Passcodes do not match.'); return; }
  SALT = crypto.getRandomValues(new Uint8Array(16));
  ITER = PBKDF2_ITER;
  KEY = await deriveKey(p1.trim(), SALT, ITER);
  await saveState();
  toast('Passcode changed');
});

$('#exportData').addEventListener('click', () => {
  const blob = new Blob([localStorage.getItem(VAULT)], { type: 'application/json' });
  downloadBlob(blob, `petal-backup-${todayISO()}.json`);
  state.settings.lastBackup = todayISO();
  saveState();
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
function fireTodayNotificationIfDue() {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const ev = patchEvents(1).find((e) => e.date === todayISO());
  if (!ev) return;
  const key = 'petal.notified.' + ev.date;
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
  lines.push('END:VCALENDAR');
  const blob = new Blob([lines.join('\r\n')], { type: 'text/calendar' });
  downloadBlob(blob, 'petal-patch-reminders.ics');
  toast('Calendar file ready 📅');
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
// Service worker only helps the browser/PWA build; native uses bundled assets.
if ('serviceWorker' in navigator && !isNative) {
  navigator.serviceWorker.register('./sw.js').catch(() => {});
}
(async function boot() {
  await restoreFromFileIfNeeded();   // pull encrypted vault from iCloud on a fresh device
  showLock(!hasVault());
})();
