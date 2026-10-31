// Client sync engine tests: pure helpers + two simulated devices against the real Worker.
// The engine source is read straight out of index.html (between the SYNC ENGINE markers).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { makeD1, installFakeGoogle } from './d1shim.mjs';
import worker from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, '..', '..', 'index.html'), 'utf8');
const src = html.slice(html.indexOf('// ═══ SYNC ENGINE START'), html.indexOf('// ═══ SYNC ENGINE END'));
assert.ok(src.length > 1000, 'engine block found in index.html');
globalThis.__fakeGoogle = installFakeGoogle();

// Build one "device": its own localStorage, Sync instance and React-like state.
function device(env, name) {
  const store = new Map();
  const localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
    key: (n) => [...store.keys()][n], get length() { return store.size; },
  };
  const net = { online: true };
  const fetchShim = async (url, init = {}) => {
    if (!net.online) throw new TypeError('Failed to fetch');
    const res = await worker.fetch(new Request(url, { ...init, headers: { ...(init.headers || {}), Origin: 'https://zacharypals.github.io' } }), env);
    return res;
  };
  const prelude = `
    const APP_CONFIG = { API_URL: 'https://api.test', STORAGE_PREFIX: 'lpt_' };
    function lsKey(k) { return APP_CONFIG.STORAGE_PREFIX + k; }
    function lsGet(k) { return localStorage.getItem(lsKey(k)); }
    function lsSet(k, v) { localStorage.setItem(lsKey(k), v); return true; }
    function lsDel(k) { localStorage.removeItem(lsKey(k)); }
    function getSession() { return lsGet('session'); }
    class ApiError extends Error { constructor(s,c,m){super(m||c);this.status=s;this.code=c;} get isAuth(){return this.status===401||(this.status===403&&this.code==='not_allowed');} }
    async function api(path, { method = 'GET', body, keepalive } = {}) {
      const headers = { Authorization: 'Bearer ' + getSession() };
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      let res;
      try { res = await fetch(APP_CONFIG.API_URL + path, { method, headers, body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)) }); }
      catch (e) { throw new ApiError(0, 'network', 'Network error'); }
      let data = null; try { data = await res.json(); } catch {}
      if (!res.ok) throw new ApiError(res.status, (data && data.error) || 'http', (data && data.error) || 'http');
      return data;
    }
  `;
  const factory = new Function('localStorage', 'fetch', 'navigator', 'setTimeout', 'clearTimeout',
    `${prelude}\n${src}\nreturn { Sync, syncSplit, syncJoin, syncMerge3, SYNC_NO_BASE, SYNC_DELETED };`);
  const timers = [];
  // Short waits run for real (the import polls for an in-progress save); sync debounces/retries never fire on their own.
  const fakeSetTimeout = (fn, ms) => (ms <= 100 ? setTimeout(fn, 1) : (timers.push(fn), timers.length));
  const lib = factory(localStorage, fetchShim, { get onLine() { return net.online; } }, fakeSetTimeout, () => {});
  const state = {};
  const statuses = [];
  const dev = {
    name, store, net, lib, state, statuses, Sync: lib.Sync,
    register(coll, init) {
      state[coll] = init;
      lib.Sync.register(coll, init, (v) => { state[coll] = typeof v === 'function' ? v(state[coll]) : v; });
    },
    edit(coll, fn) { state[coll] = fn(state[coll]); lib.Sync.capture(coll, state[coll]); },
    async signIn(email) {
      const r = await worker.fetch(new Request('https://api.test/auth/exchange', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://zacharypals.github.io' },
        body: JSON.stringify({ code: `code:${email}`, redirect_uri: env.REDIRECT_URI }),
      }), env);
      const d = await r.json();
      localStorage.setItem('lpt_session', d.session_token);
      return d;
    },
  };
  lib.Sync.onStatus = (s) => statuses.push(s.kind);
  return dev;
}

function makeEnv() {
  return {
    DB: makeD1(join(here, '..', 'migrations')),
    ALLOWED_ORIGIN: 'https://zacharypals.github.io',
    REDIRECT_URI: 'https://zacharypals.github.io/Planner_Web_App_TEST/oauth.html',
    GOOGLE_CLIENT_ID: 'cid', GOOGLE_CLIENT_SECRET: 's',
    ALLOWED_EMAILS: 'zach@example.com,fam@example.com',
    TOKEN_ENC_KEY: Buffer.alloc(32, 3).toString('base64'),
  };
}

const COLLS = { weekData: {}, pagesData: [], habitCompletions: {}, habitGoals: [{ id: 'g1', name: 'Daily Pages' }], navColor: '#5c2d52', fitnessLog: {} };
async function bootDevice(env, name, email = 'zach@example.com') {
  const d = device(env, name);
  for (const [c, init] of Object.entries(COLLS)) d.register(c, structuredClone(init));
  await d.signIn(email);
  await d.Sync.start(email);
  return d;
}

test('split / join round-trips every collection shape', () => {
  const { lib } = device(makeEnv(), 'x');
  const week = { '2026-10-18': { proverb: 'a' }, '2026-10-25': { proverb: 'b', tasks: { '2026-10-27': [{ id: 't1' }] } } };
  assert.deepEqual(Object.keys(lib.syncSplit('weekData', week)), ['2026-10-18', '2026-10-25']);
  assert.deepEqual(lib.syncJoin('weekData', lib.syncSplit('weekData', week)), week);
  const comp = { '2026-09-30': ['g1'], '2026-10-01': ['g1', 'g2'], '2026-10-27': [] };
  const split = lib.syncSplit('habitCompletions', comp);
  assert.deepEqual(Object.keys(split).sort(), ['2026-09', '2026-10']);
  assert.deepEqual(lib.syncJoin('habitCompletions', split), comp);
  const pages = [{ id: 'doc_2', title: 'B' }, { id: 'doc_1', title: 'A' }];
  const ps = lib.syncSplit('pagesData', pages);
  assert.deepEqual(ps.__order, ['p:doc_2', 'p:doc_1']);
  assert.deepEqual(lib.syncJoin('pagesData', ps), pages);
  assert.deepEqual(lib.syncJoin('navColor', lib.syncSplit('navColor', '#fff')), '#fff');
  assert.deepEqual(lib.syncJoin('weightTarget', lib.syncSplit('weightTarget', '')), '');
});

test('three-way merge rules', () => {
  const { lib } = device(makeEnv(), 'x');
  const m = lib.syncMerge3;
  // Different keys changed on each side → both kept
  assert.deepEqual(m({ a: 1, b: 1 }, { a: 2, b: 1 }, { a: 1, b: 3 }), { a: 2, b: 3 });
  // Same key changed on both → this device wins
  assert.deepEqual(m({ a: 1 }, { a: 2 }, { a: 3 }), { a: 2 });
  // Key removed on one side, untouched on the other → removed
  assert.deepEqual(m({ a: 1, b: 1 }, { a: 1 }, { a: 1, b: 1 }), { a: 1 });
  assert.deepEqual(m({ a: 1, b: 1 }, { a: 1, b: 1, c: 1 }, { a: 1 }), { a: 1, c: 1 });
  // Tasks on the same day edited on two devices → merged by id
  const base = { tasks: { d: [{ id: 't1', title: 'one' }, { id: 't2', title: 'two' }] } };
  const local = { tasks: { d: [{ id: 't1', title: 'ONE' }, { id: 't2', title: 'two' }, { id: 't3', title: 'new here' }] } };
  const remote = { tasks: { d: [{ id: 't1', title: 'one', done: true }, { id: 't4', title: 'new there' }] } };
  assert.deepEqual(m(base, local, remote), { tasks: { d: [
    { id: 't1', title: 'ONE', done: true }, { id: 't4', title: 'new there' }, { id: 't3', title: 'new here' },
  ] } });
  // No shared base (e.g. after an offline restart) → union, this device wins on overlap
  assert.deepEqual(m(lib.SYNC_NO_BASE, { a: 2, x: 1 }, { a: 3, y: 1 }), { a: 2, x: 1, y: 1 });
  // Deletion vs edit: edit made after the base wins over an untouched copy
  assert.equal(m({ a: 1 }, lib.SYNC_DELETED, { a: 1 }), lib.SYNC_DELETED);
  assert.deepEqual(m({ a: 1 }, { a: 1 }, lib.SYNC_DELETED), lib.SYNC_DELETED);
});

test('save, reload on a new device, and keep data per person', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'laptop');
  a.edit('weekData', (w) => ({ ...w, '2026-10-25': { proverb: 'hello', tasks: {} } }));
  a.edit('pagesData', (p) => [...p, { id: 'doc_1', title: 'Kitchen', body: '<p>x</p>' }]);
  a.edit('habitCompletions', (h) => ({ ...h, '2026-10-27': ['g1'] }));
  a.edit('navColor', () => '#123456');
  assert.ok(a.Sync.pendingCount() > 0);
  await a.Sync.flush();
  assert.equal(a.Sync.pendingCount(), 0);

  const b = await bootDevice(env, 'phone');
  assert.deepEqual(b.state.weekData, a.state.weekData);
  assert.deepEqual(b.state.pagesData, a.state.pagesData);
  assert.deepEqual(b.state.habitCompletions, a.state.habitCompletions);
  assert.equal(b.state.navColor, '#123456');
  assert.deepEqual(b.state.habitGoals, [{ id: 'g1', name: 'Daily Pages' }], 'default used when never saved');

  const fam = await bootDevice(env, 'family', 'fam@example.com');
  assert.deepEqual(fam.state.weekData, {}, 'other person starts empty');
});

test('only changed documents are sent', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'laptop');
  const weeks = {};
  for (let n = 0; n < 40; n++) weeks[`2026-${String(1 + (n % 9)).padStart(2, '0')}-${String(10 + n % 18)}`] = { proverb: 'p' + n, tasks: {} };
  a.edit('weekData', () => weeks);
  await a.Sync.flush();
  const before = env.DB.stats.rowsWritten;
  a.edit('weekData', (w) => ({ ...w, '2026-01-10': { ...w['2026-01-10'], proverb: 'changed' } }));
  assert.equal(a.Sync.pendingCount(), 1);
  await a.Sync.flush();
  assert.ok(env.DB.stats.rowsWritten - before <= 4, `one doc write, got ${env.DB.stats.rowsWritten - before} rows`);
});

test('two devices: changes arrive by polling, and same-week edits merge', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'laptop');
  const b = await bootDevice(env, 'phone');
  const wk = '2026-10-25';
  a.edit('weekData', (w) => ({ ...w, [wk]: { proverb: '', tasks: { mon: [{ id: 't1', title: 'Dentist' }] } } }));
  await a.Sync.flush();
  await b.Sync.pull();
  assert.deepEqual(b.state.weekData[wk].tasks.mon, [{ id: 't1', title: 'Dentist' }]);

  // Both edit the same week before either syncs: laptop edits Monday, phone adds Tuesday.
  a.edit('weekData', (w) => ({ ...w, [wk]: { ...w[wk], tasks: { ...w[wk].tasks, mon: [{ id: 't1', title: 'Dentist 10:30' }] } } }));
  b.edit('weekData', (w) => ({ ...w, [wk]: { ...w[wk], tasks: { ...w[wk].tasks, tue: [{ id: 't2', title: 'Gym' }] } } }));
  await a.Sync.flush();
  await b.Sync.flush();            // conflict → merged, re-queued
  assert.ok(b.statuses.includes('merged'));
  await b.Sync.flush();
  await a.Sync.pull();
  const expected = { mon: [{ id: 't1', title: 'Dentist 10:30' }], tue: [{ id: 't2', title: 'Gym' }] };
  assert.deepEqual(b.state.weekData[wk].tasks, expected);
  assert.deepEqual(a.state.weekData[wk].tasks, expected);
  assert.equal(a.Sync.pendingCount() + b.Sync.pendingCount(), 0);
});

test('pull merges into an edit that has not been sent yet', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'laptop');
  const b = await bootDevice(env, 'phone');
  a.edit('habitGoals', (g) => [...g, { id: 'g2', name: 'Run' }]);
  await a.Sync.flush();
  b.edit('habitGoals', (g) => [...g, { id: 'g3', name: 'Read' }]);   // queued, not sent
  await b.Sync.pull();
  assert.deepEqual(b.state.habitGoals.map((g) => g.id).sort(), ['g1', 'g2', 'g3']);
  await b.Sync.flush();
  await a.Sync.pull();
  assert.deepEqual(a.state.habitGoals.map((g) => g.id).sort(), ['g1', 'g2', 'g3']);
});

test('deletions propagate (page removed, week removed)', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'laptop');
  const b = await bootDevice(env, 'phone');
  a.edit('pagesData', () => [{ id: 'd1', title: 'One' }, { id: 'd2', title: 'Two' }]);
  a.edit('fitnessLog', () => ({ '2026-10-27': [{ id: 'x1', sets: [] }] }));
  await a.Sync.flush();
  await b.Sync.pull();
  assert.equal(b.state.pagesData.length, 2);
  b.edit('pagesData', (p) => p.filter((d) => d.id !== 'd1'));
  b.edit('fitnessLog', () => ({}));
  await b.Sync.flush();
  await a.Sync.pull();
  assert.deepEqual(a.state.pagesData, [{ id: 'd2', title: 'Two' }]);
  assert.deepEqual(a.state.fitnessLog, {});
  // A brand-new device never sees the deleted items
  const c = await bootDevice(env, 'tablet');
  assert.deepEqual(c.state.pagesData, [{ id: 'd2', title: 'Two' }]);
});

test('offline: edits wait in the outbox, survive a restart, then upload', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'phone');
  a.edit('navColor', () => '#111111');
  await a.Sync.flush();
  a.net.online = false;
  a.edit('weekData', () => ({ '2026-11-01': { proverb: 'written offline' } }));
  await a.Sync.flush();
  assert.equal(a.Sync.pendingCount(), 1, 'still queued');
  await a.Sync.flush();
  assert.ok(a.statuses.includes('error'), 'error shown after repeated failures');

  // "Restart the app" while still offline: new engine instance, same localStorage
  const a2 = device(env, 'phone-restarted');
  for (const k of a.store.keys()) a2.store.set(k, a.store.get(k));
  a2.net.online = false;
  for (const [c, init] of Object.entries(COLLS)) a2.register(c, JSON.parse(a2.store.get('lpt_' + c) || 'null') ?? structuredClone(init));
  const r = await a2.Sync.start('zach@example.com');
  assert.equal(r.offline, true);
  assert.equal(a2.Sync.pendingCount(), 1, 'outbox survived the restart');
  a2.net.online = true;
  await a2.Sync.flush({ manual: true });
  assert.equal(a2.Sync.pendingCount(), 0);
  const b = await bootDevice(env, 'laptop');
  assert.deepEqual(b.state.weekData, { '2026-11-01': { proverb: 'written offline' } });
  assert.equal(b.state.navColor, '#111111');
});

test('restart with unsent edits while another device changed the same doc', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'phone');
  a.edit('weekData', () => ({ w: { proverb: 'p', story: '' } }));
  await a.Sync.flush();
  a.net.online = false;
  a.edit('weekData', (w) => ({ w: { ...w.w, story: 'phone story' } }));
  await a.Sync.flush();
  const b = await bootDevice(env, 'laptop');
  b.edit('weekData', (w) => ({ w: { ...w.w, proverb: 'laptop proverb' } }));
  await b.Sync.flush();
  // phone comes back online and restarts
  const a2 = device(env, 'phone2');
  for (const k of a.store.keys()) a2.store.set(k, a.store.get(k));
  for (const [c, init] of Object.entries(COLLS)) a2.register(c, structuredClone(init));
  await a2.Sync.start('zach@example.com');
  assert.deepEqual(a2.state.weekData.w, { proverb: 'laptop proverb', story: 'phone story' });
  await a2.Sync.flush();
  await b.Sync.pull();
  assert.deepEqual(b.state.weekData.w, { proverb: 'laptop proverb', story: 'phone story' });
});

test('signing in as someone else on the same device clears the previous data', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'shared');
  a.edit('navColor', () => '#abcdef');
  a.store.set('lpt_navColor', JSON.stringify('#abcdef'));
  await a.Sync.flush();
  a.edit('weekData', () => ({ secret: { proverb: 'unsent' } }));   // left in outbox
  const f = device(env, 'shared-fam');
  for (const k of a.store.keys()) f.store.set(k, a.store.get(k));
  for (const [c, init] of Object.entries(COLLS)) f.register(c, structuredClone(init));
  await f.signIn('fam@example.com');
  await f.Sync.start('fam@example.com');
  assert.equal(f.store.get('lpt_navColor'), undefined, 'previous cache wiped');
  assert.equal(f.Sync.pendingCount(), 0, "previous person's unsent edits are not uploaded to this account");
  assert.deepEqual(f.state.weekData, {});
});

test('expired session reports auth loss instead of retrying', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'laptop');
  let lost = 0;
  a.Sync.onAuthLost = () => { lost++; };
  env.DB.raw.prepare('DELETE FROM sessions').run();
  a.edit('navColor', () => '#000000');
  await a.Sync.flush();
  assert.equal(lost, 1);
  assert.equal(a.Sync.pendingCount(), 1, 'edit kept for after sign-in');
});

// ── Import / restore and backup round trip ─────────────────────────
import { backupUser } from '../src/backup.js';

const BIG = () => ({
  weekData: {
    '2026-10-18': { proverb: 'Be still', goals: [{ id: 'g1', name: 'Run', done: true }], people: [], tasks: { '2026-10-19': [{ id: 't1', title: 'A', done: false, colorIndex: 2 }] }, dayNotes: { '2026-10-20': 'note' } },
    '2026-10-25': { proverb: '', tasks: { '2026-10-27': [{ id: 't2', title: 'Dentist', isEvent: true, eventTime: '10:30', gcalId: 'abc' }] } },
  },
  pagesData: [{ id: 'doc_2', title: 'Two', body: '<p>b</p>', tasks: [] }, { id: 'doc_1', title: 'One', body: '<h1>x</h1>', tasks: [{ id: 'pt1', title: 'Quote', scheduledDate: '' }] }],
  habitGoals: [{ id: 'g1', name: 'Daily Pages' }, { id: 'h2', name: 'Run', linkedExerciseIds: ['e1'] }],
  habitCompletions: { '2026-09-30': ['g1'], '2026-10-01': ['g1', 'h2'], '2026-10-27': [] },
  fitnessLog: { '2026-10-27': [{ id: 'x1', exerciseId: 'e1', collapsed: true, sets: [{ id: 's1', reps: 8, weight: 135, done: true }] }] },
  navColor: '#5c2d52',
  _savedAt: '2026-10-28T00:00:00.000Z',
});

test('import replaces everything, removes leftovers, and verifies', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'laptop');
  a.edit('weekData', () => ({ 'TEST-only': { proverb: 'scratch' } }));
  a.edit('pagesData', () => [{ id: 'junk', title: 'junk' }]);
  a.edit('navColor', () => '#ff0000');
  await a.Sync.flush();
  const b = await bootDevice(env, 'phone');
  assert.ok(b.state.weekData['TEST-only']);

  const progress = [];
  const r = await a.Sync.importAll(BIG(), (d, t) => progress.push([d, t]));
  assert.deepEqual(r.mismatches, []);
  assert.ok(r.changes > 5);
  assert.deepEqual(progress.at(-1), [r.changes, r.changes]);
  const want = BIG();
  assert.deepEqual(a.state.weekData, want.weekData);
  assert.deepEqual(a.state.pagesData, want.pagesData);
  assert.deepEqual(a.state.habitGoals, want.habitGoals);
  assert.equal(a.state.navColor, '#5c2d52');
  assert.deepEqual(a.state.fitnessLog, want.fitnessLog);
  assert.equal(a.Sync.pendingCount(), 0);
  assert.equal(a.store.get('lpt_sync_outbox'), '{}', 'outbox not bloated');

  await b.Sync.pull();
  assert.deepEqual(b.state.weekData, want.weekData, 'other device drops the test-only week');
  assert.deepEqual(b.state.pagesData, want.pagesData);
  assert.equal(b.state.navColor, '#5c2d52');

  // Re-running the same import is a no-op
  const again = await a.Sync.importAll(BIG());
  assert.equal(again.changes, 0);
  assert.deepEqual(again.mismatches, []);
});

test('import wins over a conflicting edit from another device', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'laptop');
  const b = await bootDevice(env, 'phone');
  a.edit('navColor', () => '#111111');
  await a.Sync.flush();
  b.edit('habitGoals', () => [{ id: 'zz', name: 'phone-only' }]);
  await b.Sync.flush();
  const r = await a.Sync.importAll(BIG());   // a hasn't pulled b's change; importAll pulls first anyway
  assert.deepEqual(r.mismatches, []);
  assert.deepEqual(a.state.habitGoals, BIG().habitGoals);
});

test('import fails cleanly offline, and can be re-run', async () => {
  const env = makeEnv();
  const a = await bootDevice(env, 'laptop');
  a.net.online = false;
  await assert.rejects(a.Sync.importAll(BIG()), /Upload failed|Network/);
  a.net.online = true;
  const r = await a.Sync.importAll(BIG());
  assert.deepEqual(r.mismatches, []);
  assert.deepEqual(a.state.pagesData, BIG().pagesData);
});

test('round trip: app data → D1 → nightly backup file → import on a fresh account is identical', async () => {
  const env = makeEnv();
  const google = globalThis.__fakeGoogle;
  const a = await bootDevice(env, 'laptop');
  await a.Sync.importAll(BIG());
  const user = env.DB.raw.prepare("SELECT id, email, backup_folder_id FROM users WHERE email = 'zach@example.com'").get();
  const r = await backupUser(env, user);
  assert.equal(r.status, 'ok', JSON.stringify(r));
  const file = [...google.drives.get('zach@example.com').values()].find((f) => f.name.startsWith('lp-planner-backup-'));
  const restored = JSON.parse(file.content);
  const f = await bootDevice(env, 'family', 'fam@example.com');
  const r2 = await f.Sync.importAll(restored);
  assert.deepEqual(r2.mismatches, []);
  const want = BIG(); delete want._savedAt;
  for (const k of Object.keys(want)) assert.deepEqual(f.state[k], want[k], k);
});
