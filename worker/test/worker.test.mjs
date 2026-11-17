// Worker tests against real SQLite + fake Google.  Run: node --test worker/test/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { makeD1, installFakeGoogle } from './d1shim.mjs';
import worker from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const ORIGIN = 'https://zacharypals.github.io';
const REDIRECT = 'https://zacharypals.github.io/Planner_Web_App_TEST/oauth.html';
const google = installFakeGoogle();

function makeEnv() {
  return {
    DB: makeD1(join(here, '..', 'migrations')),
    ALLOWED_ORIGIN: ORIGIN,
    REDIRECT_URI: REDIRECT,
    GOOGLE_CLIENT_ID: 'cid',
    GOOGLE_CLIENT_SECRET: 'secret',
    ALLOWED_EMAILS: 'zach@example.com, fam@example.com',
    TOKEN_ENC_KEY: Buffer.alloc(32, 7).toString('base64'),
  };
}

async function call(env, method, path, { body, token, raw } = {}) {
  const headers = { Origin: ORIGIN };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await worker.fetch(new Request('https://planner-api.test' + path, {
    method, headers, body: body === undefined ? undefined : (raw ? body : JSON.stringify(body)),
  }), env);
  const text = await res.text();
  let data = null; try { data = JSON.parse(text); } catch {}
  return { status: res.status, data, headers: res.headers };
}

async function signIn(env, email, flag = '') {
  const r = await call(env, 'POST', '/auth/exchange', { body: { code: `code:${email}${flag ? ':' + flag : ''}`, redirect_uri: REDIRECT } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return r.data;
}

test('health + CORS', async () => {
  const env = makeEnv();
  const r = await call(env, 'GET', '/health');
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), ORIGIN);
  assert.equal(r.headers.get('Cache-Control'), 'no-store');
  const other = await worker.fetch(new Request('https://x/health', { headers: { Origin: 'https://evil.example' } }), env);
  assert.equal(other.headers.get('Access-Control-Allow-Origin'), null);
});

test('sign-in rules', async () => {
  const env = makeEnv();
  assert.equal((await call(env, 'POST', '/auth/exchange', { body: { code: 'code:zach@example.com', redirect_uri: 'https://evil/x' } })).status, 400);
  assert.equal((await call(env, 'POST', '/auth/exchange', { body: { code: 'code:stranger@example.com', redirect_uri: REDIRECT } })).status, 403);
  const s = await signIn(env, 'Zach@Example.com'.toLowerCase());
  assert.ok(s.session_token && s.google_access_token && s.calendar_ok);
  const me = await call(env, 'GET', '/api/me', { token: s.session_token });
  assert.equal(me.data.email, 'zach@example.com');
  assert.equal((await call(env, 'GET', '/api/me')).status, 401);
  assert.equal((await call(env, 'GET', '/api/me', { token: 'nope' })).status, 401);
  // Only the hash is stored
  const rows = env.DB.raw.prepare('SELECT token_hash FROM sessions').all();
  assert.ok(rows.every((r) => r.token_hash !== s.session_token && r.token_hash.length === 64));
  // Google tokens are encrypted at rest
  const g = env.DB.raw.prepare('SELECT * FROM google_tokens').get();
  assert.ok(!String(g.refresh_enc).includes('grt|') && !String(g.access_enc).includes('gat|'));
  // Removing an email from the allowlist locks it out immediately
  env.ALLOWED_EMAILS = 'fam@example.com';
  assert.equal((await call(env, 'GET', '/api/me', { token: s.session_token })).status, 403);
  env.ALLOWED_EMAILS = 'zach@example.com';
  // Logout kills the session
  await call(env, 'POST', '/auth/logout', { token: s.session_token });
  assert.equal((await call(env, 'GET', '/api/me', { token: s.session_token })).status, 401);
});

test('session expiry and sliding renewal', async () => {
  const env = makeEnv();
  const s = await signIn(env, 'zach@example.com');
  const day = 86400000;
  env.DB.raw.prepare('UPDATE sessions SET last_used_at = ?, expires_at = ?').run(Date.now() - 2 * day, Date.now() + 5 * day);
  assert.equal((await call(env, 'GET', '/api/me', { token: s.session_token })).status, 200);
  const row = env.DB.raw.prepare('SELECT expires_at FROM sessions').get();
  assert.ok(row.expires_at > Date.now() + 80 * day, 'renewed to ~90 days');
  env.DB.raw.prepare('UPDATE sessions SET expires_at = ?').run(Date.now() - 1);
  assert.equal((await call(env, 'GET', '/api/me', { token: s.session_token })).status, 401);
  assert.equal(env.DB.raw.prepare('SELECT COUNT(*) n FROM sessions').get().n, 0);
});

test('google token: cached, refreshed, reconnect needed', async () => {
  const env = makeEnv();
  const s = await signIn(env, 'zach@example.com');
  let r = await call(env, 'POST', '/api/google-token', { token: s.session_token });
  assert.equal(r.data.access_token, s.google_access_token, 'served from cache');
  env.DB.raw.prepare('UPDATE google_tokens SET access_expires_at = ?').run(Date.now() + 60000);
  const before = google.refreshCalls;
  r = await call(env, 'POST', '/api/google-token', { token: s.session_token });
  assert.equal(google.refreshCalls, before + 1);
  assert.notEqual(r.data.access_token, s.google_access_token);
  // A later sign-in without a refresh token keeps the old one
  env.DB.raw.prepare('UPDATE google_tokens SET access_expires_at = 0').run();
  google.refreshOk = false;
  r = await call(env, 'POST', '/api/google-token', { token: s.session_token });
  assert.equal(r.status, 409);
  assert.equal(r.data.error, 'google_reauth_required');
  r = await call(env, 'POST', '/api/google-token', { token: s.session_token });
  assert.equal(r.status, 409, 'stays disconnected until next sign-in');
  google.refreshOk = true;
});

test('docs: create, update, conflict, delete, changes, isolation', async () => {
  const env = makeEnv();
  const a = (await signIn(env, 'zach@example.com')).session_token;
  const b = (await signIn(env, 'fam@example.com')).session_token;

  let r = await call(env, 'GET', '/api/docs', { token: a });
  assert.deepEqual(r.data, { cursor: 0, docs: [] });

  // Create two docs
  r = await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [
    { c: 'weekData', i: '2026-10-25', b: 0, j: JSON.stringify({ proverb: 'one', tasks: {} }) },
    { c: 'navColor', i: '_', b: 0, j: '"#5c2d52"' },
  ] } });
  assert.equal(r.status, 200);
  assert.deepEqual(r.data.results.map((x) => [x.i, x.ok, x.v]), [['2026-10-25', 1, 1], ['_', 1, 1]]);

  // Update with correct base
  r = await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [{ c: 'weekData', i: '2026-10-25', b: 1, j: '{"proverb":"two"}' }] } });
  assert.equal(r.data.results[0].v, 2);

  // Stale base → conflict with server copy
  r = await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [{ c: 'weekData', i: '2026-10-25', b: 1, j: '{"proverb":"stale"}' }] } });
  assert.equal(r.data.results[0].conflict, 1);
  assert.equal(r.data.results[0].v, 2);
  assert.deepEqual(r.data.results[0].d, { proverb: 'two' });

  // Creating something that already exists → conflict
  r = await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [{ c: 'navColor', i: '_', b: 0, j: '"#000"' }] } });
  assert.equal(r.data.results[0].conflict, 1);

  // Mixed batch: one ok, one conflict
  r = await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [
    { c: 'navColor', i: '_', b: 1, j: '"#111"' },
    { c: 'weekData', i: '2026-10-25', b: 9, j: '{}' },
  ] } });
  assert.equal(r.data.results.find((x) => x.i === '_').ok, 1);
  assert.equal(r.data.results.find((x) => x.i === '2026-10-25').conflict, 1);

  // Changes since 0 includes everything, latest versions
  r = await call(env, 'GET', '/api/changes?since=0', { token: a });
  const cursor1 = r.data.cursor;
  assert.equal(r.data.docs.length, 2);
  assert.equal(r.data.more, false);

  // Delete → tombstone shows in changes, hidden from full load
  r = await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [{ c: 'weekData', i: '2026-10-25', b: 2, x: 1 }] } });
  assert.equal(r.data.results[0].v, 3);
  r = await call(env, 'GET', `/api/changes?since=${cursor1}`, { token: a });
  assert.deepEqual(r.data.docs, [{ c: 'weekData', i: '2026-10-25', v: 3, x: 1 }]);
  r = await call(env, 'GET', '/api/docs', { token: a });
  assert.deepEqual(r.data.docs.map((d) => d.c), ['navColor']);
  // Re-create after delete needs the tombstone version
  r = await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [{ c: 'weekData', i: '2026-10-25', b: 0, j: '{}' }] } });
  assert.equal(r.data.results[0].conflict, 1);
  assert.equal(r.data.results[0].x, 1);
  r = await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [{ c: 'weekData', i: '2026-10-25', b: 3, j: '{"back":true}' }] } });
  assert.equal(r.data.results[0].v, 4);

  // Isolation: the other person sees nothing and can't touch these docs
  r = await call(env, 'GET', '/api/docs', { token: b });
  assert.deepEqual(r.data.docs, []);
  r = await call(env, 'PUT', '/api/docs', { token: b, body: { docs: [{ c: 'weekData', i: '2026-10-25', b: 0, j: '{"mine":1}' }] } });
  assert.equal(r.data.results[0].v, 1, 'separate copy for the other user');
  r = await call(env, 'GET', '/api/docs', { token: a });
  assert.deepEqual(r.data.docs.find((d) => d.c === 'weekData').d, { back: true });
});

test('docs: validation and limits', async () => {
  const env = makeEnv();
  const a = (await signIn(env, 'zach@example.com')).session_token;
  const put = (docs) => call(env, 'PUT', '/api/docs', { token: a, body: { docs } });
  assert.equal((await put([])).status, 400);
  assert.equal((await put([{ c: 'bad name', i: 'x', b: 0, j: '1' }])).status, 400);
  assert.equal((await put([{ c: 'ok', i: '', b: 0, j: '1' }])).status, 400);
  assert.equal((await put([{ c: 'ok', i: 'x', b: -1, j: '1' }])).status, 400);
  assert.equal((await put([{ c: 'ok', i: 'x', b: 0 }])).status, 400);
  assert.equal((await put([{ c: 'ok', i: 'x', b: 0, j: 'x'.repeat(1_900_001) }])).status, 413);
  assert.equal((await call(env, 'PUT', '/api/docs', { token: a, body: 'not json', raw: true })).status, 400);
  const many = Array.from({ length: 100 }, (_, n) => ({ c: 'fitnessLog', i: `d${n}`, b: 0, j: `{"n":${n}}` }));
  const r = await put(many);
  assert.equal(r.status, 200);
  assert.equal(r.data.results.filter((x) => x.ok).length, 100);
  assert.equal((await put([...many, { c: 'x', i: 'y', b: 0, j: '1' }])).status, 400);
});

test('changes paging and cheap polling', async () => {
  const env = makeEnv();
  const a = (await signIn(env, 'zach@example.com')).session_token;
  for (let k = 0; k < 6; k++) {
    const docs = Array.from({ length: 100 }, (_, n) => ({ c: 'fitnessLog', i: `d${k}-${n}`, b: 0, j: '{}' }));
    await call(env, 'PUT', '/api/docs', { token: a, body: { docs } });
  }
  let r = await call(env, 'GET', '/api/changes?since=0', { token: a });
  assert.equal(r.data.docs.length, 500);
  assert.equal(r.data.more, true);
  r = await call(env, 'GET', `/api/changes?since=${r.data.cursor}`, { token: a });
  assert.equal(r.data.docs.length, 100);
  assert.equal(r.data.more, false);
  // An idle poll reads almost nothing (index on user_id, seq)
  const before = env.DB.stats.rowsRead;
  r = await call(env, 'GET', `/api/changes?since=${r.data.cursor}`, { token: a });
  assert.equal(r.data.docs.length, 0);
  assert.ok(env.DB.stats.rowsRead - before <= 3, `idle poll read ${env.DB.stats.rowsRead - before} rows`);
  const plan = env.DB.raw.prepare("EXPLAIN QUERY PLAN SELECT collection FROM docs WHERE user_id = 'x' AND seq > 5 ORDER BY seq").all();
  assert.ok(plan.some((p) => /idx_docs_user_seq/.test(p.detail)), JSON.stringify(plan));
});

// ── Backups ───────────────────────────────────────────────
import { backupUser, runNightlyBackups, ptDate, assembleBackup } from '../src/backup.js';

function userRow(env, email) { return env.DB.raw.prepare('SELECT id, email, backup_folder_id FROM users WHERE email = ?').get(email); }
function driveOf(email) { return google.drives.get(email) || new Map(); }
const backups = (email) => [...driveOf(email).values()].filter((f) => /^lp-planner-backup-/.test(f.name));

test('backup: skipped when empty, written when there is data; "Back up now" never overwrites the nightly file', async () => {
  google.drives.clear();
  const env = makeEnv();
  const a = (await signIn(env, 'zach@example.com')).session_token;
  let r = await call(env, 'POST', '/api/backup', { token: a });
  assert.equal(r.data.status, 'skipped_empty');
  assert.equal(backups('zach@example.com').length, 0);

  await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [
    { c: 'navColor', i: '_', b: 0, j: '"#5c2d52"' },
    { c: 'weekData', i: '2026-10-25', b: 0, j: '{"proverb":"p","tasks":{}}' },
  ] } });
  env.DB.raw.prepare('UPDATE users SET last_backup_at = 0').run();
  r = await call(env, 'POST', '/api/backup', { token: a });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.status, 'ok');
  const files = backups('zach@example.com');
  assert.equal(files.length, 1);
  assert.match(files[0].name, new RegExp(`^lp-planner-backup-${ptDate()}-manual-\\d{4}\\.json$`));
  const folder = [...driveOf('zach@example.com').values()].find((f) => f.folder);
  assert.equal(folder.name, 'LP Planner Backups');
  assert.deepEqual(files[0].parents, [folder.id]);
  const body = JSON.parse(files[0].content);
  assert.equal(body.navColor, '#5c2d52');
  assert.deepEqual(body.weekData, { '2026-10-25': { proverb: 'p', tasks: {} } });

  // Too soon → 429
  assert.equal((await call(env, 'POST', '/api/backup', { token: a })).status, 429);

  // The nightly run writes its own file...
  const nightly = await backupUser(env, userRow(env, 'zach@example.com'));
  assert.equal(nightly.file, `lp-planner-backup-${ptDate()}.json`);
  assert.equal(backups('zach@example.com').length, 2);
  const nightlyContent = () => backups('zach@example.com').find((f) => f.name === nightly.file).content;
  const before = nightlyContent();
  assert.equal(JSON.parse(before).navColor, '#5c2d52');
  // ...and a later change plus "Back up now" leaves it exactly as it was
  await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [{ c: 'navColor', i: '_', b: 1, j: '"#000000"' }] } });
  env.DB.raw.prepare('UPDATE users SET last_backup_at = 0').run();
  await call(env, 'POST', '/api/backup', { token: a });
  assert.equal(nightlyContent(), before, 'nightly snapshot untouched by a manual backup');
  const man = backups('zach@example.com').filter((f) => /-manual-/.test(f.name));
  assert.ok(man.some((f) => JSON.parse(f.content).navColor === '#000000'), 'manual backup has the newer data');

  // Status shows on /api/me
  const me = await call(env, 'GET', '/api/me', { token: a });
  assert.equal(me.data.backup.status, 'ok');
  assert.equal(me.data.drive_ok, true);
});

test('backup: only the newest 5 manual backups are kept; nightly files are never counted', async () => {
  google.drives.clear();
  const env = makeEnv();
  const a = (await signIn(env, 'zach@example.com')).session_token;
  await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [{ c: 'navColor', i: '_', b: 0, j: '"#5c2d52"' }] } });
  const u = userRow(env, 'zach@example.com');
  const t0 = Date.now();
  await backupUser(env, u, t0);                                   // nightly
  for (let k = 0; k < 8; k++) await backupUser(env, userRow(env, 'zach@example.com'), t0 + k * 120000, { manual: true });
  const names = backups('zach@example.com').map((f) => f.name);
  assert.equal(names.filter((n) => /-manual-/.test(n)).length, 5);
  assert.equal(names.filter((n) => !/-manual-/.test(n)).length, 1);
});

test('backup: retention keeps 7 days + the 1st of each month for a year; other files untouched', async () => {
  const env = makeEnv();
  const a = (await signIn(env, 'zach@example.com')).session_token;
  await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [{ c: 'navColor', i: '_', b: 0, j: '"#1"' }] } });
  await backupUser(env, userRow(env, 'zach@example.com'));
  const drive = driveOf('zach@example.com');
  const folder = [...drive.values()].find((f) => f.folder);
  const day = 86400000, now = Date.now();
  const add = (name) => drive.set('x' + name, { id: 'x' + name, name, parents: [folder.id], content: '{}', modified: now });
  const names = [];
  for (let k = 1; k <= 40; k++) names.push(`lp-planner-backup-${ptDate(new Date(now - k * day))}.json`);
  names.push('lp-planner-backup-2020-01-01.json', 'lp-planner-backup-2020-06-15.json', 'my notes.json');
  names.forEach(add);
  await backupUser(env, userRow(env, 'zach@example.com'));
  const left = [...drive.values()].map((f) => f.name);
  const today = ptDate(new Date(now));
  for (const n of names) {
    const d = (n.match(/(\d{4}-\d{2}-\d{2})/) || [])[1];
    if (!d) { assert.ok(left.includes(n), 'non-backup file kept'); continue; }
    const recent = d >= ptDate(new Date(now - 6 * day));
    const monthly = d.endsWith('-01') && d >= ptDate(new Date(now - 12 * 31 * day));
    assert.equal(left.includes(n), recent || monthly, `${n} kept=${left.includes(n)}`);
  }
  assert.ok(left.includes(`lp-planner-backup-${today}.json`));
});

test('backup: no Drive permission, revoked Google, Drive outage, deleted folder', async (t) => {
  t.after(() => { google.driveFail = null; google.refreshOk = true; });
  google.drives.clear();
  const env = makeEnv();
  const s = await call(env, 'POST', '/auth/exchange', { body: { code: 'code:zach@example.com:nodrive', redirect_uri: REDIRECT } });
  const a = s.data.session_token;
  await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [{ c: 'navColor', i: '_', b: 0, j: '"#1"' }] } });
  let r = await backupUser(env, userRow(env, 'zach@example.com'));
  assert.equal(r.status, 'needs_drive');
  assert.equal((await call(env, 'GET', '/api/me', { token: a })).data.drive_ok, false);

  await signIn(env, 'zach@example.com');               // grants Drive
  google.driveFail = (method) => method !== 'GET';
  r = await backupUser(env, userRow(env, 'zach@example.com'));
  assert.equal(r.status, 'error');
  assert.match(r.error, /Drive 500/);
  google.driveFail = null;

  r = await backupUser(env, userRow(env, 'zach@example.com'));
  assert.equal(r.status, 'ok');
  // Folder deleted by the user → recreated
  const drive = driveOf('zach@example.com');
  for (const f of [...drive.values()]) drive.delete(f.id);
  r = await backupUser(env, userRow(env, 'zach@example.com'));
  assert.equal(r.status, 'ok');
  assert.equal(backups('zach@example.com').length, 1);

  env.DB.raw.prepare('UPDATE google_tokens SET access_expires_at = 0').run();
  google.refreshOk = false;
  r = await backupUser(env, userRow(env, 'zach@example.com'));
  assert.equal(r.status, 'error');
  assert.match(r.error, /sign in again/);
  google.refreshOk = true;
});

test('nightly cron backs up each allowed person into their own Drive', async () => {
  const env = makeEnv();
  google.drives.clear();
  const a = (await signIn(env, 'zach@example.com')).session_token;
  const b = (await signIn(env, 'fam@example.com')).session_token;
  await call(env, 'PUT', '/api/docs', { token: a, body: { docs: [{ c: 'navColor', i: '_', b: 0, j: '"#zach"' }] } });
  await call(env, 'PUT', '/api/docs', { token: b, body: { docs: [{ c: 'navColor', i: '_', b: 0, j: '"#fam"' }] } });
  const waits = [];
  await worker.scheduled({}, env, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
  assert.equal(JSON.parse(backups('zach@example.com')[0].content).navColor, '#zach');
  assert.equal(JSON.parse(backups('fam@example.com')[0].content).navColor, '#fam');
  env.ALLOWED_EMAILS = 'zach@example.com';
  google.drives.clear();
  const w2 = [];
  await worker.scheduled({}, env, { waitUntil: (p) => w2.push(p) });
  await Promise.all(w2);
  assert.equal(backups('fam@example.com').length, 0, 'removed person is skipped');
});

test('assembleBackup handles every collection shape', () => {
  const rows = [
    { collection: 'pagesData', doc_id: 'p:b', data: '{"id":"b"}' },
    { collection: 'pagesData', doc_id: '__order', data: '["p:b","p:a"]' },
    { collection: 'pagesData', doc_id: 'p:a', data: '{"id":"a"}' },
    { collection: 'habitQty', doc_id: '2026-09', data: '{"2026-09-30":{"g":1}}' },
    { collection: 'habitQty', doc_id: '2026-10', data: '{}' },
    { collection: 'habitQty', doc_id: '2026-11', data: '{"2026-11-01":{"g":2}}' },
    { collection: 'weightTarget', doc_id: '_', data: '""' },
    { collection: 'fitnessLog', doc_id: '2026-10-27', data: '[{"id":"x"}]' },
  ];
  const out = JSON.parse(assembleBackup(rows, new Date(0)));
  assert.deepEqual(out.pagesData, [{ id: 'b' }, { id: 'a' }]);
  assert.deepEqual(out.habitQty, { '2026-09-30': { g: 1 }, '2026-11-01': { g: 2 } });
  assert.equal(out.weightTarget, '');
  assert.deepEqual(out.fitnessLog, { '2026-10-27': [{ id: 'x' }] });
  assert.equal(out._backupAt, '1970-01-01T00:00:00.000Z');
});

test('exchange accepts any listed redirect URI and rejects others (0.2.2)', async () => {
  const env = makeEnv();
  const LIVE = 'https://zacharypals.github.io/Planner_Web_App/oauth.html';
  env.REDIRECT_URI = `${LIVE}, ${REDIRECT}`;
  for (const uri of [LIVE, REDIRECT]) {
    const r = await call(env, 'POST', '/auth/exchange', { body: { code: 'code:zach@example.com', redirect_uri: uri } });
    assert.equal(r.status, 200, uri + ' ' + JSON.stringify(r.data));
  }
  const bad = await call(env, 'POST', '/auth/exchange', { body: { code: 'code:zach@example.com', redirect_uri: 'https://evil.example/oauth.html' } });
  assert.equal(bad.status, 400);
});

test('shared household space (0.3.0): both members share rel* docs, privately-owned data stays private', async () => {
  const env = makeEnv();
  const z = (await signIn(env, 'zach@example.com')).session_token;
  const f = (await signIn(env, 'fam@example.com')).session_token;

  // Zach writes a shared check-in doc; Fam sees it.
  let r = await call(env, 'PUT', '/api/shared/docs', { token: z, body: { docs: [
    { c: 'relCheckins', i: '2026-11-15', b: 0, j: JSON.stringify({ answers: { z: { done: true } } }) },
  ] } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.results[0].ok, 1);
  r = await call(env, 'GET', '/api/shared/docs', { token: f });
  assert.equal(r.status, 200);
  assert.equal(r.data.docs.length, 1);
  assert.deepEqual(r.data.docs[0].d, { answers: { z: { done: true } } });
  const cursor = r.data.cursor;

  // Fam adds her half (based on version 1); Zach's change feed shows it.
  r = await call(env, 'PUT', '/api/shared/docs', { token: f, body: { docs: [
    { c: 'relCheckins', i: '2026-11-15', b: 1, j: JSON.stringify({ answers: { z: { done: true }, c: { done: true } } }) },
  ] } });
  assert.equal(r.data.results[0].v, 2);
  r = await call(env, 'GET', `/api/shared/changes?since=${cursor}`, { token: z });
  assert.equal(r.data.docs.length, 1);
  assert.equal(r.data.docs[0].v, 2);

  // A stale save comes back as a conflict with the server copy (same rules as private docs).
  r = await call(env, 'PUT', '/api/shared/docs', { token: z, body: { docs: [
    { c: 'relCheckins', i: '2026-11-15', b: 1, j: '{"stale":1}' },
  ] } });
  assert.equal(r.data.results[0].conflict, 1);

  // Only rel* collections may be written to the shared space.
  r = await call(env, 'PUT', '/api/shared/docs', { token: z, body: { docs: [{ c: 'weekData', i: 'x', b: 0, j: '{}' }] } });
  assert.equal(r.status, 400);

  // Shared and private spaces are separate: private docs don't leak in, shared docs don't leak out.
  await call(env, 'PUT', '/api/docs', { token: z, body: { docs: [{ c: 'navColor', i: '_', b: 0, j: '"#111"' }] } });
  r = await call(env, 'GET', '/api/shared/docs', { token: f });
  assert.deepEqual(r.data.docs.map((d) => d.c), ['relCheckins']);
  r = await call(env, 'GET', '/api/docs', { token: f });
  assert.deepEqual(r.data.docs, []);

  // Not a member → refused (HOUSEHOLD_EMAILS narrows membership), and no session → 401.
  env.HOUSEHOLD_EMAILS = 'zach@example.com';
  assert.equal((await call(env, 'GET', '/api/shared/docs', { token: f })).status, 403);
  assert.equal((await call(env, 'GET', '/api/shared/docs', { token: z })).status, 200);
  assert.equal((await call(env, 'GET', '/api/shared/docs')).status, 401);
});

const sharedBackups = (email) => [...driveOf(email).values()].filter((f) => /^lp-shared-backup-/.test(f.name));

test('backup 0.3.1: shared (Us) data is written to each member\'s Drive folder; private backups unchanged', async () => {
  google.drives.clear();
  const env = makeEnv();
  const z = (await signIn(env, 'zach@example.com')).session_token;
  const f = (await signIn(env, 'fam@example.com')).session_token;
  await call(env, 'PUT', '/api/docs', { token: z, body: { docs: [{ c: 'navColor', i: '_', b: 0, j: '"#z"' }] } });
  await call(env, 'PUT', '/api/docs', { token: f, body: { docs: [{ c: 'navColor', i: '_', b: 0, j: '"#f"' }] } });
  // Nothing shared yet → no shared file.
  await backupUser(env, userRow(env, 'zach@example.com'));
  assert.equal(sharedBackups('zach@example.com').length, 0);

  await call(env, 'PUT', '/api/shared/docs', { token: z, body: { docs: [
    { c: 'relMeta', i: '_', b: 0, j: JSON.stringify({ members: { 'zach@example.com': { name: 'Zach' } } }) },
    { c: 'relCheckins', i: 'ck1', b: 0, j: JSON.stringify({ id: 'ck1', answers: { z: { r: { q1: 'high' } } } }) },
    { c: 'relMoments', i: 'm1', b: 0, j: JSON.stringify({ id: 'm1', note: 'Sunrise hike' }) },
    { c: 'relMoments', i: 'm2', b: 0, j: JSON.stringify({ id: 'm2', note: 'deleted one' }) },
  ] } });
  await call(env, 'PUT', '/api/shared/docs', { token: z, body: { docs: [{ c: 'relMoments', i: 'm2', b: 1, x: 1 }] } });

  const r = await backupUser(env, userRow(env, 'zach@example.com'));
  assert.equal(r.status, 'ok');
  assert.equal(r.shared.docs, 3, 'deleted docs are not backed up');
  await backupUser(env, userRow(env, 'fam@example.com'));
  for (const email of ['zach@example.com', 'fam@example.com']) {
    const files = sharedBackups(email);
    assert.equal(files.length, 1, email);
    assert.equal(files[0].name, `lp-shared-backup-${ptDate()}.json`);
    const data = JSON.parse(files[0].content);
    assert.equal(data._source, 'planner-api-shared');
    assert.deepEqual(Object.keys(data.collections).sort(), ['relCheckins', 'relMeta', 'relMoments']);
    assert.equal(data.collections.relCheckins.ck1.answers.z.r.q1, 'high');
    assert.deepEqual(Object.keys(data.collections.relMoments), ['m1']);
    assert.equal(data.collections.relMeta._.members['zach@example.com'].name, 'Zach');
  }
  // The private file is still its own thing and never contains shared collections.
  const priv = JSON.parse(backups('zach@example.com')[0].content);
  assert.equal(priv.navColor, '#z');
  assert.ok(!('relCheckins' in priv) && !('collections' in priv));
  // Same-day rerun overwrites rather than duplicating.
  await backupUser(env, userRow(env, 'zach@example.com'));
  assert.equal(sharedBackups('zach@example.com').length, 1);

  // Retention: old shared files follow the same 7-day + monthly rule; other files untouched.
  const drive = driveOf('zach@example.com');
  const folder = [...drive.values()].find((x) => x.folder);
  const day = 86400000, now = Date.now();
  const names = [`lp-shared-backup-${ptDate(new Date(now - 3 * day))}.json`, `lp-shared-backup-${ptDate(new Date(now - 20 * day))}.json`, 'lp-shared-backup-2020-01-01.json', 'lp-shared-backup-2020-06-15.json'];
  names.forEach((n) => drive.set('s' + n, { id: 's' + n, name: n, parents: [folder.id], content: '{}', modified: now }));
  await backupUser(env, userRow(env, 'zach@example.com'));
  const left = sharedBackups('zach@example.com').map((x) => x.name);
  assert.ok(left.includes(names[0]), 'recent kept');
  assert.ok(!left.includes(names[1]) || names[1].endsWith('-01.json'), '20-day-old non-monthly removed');
  assert.ok(left.includes('lp-shared-backup-2020-01-01.json') === false, 'a 2020 monthly is older than a year');
  assert.ok(!left.includes('lp-shared-backup-2020-06-15.json'));
});

test('backup 0.3.1: non-members get no shared file; a failing shared upload is reported, private backup still saved', async (t) => {
  t.after(() => { google.driveFail = null; });
  google.drives.clear();
  const env = makeEnv();
  env.HOUSEHOLD_EMAILS = 'zach@example.com';
  const z = (await signIn(env, 'zach@example.com')).session_token;
  const f = (await signIn(env, 'fam@example.com')).session_token;
  await call(env, 'PUT', '/api/docs', { token: z, body: { docs: [{ c: 'navColor', i: '_', b: 0, j: '"#z"' }] } });
  await call(env, 'PUT', '/api/docs', { token: f, body: { docs: [{ c: 'navColor', i: '_', b: 0, j: '"#f"' }] } });
  await call(env, 'PUT', '/api/shared/docs', { token: z, body: { docs: [{ c: 'relMoments', i: 'm1', b: 0, j: '{"id":"m1"}' }] } });
  await backupUser(env, userRow(env, 'fam@example.com'));
  assert.equal(sharedBackups('fam@example.com').length, 0, 'not a household member');
  assert.equal(backups('fam@example.com').length, 1, 'private backup still made');

  let uploads = 0;
  google.driveFail = (method, u) => method !== 'GET' && u.pathname.startsWith('/upload/') && ++uploads === 2;
  const r = await backupUser(env, userRow(env, 'zach@example.com'));
  assert.equal(r.status, 'error');
  assert.match(r.error, /shared \(Us\) backup failed/);
  assert.equal(backups('zach@example.com').length, 1, 'private file was written');
  assert.equal(sharedBackups('zach@example.com').length, 0);
  google.driveFail = null;
  assert.equal((await backupUser(env, userRow(env, 'zach@example.com'))).status, 'ok', 'recovers next run');
  assert.equal(sharedBackups('zach@example.com').length, 1);
});

function fakeR2() {
  const m = new Map();
  return {
    m,
    async put(k, v, o) { m.set(k, { bytes: new Uint8Array(v), type: o && o.httpMetadata && o.httpMetadata.contentType }); },
    async get(k) { const x = m.get(k); return x ? { body: new Blob([x.bytes]).stream(), httpEtag: '"e"' } : null; },
    async delete(keys) { for (const k of [].concat(keys)) m.delete(k); },
  };
}
const jpeg = (n = 100) => { const b = new Uint8Array(n); b[0] = 0xff; b[1] = 0xd8; b[2] = 0xff; return b; };
async function rawCall(env, method, path, token, body) {
  const res = await worker.fetch(new Request('https://planner-api.test' + path, { method, headers: { Origin: ORIGIN, ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body }), env);
  return res;
}

test('photos (0.4.0): members upload/read/delete JPEGs in R2; validation and access rules', async () => {
  const env = makeEnv();
  env.PHOTOS = fakeR2();
  const z = (await signIn(env, 'zach@example.com')).session_token;
  const f = (await signIn(env, 'fam@example.com')).session_token;

  let r = await rawCall(env, 'PUT', '/api/shared/photos/p_abc123xyz?v=full', z, jpeg(5000));
  assert.equal(r.status, 200);
  r = await rawCall(env, 'PUT', '/api/shared/photos/p_abc123xyz?v=thumb', z, jpeg(800));
  assert.equal(r.status, 200);
  assert.deepEqual([...env.PHOTOS.m.keys()].sort(), ['household/p_abc123xyz-t.jpg', 'household/p_abc123xyz.jpg']);

  // The other member can read both sizes; caching is allowed but private + immutable.
  r = await rawCall(env, 'GET', '/api/shared/photos/p_abc123xyz?v=thumb', f);
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('Content-Type'), 'image/jpeg');
  assert.match(r.headers.get('Cache-Control'), /private.*immutable/);
  assert.equal((await r.arrayBuffer()).byteLength, 800);
  r = await rawCall(env, 'GET', '/api/shared/photos/p_abc123xyz', f);
  assert.equal((await r.arrayBuffer()).byteLength, 5000);
  assert.equal((await rawCall(env, 'GET', '/api/shared/photos/p_nothere1234', f)).status, 404);
  // Other endpoints are still never cached.
  assert.equal((await call(env, 'GET', '/health')).headers.get('Cache-Control'), 'no-store');

  // Validation: id shape, JPEG only, size limits, empty body.
  assert.equal((await rawCall(env, 'PUT', '/api/shared/photos/%2e%2e%2fx', z, jpeg())).status, 400);
  assert.equal((await rawCall(env, 'PUT', '/api/shared/photos/NOPE', z, jpeg())).status, 400);
  assert.equal((await rawCall(env, 'PUT', '/api/shared/photos/p_abc123xyz', z, new Uint8Array([1, 2, 3, 4]))).status, 400);
  assert.equal((await rawCall(env, 'PUT', '/api/shared/photos/p_abc123xyz', z, new Uint8Array(0))).status, 400);
  assert.equal((await rawCall(env, 'PUT', '/api/shared/photos/p_abc123xyz?v=thumb', z, jpeg(700_000))).status, 413);
  assert.equal((await rawCall(env, 'PUT', '/api/shared/photos/p_abc123xyz?v=full', z, jpeg(3_100_000))).status, 413);

  // Delete removes both sizes.
  r = await rawCall(env, 'DELETE', '/api/shared/photos/p_abc123xyz', f);
  assert.equal(r.status, 200);
  assert.equal(env.PHOTOS.m.size, 0);

  // Access: no session → 401; not a household member → 403; no bucket bound → 501.
  assert.equal((await rawCall(env, 'GET', '/api/shared/photos/p_abc123xyz', null)).status, 401);
  env.HOUSEHOLD_EMAILS = 'zach@example.com';
  assert.equal((await rawCall(env, 'PUT', '/api/shared/photos/p_abc123xyz', f, jpeg())).status, 403);
  delete env.PHOTOS;
  assert.equal((await rawCall(env, 'PUT', '/api/shared/photos/p_abc123xyz', z, jpeg())).status, 501);
});

test('CORS allows DELETE for the app origin (photos)', async () => {
  const env = makeEnv();
  const res = await worker.fetch(new Request('https://planner-api.test/api/shared/photos/p_abc123xyz', { method: 'OPTIONS', headers: { Origin: ORIGIN } }), env);
  assert.equal(res.status, 204);
  assert.match(res.headers.get('Access-Control-Allow-Methods'), /DELETE/);
});
