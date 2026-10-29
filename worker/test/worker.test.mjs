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
