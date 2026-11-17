// Shared-space client (index.src.html "SHARED SPACE" block) against the real Worker:
// two simulated devices (Zach, Fam), each with its own localStorage and Shared instance.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { makeD1, installFakeGoogle } from './d1shim.mjs';
import worker from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, '..', '..', 'index.src.html'), 'utf8');
const a = html.indexOf('// ═══ SHARED SPACE');
const b = html.indexOf('\n}\n', html.indexOf('function usDueNow')) + 3;
const src = html.slice(a, b);
assert.ok(src.includes('const Shared') && src.includes('function usComplete'), 'shared block found');
installFakeGoogle();
const ORIGIN = 'https://zacharypals.github.io';
const REDIRECT = 'https://zacharypals.github.io/Planner_Web_App_TEST/oauth.html';

function makeEnv() {
  return { DB: makeD1(join(here, '..', 'migrations')), ALLOWED_ORIGIN: ORIGIN, REDIRECT_URI: REDIRECT, GOOGLE_CLIENT_ID: 'cid',
    GOOGLE_CLIENT_SECRET: 's', ALLOWED_EMAILS: 'zach@example.com, fam@example.com', TOKEN_ENC_KEY: Buffer.alloc(32, 7).toString('base64') };
}
async function device(env, email) {
  const store = new Map();
  const ls = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)) };
  const net = { online: true };
  const fetchShim = async (url, init = {}) => {
    if (!net.online) throw new TypeError('Failed to fetch');
    return worker.fetch(new Request(url, { ...init, headers: { ...(init.headers || {}), Origin: ORIGIN } }), env);
  };
  const signed = await (await worker.fetch(new Request('https://api.test/auth/exchange', { method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN }, body: JSON.stringify({ code: 'code:' + email, redirect_uri: REDIRECT }) }), env)).json();
  const prelude = `
    function lsGet(k) { return localStorage.getItem('lpt_' + k); }
    function lsSet(k, v) { localStorage.setItem('lpt_' + k, v); return true; }
    function getSession() { return ${JSON.stringify(signed.session_token)}; }
    function fmtLocal(d) { return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'); }
    function getWeekStart(d) { const x = new Date(d); x.setDate(x.getDate() - x.getDay()); return x; }
    const React = { useSyncExternalStore() {} };
    class ApiError extends Error { constructor(s,c,m){super(m||c);this.status=s;this.code=c;} get isAuth(){return this.status===401;} }
    async function api(path, { method = 'GET', body } = {}) {
      const headers = { Authorization: 'Bearer ' + getSession() };
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      let res; try { res = await fetch('https://api.test' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }); }
      catch (e) { throw new ApiError(0, 'network', 'Network error'); }
      const data = await res.json().catch(() => null);
      if (!res.ok) throw new ApiError(res.status, (data && data.error) || 'http', (data && data.error) || 'http');
      return data;
    }`;
  const make = () => new Function('localStorage', 'fetch', 'setTimeout', 'clearTimeout',
    `${prelude}\n${src}\nreturn { Shared, usComplete, usDueNow };`)(ls, fetchShim, () => 0, () => {});
  let lib = make();
  return { store, net, email, get lib() { return lib; }, get Shared() { return lib.Shared; }, restart() { lib = make(); return lib; } };
}

// start() already begins a pull; wait for any in-flight pull/flush before the next step.
async function settle(...ds) { const t0 = Date.now(); for (let n = 0; Date.now() - t0 < 8000 && (n < 3 || ds.some((d) => d.Shared.pulling || d.Shared.busy)); n++) await new Promise((r) => setTimeout(r, 2)); }   // wait by the clock, not by tick count, so a busy machine can't cut it short

test('two devices share a check-in; each writes only their own section; edits survive races', async () => {
  const env = makeEnv();
  const z = await device(env, 'zach@example.com');
  const f = await device(env, 'fam@example.com');
  z.Shared.start(); f.Shared.start();
  await settle(z, f);
  assert.ok(z.Shared.synced && f.Shared.synced, z.Shared.error + f.Shared.error);

  z.Shared.set('relMeta', '_', ['questions'], [{ id: 'q1', text: 'High / Low?' }]);
  z.Shared.set('relMeta', '_', ['members', 'zach@example.com'], { name: 'Zach' });
  f.Shared.set('relMeta', '_', ['members', 'fam@example.com'], { name: 'Fam' });   // same doc, written concurrently
  await z.Shared.flush(); await f.Shared.flush(); await z.Shared.pull();
  const meta = z.Shared.get('relMeta', '_');
  assert.deepEqual(meta.questions, [{ id: 'q1', text: 'High / Low?' }]);
  assert.deepEqual(Object.keys(meta.members).sort(), ['fam@example.com', 'zach@example.com'], 'concurrent edits to different fields both survive');

  // Zach creates a check-in; Fam sees it after a pull and writes her section while Zach writes his — same doc, same moment.
  z.Shared.set('relCheckins', 'ck1', [], { id: 'ck1', date: '2026-11-16', createdAt: 1, qs: [{ id: 'q1', text: 'High / Low?' }], answers: {}, together: { notes: '', actions: {} } });
  await z.Shared.flush(); await f.Shared.pull();
  assert.equal(f.Shared.list('relCheckins').length, 1);
  z.Shared.set('relCheckins', 'ck1', ['answers', 'zach@example.com', 'r', 'q1'], 'my high');
  f.Shared.set('relCheckins', 'ck1', ['answers', 'fam@example.com', 'r', 'q1'], 'her high');
  f.Shared.set('relCheckins', 'ck1', ['together', 'actions', 'a1'], { text: 'plan date', done: false, at: 1 });
  await z.Shared.flush(); await f.Shared.flush();       // second one loses the race and replays on top of the server copy
  await z.Shared.pull(); await f.Shared.pull();
  for (const d of [z, f]) {
    const ck = d.Shared.get('relCheckins', 'ck1');
    assert.equal(ck.answers['zach@example.com'].r.q1, 'my high');
    assert.equal(ck.answers['fam@example.com'].r.q1, 'her high');
    assert.equal(ck.together.actions.a1.text, 'plan date');
  }
  assert.equal(z.Shared.ops.length, 0); assert.equal(f.Shared.ops.length, 0);

  // Completion: needs both Done (or a close).
  const members = Object.keys(z.Shared.get('relMeta', '_').members);
  z.Shared.set('relCheckins', 'ck1', ['answers', 'zach@example.com', 'done'], true);
  assert.equal(z.lib.usComplete(z.Shared.get('relCheckins', 'ck1'), members), false);
  await z.Shared.flush(); await f.Shared.pull();
  f.Shared.set('relCheckins', 'ck1', ['answers', 'fam@example.com', 'done'], true);
  assert.equal(f.lib.usComplete(f.Shared.get('relCheckins', 'ck1'), members), true);
  assert.equal(f.lib.usDueNow(f.Shared), false, 'no longer due once this week has a complete check-in');

  // Removing a field (action item) works and propagates.
  f.Shared.set('relCheckins', 'ck1', ['together', 'actions', 'a1'], undefined);
  await f.Shared.flush(); await z.Shared.pull();
  assert.deepEqual(z.Shared.get('relCheckins', 'ck1').together.actions, {});
});

test('offline edits wait in the outbox, survive a restart, then upload', async () => {
  const env = makeEnv();
  const z = await device(env, 'zach@example.com');
  const f = await device(env, 'fam@example.com');
  z.Shared.start(); await settle(z);
  z.Shared.set('relCheckins', 'ck9', [], { id: 'ck9', date: '2026-11-16', answers: {} });
  await z.Shared.flush();
  z.net.online = false;
  z.Shared.set('relCheckins', 'ck9', ['answers', 'zach@example.com', 'r', 'q1'], 'typed offline');
  z.Shared.set('relCheckins', 'ck9', ['answers', 'zach@example.com', 'r', 'q1'], 'typed offline, longer');   // collapses with the first
  assert.equal(z.Shared.ops.length, 1);
  await z.Shared.flush();
  assert.ok(z.Shared.error, 'error is surfaced');
  assert.equal(z.Shared.get('relCheckins', 'ck9').answers['zach@example.com'].r.q1, 'typed offline, longer', 'still visible locally');
  // App closed and reopened offline: the edit is reloaded from the persisted outbox.
  const lib2 = z.restart();
  lib2.Shared.start();
  assert.equal(lib2.Shared.ops.length, 1);
  assert.equal(lib2.Shared.get('relCheckins', 'ck9').answers['zach@example.com'].r.q1, 'typed offline, longer');
  z.net.online = true;
  for (let n = 0; n < 6 && lib2.Shared.ops.length; n++) { await settle({ Shared: lib2.Shared }); await lib2.Shared.pull(); await lib2.Shared.flush(); }   // retry: the start-up pull can still be in flight on a busy machine
  assert.equal(lib2.Shared.ops.length, 0);
  f.Shared.start(); await settle(f);
  assert.equal(f.Shared.get('relCheckins', 'ck9').answers['zach@example.com'].r.q1, 'typed offline, longer');
});

test('timeline moments: one doc per moment, edits and deletes propagate', async () => {
  const env = makeEnv();
  const z = await device(env, 'zach@example.com');
  const f = await device(env, 'fam@example.com');
  z.Shared.start(); f.Shared.start(); await settle(z, f);
  z.Shared.set('relMoments', 'm1', [], { id: 'm1', date: '2026-11-10', note: 'Hike at sunrise', by: 'zach@example.com', createdAt: 1 });
  f.Shared.set('relMoments', 'm2', [], { id: 'm2', date: '2026-11-12', note: 'Dinner out', by: 'fam@example.com', createdAt: 2 });
  await z.Shared.flush(); await f.Shared.flush(); await z.Shared.pull(); await f.Shared.pull();
  for (const d of [z, f]) assert.deepEqual(d.Shared.list('relMoments').map((x) => x.id).sort(), ['m1', 'm2']);
  z.Shared.set('relMoments', 'm1', ['note'], 'Hike at sunrise, then pancakes');
  f.Shared.remove('relMoments', 'm2');
  await z.Shared.flush(); await f.Shared.flush(); await z.Shared.pull(); await f.Shared.pull();
  for (const d of [z, f]) {
    assert.deepEqual(d.Shared.list('relMoments').map((x) => x.id), ['m1']);
    assert.equal(d.Shared.get('relMoments', 'm1').note, 'Hike at sunrise, then pancakes');
  }
});
