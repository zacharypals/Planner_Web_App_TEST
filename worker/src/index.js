// LP Planner — planner-api Worker
//
// Stores each person's planner data in D1 as small versioned documents and handles sign-in.
// See auth.js (sessions + Google token custody) and docs.js (data API).

import { json, allowedEmails } from './util.js';
import { authExchange, authLogout, authenticate, googleToken, googleScope } from './auth.js';
import { backupNow, runNightlyBackups } from './backup.js';
import { listDocs, listChanges, putDocs } from './docs.js';

const WORKER_VERSION = '0.2.0';

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const cors = corsHeaders(req, env);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    let res;
    try {
      const path = url.pathname;
      const method = req.method;
      if (path === '/health' && method === 'GET') {
        res = json({ ok: true, version: WORKER_VERSION });
      } else if (path === '/auth/exchange' && method === 'POST') {
        res = await authExchange(req, env);
      } else if (path === '/auth/logout' && method === 'POST') {
        res = await authLogout(req, env);
      } else if (path.startsWith('/api/')) {
        const auth = await authenticate(req, env);
        res = auth.error ? auth.error : await routeApi(req, env, url, auth.user);
      } else {
        res = json({ error: 'not_found' }, 404);
      }
    } catch (err) {
      console.error('Unhandled error', err && err.stack ? err.stack : err);
      res = json({ error: 'server_error', message: String((err && err.message) || err) }, 500);
    }
    return withHeaders(res, cors);
  },

  // Nightly Google Drive backups (cron set in wrangler.toml [triggers]).
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runNightlyBackups(env, allowedEmails(env)));
  },
};

async function routeApi(req, env, url, user) {
  const path = url.pathname;
  const method = req.method;
  if (path === '/api/me' && method === 'GET') {
    const [b, scope] = await Promise.all([
      env.DB.prepare('SELECT last_backup_at, last_backup_status, last_backup_error, last_backup_file FROM users WHERE id = ?').bind(user.id).first(),
      googleScope(env, user.id),
    ]);
    return json({
      email: user.email, name: user.name, picture: user.picture, worker_version: WORKER_VERSION,
      drive_ok: /drive\.file/.test(scope), calendar_ok: /calendar/.test(scope),
      backup: b && b.last_backup_at ? { at: b.last_backup_at, status: b.last_backup_status, error: b.last_backup_error, file: b.last_backup_file } : null,
    });
  }
  if (path === '/api/backup' && method === 'POST') return backupNow(env, user);
  if (path === '/api/google-token' && method === 'POST') return googleToken(env, user);
  if (path === '/api/docs' && method === 'GET') return listDocs(env, user);
  if (path === '/api/docs' && method === 'PUT') return putDocs(env, user, await req.json().catch(() => null));
  if (path === '/api/changes' && method === 'GET') return listChanges(env, user, url.searchParams.get('since'));
  return json({ error: 'not_found' }, 404);
}

function corsHeaders(req, env) {
  const origin = req.headers.get('Origin');
  const h = { Vary: 'Origin' };
  if (origin && origin === env.ALLOWED_ORIGIN) {
    h['Access-Control-Allow-Origin'] = origin;
    h['Access-Control-Allow-Headers'] = 'Authorization, Content-Type';
    h['Access-Control-Allow-Methods'] = 'GET, POST, PUT, OPTIONS';
    h['Access-Control-Max-Age'] = '86400';
  }
  return h;
}

function withHeaders(res, extra) {
  const r = new Response(res.body, res);
  for (const [k, v] of Object.entries(extra)) r.headers.set(k, v);
  r.headers.set('Cache-Control', 'no-store');
  return r;
}
