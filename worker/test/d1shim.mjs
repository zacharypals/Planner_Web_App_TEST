// Minimal Cloudflare D1 stand-in backed by Node's built-in SQLite, for local tests only.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

class Stmt {
  constructor(db, sql, args = []) { this.db = db; this.sql = sql; this.args = args; }
  bind(...args) { return new Stmt(this.db, this.sql, args); }
  _exec() {
    const s = this.db.prepare(this.sql);
    const isRead = /^\s*(SELECT|WITH)/i.test(this.sql) || /\bRETURNING\b/i.test(this.sql);
    this.db.stats.queries++;
    if (isRead) {
      const rows = s.all(...this.args).map((r) => ({ ...r }));
      this.db.stats.rowsRead += rows.length;
      return { results: rows, meta: { changes: 0 } };
    }
    const r = s.run(...this.args);
    this.db.stats.rowsWritten += Number(r.changes);
    return { results: [], meta: { changes: Number(r.changes) } };
  }
  async first() { return this._exec().results[0] ?? null; }
  async all() { return this._exec(); }
  async run() { return this._exec(); }
}

export function makeD1(migrationsDir) {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  db.stats = { queries: 0, rowsRead: 0, rowsWritten: 0 };
  for (const f of readdirSync(migrationsDir).filter((f) => f.endsWith('.sql')).sort()) {
    db.exec(readFileSync(join(migrationsDir, f), 'utf8'));
  }
  return {
    raw: db,
    stats: db.stats,
    prepare: (sql) => new Stmt(db, sql),
    async batch(stmts) {
      db.exec('BEGIN');
      try {
        const out = stmts.map((s) => s._exec());
        db.exec('COMMIT');
        return out;
      } catch (e) { db.exec('ROLLBACK'); throw e; }
    },
  };
}

// Fake Google OAuth + userinfo. Codes look like "code:<email>[:noscope]".
export function installFakeGoogle(realFetch = globalThis.fetch) {
  const state = { refreshOk: true, issued: 0, refreshCalls: 0, drives: new Map(), driveCalls: [], driveFail: null };
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    if (url === 'https://oauth2.googleapis.com/token') {
      const p = new URLSearchParams(init.body);
      if (p.get('grant_type') === 'authorization_code') {
        const code = p.get('code') || '';
        if (!code.startsWith('code:')) return Response.json({ error: 'invalid_grant' }, { status: 400 });
        const [, email, flag] = code.split(':');
        state.issued++;
        return Response.json({
          access_token: `gat|${email}|${state.issued}`, expires_in: 3599,
          refresh_token: `grt|${email}`,
          scope: flag === 'noscope' ? 'openid email'
            : flag === 'nodrive' ? 'openid email https://www.googleapis.com/auth/calendar'
            : 'openid email https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/drive.file',
        });
      }
      if (p.get('grant_type') === 'refresh_token') {
        state.refreshCalls++;
        if (!state.refreshOk) return Response.json({ error: 'invalid_grant' }, { status: 400 });
        const email = (p.get('refresh_token') || '').split('|')[1];
        state.issued++;
        return Response.json({ access_token: `gat|${email}|${state.issued}`, expires_in: 3599 });
      }
    }
    if (url.startsWith('https://www.googleapis.com/drive/') || url.startsWith('https://www.googleapis.com/upload/drive/')) {
      return fakeDrive(state, url, init);
    }
    if (url === 'https://openidconnect.googleapis.com/v1/userinfo') {
      const auth = (init.headers && (init.headers.Authorization || init.headers.authorization)) || '';
      const email = auth.split('|')[1];
      return Response.json({ email, email_verified: true, name: email.split('@')[0], picture: '' });
    }
    return realFetch(input, init);
  };
  return state;
}

// Tiny in-memory Google Drive, one per account (keyed by the email inside the fake access token).
function fakeDrive(state, url, init) {
  const auth = (init.headers && (init.headers.Authorization || init.headers.authorization)) || '';
  const email = auth.split('|')[1];
  if (!email) return Response.json({ error: { message: 'no auth' } }, { status: 401 });
  if (!state.drives.has(email)) state.drives.set(email, new Map());
  const files = state.drives.get(email);
  const method = (init.method || 'GET').toUpperCase();
  const u = new URL(url);
  state.driveCalls.push(method + ' ' + u.pathname);
  if (state.driveFail && state.driveFail(method, u)) return Response.json({ error: { message: 'boom' } }, { status: 500 });
  let n = files.size;
  const newId = () => 'f' + (++n) + Math.random().toString(36).slice(2, 6);
  const m = u.pathname.match(/\/files\/([^/]+)$/);
  if (u.pathname === '/drive/v3/files' && method === 'GET') {
    const q = u.searchParams.get('q') || '';
    let list = [...files.values()].filter((f) => !f.trashed);
    const name = q.match(/name='([^']+)'/);
    if (name) list = list.filter((f) => f.name === name[1]);
    if (/mimeType='application\/vnd.google-apps.folder'/.test(q)) list = list.filter((f) => f.folder);
    const parent = q.match(/'([^']+)' in parents/);
    if (parent) list = list.filter((f) => (f.parents || []).includes(parent[1]));
    const contains = q.match(/name contains '([^']+)'/);
    if (contains) list = [...files.values()].filter((f) => !f.trashed && (f.name.includes(contains[1]) || (name && f.name === name[1])));
    return Response.json({ files: list.map((f) => ({ id: f.id, name: f.name, modifiedTime: new Date(f.modified).toISOString(), size: String((f.content || '').length) })) });
  }
  if (u.pathname === '/drive/v3/files' && method === 'POST') {
    const meta = JSON.parse(init.body);
    const id = newId();
    files.set(id, { id, name: meta.name, folder: meta.mimeType === 'application/vnd.google-apps.folder', parents: meta.parents || [], modified: Date.now() });
    return Response.json({ id });
  }
  if (u.pathname === '/upload/drive/v3/files' && method === 'POST') {
    const ct = (init.headers['Content-Type'] || '');
    const boundary = ct.split('boundary=')[1];
    const parts = String(init.body).split('--' + boundary).slice(1, -1).map((p) => p.split('\r\n\r\n').slice(1).join('\r\n\r\n').replace(/\r\n$/, ''));
    const meta = JSON.parse(parts[0]);
    const id = newId();
    files.set(id, { id, name: meta.name, parents: meta.parents || [], content: parts[1], modified: Date.now() });
    return Response.json({ id });
  }
  if (m) {
    const f = files.get(decodeURIComponent(m[1]));
    if (!f || (f.trashed && method !== 'GET')) return Response.json({ error: { message: 'File not found' } }, { status: 404 });
    if (method === 'GET') {
      if (u.searchParams.get('alt') === 'media') return new Response(f.content || '', { headers: { 'Content-Type': 'application/json' } });
      return Response.json({ id: f.id, name: f.name, trashed: !!f.trashed });
    }
    if (method === 'PATCH') { f.content = String(init.body); f.modified = Date.now(); return Response.json({ id: f.id }); }
    if (method === 'DELETE') { files.delete(f.id); return new Response(null, { status: 204 }); }
  }
  return Response.json({ error: { message: 'unhandled ' + method + ' ' + u.pathname } }, { status: 400 });
}
