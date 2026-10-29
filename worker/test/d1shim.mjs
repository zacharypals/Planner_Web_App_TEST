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
  const state = { refreshOk: true, issued: 0, refreshCalls: 0 };
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
          refresh_token: `grt|${email}`, scope: flag === 'noscope' ? 'openid email' : 'openid email https://www.googleapis.com/auth/calendar',
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
    if (url === 'https://openidconnect.googleapis.com/v1/userinfo') {
      const auth = (init.headers && (init.headers.Authorization || init.headers.authorization)) || '';
      const email = auth.split('|')[1];
      return Response.json({ email, email_verified: true, name: email.split('@')[0], picture: '' });
    }
    return realFetch(input, init);
  };
  return state;
}
