// Sign-in, sessions, and Google token custody.
//
//   * Google proves WHO you are (full-page redirect → oauth.html → /auth/exchange).
//   * The Worker then issues its own random session token. Only its SHA-256 hash is stored.
//   * Every /api/* request carries `Authorization: Bearer <session>`; the allowlist is
//     re-checked on every request.
//   * Calendar still needs Google access tokens in the browser. The Google refresh token is
//     stored encrypted and never leaves the Worker; /api/google-token hands a short-lived
//     access token to a valid session only. (Replaces planner-auth's /refresh-by-email,
//     which gave a token to anyone who knew the email address.)

import { json, sha256Hex, randomToken, bearer, allowedEmails } from './util.js';
import { encryptToken, decryptToken } from './crypto.js';

export const SESSION_DAYS = 90;   // sliding: extended on use, at most once per day
const DAY_MS = 24 * 60 * 60 * 1000;
const ACCESS_MARGIN_MS = 5 * 60 * 1000;

export async function authExchange(req, env) {
  const body = await req.json().catch(() => ({}));
  const { code, redirect_uri } = body;
  if (!code || redirect_uri !== env.REDIRECT_URI) return json({ error: 'bad_request' }, 400);
  if (!env.GOOGLE_CLIENT_SECRET) return json({ error: 'worker_missing_google_secret' }, 500);

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri,
      grant_type: 'authorization_code',
    }),
  });
  const tok = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || !tok.access_token) {
    console.warn('Google token exchange failed', tokenRes.status, tok.error);
    return json({ error: 'google_exchange_failed' }, 400);
  }

  const infoRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
    headers: { Authorization: `Bearer ${tok.access_token}` },
  });
  const info = await infoRes.json().catch(() => ({}));
  if (!infoRes.ok || !info.email || info.email_verified !== true) return json({ error: 'unverified_email' }, 403);
  const email = String(info.email).toLowerCase();
  if (!allowedEmails(env).includes(email)) return json({ error: 'not_allowed' }, 403);

  const now = Date.now();
  const user = await env.DB.prepare(
    `INSERT INTO users (id, email, name, picture, created_at) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(email) DO UPDATE SET name = excluded.name, picture = excluded.picture
     RETURNING id`
  ).bind(crypto.randomUUID(), email, info.name || null, info.picture || null, now).first();

  // Keep Google tokens for Calendar. Google only sends a refresh token on a consent screen,
  // so keep the previous one if this sign-in didn't include a new one.
  const expiresAt = now + (Number(tok.expires_in) || 3600) * 1000;
  const acc = await encryptToken(env, tok.access_token);
  const ref = tok.refresh_token ? await encryptToken(env, tok.refresh_token) : null;
  await env.DB.prepare(
    `INSERT INTO google_tokens (user_id, refresh_enc, refresh_iv, access_enc, access_iv, access_expires_at, scope, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
     ON CONFLICT(user_id) DO UPDATE SET
       refresh_enc = COALESCE(excluded.refresh_enc, google_tokens.refresh_enc),
       refresh_iv  = COALESCE(excluded.refresh_iv,  google_tokens.refresh_iv),
       access_enc = excluded.access_enc, access_iv = excluded.access_iv,
       access_expires_at = excluded.access_expires_at, scope = excluded.scope, updated_at = excluded.updated_at`
  ).bind(user.id, ref ? ref.ct : null, ref ? ref.iv : null, acc.ct, acc.iv, expiresAt, tok.scope || '', now).run();

  const token = randomToken();
  const sessionExpires = now + SESSION_DAYS * DAY_MS;
  await env.DB.prepare(
    'INSERT INTO sessions (token_hash, user_id, created_at, last_used_at, expires_at, user_agent) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(await sha256Hex(token), user.id, now, now, sessionExpires, (req.headers.get('User-Agent') || '').slice(0, 200)).run();

  return json({
    session_token: token,
    expires_at: sessionExpires,
    email,
    name: info.name || '',
    picture: info.picture || '',
    google_access_token: tok.access_token,
    google_expires_at: expiresAt,
    calendar_ok: String(tok.scope || '').includes('calendar'),
  });
}

export async function authLogout(req, env) {
  const token = bearer(req);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256Hex(token)).run();
  return json({ ok: true });
}

export async function authenticate(req, env) {
  const token = bearer(req);
  if (!token) return { error: json({ error: 'unauthenticated' }, 401) };

  const hash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT s.last_used_at, s.expires_at, u.id, u.email, u.name, u.picture
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?`
  ).bind(hash).first();

  const now = Date.now();
  if (!row || row.expires_at <= now) {
    if (row) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(hash).run();
    return { error: json({ error: 'session_expired' }, 401) };
  }
  if (!allowedEmails(env).includes(row.email)) return { error: json({ error: 'not_allowed' }, 403) };

  if (now - row.last_used_at > DAY_MS) {
    await env.DB.prepare('UPDATE sessions SET last_used_at = ?, expires_at = ? WHERE token_hash = ?')
      .bind(now, now + SESSION_DAYS * DAY_MS, hash).run();
  }
  return { user: { id: row.id, email: row.email, name: row.name, picture: row.picture } };
}

// Short-lived Google access token for Calendar calls made from the browser.
export async function googleToken(env, user) {
  const row = await env.DB.prepare('SELECT * FROM google_tokens WHERE user_id = ?').bind(user.id).first();
  const now = Date.now();
  if (row && row.access_enc && row.access_expires_at > now + ACCESS_MARGIN_MS) {
    return json({ access_token: await decryptToken(env, row.access_enc, row.access_iv), expires_at: row.access_expires_at });
  }
  if (!row || !row.refresh_enc) return json({ error: 'google_reauth_required' }, 409);

  const refreshToken = await decryptToken(env, row.refresh_enc, row.refresh_iv);
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      refresh_token: refreshToken,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      grant_type: 'refresh_token',
    }),
  });
  const tok = await res.json().catch(() => ({}));
  if (!res.ok || !tok.access_token) {
    if (tok.error === 'invalid_grant') {
      // Revoked or expired at Google — forget it so the app asks to reconnect.
      await env.DB.prepare('UPDATE google_tokens SET refresh_enc = NULL, refresh_iv = NULL, access_enc = NULL, access_iv = NULL, updated_at = ? WHERE user_id = ?')
        .bind(now, user.id).run();
      return json({ error: 'google_reauth_required' }, 409);
    }
    console.warn('Google refresh failed', res.status, tok.error);
    return json({ error: 'google_unavailable' }, 502);
  }
  const expiresAt = now + (Number(tok.expires_in) || 3600) * 1000;
  const acc = await encryptToken(env, tok.access_token);
  await env.DB.prepare('UPDATE google_tokens SET access_enc = ?, access_iv = ?, access_expires_at = ?, updated_at = ? WHERE user_id = ?')
    .bind(acc.ct, acc.iv, expiresAt, now, user.id).run();
  return json({ access_token: tok.access_token, expires_at: expiresAt });
}
