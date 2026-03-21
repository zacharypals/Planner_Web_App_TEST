/**
 * Planner Auth Worker
 * Handles OAuth2 authorization code exchange and silent token refresh.
 *
 * Endpoints:
 *   POST /exchange  { code, redirect_uri } → { access_token, expires_in, email, picture, name }
 *   POST /refresh   { email }              → { access_token, expires_in }
 *   POST /revoke    { email }              → { ok: true }
 *
 * Secrets (set via `wrangler secret put`):
 *   GOOGLE_CLIENT_SECRET
 *
 * KV namespace binding (set in wrangler.toml):
 *   TOKENS  (stores refresh tokens keyed by email)
 */

const CLIENT_ID = '1050376914317-d9al0irmqsmhkq334rffqg30mbtlguuf.apps.googleusercontent.com';
const ALLOWED_ORIGIN = 'https://zacharypals.github.io';

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };
}

function json(data, status = 200, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders(origin),
  });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed' }, 405, origin);
    }

    const url = new URL(request.url);
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'Invalid JSON body' }, 400, origin);
    }

    // ── /exchange: swap authorization code for tokens ──
    if (url.pathname === '/exchange') {
      const { code, redirect_uri } = body;
      if (!code || !redirect_uri) {
        return json({ error: 'Missing code or redirect_uri' }, 400, origin);
      }

      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri,
          grant_type: 'authorization_code',
        }),
      });

      const tokenData = await tokenRes.json();
      if (!tokenRes.ok || !tokenData.access_token) {
        return json({ error: tokenData.error || 'Token exchange failed', detail: tokenData.error_description }, 400, origin);
      }

      // Fetch user info
      const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      const user = await userRes.json();

      // Store refresh token in KV keyed by email
      if (tokenData.refresh_token && user.email) {
        await env.TOKENS.put(`refresh:${user.email}`, tokenData.refresh_token);
      }

      return json({
        access_token: tokenData.access_token,
        expires_in: tokenData.expires_in || 3600,
        email: user.email,
        name: user.name,
        picture: user.picture,
      }, 200, origin);
    }

    // ── /refresh: use stored refresh token to get new access token ──
    if (url.pathname === '/refresh') {
      const { email } = body;
      if (!email) return json({ error: 'Missing email' }, 400, origin);

      const refreshToken = await env.TOKENS.get(`refresh:${email}`);
      if (!refreshToken) {
        return json({ error: 'No refresh token stored — user must sign in again' }, 401, origin);
      }

      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          refresh_token: refreshToken,
          client_id: CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          grant_type: 'refresh_token',
        }),
      });

      const tokenData = await tokenRes.json();
      if (!tokenRes.ok || !tokenData.access_token) {
        // Refresh token may have been revoked — delete it so user gets a clean re-auth
        await env.TOKENS.delete(`refresh:${email}`);
        return json({ error: 'Refresh failed — please sign in again' }, 401, origin);
      }

      return json({
        access_token: tokenData.access_token,
        expires_in: tokenData.expires_in || 3600,
      }, 200, origin);
    }

    // ── /revoke: delete stored refresh token ──
    if (url.pathname === '/revoke') {
      const { email } = body;
      if (email) await env.TOKENS.delete(`refresh:${email}`);
      return json({ ok: true }, 200, origin);
    }

    return json({ error: 'Not found' }, 404, origin);
  },
};