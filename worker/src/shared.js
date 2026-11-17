// Shared household space (Worker 0.3.0).
//
// Two people, one set of shared documents (relationship check-ins, timeline moments, …).
// The shared space is stored exactly like a person's data — same `docs` table, same
// versioned-document rules — under a synthetic user row (id 'household:home'). Both members
// read and write it through /api/shared/*; their private data under /api/docs is untouched.
//
//   GET  /api/shared/docs                 everything shared + change cursor
//   GET  /api/shared/changes?since=N      only shared documents changed after N
//   PUT  /api/shared/docs                 batch save (same rules as /api/docs)
//
// Who is a member: HOUSEHOLD_EMAILS (comma-separated), falling back to ALLOWED_EMAILS.
// Only collections whose names start with "rel" may be written here, so a bug can never
// spill ordinary planner collections into the shared space.

import { json } from './util.js';
import { listDocs, listChanges, putDocs } from './docs.js';

export const HOUSEHOLD_ID = 'household:home';
const HOUSEHOLD_EMAIL = 'household-home@shared.invalid';
const SHARED_COLLECTION_RE = /^rel[A-Za-z0-9_]{0,37}$/;

export function memberEmails(env) {
  const raw = env.HOUSEHOLD_EMAILS || env.ALLOWED_EMAILS || '';
  return String(raw).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
}

async function ensureHousehold(env) {
  await env.DB.prepare(
    'INSERT OR IGNORE INTO users (id, email, name, created_at) VALUES (?, ?, ?, ?)'
  ).bind(HOUSEHOLD_ID, HOUSEHOLD_EMAIL, 'Household', Date.now()).run();
}

export async function sharedApi(req, env, url, user) {
  if (!memberEmails(env).includes(String(user.email || '').toLowerCase())) {
    return json({ error: 'not_a_member' }, 403);
  }
  const path = url.pathname;
  const method = req.method;
  const space = { id: HOUSEHOLD_ID };

  if (path === '/api/shared/docs' && method === 'GET') {
    await ensureHousehold(env);
    return listDocs(env, space);
  }
  if (path === '/api/shared/changes' && method === 'GET') {
    await ensureHousehold(env);
    return listChanges(env, space, url.searchParams.get('since'));
  }
  if (path === '/api/shared/docs' && method === 'PUT') {
    const body = await req.json().catch(() => null);
    const docs = Array.isArray(body && body.docs) ? body.docs : [];
    if (docs.some((d) => !SHARED_COLLECTION_RE.test(String(d && d.c || '')))) {
      return json({ error: 'bad_request', detail: 'shared collections must start with "rel"' }, 400);
    }
    await ensureHousehold(env);
    return putDocs(env, space, body);
  }
  return json({ error: 'not_found' }, 404);
}
