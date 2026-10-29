// Planner data as small versioned JSON documents.
//
//   GET  /api/docs                 everything (initial load on a device) + change cursor
//   GET  /api/changes?since=N      only documents changed after cursor N
//   PUT  /api/docs                 batch save; each doc names the version it was based on
//
// Document bodies are stored and returned as JSON text without being parsed by the Worker,
// which keeps CPU time low (free plan: ~10 ms per request).

import { json, rawJson } from './util.js';

const MAX_DOCS_PER_PUT = 100;
const MAX_DOC_BYTES = 1_900_000;            // D1 row limit is 2 MB
const CHANGES_PAGE = 500;
const COLLECTION_RE = /^[A-Za-z][A-Za-z0-9_]{0,39}$/;

const q = (s) => JSON.stringify(s);

export async function listDocs(env, user) {
  const [seqRes, docsRes] = await env.DB.batch([
    env.DB.prepare('SELECT seq FROM users WHERE id = ?').bind(user.id),
    env.DB.prepare('SELECT collection, doc_id, version, data FROM docs WHERE user_id = ? AND deleted = 0').bind(user.id),
  ]);
  const cursor = seqRes.results[0] ? seqRes.results[0].seq : 0;
  const parts = docsRes.results.map((r) => `{"c":${q(r.collection)},"i":${q(r.doc_id)},"v":${r.version},"d":${r.data}}`);
  return rawJson(`{"cursor":${cursor},"docs":[${parts.join(',')}]}`);
}

export async function listChanges(env, user, sinceRaw) {
  const since = Math.max(0, Math.floor(Number(sinceRaw) || 0));
  const [seqRes, docsRes] = await env.DB.batch([
    env.DB.prepare('SELECT seq FROM users WHERE id = ?').bind(user.id),
    env.DB.prepare(
      `SELECT collection, doc_id, version, deleted, data, seq FROM docs
        WHERE user_id = ? AND seq > ? ORDER BY seq LIMIT ${CHANGES_PAGE}`
    ).bind(user.id, since),
  ]);
  const rows = docsRes.results;
  const more = rows.length === CHANGES_PAGE;
  const cursor = more ? rows[rows.length - 1].seq : (seqRes.results[0] ? seqRes.results[0].seq : since);
  const parts = rows.map((r) => r.deleted
    ? `{"c":${q(r.collection)},"i":${q(r.doc_id)},"v":${r.version},"x":1}`
    : `{"c":${q(r.collection)},"i":${q(r.doc_id)},"v":${r.version},"d":${r.data}}`);
  return rawJson(`{"cursor":${cursor},"more":${more},"docs":[${parts.join(',')}]}`);
}

// body: { docs: [{ c: collection, i: doc_id, b: base_version, j: "<json text>" } | { c, i, b, x: 1 }] }
// A doc is written only if the server's current version equals b (0 = "I think it's new").
// Otherwise it comes back as a conflict carrying the server's copy, for the app to merge.
export async function putDocs(env, user, body) {
  const docs = Array.isArray(body && body.docs) ? body.docs : null;
  if (!docs || docs.length === 0 || docs.length > MAX_DOCS_PER_PUT) return json({ error: 'bad_request', detail: 'docs: 1–100 items' }, 400);

  const items = [];
  for (const d of docs) {
    const c = String(d && d.c || '');
    const i = String(d && d.i != null ? d.i : '');
    const b = Number(d && d.b);
    const del = !!(d && d.x);
    const j = del ? 'null' : d && d.j;
    if (!COLLECTION_RE.test(c) || !i || i.length > 200 || !Number.isInteger(b) || b < 0) {
      return json({ error: 'bad_request', detail: `invalid doc ${c}/${i}` }, 400);
    }
    if (typeof j !== 'string' || !j.length) return json({ error: 'bad_request', detail: `missing body ${c}/${i}` }, 400);
    if (j.length > MAX_DOC_BYTES) return json({ error: 'doc_too_large', c, i, bytes: j.length }, 413);
    items.push({ c, i, b, j, del });
  }

  const now = Date.now();
  const stmts = [];
  for (const it of items) {
    stmts.push(env.DB.prepare('UPDATE users SET seq = seq + 1 WHERE id = ?').bind(user.id));
    stmts.push(env.DB.prepare(
      `INSERT INTO docs (user_id, collection, doc_id, data, version, seq, deleted, updated_at)
       SELECT ?1, ?2, ?3, ?4, 1, u.seq, ?5, ?6 FROM users u WHERE u.id = ?1
       ON CONFLICT(user_id, collection, doc_id) DO UPDATE SET
         data = excluded.data, version = docs.version + 1, seq = excluded.seq,
         deleted = excluded.deleted, updated_at = excluded.updated_at
       WHERE docs.version = ?7`
    ).bind(user.id, it.c, it.i, it.j, it.del ? 1 : 0, now, it.b));
    stmts.push(env.DB.prepare('SELECT version FROM docs WHERE user_id = ? AND collection = ? AND doc_id = ?').bind(user.id, it.c, it.i));
  }
  const res = await env.DB.batch(stmts);

  const results = [];
  const conflicts = [];
  items.forEach((it, k) => {
    const changed = res[k * 3 + 1].meta && res[k * 3 + 1].meta.changes;
    const row = res[k * 3 + 2].results[0];
    if (changed) results.push(`{"c":${q(it.c)},"i":${q(it.i)},"ok":1,"v":${row ? row.version : it.b + 1}}`);
    else conflicts.push(it);
  });

  if (conflicts.length) {
    const sel = await env.DB.batch(conflicts.map((it) =>
      env.DB.prepare('SELECT version, deleted, data FROM docs WHERE user_id = ? AND collection = ? AND doc_id = ?').bind(user.id, it.c, it.i)));
    conflicts.forEach((it, k) => {
      const r = sel[k].results[0];
      if (!r) results.push(`{"c":${q(it.c)},"i":${q(it.i)},"conflict":1,"v":0,"x":1}`);
      else if (r.deleted) results.push(`{"c":${q(it.c)},"i":${q(it.i)},"conflict":1,"v":${r.version},"x":1}`);
      else results.push(`{"c":${q(it.c)},"i":${q(it.i)},"conflict":1,"v":${r.version},"d":${r.data}}`);
    });
  }
  return rawJson(`{"results":[${results.join(',')}]}`);
}
