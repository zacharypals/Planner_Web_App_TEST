// Nightly Google Drive backups.
//
// Each person's documents are stitched back into ONE JSON file in the same shape as the old
// planner-data.json ({ weekData, habitGoals, … }), so the app's "Import / restore from Drive"
// can restore from any backup. The file goes to a "LP Planner Backups" folder in that person's
// own Drive, using the Google access they granted at sign-in (drive.file scope).
//
// Kept: the last 7 days, plus the 1st of each month for 12 months. Older ones are deleted.
// "Back up now" never touches a nightly file: it writes its own lp-planner-backup-DATE-manual-HHMM.json
// (the newest 5 are kept), so the overnight snapshot can't be replaced by the state you may want to
// recover from. The old planner-data.json is never touched.
//
// The shared household space (relationship check-ins, timeline — Worker 0.3.0) is backed up too:
// each member gets lp-shared-backup-DATE.json in the same folder, same retention. It is a separate
// file because it isn't part of the planner-data.json shape the app's importer understands.
//
// The JSON is assembled by joining the stored text — document bodies are never parsed — which
// keeps CPU time low enough for the free plan.

import { json } from './util.js';
import { getGoogleAccess } from './auth.js';
import { HOUSEHOLD_ID, memberEmails } from './shared.js';

const FOLDER_NAME = 'LP Planner Backups';
const FILE_RE = /^lp-planner-backup-(\d{4}-\d{2}-\d{2})\.json$/;
const MANUAL_RE = /^lp-planner-backup-(\d{4}-\d{2}-\d{2})-manual-(\d{4})\.json$/;
const SHARED_RE = /^lp-shared-backup-(\d{4}-\d{2}-\d{2})\.json$/;
const KEEP_MANUAL = 5;
const KEEP_DAYS = 7;
const KEEP_MONTHS = 12;
const DRIVE = 'https://www.googleapis.com/drive/v3';
const UPLOAD = 'https://www.googleapis.com/upload/drive/v3';

// Must match SYNC_SPLITS in index.html. Anything not listed is one whole document ('_').
const SPLITS = {
  weekData: 'map', fitnessLog: 'map', pagesData: 'list',
  habitCompletions: 'month', habitQty: 'month', habitNotes: 'month', habitMetrics: 'month',
  goals: 'list',    // the Projects, before app v5.96.0 (kept: those documents are the safety copy and live still uses them)
  projects: 'list', // the Projects, from app v5.96.0
};

export function ptDate(d = new Date()) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Los_Angeles', year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
}

// rows: [{ collection, doc_id, data }] (non-deleted). Returns the backup file text.
export function assembleBackup(rows, at = new Date()) {
  const by = new Map();
  for (const r of rows) {
    if (!by.has(r.collection)) by.set(r.collection, []);
    by.get(r.collection).push(r);
  }
  const q = (s) => JSON.stringify(s);
  const parts = [`"_backupAt":${q(at.toISOString())}`, `"_source":"planner-api"`];
  for (const [coll, list] of by) {
    const mode = SPLITS[coll] || 'whole';
    let text;
    if (mode === 'whole') {
      const doc = list.find((r) => r.doc_id === '_');
      if (!doc) continue;
      text = doc.data;
    } else if (mode === 'map') {
      text = '{' + list.map((r) => `${q(r.doc_id)}:${r.data}`).join(',') + '}';
    } else if (mode === 'month') {
      const inner = [];
      for (const r of list) {
        const t = r.data.trim();
        if (t[0] !== '{' || t[t.length - 1] !== '}') continue;
        const body = t.slice(1, -1).trim();
        if (body) inner.push(body);
      }
      text = '{' + inner.join(',') + '}';
    } else { // list
      const orderDoc = list.find((r) => r.doc_id === '__order');
      let order = [];
      try { order = orderDoc ? JSON.parse(orderDoc.data) : []; } catch {}
      const items = new Map(list.filter((r) => r.doc_id !== '__order').map((r) => [r.doc_id, r.data]));
      const out = [];
      for (const id of Array.isArray(order) ? order : []) if (items.has(id)) { out.push(items.get(id)); items.delete(id); }
      for (const v of items.values()) out.push(v);
      text = '[' + out.join(',') + ']';
    }
    parts.push(`${q(coll)}:${text}`);
  }
  return '{' + parts.join(',') + '}';
}

// rows: shared-space documents [{ collection, doc_id, data }]. Shape:
// { _backupAt, _source, collections: { relCheckins: { <docId>: <doc>, … }, relMeta: { "_": <doc> }, … } }
export function assembleSharedBackup(rows, at = new Date()) {
  const by = new Map();
  for (const r of rows) {
    if (!by.has(r.collection)) by.set(r.collection, []);
    by.get(r.collection).push(r);
  }
  const q = (s) => JSON.stringify(s);
  const cols = [...by].map(([coll, list]) => `${q(coll)}:{${list.map((r) => `${q(r.doc_id)}:${r.data}`).join(',')}}`);
  return `{"_backupAt":${q(at.toISOString())},"_source":"planner-api-shared","collections":{${cols.join(',')}}}`;
}

class DriveError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function drive(token, url, init = {}) {
  const res = await fetch(url, { ...init, headers: { Authorization: `Bearer ${token}`, ...(init.headers || {}) } });
  if (!res.ok) {
    let msg = '';
    try { const j = await res.json(); msg = (j.error && (j.error.message || j.error.status)) || ''; } catch {}
    throw new DriveError(res.status, `Drive ${res.status}${msg ? ': ' + msg : ''}`);
  }
  return res.status === 204 ? null : res.json().catch(() => null);
}

const qs = (o) => new URLSearchParams(o).toString();

async function ensureFolder(token, knownId) {
  if (knownId) {
    try {
      const f = await drive(token, `${DRIVE}/files/${encodeURIComponent(knownId)}?fields=id,trashed`);
      if (f && !f.trashed) return knownId;
    } catch (e) { if (e.status !== 404) throw e; }
  }
  const found = await drive(token, `${DRIVE}/files?` + qs({
    q: `name='${FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
    fields: 'files(id)', pageSize: '10',
  }));
  if (found && found.files && found.files.length) return found.files[0].id;
  const made = await drive(token, `${DRIVE}/files?fields=id`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: FOLDER_NAME, mimeType: 'application/vnd.google-apps.folder' }),
  });
  return made.id;
}

function keepFile(dateStr, today, now) {
  if (dateStr === today) return true;
  const dayCutoff = ptDate(new Date(now - (KEEP_DAYS - 1) * 86400000));
  if (dateStr >= dayCutoff) return true;
  const monthCutoff = ptDate(new Date(now - KEEP_MONTHS * 31 * 86400000));
  return dateStr.endsWith('-01') && dateStr >= monthCutoff;
}

// "HHMM" in Pacific time, 24-hour
function ptHHMM(d = new Date()) {
  return new Intl.DateTimeFormat('en-GB', { timeZone: 'America/Los_Angeles', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
    .format(d).replace(':', '');
}

async function record(env, userId, fields) {
  await env.DB.prepare(
    `UPDATE users SET last_backup_at = ?, last_backup_status = ?, last_backup_error = ?,
       last_backup_file = COALESCE(?, last_backup_file), backup_folder_id = COALESCE(?, backup_folder_id) WHERE id = ?`
  ).bind(Date.now(), fields.status, fields.error || null, fields.file || null, fields.folder || null, userId).run();
}

// Write (or overwrite) today's shared-space backup in the person's folder and trim old ones.
// `files` is the folder listing already fetched for the private backup. Returns { file, docs } or null.
async function backupShared(env, user, token, folder, files, now) {
  if (!memberEmails(env).includes(String(user.email || '').toLowerCase())) return null;
  const { results: rows } = await env.DB.prepare(
    'SELECT collection, doc_id, data FROM docs WHERE user_id = ? AND deleted = 0 ORDER BY collection, seq'
  ).bind(HOUSEHOLD_ID).all();
  if (!rows.length) return null;
  const today = ptDate(new Date(now));
  const name = `lp-shared-backup-${today}.json`;
  const text = assembleSharedBackup(rows, new Date(now));
  const existing = files.find((f) => f.name === name);
  if (existing) {
    await drive(token, `${UPLOAD}/files/${encodeURIComponent(existing.id)}?uploadType=media`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: text,
    });
  } else {
    const boundary = 'lpshared' + crypto.randomUUID().replace(/-/g, '');
    const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n` +
      JSON.stringify({ name, parents: [folder], mimeType: 'application/json' }) +
      `\r\n--${boundary}\r\nContent-Type: application/json\r\n\r\n` + text + `\r\n--${boundary}--`;
    await drive(token, `${UPLOAD}/files?uploadType=multipart&fields=id`, {
      method: 'POST', headers: { 'Content-Type': `multipart/related; boundary=${boundary}` }, body,
    });
  }
  for (const f of files) {
    const m = f.name.match(SHARED_RE);
    if (!m || f.name === name || keepFile(m[1], today, now)) continue;
    try { await drive(token, `${DRIVE}/files/${encodeURIComponent(f.id)}`, { method: 'DELETE' }); }
    catch (e) { console.warn('Shared backup cleanup failed', f.name, e.message); }
  }
  return { file: name, docs: rows.length };
}

// Back up one person. Never throws; returns { status, file?, bytes?, docs?, deleted?, error? }.
export async function backupUser(env, user, now = Date.now(), opts = {}) {
  const manual = !!opts.manual;
  try {
    const { results: rows } = await env.DB.prepare(
      'SELECT collection, doc_id, data FROM docs WHERE user_id = ? AND deleted = 0 ORDER BY collection, seq'
    ).bind(user.id).all();
    if (!rows.length) {
      // Never let an empty account rotate out good backups.
      await record(env, user.id, { status: 'skipped_empty' });
      return { status: 'skipped_empty' };
    }
    const g = await getGoogleAccess(env, user.id);
    if (g.error) {
      const out = { status: 'error', error: g.error === 'google_reauth_required' ? 'Google access expired — sign in again' : 'Google unavailable' };
      await record(env, user.id, out);
      return out;
    }
    if (!/drive\.file/.test(g.scope || '')) {
      const out = { status: 'needs_drive', error: 'Google Drive access not granted — sign in again and allow Drive' };
      await record(env, user.id, out);
      return out;
    }

    const today = ptDate(new Date(now));
    const text = assembleBackup(rows, new Date(now));
    const name = manual ? `lp-planner-backup-${today}-manual-${ptHHMM(new Date(now))}.json` : `lp-planner-backup-${today}.json`;
    const folder = await ensureFolder(g.token, user.backup_folder_id);
    const listing = await drive(g.token, `${DRIVE}/files?` + qs({
      q: `'${folder}' in parents and trashed=false`, fields: 'files(id,name)', pageSize: '1000',
    }));
    const files = (listing && listing.files) || [];

    const existing = files.find((f) => f.name === name);
    if (existing) {
      await drive(g.token, `${UPLOAD}/files/${encodeURIComponent(existing.id)}?uploadType=media`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: text,
      });
    } else {
      const boundary = 'lpbackup' + crypto.randomUUID().replace(/-/g, '');
      const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n` +
        JSON.stringify({ name, parents: [folder], mimeType: 'application/json' }) +
        `\r\n--${boundary}\r\nContent-Type: application/json\r\n\r\n` + text + `\r\n--${boundary}--`;
      await drive(g.token, `${UPLOAD}/files?uploadType=multipart&fields=id`, {
        method: 'POST', headers: { 'Content-Type': `multipart/related; boundary=${boundary}` }, body,
      });
    }

    let deleted = 0;
    for (const f of files) {
      const m = f.name.match(FILE_RE);
      if (!m || f.name === name || keepFile(m[1], today, now)) continue;
      try { await drive(g.token, `${DRIVE}/files/${encodeURIComponent(f.id)}`, { method: 'DELETE' }); deleted++; }
      catch (e) { console.warn('Backup cleanup failed', f.name, e.message); }
    }

    // Manual backups: keep only the newest few (names sort by date, then time)
    const manualFiles = files.filter((f) => MANUAL_RE.test(f.name) && f.name !== name).map((f) => f.name);
    manualFiles.push(name);
    const dropNames = new Set(manualFiles.sort().reverse().slice(KEEP_MANUAL));
    for (const f of files) {
      if (!dropNames.has(f.name)) continue;
      try { await drive(g.token, `${DRIVE}/files/${encodeURIComponent(f.id)}`, { method: 'DELETE' }); deleted++; }
      catch (e) { console.warn('Manual backup cleanup failed', f.name, e.message); }
    }

    // Shared household data (v0.3.1). The private backup above has already succeeded; if this step
    // fails, say so in the status the app shows rather than failing silently.
    let shared = null;
    try { shared = await backupShared(env, user, g.token, folder, files, now); }
    catch (e) {
      console.error('Shared backup failed', user.email, e && e.stack ? e.stack : e);
      const out = { status: 'error', error: ('Your planner was backed up, but the shared (Us) backup failed: ' + String((e && e.message) || e)).slice(0, 300), file: name, folder };
      await record(env, user.id, out);
      return { ...out, bytes: text.length, docs: rows.length, deleted };
    }
    await record(env, user.id, { status: 'ok', file: name, folder });
    return { status: 'ok', file: name, bytes: text.length, docs: rows.length, deleted, shared };
  } catch (e) {
    console.error('Backup failed', user.email, e && e.stack ? e.stack : e);
    const out = { status: 'error', error: String((e && e.message) || e).slice(0, 300) };
    try { await record(env, user.id, out); } catch {}
    return out;
  }
}

// Cron: everyone who has connected Google and is still allowed.
export async function runNightlyBackups(env, allowed) {
  const { results } = await env.DB.prepare(
    `SELECT u.id, u.email, u.backup_folder_id FROM users u
       JOIN google_tokens g ON g.user_id = u.id WHERE g.refresh_enc IS NOT NULL`
  ).all();
  for (const u of results) {
    if (!allowed.includes(u.email)) continue;
    const r = await backupUser(env, u);
    console.log('Backup', u.email, r.status, r.file || r.error || '');
  }
}

// POST /api/backup — "Back up to Drive now".
export async function backupNow(env, user) {
  const row = await env.DB.prepare('SELECT backup_folder_id, last_backup_at FROM users WHERE id = ?').bind(user.id).first();
  if (row && row.last_backup_at && Date.now() - row.last_backup_at < 20000) return json({ error: 'too_soon' }, 429);
  const r = await backupUser(env, { ...user, backup_folder_id: row && row.backup_folder_id }, Date.now(), { manual: true });
  return json(r, r.status === 'ok' || r.status === 'skipped_empty' ? 200 : 502);
}
