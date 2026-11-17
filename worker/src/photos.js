// Photos for the shared space (Worker 0.4.0), stored in an R2 bucket bound as env.PHOTOS.
//
//   PUT    /api/shared/photos/<id>?v=full|thumb   raw JPEG body (the app shrinks photos first)
//   GET    /api/shared/photos/<id>?v=full|thumb   the JPEG
//   DELETE /api/shared/photos/<id>                removes both sizes
//
// Membership is checked by sharedApi before we get here. Ids are made by the app ("p_" + letters/digits).
// Objects are immutable once written (a new photo gets a new id), so GETs are cacheable by the browser.

import { json } from './util.js';

const PREFIX = '/api/shared/photos/';
const ID_RE = /^p_[a-z0-9]{6,40}$/;
const MAX_BYTES = { full: 3_000_000, thumb: 600_000 };
const keyOf = (id, v) => `household/${id}${v === 'thumb' ? '-t' : ''}.jpg`;

export async function photosApi(req, env, url) {
  if (!env.PHOTOS) return json({ error: 'photos_not_configured' }, 501);
  const id = decodeURIComponent(url.pathname.slice(PREFIX.length));
  if (!ID_RE.test(id)) return json({ error: 'bad_request', detail: 'bad photo id' }, 400);
  const variant = url.searchParams.get('v') === 'thumb' ? 'thumb' : 'full';

  if (req.method === 'PUT') {
    const buf = await req.arrayBuffer();
    if (!buf.byteLength) return json({ error: 'bad_request', detail: 'empty body' }, 400);
    if (buf.byteLength > MAX_BYTES[variant]) return json({ error: 'photo_too_large', max: MAX_BYTES[variant] }, 413);
    const head = new Uint8Array(buf, 0, 3);
    if (!(head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff)) return json({ error: 'bad_request', detail: 'JPEG only' }, 400);
    await env.PHOTOS.put(keyOf(id, variant), buf, { httpMetadata: { contentType: 'image/jpeg' } });
    return json({ ok: true, id, variant, bytes: buf.byteLength });
  }
  if (req.method === 'GET') {
    const obj = await env.PHOTOS.get(keyOf(id, variant));
    if (!obj) return json({ error: 'not_found' }, 404);
    return new Response(obj.body, { headers: { 'Content-Type': 'image/jpeg', 'Cache-Control': 'private, max-age=31536000, immutable' } });
  }
  if (req.method === 'DELETE') {
    await env.PHOTOS.delete([keyOf(id, 'full'), keyOf(id, 'thumb')]);
    return json({ ok: true });
  }
  return json({ error: 'not_found' }, 404);
}
