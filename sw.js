/* LP Planner service worker — offline app shell.
   - Pages (index.html, navigation): network-first, falling back to the cached copy, so updates arrive when online.
   - Pinned CDN libraries, fonts, icons: cache-first (their URLs are versioned, so they never change).
   - API calls (the Worker, Google) are never touched: the app's own sync layer handles those.
   Bump CACHE when this file's strategy changes. */
const CACHE = 'lp-shell-v1';
const SHELL = ['./', 'index.html', 'manifest.json', 'icon-192.png', 'icon-512.png'];
const LIBS = [
  'https://unpkg.com/react@18.3.1/umd/react.development.js',
  'https://unpkg.com/react-dom@18.3.1/umd/react-dom.development.js',
  'https://unpkg.com/@babel/standalone@7.26.5/babel.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js',
];
const STATIC_HOSTS = ['unpkg.com', 'cdnjs.cloudflare.com', 'fonts.googleapis.com', 'fonts.gstatic.com'];

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    // Shell files must succeed; CDN libs are best-effort (they also get cached on first use).
    await c.addAll(SHELL).catch(() => {});
    await Promise.all(LIBS.map(u => fetch(u, { mode: 'cors', signal: AbortSignal.timeout(15000) }).then(r => r.ok && c.put(u, r)).catch(() => {})));
    self.skipWaiting();
  })());
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k.startsWith('lp-shell-') && k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // Same-origin pages and files: network first, cache as the offline fallback.
  if (url.origin === self.location.origin) {
    if (url.pathname.endsWith('/oauth.html')) return;   // sign-in redirect must always hit the network
    e.respondWith((async () => {
      const c = await caches.open(CACHE);
      try {
        const r = await fetch(req, { cache: 'no-cache' });
        if (r.ok) c.put(req, r.clone());
        return r;
      } catch (err) {
        const hit = await c.match(req, { ignoreSearch: true })
          || (req.mode === 'navigate' ? await c.match('index.html') || await c.match('./') : null);
        if (hit) return hit;
        throw err;
      }
    })());
    return;
  }

  // Versioned libraries and fonts: cache first.
  if (STATIC_HOSTS.includes(url.hostname)) {
    e.respondWith((async () => {
      const c = await caches.open(CACHE);
      const hit = await c.match(req);
      if (hit) return hit;
      try {
        const r = await fetch(req);
        if (r.ok || r.type === 'opaque') c.put(req, r.clone());
        return r;
      } catch (err) { return Response.error(); }
    })());
  }
});
