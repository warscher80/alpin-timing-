/* ALPIN TIMING — Service Worker
 * Strategie: NETZWERK ZUERST (damit der eingebaute Update-Hinweis weiter greift
 * und nie eine veraltete Version „hängenbleibt"), Cache nur als Offline-Reserve.
 * Bei schlechtem/keinem Netz am Berg läuft die App damit trotzdem.
 */
const CACHE = 'alpin-v1';
const SHELL = ['/', '/alpin-timing.html', '/manifest.json', '/icon.svg'];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).catch(() => {}));
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('message', (e) => { if (e.data === 'skipWaiting') self.skipWaiting(); });

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;                 // nie POST (Login/Register) cachen
  const url = new URL(req.url);
  if (url.protocol === 'ws:' || url.protocol === 'wss:') return;
  // Versionsabfrage immer frisch aus dem Netz (kein respondWith -> Standardverhalten)
  if (url.origin === location.origin && url.pathname === '/api/version') return;

  const sameOrigin = url.origin === location.origin;
  const isFont = /(^|\.)gstatic\.com$/.test(url.hostname) || /(^|\.)googleapis\.com$/.test(url.hostname);
  if (!sameOrigin && !isFont) return;               // fremde Hosts unangetastet lassen

  e.respondWith((async () => {
    try {
      const res = await fetch(req);
      if (res && res.status === 200 && (res.type === 'basic' || res.type === 'cors')) {
        const cache = await caches.open(CACHE);
        cache.put(req, res.clone());
      }
      return res;
    } catch (err) {
      const hit = await caches.match(req, { ignoreSearch: sameOrigin });
      if (hit) return hit;
      if (req.mode === 'navigate') {
        const shell = await caches.match('/alpin-timing.html') || await caches.match('/');
        if (shell) return shell;
      }
      throw err;
    }
  })());
});
