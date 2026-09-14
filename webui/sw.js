/**
 * DREX-V2 Forensic Progressive Web App (PWA) Service Worker
 * ==========================================================
 * Strict Safety & Forensic Integrity Policy:
 * 1. Offline capability is limited to static shell assets and approved non-sensitive cached metadata.
 * 2. Destructive operations (Drive Erasure, File Shredding), live recovery scans, evidence exports,
 *    audit verifications, and live workstation jobs STRICTLY REQUIRE CONNECTIVITY.
 * 3. Offline requests to mutation/live endpoints are intercepted and rejected with 503.
 */

const CACHE_NAME = 'drex-v2-shell-v1';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/styles.css',
  '/app.js',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png'
];

// Live endpoints that MUST NEVER be executed or simulated offline
const CONNECTIVITY_REQUIRED_PREFIXES = [
  '/api/sanitization/',
  '/api/recovery/',
  '/api/demo/',
  '/api/auth/',
  '/api/cases',
  '/ws/'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // 1. Check for live/destructive operation gating
  const isProtectedAction = CONNECTIVITY_REQUIRED_PREFIXES.some((prefix) => url.pathname.startsWith(prefix));

  if (isProtectedAction) {
    // Attempt network only; if offline, return structured 503 error
    event.respondWith(
      fetch(event.request).catch(() => {
        return new Response(
          JSON.stringify({
            error: 'OFFLINE_RESTRICTED',
            message: 'Live forensic and destructive operations require active connectivity to the DREX workstation.',
            path: url.pathname,
            timestamp: new Date().toISOString()
          }),
          {
            status: 503,
            statusText: 'Service Unavailable (Offline Gated)',
            headers: { 'Content-Type': 'application/json' }
          }
        );
      })
    );
    return;
  }

  // 2. Static Assets: Cache-first strategy
  if (STATIC_ASSETS.includes(url.pathname) || url.pathname.endsWith('.css') || url.pathname.endsWith('.js') || url.pathname.endsWith('.png')) {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        if (cachedResponse) return cachedResponse;
        return fetch(event.request).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const responseClone = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, responseClone));
          }
          return networkResponse;
        });
      })
    );
    return;
  }

  // 3. General requests: Network first, cache fallback
  event.respondWith(
    fetch(event.request).catch(() => {
      return caches.match(event.request).then((cached) => {
        if (cached) return cached;
        if (event.request.mode === 'navigate') {
          return caches.match('/index.html');
        }
        return new Response('Offline - resource not available', { status: 503, statusText: 'Offline' });
      });
    })
  );
});
