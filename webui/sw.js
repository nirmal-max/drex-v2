/**
 * DREX-V2 Forensic Progressive Web App (PWA) Service Worker
 * ==========================================================
 * Version: drex-v2-shell-2.0.0-final
 * 
 * Strict Safety & Forensic Integrity Policy:
 * 1. Network-First Strategy: All UI assets (index.html, app.js, styles.css) are fetched
 *    from the network first to guarantee runtime source truth matching repository HEAD.
 * 2. Instant Invalidation: On upgrade/new release, old caches are immediately purged and
 *    the active worker claims clients immediately (skipWaiting + clients.claim).
 * 3. Offline Safety Gating: Destructive operations (Drive Erasure, File Shredding), live
 *    recovery scans, evidence exports, and live workstation jobs STRICTLY REQUIRE CONNECTIVITY.
 *    Offline requests to mutation/live endpoints are intercepted and rejected with 503.
 */

const CACHE_VERSION = '2.0.0-final';
const CACHE_NAME = `drex-v2-shell-${CACHE_VERSION}`;
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
  '/api/dialog/',
  '/ws/'
];

self.addEventListener('install', (event) => {
  // Precache shell assets and activate immediately without waiting
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  // Delete all stale caches from previous commits/releases and claim clients immediately
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

  // 2. Network-First Strategy for application shell assets (app.js, index.html, styles.css)
  // Ensures updates in source code are served immediately without stale cache persistence
  if (STATIC_ASSETS.includes(url.pathname) || url.pathname.endsWith('.css') || url.pathname.endsWith('.js') || url.pathname.endsWith('.html') || url.pathname === '/') {
    event.respondWith(
      fetch(event.request).then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200) {
          const responseClone = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, responseClone));
        }
        return networkResponse;
      }).catch(() => {
        // Fallback to cache only when offline
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) return cachedResponse;
          if (event.request.mode === 'navigate') {
            return caches.match('/index.html');
          }
          return new Response('Network error and asset not cached', { status: 408, headers: { 'Content-Type': 'text/plain' } });
        });
      })
    );
    return;
  }

  // 3. Static Media/Icons: Cache-first fallback to network
  if (url.pathname.endsWith('.png') || url.pathname.endsWith('.ico') || url.pathname.endsWith('.svg')) {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        if (cached) return cached;
        return fetch(event.request).then((res) => {
          if (res && res.status === 200) {
            const clone = res.clone();
            caches.open(CACHE_NAME).then((c) => c.put(event.request, clone));
          }
          return res;
        });
      })
    );
    return;
  }

  // 4. General API & Other Requests: Network first, cache fallback
  event.respondWith(
    fetch(event.request).catch(() => {
      return caches.match(event.request).then((cached) => {
        if (cached) return cached;
        if (event.request.mode === 'navigate') {
          return caches.match('/index.html');
        }
        return new Response(JSON.stringify({ error: 'OFFLINE', message: 'Workstation offline' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      });
    })
  );
});
