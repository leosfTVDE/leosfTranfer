const CACHE_NAME = 'trajeto-v29';
const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './icon-192-v2.png',
  './icon-512-v2.png',
  './apple-touch-icon-v2.png',
  './favicon-v2.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Rede primeiro: sempre tenta buscar a versão mais recente.
// Só usa a cópia guardada se não houver internet (fallback offline).
self.addEventListener('fetch', (event) => {
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copia = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copia));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
