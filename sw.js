// Минимален service worker: БЕЗ кеширане, всичко върви през мрежата.
// Служи само за да може приложението да се инсталира като иконка.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => { /* без пренасочване и кеш */ });
