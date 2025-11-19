// Service Worker Simplificado - Sin iconos
const CACHE_NAME = 'revista-digital-csf-v3.0';
const OFFLINE_URL = '/offline.html';

// Archivos críticos para cachear
const STATIC_CACHE = [
    '/',
    '/index.html',
    '/styles.css',
    '/script.js',
    '/offline.html',
    '/manifest.json'
    
];

// Instalación
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(STATIC_CACHE))
            .then(() => self.skipWaiting())
    );
});

// Activación
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== CACHE_NAME) {
                        return caches.delete(cacheName);
                    }
                })
            );
        }).then(() => self.clients.claim())
    );
});

// Fetch - Estrategia simple
self.addEventListener('fetch', (event) => {
    if (!event.request.url.startsWith('http')) return;

    // Para API, no cachear
    if (event.request.url.includes('/api/')) {
        event.respondWith(fetch(event.request));
        return;
    }

    event.respondWith(
        fetch(event.request)
            .catch(() => {
                return caches.match(event.request)
                    .then((cachedResponse) => {
                        if (cachedResponse) {
                            return cachedResponse;
                        }
                        if (event.request.mode === 'navigate') {
                            return caches.match(OFFLINE_URL);
                        }
                        return new Response('Offline');
                    });
            })
    );
});