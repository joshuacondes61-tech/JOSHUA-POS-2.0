/* SINSIN STORE POS installability worker.
   Keep POS pages and API responses network-only: never cache sessions,
   credentials, inventory, sales, or other private store data. */
self.addEventListener("install", event => {
  self.skipWaiting();
});
self.addEventListener("activate", event => {
  event.waitUntil(self.clients.claim());
});
self.addEventListener("fetch", event => {
  if (event.request.method !== "GET") return;
  event.respondWith(fetch(event.request));
});
