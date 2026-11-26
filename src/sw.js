'use strict';
// Network-only: never cache authenticated content, API responses or credentials.
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('fetch',event=>{if(event.request.mode!=='navigate')return;event.respondWith(fetch(event.request).catch(()=>new Response('<!doctype html><html lang="en"><meta charset="utf-8"><title>LinkScope offline</title><h1>LinkScope is offline</h1><p>Reconnect to the monitoring server and reload this page.</p></html>',{status:503,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'"}})));});
