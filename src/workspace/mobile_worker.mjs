const workerWasm = loadBrowserWasm(encounterMobileWorkerWasm);
const workerPolicy = selectBrowserPolicy(workerWasm);
if (!workerPolicy) throw new Error('This release requires WebAssembly to serve an offline Mobile shell.');
const workerText = (...values) => workerWasm ? browserWasmText(workerWasm.memory, ...values) : values;

const workerResultText = value => workerWasm ? browserWasmTextResult(workerWasm.memory, value) : value;
const [shellPrefix, phone, runtime] = workerPolicy.shellPaths().map(workerResultText);
const shellCache = shellPrefix + mobileVersion;
let requestSequence = 0;
let latestRefresh = 0;
let shellWrite = Promise.resolve();
self.addEventListener('install', event => {
  event.waitUntil(caches.open(shellCache).then(cache => cache.addAll([phone, runtime])).then(() => self.skipWaiting()));
});
self.addEventListener('activate', event => event.waitUntil((async () => {
  const keys = await caches.keys();
  const retired = keys.filter(key => workerPolicy.retiredShellCache(
    ...workerText(key.slice(0, shellPrefix.length), key, shellCache)));
  await Promise.all(retired.map(key => caches.delete(key)));
  await self.clients.claim();
})()));
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  const route = workerPolicy.shellRoute(url.origin === self.location.origin,
    ...workerText(event.request.method, url.pathname));
  if (route === 0) return;
  const sequence = ++requestSequence;
  event.respondWith((async () => {
    try {
      const response = await fetch(event.request);
      if (workerPolicy.shellReply(route, response.ok, false) === 0) {
        const policy = response.headers.get('Content-Security-Policy');
        const type = (response.headers.get('Content-Type') ?? '').split(';', 1)[0].trim().toLowerCase();
        const [refresh, latest] = workerPolicy.shellCacheRefresh(route, Boolean(url.search),
          response.redirected, response.url === url.href, response.status, ...workerText(type),
          Boolean(policy), sequence, latestRefresh);
        latestRefresh = latest;
        if (refresh) {
          shellWrite = shellWrite.then(async () => {
            const cache = await caches.open(shellCache);
            const cached = await cache.match(phone);
            const saved = cached?.headers.get('Content-Security-Policy');
            const matches = workerWasm
              ? browserWasmTextMatches(workerWasm.memory, workerPolicy.shellPolicyMatches, policy, saved)
              : workerPolicy.shellPolicyMatches(policy.length, saved?.length ?? -1, policy, saved);
            if (!matches) {
              await cache.put(phone, response.clone());
            }
          }).catch(() => { /* A cache write failure leaves the live response usable. */ });
          await shellWrite;
        }
        return response;
      }
    } catch {}
    const cache = await caches.open(shellCache);
    const response = await cache.match(workerResultText(workerPolicy.shellCacheKey(route)));
    const action = workerPolicy.shellReply(route, false, Boolean(response));
    if (action === 3) {
      const [message, status] = workerPolicy.shellUnavailable();
      return new Response(workerResultText(message), {status});
    }
    if (action === 1) return response;
    // Only the offline navigation path adds this marker.
    const [online, offline, removeHeader] = workerPolicy.offlineMarkers().map(workerResultText);
    const body = (await response.text()).replace(online, offline);
    const headers = new Headers(response.headers);
    headers.delete(removeHeader);
    return new Response(body, {headers});
  })());
});
