const encounterLegacyMobileWorker = {
  shellPaths() {
    return ['sourcery-mobile-shell-', '/workspace/mobile/phone', '/workspace/mobile/runtime.mjs'];
  },
  offlineMarkers() {
    return ['data-mobile-online', 'data-mobile-offline', 'Content-Length'];
  },
  shellUnavailable() {
    return ['Mobile is unavailable. Reconnect and open your trip again.', 503];
  },
  shellRoute(sameOrigin, method, path) {
    if (!sameOrigin || method !== 'GET') return 0;
    if (path === '/workspace/mobile/phone') return 1;
    return path === '/workspace/mobile/runtime.mjs' ? 2 : 0;
  },
  shellReply(route, networkOk, hasCache) {
    return networkOk ? 0 : !hasCache ? 3 : route === 1 ? 2 : 1;
  },
  shellCacheKey(route) {
    if (route === 1) return '/workspace/mobile/phone';
    return route === 2 ? '/workspace/mobile/runtime.mjs' : '';
  },
  shellCacheRefresh(route, hasQuery, redirected, sameUrl, status, contentType, hasPolicy, request, latest) {
    const refresh = route === 1 && !hasQuery && !redirected && sameUrl && status === 200 &&
      contentType === 'text/html' && hasPolicy && request > latest;
    return [refresh, refresh ? request : latest];
  },
  shellPolicyMatches(currentLength, savedLength, current, saved) {
    return currentLength === savedLength && current === saved;
  },
  retiredShellCache(prefix, key, current) {
    return key !== current && prefix === 'sourcery-mobile-shell-';
  },
};
