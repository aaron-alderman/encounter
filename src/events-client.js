'use strict';

(() => {
  const marker = () => document.querySelector('[data-encounter-events]');
  if (!marker()) return;
  const wasm = loadBrowserWasm(encounterLiveEventsWasm);
  const policy = selectBrowserPolicy(wasm);
  if (!policy) {
    const indicator = document.querySelector('[data-encounter-connection]');
    if (indicator) indicator.textContent = 'This release requires WebAssembly for live updates.';
    return;
  }
  const textResult = value => wasm ? browserWasmTextResult(wasm.memory, value) : value;
  const stream = marker().dataset.encounterEvents;
  const [protocol, cursorParameter, storagePrefix] = policy.socketCoordinates(location.protocol === 'https:').map(textResult);
  const key = storagePrefix + stream;
  let savedCursor = 0;
  try { savedCursor = Number(sessionStorage.getItem(key)); }
  catch { /* Resume without a saved cursor when session storage is unavailable. */ }
  const safeCursor = Number.isSafeInteger(savedCursor);
  let after = policy.resumeCursor(safeCursor, safeCursor ? savedCursor : 0);
  let updating = false;
  let queuedApply;
  let wanted = 0;
  let retained = '';
  const connection = () => document.querySelector('[data-encounter-connection]');
  let connectionText = '';
  let retryDelay = 0;
  schedule('start');

  function showConnection(text) {
    const indicator = connection();
    if (indicator && indicator.textContent !== text) indicator.textContent = text;
  }

  function draftChanged(current, saved) {
    if (!wasm) return policy.draftChanged(current.length, saved.length, current, saved);
    return browserWasmTextChanged(wasm.memory, policy.draftChanged, current, saved);
  }

  function sameCoordinate(expected, observed) {
    return wasm ? browserWasmTextMatches(wasm.memory, policy.sameCoordinate, expected, observed)
      : policy.sameCoordinate(expected.length, observed?.length ?? -1, expected, observed);
  }

  function draft() {
    const field = document.querySelector('[data-encounter-draft]');
    return field && draftChanged(field.value, field.defaultValue) ? field : null;
  }

  function mediaClock() {
    return document.querySelector('video[data-encounter-media-clock]');
  }

  function mediaRoute() {
    const video = mediaClock();
    if (!policy.mediaClockReady((video?.readyState ?? 0) >= 2, Boolean(video?.seeking))) return null;
    const timeline = document.getElementById(video.dataset.encounterMediaClock);
    const now = video.currentTime;
    let cue = null;
    let previous = 0;
    for (const link of timeline?.querySelectorAll('[data-encounter-media-start]') || []) {
      const start = Number(link.dataset.encounterMediaStart);
      const valid = [start, now, previous].every(Number.isFinite);
      const candidate = policy.cueCandidate(valid, wasm && !valid ? 0 : start,
        wasm && !valid ? 0 : now, wasm && !valid ? 0 : previous, Boolean(cue));
      if (candidate) {
        cue = link;
        previous = start;
      }
    }
    if (!cue) return null;
    return new URL(cue.getAttribute('href'), location.href);
  }

  const currentRoute = () => location.pathname + location.search;
  const requestRoute = route => route ? route.pathname + route.search : currentRoute();

  function pending(show, moved = false) {
    const notice = document.querySelector('[data-encounter-pending]');
    const button = document.querySelector('[data-encounter-apply]');
    const [message, hideApply, disableSubmit] = policy.pendingNotice(show, moved, Boolean(connection()));
    if (notice) {
      const text = textResult(message);
      if (notice.textContent !== text) notice.textContent = text;
    }
    if (button) button.hidden = Boolean(hideApply);
    const form = document.querySelector('[data-encounter-draft]')?.form;
    const submit = form?.querySelector('button[type="submit"]');
    if (submit) submit.disabled = Boolean(disableSubmit);
  }

  function replace(next, force, route) {
    const dirty = draft();
    const main = document.querySelector('main');
    const incoming = next.querySelector('main');
    const displayed = marker();
    const rendered = next.querySelector('[data-encounter-events]');
    const markerInside = Boolean(main?.contains(displayed));
    const incomingMarkerInside = Boolean(incoming?.contains(rendered));
    const media = Boolean(mediaClock() || main?.querySelector("canvas[data-encounter-canvas]"));
    const parts = media && main ? [...main.querySelectorAll('[data-encounter-live-part][id]')] : [];
    const fresh = parts.map(part => incoming?.querySelector('#' + CSS.escape(part.id)));
    const matchedParts = fresh.filter(Boolean).length;
    const moved = !sameCoordinate(requestRoute(route), currentRoute());
    const [action, retainDraft, changeRoute, focus, updateMarker] = policy.replace(Boolean(dirty), force, media,
      parts.length, matchedParts, moved, Boolean(main && incoming), markerInside, incomingMarkerInside);
    if (action === 0) {
      pending(true, moved);
      return false;
    }
    if (action === 3) return false;
    if (retainDraft) retained = dirty.value;
    const x = window.scrollX;
    const y = window.scrollY;
    for (const details of main.querySelectorAll('details[open][id]')) {
      const corresponding = next.getElementById(details.id);
      if (corresponding?.tagName === 'DETAILS') corresponding.open = true;
    }
    if (retained) {
      const copy = incoming.querySelector('[data-encounter-retained]');
      if (copy) {
        copy.querySelector('[data-encounter-retained-text]').value = retained;
        copy.hidden = false;
      }
    }
    // Live parts preserve a surface’s current picture and transport.
    if (action === 1) {
      parts.forEach((part, index) => part.replaceWith(fresh[index]));
    } else {
      main.replaceWith(incoming);
    }
    if (updateMarker) (action === 1 ? marker() : displayed).dataset.rendered = rendered.dataset.rendered;
    if (changeRoute) history.replaceState(history.state, '', requestRoute(route) + location.hash);
    showConnection(connectionText);
    document.dispatchEvent(new Event("encounter:live-refresh"));
    if (focus) document.querySelector('[data-encounter-decision]')?.focus({ preventScroll: true });
    window.scrollTo({ left: x, top: y, behavior: 'instant' });
    return true;
  }

  async function update(force = false) {
    const displayed = marker();
    const plan = policy.updatePlan(Boolean(displayed), updating, force);
    if (plan === 0) return;
    const route = mediaRoute();
    const requested = requestRoute(route);
    if (plan === 2) {
      queuedApply = requested;
      return;
    }
    const moved = !sameCoordinate(requested, currentRoute());
    const rendered = Number(displayed.dataset.rendered);
    const validRendered = Number.isFinite(rendered);
    const dirty = Boolean(draft());
    const active = document.activeElement;
    const editing = policy.editorActive(Boolean(active?.matches('textarea, input:not([type=hidden]), select')),
      Boolean(active?.closest('[data-canvas-stage]')));
    const media = Boolean(mediaClock() || document.querySelector("canvas[data-encounter-canvas]"));
    const [fetchUpdate, pendingAction] = policy.refresh(moved, validRendered, wasm && !validRendered ? 0 : rendered,
      wanted, force, dirty, editing, media);
    if (pendingAction) pending(pendingAction === 2, moved);
    if (!fetchUpdate) return;
    updating = true;
    let applied = false;
    try {
      const response = await fetch(requested, { cache: 'no-store' });
      const currentRouteMatches = () => sameCoordinate(requested, requestRoute(mediaRoute()));
      const current = currentRouteMatches();
      if (!policy.refreshReply(response.ok, current)) return;
      const next = new DOMParser().parseFromString(await response.text(), 'text/html');
      const displayed = marker();
      if (!displayed) return;
      const stillCurrent = currentRouteMatches();
      const rendered = next.querySelector('[data-encounter-events]');
      const sameStream = sameCoordinate(stream, rendered?.dataset.encounterEvents);
      const incoming = Number(rendered?.dataset.rendered);
      const shown = Number(displayed.dataset.rendered);
      const valid = Number.isFinite(shown) && Number.isFinite(incoming);
      const admissible = policy.replaceReply(stillCurrent, sameStream, moved, valid,
        wasm && !valid ? 0 : shown, wasm && !valid ? 0 : incoming);
      if (admissible) {
        const [apply, consume] = policy.applyQueued(force, queuedApply !== undefined, sameCoordinate(requested, queuedApply));
        applied = Boolean(policy.queuedApplied(replace(next, apply, route), consume));
      }
    } catch {
      // The next delivery or reconnect can rebuild from committed state.
    } finally {
      updating = false;
      const queued = queuedApply !== undefined;
      const sameRoute = Boolean(policy.inspectQueuedRoute(queued, applied)) &&
        sameCoordinate(queuedApply, requestRoute(mediaRoute()));
      const [clear, retry] = policy.finishQueued(queued, sameRoute, applied);
      if (clear) queuedApply = undefined;
      if (retry) void update(true);
    }
  }

  function schedule(event) {
    const input = policy.memory ? browserWasmText(policy.memory, event) : [event];
    const [delay, wait, notice, publish] = policy.socketSchedule(...input, retryDelay, Boolean(connection()));
    retryDelay = delay;
    const text = textResult(notice);
    if (text) {
      connectionText = text;
      if (publish) showConnection(text);
    }
    return wait;
  }

  async function reconnect() {
    const [refresh, cache, redirect] = policy.reconnectRequest(Boolean(connection()));
    if (refresh) {
      // The socket and the HTTP session can both disappear when the app restarts.
      // Open a fresh session before retrying and keep the editor DOM intact.
      try {
        const response = await fetch(currentRoute(), {cache: textResult(cache), redirect: textResult(redirect)});
        const redirected = response.type === 'opaqueredirect';
        const [read, retryEvent] = policy.reconnectAction(response.status, redirected, response.ok);
        if (!read) {
          setTimeout(reconnect, schedule(textResult(retryEvent)));
          return;
        }
        const page = new DOMParser().parseFromString(await response.text(), 'text/html');
        const fresh = page.querySelector('input[name="_csrf"]');
        const freshStream = page.querySelector('[data-encounter-events]')?.dataset.encounterEvents;
        const sameStream = sameCoordinate(stream, freshStream);
        if (policy.replaceToken(Boolean(fresh), sameStream)) {
          for (const token of document.querySelectorAll('input[name="_csrf"]')) token.value = fresh.value;
        }
      } catch {
        setTimeout(reconnect, schedule('failed'));
        return;
      }
    }
    connect();
  }

  function connect() {
    const endpoint = new URL(stream, location.href);
    endpoint.protocol = protocol;
    endpoint.searchParams.set(cursorParameter, String(after));
    const socket = new WebSocket(endpoint);
    socket.addEventListener('message', ({ data }) => {
      let sequence;
      try { sequence = JSON.parse(data)?.sequence; } catch { return; }
      const valid = Number.isSafeInteger(sequence);
      const [accept, cursor, watermark] = policy.socketDelivery(false, valid, after, wanted, valid ? sequence : 0);
      if (!accept) return;
      after = cursor;
      wanted = watermark;
      try { sessionStorage.setItem(key, String(after)); }
      catch { /* Keep delivering events even when session storage is unavailable. */ }
      void update();
    });
    socket.addEventListener('open', () => {
      schedule('open');
      const [, , watermark] = policy.socketDelivery(true, false, after, wanted, 0);
      wanted = watermark;
      void update();
    });
    socket.addEventListener('close', () => {
      setTimeout(reconnect, schedule('close'));
    });
  }

  document.addEventListener('click', event => {
    if (event.target.closest('[data-encounter-apply]')) void update(true);
    const cue = event.target.closest('[data-encounter-media-start]');
    const video = mediaClock();
    const modified = Boolean(event.metaKey || event.ctrlKey || event.shiftKey || event.altKey);
    if (!policy.seekCue(Boolean(cue), (video?.readyState ?? 0) >= 2, event.button === 0, modified)) return;
    event.preventDefault();
    video.currentTime = Number(cue.dataset.encounterMediaStart);
  });
  document.addEventListener('submit', event => {
    const video = mediaClock();
    if (!video) return;
    const hasDraft = Boolean(event.target.querySelector('[data-encounter-draft]'));
    const moved = hasDraft && !video.seeking && !sameCoordinate(requestRoute(mediaRoute()), currentRoute());
    const hold = policy.holdSubmit(hasDraft, video.seeking, moved);
    if (hold) {
      event.preventDefault();
      void update();
    }
  });
  for (const name of ['seeked', 'timeupdate']) {
    document.addEventListener(name, event => {
      if (event.target === mediaClock()) void update();
    }, true);
  }
  document.addEventListener('input', () => { void update(); });
  document.addEventListener('focusout', () => setTimeout(update, schedule('focus-out')));
  setInterval(update, schedule('poll'));
  connect();
})();
