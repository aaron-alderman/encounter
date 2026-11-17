const endpoint = new URL('./browser', import.meta.url);
endpoint.protocol = endpoint.protocol === 'https:' ? 'wss:' : 'ws:';
// Aster can connect on the same page. Only Home's bridge owns the header indicator.
const connectionPanel = document.querySelector(endpoint.pathname === '/_encounter/browser'
  ? '[data-home-connection], [data-encounter-connection]'
  : '[data-encounter-connection]');
const homeAster = endpoint.pathname === '/_aster/browser' && Boolean(document.querySelector('[data-home-connection]'));
const queue = [];
const workspaceSessionPath = '/workspace/session';
let workspaceSessionRequest;
const recentTimings = [];
let nextTimingId = 0;
const cleanups = [];
const observations = new Map();
const documentState = new Map();
let documentStateSize = 0;
// The workspace and Aster can be served by different browser modules.
const startupKey = Symbol.for('encounter.browser.startup');
const startup = document[startupKey] ??= {
  location: new URL(location.href), receivers: new Set(),
};

function receiveStartup({receiver, paths = [], hashes = [], encoded = []}, consume = true) {
  const policy = interactionWasm();
  const arrays = [paths, hashes, encoded].every(Array.isArray);
  const admission = policy.startupReceiver(...interactionText(policy, typeof receiver === 'string' ? receiver : ''),
    arrays, arrays ? paths.length : 0,
    arrays ? hashes.length : 0, arrays ? encoded.length : 0, startup.receivers.has(receiver), startup.receivers.size);
  if (admission === 0) throw new Error('Invalid startup receiver');
  const {pathname: path, search, hash} = startup.location;
  const allowed = paths.includes(path);
  const [hadInput, launchHash] = policy.startupRoute(allowed, hashes.includes(hash), Boolean(search), Boolean(hash));
  if (admission === 1) return {first: false, path, hadInput: Boolean(hadInput), hash: '', fields: {}};
  if (admission === 2) throw new Error('Startup receiver capacity');

  const fields = Object.create(null);
  if (allowed) {
    const params = [...startup.location.searchParams];
    const unique = new Set(params.map(([key]) => key)).size === params.length;
    if (policy.startupFields(search.length, params.length, unique)) {
      for (const [key, value] of params) {
        const field = policy.startupField(...interactionText(policy, key), encoded.includes(key));
        if (field === 1) fields[key] = value;
        if (field === 2) fields[key] = encodeURIComponent(value);
      }
    }
    const current = new URL(location.href);
    const samePath = current.pathname === path;
    const sameLaunchHash = launchHash && current.hash === hash;
    const action = policy.startupCleanup(consume, samePath, Boolean(current.search), sameLaunchHash);
    if (action !== 0) {
      current.search = '';
      if (action === 2) current.hash = '';
      history.replaceState(history.state, '', current);
    }
  }
  if (consume) startup.receivers.add(receiver);
  return {first: true, path, hadInput: Boolean(hadInput), hash: launchHash ? hash : '', fields};
}

let nodeHandles = new WeakMap();
let nextHandle = 0;
let socket;
let busy = true;
let booting = true;
let active;
let retryTimer;
let timeoutTimer;
let countdownTimer;
let nextRetryAt = 0;
let lastAttemptAt = -Infinity;
let connectionReason = '';
let leaving = false;
let resumeAfterClose = false;
let interactionPolicy;
const [reconnectEnabled, firstRetryDelay, connectionTimeout] = loadInteractionPolicy()?.connectionProfile(
  Boolean(connectionPanel), homeAster, typeof encounterReconnect !== 'undefined' && Boolean(encounterReconnect),
) ?? [];
const [requestDeadline, asterDeadline] = loadInteractionPolicy()?.transportLimits() ?? [];
let retryDelay = firstRetryDelay;

function loadInteractionPolicy() {
  if (interactionPolicy === undefined) {
    const module = loadBrowserWasm(typeof encounterInteractionWasm === 'string' ? encounterInteractionWasm : null);
    interactionPolicy = selectBrowserPolicy(module, 'interaction');
  }
  return interactionPolicy;
}

function interactionWasm() {
  const policy = loadInteractionPolicy();
  if (!policy) throw new Error('This release requires the browser Wasm interaction policy');
  return policy;
}

export function asterStartupPlan(connected, view, restored, ready, deadline, idle) {
  const policy = interactionWasm();
  return policy.asterStartupPlan(connected, ...interactionText(policy, view), restored, ready, deadline, idle);
}

export function asterStartupCoordinates() {
  const policy = interactionWasm();
  return policy.asterStartupCoordinates().map(value => interactionResultText(policy, value));
}

function retryAllowed(hasSocket) {
  const now = Date.now();
  const policy = interactionWasm();
  const hasAttempt = Number.isFinite(lastAttemptAt);
  return Boolean(policy.retryAllowed(now, hasAttempt ? lastAttemptAt : 0, hasAttempt, hasSocket));
}

function connectionStatus(state, reason = '') {
  if (!connectionPanel) return;
  connectionPanel.dataset.state = state;
  const name = connectionPanel.dataset.connectionName || 'Workspace';
  const destination = endpoint.host + endpoint.pathname;
  const policy = interactionWasm();
  const manualRetry = retryAllowed(false);
  const [labelText, prefix, waiting, suffix, showRetry, retryTitle] =
    policy.connectionView(...interactionText(policy, state), Date.now(), nextRetryAt, manualRetry);
  const text = interactionResultText(policy, labelText);
  const label = connectionPanel.querySelector('[data-connection-label]');
  const stateLabel = label.querySelector('[data-connection-state]');
  const status = stateLabel ? text : name + ' · ' + text;
  const target = stateLabel || label;
  if (target.textContent !== status) target.textContent = status;
  const countdown = interactionResultText(policy, prefix);
  connectionPanel.querySelector('[data-connection-countdown]').textContent =
    countdown ? countdown + waiting + interactionResultText(policy, suffix) : '';
  connectionPanel.title = reason ? '' : destination;
  connectionPanel.querySelector('[data-connection-reason]').textContent = reason;
  const button = connectionPanel.querySelector('[data-encounter-retry]');
  button.hidden = !showRetry;
  button.disabled = !manualRetry;
  button.title = interactionResultText(policy, retryTitle) + (manualRetry ? destination : '');
}

function scheduleRetry(reason) {
  connectionReason = reason;
  const policy = interactionWasm();
  const [at, schedule, nextDelay, state, countdownInterval, panelState, wait] =
    policy.retryPlan(reconnectEnabled, Date.now(), retryDelay, Boolean(connectionPanel));
  nextRetryAt = at;
  document.documentElement.dataset.encounter = interactionResultText(policy, state);
  const status = interactionResultText(policy, panelState);
  connectionStatus(status, reason);
  clearInterval(countdownTimer);
  if (schedule) retryTimer = setTimeout(connect, wait);
  retryDelay = nextDelay;
  if (countdownInterval) {
    countdownTimer = setInterval(() => connectionStatus(status, connectionReason), countdownInterval);
  }
}

function target(ref) {
  if (ref === 'window') return window;
  if (ref === 'document') return document;
  const { selector, index = 0, handle } = typeof ref === 'string' ? { selector: ref } : ref;
  if (handle !== undefined) {
    const node = observations.get(handle)?.deref();
    if (!node) throw new Error('Expired DOM observation handle');
    return node;
  }
  const element = document.querySelectorAll(selector)[index];
  if (!element) throw new Error('Missing DOM observation target: ' + selector);
  return element;
}

function describe(node) {
  if (!(node instanceof Element)) return null;
  let handle = nodeHandles.get(node);
  const [allocate, evict] = interactionWasm().observationHandle(observations.has(handle), observations.size);
  if (allocate) {
    if (evict) observations.delete(observations.keys().next().value);
    handle = ++nextHandle;
    nodeHandles.set(node, handle);
    observations.set(handle, new WeakRef(node));
  }
  const {x, y, width, height, top, right, bottom, left} = node.getBoundingClientRect();
  return {
    ref: {handle}, tag: node.tagName,
    attributes: Object.fromEntries([...node.attributes].map(({name, value}) => [name, value])),
    text: node.textContent, rect: {x, y, width, height, top, right, bottom, left},
    value: node.value ?? null, checked: Boolean(node.checked),
    disabled: Boolean(node.disabled), hidden: Boolean(node.hidden),
  };
}

function recordTiming(timing, outcome, host) {
  if (!timing) return;
  const ended = performance.now();
  const {label, started, enqueued, dispatched, revealed, requests, responseMs, requestMs, status,
    blockers, omittedBlockers, blockedMs} = timing;
  const policy = interactionWasm();
  const [input, dispatch, total, queueTime, reveal] = policy.timingIntervals(started, enqueued, ended,
    dispatched !== undefined, dispatched ?? 0, revealed ?? 0);
  const hostTimingValid = Number.isFinite(host?.hostMs) && Number.isFinite(host?.exchangeMs);
  const detail = {
    inputMs: Math.round(input),
    dispatchMs: dispatched === undefined ? null : Math.round(dispatch),
    blockedMs: Math.round(blockedMs), blockers, omittedBlockers,
    hostMs: host ? Math.round(host.hostMs) : null,
    nativeMs: hostTimingValid ? Math.round(policy.timingHost(host.hostMs, host.exchangeMs)) : null,
    exchangeMs: host ? Math.round(host.exchangeMs) : null,
    browserMs: Math.round(timing.browserMs),
    effects: timing.effects.map((effect, index) => {
      const span = host?.effects[index];
      const matched = span?.port === effect.port ? span : null;
      return {...effect, process: matched?.process ?? '', label: matched?.label ?? '',
        exchangeMs: matched ? Math.round(matched.exchangeMs) : null};
    }),
    omittedEffects: timing.omittedEffects,
  };
  recentTimings.unshift({
    id: String(++nextTimingId), label, outcome: outcome || timing.outcome, recordedAt: Date.now(),
    totalMs: Math.round(total),
    queueMs: Math.round(queueTime),
    revealMs: revealed === undefined ? null : Math.round(reveal),
    requests, responseMs: Math.round(responseMs), requestMs: Math.round(requestMs), status, detail,
  });
  if (policy.timingEvict(recentTimings.length)) recentTimings.pop();
}

function recordBlocker(entry) {
  if (!entry) return;
  const ended = performance.now();
  const policy = interactionWasm();
  for (const {timing} of queue) {
    if (!timing) continue;
    const [overlap, offset, keep] = policy.timingBlocker(timing.enqueued, entry.dispatched, ended,
      timing.started, timing.blockers.length);
    if (overlap <= 0) continue;
    timing.blockedMs += overlap;
    if (keep) {
      timing.blockers.push({label: entry.label, atMs: Math.round(offset),
        ms: Math.round(overlap)});
    } else {
      timing.omittedBlockers++;
    }
  }
}

function recordResponse(timing, status) {
  if (!timing) return;
  const policy = interactionWasm();
  const started = Number.isFinite(timing.requestStarted);
  const now = performance.now();
  const [elapsed, failed] = policy.timingResponse(now, started ? timing.requestStarted : now, status);
  timing.responseMs += started ? elapsed : NaN;
  timing.status = status;
  if (failed) timing.outcome = interactionResultText(policy, policy.timingFailure(true));
}

function flush() {
  if (interactionWasm().canDispatch(busy, queue.length > 0, socket?.readyState === WebSocket.OPEN)) {
    busy = true;
    active = queue.shift();
    active.dispatched = performance.now();
    if (active.timing) active.timing.dispatched = active.dispatched;
    socket.send(JSON.stringify(active.message));
  }
}

function queueHasRoom() {
  return interactionWasm().queueHasRoom(queue.length);
}

function canPoll() {
  return interactionWasm().canPoll(busy, queue.length > 0, socket?.readyState === WebSocket.OPEN);
}

function canDeliverObservation(controller, connection) {
  return interactionWasm().canDeliverObservation(controller.signal.aborted, socket === connection,
    socket?.readyState === WebSocket.OPEN, queue.length);
}

function cancelWorkspaceSession() {
  workspaceSessionRequest?.abort();
  workspaceSessionRequest = undefined;
  const pending = queue.findIndex(entry => entry.workspaceSession);
  if (pending !== -1) queue.splice(pending, 1);
}

async function observeWorkspaceAccess(binding, label, controller) {
  const connection = socket;
  let platform = false;
  try {
    const response = await fetch('/workspace/access', {
      cache: 'no-store', redirect: 'manual',
      signal: AbortSignal.any([controller.signal, AbortSignal.timeout(requestDeadline)]),
    });
    if (interactionWasm().observationReply(response.status)) {
      const access = JSON.parse(await boundedResponse(response));
      platform = access.platform === true;
    }
  } catch {
    // Keep the Platform link hidden when the check cannot be completed.
  }
  if (!canDeliverObservation(controller, connection)) return;
  queue.push({label, message: {binding, event: {type: 'workspace-access', platform}}});
  flush();
}

async function observeWorkspaceSession(binding, label, type) {
  const policy = interactionWasm();
  if (!policy.sessionRequestAllowed(Boolean(workspaceSessionRequest), queue.some(entry => entry.workspaceSession))) return;
  const controller = new AbortController();
  workspaceSessionRequest = controller;
  const connection = socket;
  let session = null;
  try {
    const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(requestDeadline)]);
    const read = () => fetch(workspaceSessionPath, {
      cache: 'no-store', redirect: 'manual',
      signal,
    });
    let response = await read().catch(() => null);
    if (policy.sessionRetry(Boolean(response), response?.status ?? 0, signal.aborted)) {
      void response?.body?.cancel().catch(() => {});
      response = await read();
    }
    if (policy.observationReply(response?.status ?? 0)) {
      const body = JSON.parse(await boundedResponse(response));
      const [identityLimit, usernameLimit, xAvailable] = policy.sessionFields(
        typeof body.templeIdentity === 'string', typeof body.username === 'string', body.xAvailable === true);
      session = {
        templeIdentity: identityLimit ? body.templeIdentity.slice(0, identityLimit) : null,
        username: usernameLimit ? body.username.slice(0, usernameLimit) : null,
        xAvailable: Boolean(xAvailable),
      };
    }
  } catch {
    // Encounter renders the unavailable state if this observation failed.
  } finally {
    if (workspaceSessionRequest === controller) workspaceSessionRequest = undefined;
  }
  if (!canDeliverObservation(controller, connection)) return;
  queue.push({label, workspaceSession: true, message: {binding, event: {type, session}}});
  flush();
}

function report(error, logError = true) {
  const sink = document.querySelector('[data-temple-errors]');
  if (sink) sink.textContent = error ?? '';
  if (error && logError) console.error(error);
}

function sameOriginPath(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') ||
      /[\\\x00-\x20]/.test(path) || new URL(path, location.origin).origin !== location.origin) {
    throw new Error('Expected a same-origin browser path');
  }
  return path;
}

function browserStorage(policy, scope) {
  return policy.storageInTab(...interactionText(policy, typeof scope === 'string' ? scope : ''))
    ? sessionStorage : localStorage;
}

function requestHeaders(bearer) {
  const policy = interactionWasm();
  const action = policy.requestBearer(bearer != null, ...interactionText(policy, typeof bearer === 'string' ? bearer : ''));
  if (action === 2) throw new Error('Invalid browser request bearer');
  return action === 1 ? {Authorization: 'Bearer ' + bearer} : {};
}

function localUrl(value) {
  const url = new URL(value, location.origin);
  if (url.origin !== location.origin || url.username || url.password) throw new Error('Expected a same-origin URL');
  return url;
}

const asterEventsPath = '/workspace/aster/events';
let asterSubscription;
let asterWatch;

function interactionText(policy, ...values) {
  return policy.memory ? browserWasmText(policy.memory, ...values) : values;
}

function interactionResultText(policy, value) {
  return policy.memory ? browserWasmTextResult(policy.memory, value) : value;
}

function admitPngSource(policy, value) {
  if (typeof value !== 'string') return false;
  const offset = policy.pngPayloadOffset(...interactionText(policy, value.slice(0, 128)), value.length);
  if (!offset) return false;
  return policy.memory
    ? browserWasmTextEvery(policy.memory, policy.pngPayloadChunk, value, offset)
    : policy.pngPayloadChunk(value.slice(offset));
}

function asterFragment(text, fragment, captureWatch) {
  const page = new DOMParser().parseFromString(text, 'text/html');
  const live = page.querySelector('[data-notes-content="aster"] #aster-live');
  const thread = live?.getAttribute('data-thread') ?? '';
  const bearer = live?.getAttribute('data-stream-bearer') ?? '';
  const policy = interactionWasm();
  const action = policy.asterCredential(captureWatch, ...interactionText(policy, thread, bearer));
  if (action === 1) asterWatch = undefined;
  if (action === 2) asterWatch = {thread, bearer};
  for (const marker of page.querySelectorAll('[data-stream-bearer], [data-stream-path]')) {
    marker.removeAttribute('data-stream-bearer');
    marker.removeAttribute('data-stream-path');
  }
  return fragment ? page.querySelector(fragment)?.outerHTML ?? null : page.body.innerHTML;
}

async function streamAster(watch, signal, emit) {
  const policy = interactionWasm();
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(asterDeadline)]);
  for (let attempt = 0; policy.asterAttempt(attempt, deadline.aborted); attempt++) {
    if (await readAsterStream(watch, deadline, emit)) return;
    const delay = policy.asterRetryDelay(attempt, deadline.aborted);
    if (delay) await new Promise(resolve => setTimeout(resolve, delay));
  }
  if (!signal.aborted) emit({type: 'stream-error', thread: watch.thread});
}

async function readAsterStream({thread, bearer}, signal, emit) {
  const policy = interactionWasm();
  const destination = localUrl(asterEventsPath);
  destination.searchParams.set('thread', thread);
  try {
    const response = await fetch(destination, {
      headers: {...requestHeaders(bearer), Accept: 'text/event-stream'},
      credentials: 'omit', redirect: 'error', cache: 'no-store', signal,
    });
    const mediaType = (response.headers.get('content-type') ?? '').split(';', 1)[0].trim().toLowerCase();
    if (!policy.asterResponse(response.ok, ...interactionText(policy, mediaType), Boolean(response.body))) {
      throw new Error('Ask Aster stream unavailable');
    }
    const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
    try {
      let pending = '';
      let endedWithCR = false;
      for (;;) {
        const {value, done} = await reader.read();
        if (done || signal.aborted) break;
        if (!value) continue;
        const [start, carryCR] = policy.asterChunkBoundary(endedWithCR, value.startsWith('\n'), value.endsWith('\r'));
        endedWithCR = Boolean(carryCR);
        pending += value.slice(start).replace(/\r\n?/g, '\n');
        for (;;) {
          const boundary = pending.indexOf('\n\n');
          const buffer = policy.asterBuffer(boundary, pending.length);
          if (buffer === 0) break;
          if (buffer === 2) throw new Error('Ask Aster stream event exceeds its limit');
          const lines = pending.slice(0, boundary).split('\n');
          pending = pending.slice(boundary + 2);
          let name;
          const payload = [];
          for (const line of lines) {
            const colon = line.indexOf(':');
            const end = colon === -1 ? line.length : colon;
            const field = line.slice(0, end);
            const [kind, skip] = policy.asterField(...interactionText(policy, field), colon !== -1,
              line[end + 1] === ' ', name !== undefined);
            if (kind === 1) name = line.slice(end + skip);
            if (kind === 2) payload.push(line.slice(end + skip));
          }
          const action = policy.asterFrameKind(...interactionText(policy, name ?? ''));
          if (action === 0) continue;
          const data = JSON.parse(payload.join('\n'));
          const observed = typeof data?.thread === 'string' ? data.thread : '';
          const dispatch = policy.asterDispatchFrame(action, ...interactionText(policy, thread, observed));
          if (dispatch === 0) throw new Error('Ask Aster stream thread mismatch');
          emit({type: 'stream', thread, name, data});
          if (dispatch === 2) return true;
        }
      }
    } finally {
      await reader.cancel().catch(() => {});
    }
  } catch {
    // The subscription handles bounded retries and final error delivery.
  }
  return false;
}

function observeAsterStream(binding, dispatchLabel) {
  if (asterSubscription) throw new Error('Ask Aster stream is already registered');
  const policy = interactionWasm();
  let current;
  let controller;
  const emit = event => {
    const existing = queue.find(entry => entry.message.binding === binding);
    const action = policy.asterQueueAction(Boolean(existing), !existing && Boolean(queueHasRoom()));
    if (action === 1) existing.message.event = event;
    else if (action === 2) queue.push({label: dispatchLabel ?? 'Aster stream', message: {binding, event}});
    else {
      report('Browser event queue is full');
      return;
    }
    flush();
  };
  const refresh = () => {
    const marker = document.querySelector('#aster-content #aster-live, #aster-panel-content #aster-live');
    const sameMarker = marker === current;
    const watch = asterWatch;
    const action = policy.asterWatchAction(sameMarker, Boolean(watch),
      ...interactionText(policy, watch?.thread ?? '', marker?.getAttribute('data-thread') ?? ''));
    if (action === 0) return;
    current = marker;
    controller?.abort();
    if (action === 1) return;
    asterWatch = undefined;
    controller = new AbortController();
    void streamAster(watch, controller.signal, emit);
  };
  const observer = new MutationObserver(refresh);
  observer.observe(document.documentElement, {childList: true, subtree: true});
  asterSubscription = observer;
  cleanups.push(() => {
    observer.disconnect();
    controller?.abort();
    asterWatch = undefined;
    asterSubscription = undefined;
  });
  refresh();
  return true;
}

let exitRequest;

// Place an overlay at a viewport point or beneath a trigger.
let overlaySheet;

function overlayPlacement(overlay, position) {
  const anchor = position.anchor == null ? null : target(position.anchor);
  if (anchor !== null && !(anchor instanceof Element)) throw new Error('Expected a dialog anchor element');
  if (anchor === null && !(Number.isFinite(position.x) && Number.isFinite(position.y))) {
    throw new Error('Expected finite dialog coordinates');
  }
  return () => {
    const trigger = anchor?.getBoundingClientRect();
    const {width, height} = overlay.getBoundingClientRect();
    const {clientWidth, clientHeight} = document.documentElement;
    const [left, top] = interactionWasm().overlayPlacement(Boolean(trigger),
      trigger?.left ?? position.x, trigger ? 0 : position.y, trigger?.top ?? 0, trigger?.bottom ?? 0,
      width, height, clientWidth, clientHeight);
    if (!overlaySheet) {
      overlaySheet = new CSSStyleSheet();
      overlaySheet.replaceSync(encounterOverlayCss);
      document.adoptedStyleSheets.push(overlaySheet);
    }
    overlay.toggleAttribute('data-encounter-positioned', true);
    overlay.style.setProperty('--encounter-overlay-left', `${left}px`);
    overlay.style.setProperty('--encounter-overlay-top', `${top}px`);
  };
}

const countdowns = new Map();
const countdownAnchors = new Map();
let countdownPolicy;

function countdownWasm() {
  if (countdownPolicy === undefined) {
    const module = loadBrowserWasm(typeof encounterCountdownWasm === 'string' ? encounterCountdownWasm : null);
    countdownPolicy = selectBrowserPolicy(module, 'countdown');
  }
  if (!countdownPolicy) throw new Error('This release requires the browser Wasm countdown');
  return countdownPolicy;
}

function bindCountdown({ref, control, surface, container, choices, storageKey, binding, dispatchLabel}) {
  const policy = countdownWasm();
  const array = Array.isArray(choices);
  const [refText, storageText] = interactionText(policy, typeof ref === 'string' ? ref : '',
    typeof storageKey === 'string' ? storageKey : '');
  if (!policy.bindingAllowed(refText, countdowns.has(ref), countdowns.size, storageText, array, array ? choices.length : 0)) {
    throw new Error('Invalid browser countdown');
  }
  const caption = target(ref);
  const preference = target(control);
  const panel = target(surface);
  const desktop = target(container);
  const correctTypes = preference instanceof HTMLSelectElement && caption instanceof HTMLElement &&
    panel instanceof HTMLElement && desktop instanceof HTMLElement;
  if (!policy.controlsAllowed(correctTypes && panel.contains(caption), correctTypes && panel.contains(preference),
    correctTypes && desktop.contains(panel), correctTypes)) {
    throw new Error('Invalid browser countdown controls');
  }
  const options = new Map();
  let defaultChoice;
  for (const {value, milliseconds, default: preferred} of choices) {
    const whole = Number.isSafeInteger(milliseconds);
    if (!policy.choiceAllowed(...interactionText(policy, typeof value === 'string' ? value : ''),
      options.has(value), whole, whole ? milliseconds : 0,
      Boolean(preferred) && defaultChoice !== undefined)) {
      throw new Error('Invalid browser countdown choice');
    }
    options.set(value, milliseconds);
    if (preferred) defaultChoice = value;
  }
  const presentOptions = new Set([...preference.options].map(option => option.value));
  if (!policy.optionsReady(defaultChoice !== undefined, [...options.keys()].every(value => presentOptions.has(value)))) {
    throw new Error('Missing browser countdown options');
  }
  const saved = effects['storage.read']({key: storageKey, maxLength: 32}).value;
  const setChoice = value => {
    const current = preference.value;
    const [useCandidate, update] = policy.preferenceChoice(options.has(value), current === value, current === defaultChoice);
    const choice = useCandidate ? value : defaultChoice;
    if (update) preference.value = choice;
    return choice;
  };
  setChoice(saved);
  let timer;
  let bound = true;
  let requests = 0;
  const clock = {
    begin() {
      requests++;
      if (policy.refreshAnchor(bound, active?.countdown === clock)) countdownAnchors.set(ref, performance.now());
      tick();
      return () => {
        requests--;
        tick();
      };
    },
  };
  function tick() {
    clearTimeout(timer);
    if (!policy.tickVisible(bound, panel.hidden, desktop.hidden)) return;
    const selected = options.get(preference.value);
    const interval = policy.selectedInterval(selected !== undefined, selected ?? 0, options.get(defaultChoice));
    const now = performance.now();
    const anchor = countdownAnchors.get(ref);
    const idle = Boolean(canPoll());
    const [captionSeconds, dispatch, nextAnchor, delay, label, suffix, showSeconds] =
      policy.tick(anchor !== undefined, anchor ?? 0, interval, now, requests, active?.countdown === clock, idle);
    const text = interactionResultText(policy, label) +
      (showSeconds ? captionSeconds + interactionResultText(policy, suffix) : '');
    if (caption.textContent !== text) caption.textContent = text;
    if (dispatch) {
      countdownAnchors.set(ref, nextAnchor);
      queue.push({label: dispatchLabel, countdown: clock, message: {binding, event: {type: 'countdown'}}});
      flush();
    }
    if (delay) timer = setTimeout(tick, delay);
  }
  const changed = () => {
    effects['storage.write']({key: storageKey, value: setChoice(preference.value)});
    tick();
  };
  const visibility = new MutationObserver(tick);
  for (const element of [panel, desktop]) visibility.observe(element, {attributes: true, attributeFilter: ['hidden']});
  preference.addEventListener('change', changed);
  countdowns.set(ref, clock);
  cleanups.push(() => {
    bound = false;
    clearTimeout(timer);
    visibility.disconnect();
    preference.removeEventListener('change', changed);
    countdowns.delete(ref);
  });
  tick();
  return true;
}

const activeGroups = new Map();

function activateMember(group, member) {
  const sameMember = group.current === member;
  const hasPrevious = Boolean(group.current);
  const policy = interactionWasm();
  const writes = policy.activate(sameMember, hasPrevious);
  if (writes === 0) return 0;
  if (writes === 2) group.current.removeAttribute('data-active');
  member.setAttribute('data-active', 'true');
  group.current = member;
  return writes;
}

function bindActiveGroup({ref, members}) {
  const policy = interactionWasm();
  const array = Array.isArray(members);
  if (!policy.activeGroupAdmission(typeof ref === 'string', activeGroups.has(ref), activeGroups.size,
    array, array ? members.length : 0)) {
    throw new Error('Invalid browser active group');
  }
  const container = target(ref);
  const entries = new Map();
  const elements = new Set();
  for (const member of members) {
    if (!policy.activeMemberId(...interactionText(policy, typeof member === 'string' ? member : ''))) {
      throw new Error('Expected an active group member ID');
    }
    const element = target(member);
    if (!policy.activeMemberAdmission(element instanceof HTMLElement, element.parentElement === container, elements.has(element))) {
      throw new Error('Expected distinct direct children in the active group');
    }
    entries.set(member, element);
    elements.add(element);
  }
  const group = {entries, current: null};
  for (const element of elements) {
    const action = policy.activeMemberInitial(element.getAttribute('data-active') === 'true', Boolean(group.current));
    if (action === 1) group.current = element;
    if (action === 2) element.removeAttribute('data-active');
  }
  const activate = event => {
    let member = event.target;
    while (member && member.parentElement !== container) member = member.parentElement;
    if (elements.has(member)) activateMember(group, member);
  };
  for (const type of ['pointerdown', 'focusin']) container.addEventListener(type, activate);
  activeGroups.set(ref, group);
  cleanups.push(() => {
    for (const type of ['pointerdown', 'focusin']) container.removeEventListener(type, activate);
    activeGroups.delete(ref);
  });
  return true;
}

function bindAppDescriptions({ref}) {
  const policy = interactionWasm();
  const root = target(ref);
  const cards = root.querySelectorAll('[data-app-card]');
  if (!policy.descriptionCards(cards.length)) throw new Error('Expected at most 128 app cards');
  const descriptions = new Map();
  const listeners = new AbortController();
  const options = {signal: listeners.signal};
  const timers = [];
  for (const card of cards) {
    const summary = card.querySelector(':scope > .app-link .app-card-summary');
    const button = card.querySelector(':scope > .app-card-description-button[popovertarget]');
    const panel = card.querySelector(':scope > .app-card-description-panel[popover=auto]');
    if (policy.descriptionBinding(Boolean(summary), button instanceof HTMLButtonElement,
      Boolean(panel && panel.id === button?.getAttribute('popovertarget')))) {
      descriptions.set(summary, {card, button, panel});
      let preview = false;
      let timer;
      const cancel = () => clearTimeout(timer);
      const transition = (kind, event) => {
        cancel();
        const [action, delay, nextPreview] = policy.descriptionTransition(...interactionText(policy, kind),
          preview, event?.pointerType === 'mouse', panel.matches(':popover-open'), button.hidden);
        if (delay) {
          timer = setTimeout(() => transition(action === 1 ? 'show' : 'hide'), delay);
          return;
        }
        if (action === 1) panel.showPopover({source: button});
        if (action === 2) panel.hidePopover();
        if (action === 3) event.preventDefault();
        if (action !== 2) preview = Boolean(nextPreview);
      };
      const leave = () => transition('leave');
      button.addEventListener('pointerenter', event => transition('enter', event), options);
      button.addEventListener('pointerleave', leave, options);
      panel.addEventListener('pointerenter', cancel, options);
      panel.addEventListener('pointerleave', leave, options);
      panel.addEventListener('beforetoggle', event => {
        if (event.newState === 'closed') transition('closed');
      }, options);
      button.addEventListener('click', event => transition('click', event), options);
      timers.push(cancel);
    }
  }
  const observer = new ResizeObserver(entries => {
    for (const {target: summary} of entries) {
      const {button, panel} = descriptions.get(summary);
      const action = policy.descriptionLayout(summary.clientHeight, summary.scrollHeight, panel.matches(':popover-open'));
      if (action === 0) continue;
      if (action === 3) panel.hidePopover();
      button.hidden = action !== 2;
    }
  });
  for (const summary of descriptions.keys()) observer.observe(summary);
  cleanups.push(() => {
    observer.disconnect();
    listeners.abort();
    for (const cancel of timers) cancel();
  });
  return true;
}

function markReveal(timing, port, args) {
  if (!timing?.reveal || timing.revealed !== undefined) return;
  const policy = interactionWasm();
  if (policy.markReveal(...interactionText(policy, typeof port === 'string' ? port : ''), args.ref === timing.reveal,
    Boolean(args.open), args.name === 'hidden' && args.value === false)) {
    timing.revealed = performance.now();
  }
}

function runBatch({steps}) {
  const policy = interactionWasm();
  const array = Array.isArray(steps);
  if (!policy.batchLength(array, array ? steps.length : 0)) {
    throw new Error('Expected 1 to 64 browser batch steps');
  }
  const observations = new Map();
  for (const {port, args, save, unless} of steps) {
    const kind = policy.batchPort(...interactionText(policy, typeof port === 'string' ? port : ''));
    const record = Boolean(args && typeof args === 'object' && !Array.isArray(args));
    const action = policy.batchStep(kind, record, unless != null, observations.get(unless) ?? 0,
      save != null, ...interactionText(policy, typeof save === 'string' ? save : ''), observations.has(save));
    if (action === 1) throw new Error('Invalid browser batch step');
    if (action === 2) throw new Error('Invalid browser batch observation');
    if (save != null) observations.set(save, kind);
  }
  const results = Object.create(null);
  for (const {port, args, save, unless} of steps) {
    if (!policy.batchExecute(unless != null, unless != null && Boolean(results[unless]))) continue;
    const value = effects[port](args);
    markReveal(active?.timing, port, args);
    if (save != null) results[save] = value;
  }
  return results;
}

async function refreshAssurance() {
  const dialog = document.querySelector('#mobile-assurance[open]');
  const warnings = dialog?.querySelector('#mobile-performance-warnings > section');
  const history = dialog?.querySelector('#notes-assurance-history > section');
  if (!warnings || !history) return {historyStatus:null};
  if (!history.dataset.status) {
    dialog.addEventListener('close', () => {
      warnings.hidden = true;
      history.hidden = true;
    });
  }
  const [, status] = await Promise.all([
    refreshAssuranceList(warnings, '/workspace/platform/performance-badge', true),
    refreshAssuranceList(history, '/identity-management/?view=assurance-program', false),
  ]);
  if (history.dataset.status === String(status)) return {historyStatus:null};
  history.dataset.status = String(status);
  return {historyStatus:status};
}

function formatFileSizes({bytes}) {
  const policy = interactionWasm();
  const array = Array.isArray(bytes);
  if (!policy.fileSizeBatch(array, array ? bytes.length : 0)) throw new Error('Invalid file byte sizes');
  const whole = new Intl.NumberFormat(navigator.languages, {maximumFractionDigits: 0});
  const decimal = new Intl.NumberFormat(navigator.languages, {maximumFractionDigits: 1});
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  return Object.fromEntries([...new Set(bytes)].map(value => {
    const safe = Number.isSafeInteger(value);
    const [valid, scaled, unit] = policy.fileSize(safe, safe ? value : 0);
    if (!valid) throw new Error('Invalid file byte sizes');
    const long = `${whole.format(value)} B`;
    return [value, {long, short: unit === 0 ? long : `${decimal.format(scaled)} ${units[unit]}`}];
  }));
}

function bindClockDisplay() {
  const fields = [...document.querySelectorAll("time[data-clock]")];
  if (!fields.length) return;
  const formats = new Map([
    ['time', new Intl.DateTimeFormat(undefined, {hour: 'numeric', minute: '2-digit'})],
    ['date', new Intl.DateTimeFormat(undefined, {dateStyle: 'short'})],
    ['full', new Intl.DateTimeFormat(undefined, {dateStyle: 'full'})],
  ]);
  if (fields.length > 12 || fields.some(field => !formats.has(field.dataset.clock))) return;
  const update = () => {
    const now = new Date();
    for (const field of fields) {
      field.textContent = formats.get(field.dataset.clock).format(now);
      field.dateTime = now.toISOString();
    }
    setTimeout(update, 60_000 - now.getTime() % 60_000);
  };
  update();
}

function markupRows(html, {row, fields}) {
  const entries = Object.entries(fields);
  if (typeof html !== 'string' || html.length > 1_000_000 || entries.length > 8) {
    throw new Error('Markup projection exceeds its limit');
  }
  const page = new DOMParser().parseFromString(html, 'text/html');
  return Array.from(page.querySelectorAll(row)).slice(0, 100).map(node =>
    Object.fromEntries(entries.map(([name, {selector, attr}]) => {
      const element = selector ? node.querySelector(selector) : node;
      const value = attr ? element?.getAttribute(attr) : element?.textContent;
      return [name, (value ?? '').trim().slice(0, 256)];
    })));
}

async function storageRecord(key, mode, update) {
  const database = await new Promise((resolve, reject) => {
    const request = indexedDB.open('encounter-storage', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('records');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction('records', mode);
      const store = transaction.objectStore('records');
      const request = store.get(key);
      let result;
      request.onsuccess = () => { result = update(store, request.result ?? null); };
      transaction.oncomplete = () => resolve(result);
      transaction.onabort = () => reject(transaction.error);
    });
  } finally {
    database.close();
  }
}

const effects = {
  'browser.preflight': ({reads, probes, when}) => {
    const policy = interactionWasm();
    const array = Array.isArray(reads);
    if (!policy.bootBatchAllowed(booting, array, array ? reads.length : 0)) {
      throw new Error('Invalid browser preflight');
    }
    const detected = Object.fromEntries(Object.entries(probes ?? {}).map(([name, selector]) =>
      [name, Boolean(document.querySelector(selector))]));
    if (when && !document.querySelector(when)) return {probes: detected, enabled: false};
    const plain = policy.preflightPlain(Boolean(startup.location.search), Boolean(startup.location.hash),
      location.href === startup.location.href);
    const values = reads.map(({port, args}) => {
      const action = policy.preflightRead(...interactionText(policy, typeof port === 'string' ? port : ''), plain);
      if (action === 0) throw new Error('Invalid browser preflight observation');
      if (action === 1) return {};
      if (action === 2) return {value: receiveStartup(args, false)};
      if (action === 3) return {value: effects[port](args)};
      try { return {value: effects[port](args)}; }
      catch { return {}; } // Optional elements may be absent on this surface.
    });
    return probes || when ? {probes: detected, enabled: true, values} : values;
  },
  'browser.bootEffects': async ({steps, next}) => {
    const policy = interactionWasm();
    const array = Array.isArray(steps);
    if (!policy.bootBatchAllowed(booting, array, array ? steps.length : 0)) {
      throw new Error('Invalid browser boot effects');
    }
    try {
      for (const {effect, args, expected} of steps) {
        const action = policy.deferredBootEffect(...interactionText(policy, typeof effect === 'string' ? effect : ''));
        if (action === 0) throw new Error('Unsupported deferred browser effect');
        if (action === 1) {
          const actual = receiveStartup(args);
          if (!policy.bootStartupMatches(actual.first === expected?.first, actual.path === expected?.path,
            actual.hadInput, Boolean(actual.hash), Object.keys(actual.fields).length > 0)) {
            throw new Error('Browser startup changed after preflight');
          }
          continue;
        }
        effects[effect](args);
      }
    } catch (error) {
      return {setupError: String(error.message ?? error)};
    }
    const effect = typeof next?.effect === 'string' ? next.effect : '';
    const followup = policy.followupBootEffect(...interactionText(policy, effect),
      Boolean(next), Object.hasOwn(effects, effect));
    if (followup === 0) return {value: true};
    if (followup === 1) {
      throw new Error('Unsupported browser boot effect');
    }
    return {value: await effects[effect](next.args)};
  },
  'browser.startup': receiveStartup,
  'browser.batch': runBatch,
  'browser.activeGroup': bindActiveGroup,
  'browser.countdown': bindCountdown,
  'browser.formatFileSizes': formatFileSizes,
  'browser.appDescriptions': bindAppDescriptions,
  'browser.activate': ({group: ref, member}) => {
    const group = activeGroups.get(ref);
    const element = group?.entries.get(member);
    if (!element) throw new Error('Unknown browser active group member');
    const writes = activateMember(group, element);
    const timing = active?.timing;
    if (timing) timing.activationWrites = (timing.activationWrites ?? 0) + writes;
    return true;
  },
  'browser.performance': args => {
    if (Object.keys(args).some(key => key !== 'id')) throw new Error('Invalid browser performance request');
    if (args.id !== undefined) {
      const policy = interactionWasm();
      if (!policy.launchId(...interactionText(policy, typeof args.id === 'string' ? args.id : ''))) {
        throw new Error('Invalid launch ID');
      }
      return recentTimings.find(timing => timing.id === args.id) ?? null;
    }
    const policy = interactionWasm();
    const now = Date.now();
    return recentTimings.map(({recordedAt, detail, ...timing}) =>
      ({...timing, ageSeconds: policy.timingAge(now, recordedAt)}));
  },
  'state.get': ({key}) => documentState.get(key)?.value ?? null,
  'state.set': ({key, value = null}) => {
    const policy = interactionWasm();
    const text = typeof key === 'string';
    const keyLength = text ? key.length : 0;
    if (!policy.documentStateKey(text, keyLength)) throw new Error('Invalid document state key');
    const previous = documentState.get(key);
    const remove = value === null;
    const valueLength = remove ? 0 : JSON.stringify(value).length;
    const [total, allowed, size] = policy.documentStateAdmission(documentStateSize, previous?.size ?? 0,
      keyLength, valueLength, remove, documentState.size, Boolean(previous));
    if (!allowed) {
      throw new Error('Document state capacity');
    }
    if (size) documentState.set(key, {value, size});
    else documentState.delete(key);
    documentStateSize = total;
    return true;
  },

  'storage.read': ({key, maxLength = 65536, scope}) => {
    try {
      const policy = interactionWasm();
      const value = browserStorage(policy, scope).getItem(key);
      const limit = value === null ? 0 : Number(maxLength);
      // Preserve the browser comparison for unbounded and nonnumeric limits.
      const length = value?.length ?? 0;
      const bound = Number.isFinite(limit) ? limit : limit === -Infinity ? -1 : length;
      return policy.storageReadAllowed(value !== null, length, bound)
        ? {ok: true, value} : {ok: false, value: null};
    } catch { return {ok: false, value: null}; }
  },
  'storage.write': ({key, value, scope}) => {
    if (typeof value !== 'string') throw new Error('Storage requires text');
    try { browserStorage(interactionWasm(), scope).setItem(key, value); return {ok: true}; }
    catch { return {ok: false}; }
  },
  'storage.readRecord': async ({key, maxLength = 65536}) => {
    if (typeof key !== 'string' || !Number.isSafeInteger(maxLength) || maxLength < 0) {
      throw new Error('Invalid storage record request');
    }
    try {
      return await storageRecord(key, 'readonly', (_, value) =>
        value === null || (typeof value === 'string' && value.length <= maxLength)
          ? {ok: true, value} : {ok: false, value: null});
    } catch { return {ok: false, value: null}; }
  },
  'storage.compareAndSet': async ({key, expected, value}) => {
    if (typeof key !== 'string' || (expected !== null && typeof expected !== 'string') || typeof value !== 'string') {
      throw new Error('Invalid storage comparison');
    }
    try {
      return await storageRecord(key, 'readwrite', (store, current) => {
        if (current !== expected) return {ok: false};
        store.put(value, key);
        return {ok: true};
      });
    } catch { return {ok: false}; }
  },
  'storage.remove': ({key}) => {
    try { localStorage.removeItem(key); return {ok: true}; }
    catch { return {ok: false}; }
  },
  'dom.exists': ({selector}) => Boolean(document.querySelector(selector)),
  'browser.on': ({ref, event, binding, preventDefault, preventKeys, delegate, outside, unmodified, milliseconds, timing, reveal, dispatchLabel, backgroundSession, initialSession}) => {
    const policy = interactionWasm();
    const trigger = policy.workspaceObservationTrigger(...interactionText(policy,
      typeof ref === 'string' ? ref : '', typeof event === 'string' ? event : ''), booting, backgroundSession === true);
    if (trigger === 3) throw new Error('Invalid workspace access trigger');
    if (trigger === 4) throw new Error('Invalid workspace session trigger');
    if (trigger === 1) {
      const controller = new AbortController();
      cleanups.push(() => controller.abort());
      void observeWorkspaceAccess(binding, dispatchLabel, controller);
      return true;
    }
    if (trigger === 2) {
      const refresh = () => {
        if (policy.sessionObservation(false, booting, leaving, socket?.readyState === WebSocket.OPEN)) {
          void observeWorkspaceSession(binding, dispatchLabel, event);
        }
      };
      window.addEventListener(event, refresh);
      cleanups.push(() => window.removeEventListener(event, refresh));
      if (initialSession === true && policy.sessionObservation(true, booting, leaving, socket?.readyState === WebSocket.OPEN)) {
        void observeWorkspaceSession(binding, dispatchLabel, 'startup');
      }
      return true;
    }
    if (timing != null) {
      const text = typeof timing === 'string';
      if (!policy.timingLabelAllowed(event === 'click', text, text ? timing.length : 0)) {
        throw new Error('Invalid browser timing label');
      }
    }
    if (reveal != null) {
      if (!policy.timingTarget(...interactionText(policy, typeof reveal === 'string' ? reveal : ''))) {
        throw new Error('Invalid browser timing target');
      }
    }
    if (event === 'interval') {
      const whole = Number.isSafeInteger(milliseconds);
      if (!interactionWasm().intervalAllowed(whole, whole ? milliseconds : 0)) {
        throw new Error('Browser interval outside the supported range');
      }
      const scoped = policy.intervalSelector(...interactionText(policy, typeof ref === 'string' ? ref : ''), ref === null);
      if (scoped) document.querySelector(ref);
      const timer = setInterval(() => {
        if (!canPoll()) return;
        const visible = scoped && [...document.querySelectorAll(ref)].some(node => node.checkVisibility());
        if (!policy.intervalDispatch(scoped, Boolean(visible))) return;
        queue.push({label: dispatchLabel ?? 'Interval', message: {binding, event: {type: 'interval'}}});
        flush();
      }, milliseconds);
      cleanups.push(() => clearInterval(timer));
      return true;
    }
    const node = target(ref);
    const delegated = typeof delegate === 'string';
    const handler = observation => {
      const excluded = typeof outside === 'string' && Boolean(observation.target?.closest?.(outside));
      const matched = delegated && !excluded ? observation.target?.closest?.(delegate) : null;
      const withinScope = Boolean(matched && (!(node instanceof Element) || node.contains(matched)));
      const modified = Boolean(observation.metaKey || observation.ctrlKey || observation.shiftKey || observation.altKey);
      const preventKey = Array.isArray(preventKeys) && preventKeys.includes(observation.key);
      const [prevent, dispatch] = policy.eventAdmission(excluded, delegated, withinScope, unmodified === true,
        observation.button === 0, modified, observation.defaultPrevented, preventDefault === true, preventKey,
        Boolean(reconnectEnabled && booting));
      if (prevent) observation.preventDefault();
      if (!dispatch) return;
      const enqueued = timing == null ? undefined : performance.now();
      const measurement = timing == null ? undefined : {
        label: timing, reveal, enqueued, started: Math.max(0, Math.min(enqueued, observation.timeStamp)),
        requests: 0, responseMs: 0, requestMs: 0, status: null, outcome: 'Completed',
        effects: [], browserMs: 0, omittedEffects: 0, blockers: [], blockedMs: 0, omittedBlockers: 0,
      };
      if (!queueHasRoom()) {
        recordTiming(measurement, 'Queue full');
        report('Browser event queue is full');
        return;
      }
      queue.push({label: dispatchLabel ?? timing ?? event, timing: measurement, message: {binding, matched: describe(matched), event: {
        type: observation.type, key: observation.key ?? '', code: observation.code ?? '', shiftKey: !!observation.shiftKey,
        timeStamp: observation.timeStamp, clientX: observation.clientX ?? 0,
        clientY: observation.clientY ?? 0, target: describe(observation.target),
      }}});
      flush();
    };
    node.addEventListener(event, handler);
    cleanups.push(() => node.removeEventListener(event, handler));
    return true;
  },
  'browser.onMany': ({bindings}) => {
    const before = cleanups.length;
    try {
      for (const binding of bindings) effects['browser.on'](binding);
    } catch (error) {
      for (const cleanup of cleanups.splice(before)) cleanup();
      throw error;
    }
    return true;
  },
  'browser.formFields': ({ref}) => {
    const form = target(ref);
    if (!(form instanceof HTMLFormElement)) throw new Error('Expected an observed form');
    const fields = Object.create(null);
    const policy = interactionWasm();
    let count = 0;
    let size = 0;
    for (const [name, value] of new FormData(form)) {
      const text = typeof value === 'string';
      const [action, nextSize] = policy.formField(...interactionText(policy, name), name.length,
        text, text ? value.length : 0, Object.hasOwn(fields, name), count, size);
      if (action === 1) throw new Error('Expected unique text form fields');
      if (action === 2) throw new Error('Form exceeds the observation limit');
      count++;
      size = nextSize;
      fields[name] = value;
    }
    return fields;
  },
  'browser.property': ({ref, name}) => {
    const value = target(ref)[name];
    if (value !== null && !['string', 'number', 'boolean'].includes(typeof value)) {
      throw new Error('Nonportable DOM property observation');
    }
    return value;
  },
  'browser.write': ({ref, name, value}) => {
    const policy = interactionWasm();
    if (!policy.domWriteProperty(...interactionText(policy, typeof name === 'string' ? name : ''))) {
      throw new Error('Undeclared DOM property effect');
    }
    target(ref)[name] = value;
    return true;
  },
  'browser.content': ({ref, html}) => {
    target(ref).innerHTML = html;
    return true;
  },
  'browser.copyText': ({trigger, source, status}) => {
    const policy = interactionWasm();
    const validControl = ref => typeof ref === 'string' &&
      policy.clipboardControl(...interactionText(policy, ref));
    if (![trigger, source, status].every(validControl)) throw new Error('Expected clipboard control IDs');
    const copy = async event => {
      if (!policy.clipboardTrigger(event.isTrusted, Boolean(event.target.closest?.(trigger)))) return;
      const field = document.querySelector(source);
      const feedback = document.querySelector(status);
      const textarea = field instanceof HTMLTextAreaElement ? field : null;
      const text = textarea?.value ?? '';
      if (!policy.clipboardSelection(Boolean(textarea?.readOnly), Boolean(feedback), text.length)) return;
      let copied = false;
      try {
        await navigator.clipboard.writeText(text);
        copied = true;
      } catch {
        // The selected textarea provides the manual browser copy path.
      }
      textarea.hidden = copied;
      if (!copied) {
        textarea.focus();
        textarea.select();
      }
      const message = policy.clipboardNotice(copied);
      feedback.textContent = interactionResultText(policy, message);
    };
    document.addEventListener('click', copy);
    cleanups.push(() => document.removeEventListener('click', copy));
    return true;
  },
  'browser.focus': ({ref, preventScroll}) => {
    target(ref).focus({preventScroll: Boolean(preventScroll)});
    return true;
  },
  'browser.popover': ({ref, open, position}) => {
    const element = target(ref);
    if (!(element instanceof HTMLElement) || element.parentElement !== document.body ||
        element.popover !== 'auto' || typeof open !== 'boolean') {
      throw new Error('Expected a document-level auto popover');
    }
    if (open) {
      const place = overlayPlacement(element, position);
      if (!element.matches(':popover-open')) element.showPopover();
      place();
    } else if (element.matches(':popover-open')) {
      element.hidePopover();
    }
    return true;
  },
  'browser.dialog': ({ref, open, close, content, position}) => {
    const dialog = target(ref);
    if (!(dialog instanceof HTMLDialogElement) || typeof open !== 'boolean') throw new Error('Expected a browser dialog');
    if (position != null && (dialog.parentElement !== document.body || dialog.hasAttribute('data-encounter-nonmodal'))) {
      throw new Error('A positioned dialog must be a document-level modal');
    }
    const placement = position == null ? null : overlayPlacement(dialog, position);
    if (content != null) {
      const body = target(content.ref);
      if (body === dialog || !dialog.contains(body) || typeof content.html !== 'string') {
        throw new Error('Expected content inside the browser dialog');
      }
      body.innerHTML = content.html;
    }
    if (open && !dialog.open) {
      if (close != null) {
        if (typeof close !== 'string') throw new Error('Expected a selector for the dialog to close');
        const previous = document.querySelector(close);
        if (previous !== null && !(previous instanceof HTMLDialogElement)) throw new Error('Expected a dialog to close');
        previous?.close();
      }
      dialog.showModal();
      if (placement) {
        const previous = dialog.getAttribute('style');
        placement();
        dialog.addEventListener('close', () => {
          if (previous === null) dialog.removeAttribute('style');
          else dialog.setAttribute('style', previous);
        }, {once: true});
      }
    }
    if (!open && dialog.open) dialog.close();
    return true;
  },
  'browser.attribute': ({ref, name, value}) => {
    const element = target(ref);
    const policy = interactionWasm();
    const attribute = typeof name === 'string' ? name : '';
    const action = policy.domAttribute(...interactionText(policy, attribute),
      element instanceof HTMLAnchorElement, element instanceof HTMLImageElement, value === 'page', value === null,
      typeof value === 'boolean', value === true);
    if (action === 0) throw new Error('Undeclared browser attribute');
    if (action === 5 && !admitPngSource(policy, value)) throw new Error('Expected a bounded PNG data URL');
    if (action === 1) element.removeAttribute(name);
    if (action === 2 || action === 5) element.setAttribute(name, value);
    if (action === 3) element.setAttribute(name, String(value));
    if (action === 4) element.setAttribute(name, 'true');
    return true;
  },
  'browser.guard': ({active, allow, within}) => {
    if (![active, allow, within].every(value => typeof value === 'string' && value.length <= 512)) {
      throw new Error('Expected bounded browser guard selectors');
    }
    for (const selector of [active, allow, within]) document.querySelector(selector);
    const handler = event => {
      if (!document.querySelector(active)) return;
      const control = event.target.closest?.(within);
      if (!control || (event.type === 'click' && control.closest(allow))) return;
      event.preventDefault();
      event.stopImmediatePropagation();
    };
    for (const event of ['click', 'auxclick', 'contextmenu']) document.addEventListener(event, handler, true);
    cleanups.push(() => {
      for (const event of ['click', 'auxclick', 'contextmenu']) document.removeEventListener(event, handler, true);
    });
    return true;
  },
  'browser.target': ({ref}) => {
    const element = target(ref);
    const form = element instanceof HTMLFormElement;
    if (!form && !(element instanceof HTMLAnchorElement)) throw new Error('Expected a browser form or link');
    const url = localUrl(form ? element.action : element.href);
    return {path: url.pathname + url.search, pathname: url.pathname, method: form ? element.method.toUpperCase() : 'GET'};
  },
  'browser.location': () => ({path: location.pathname, search: location.search, hash: location.hash}),
  'browser.navigate': ({path, historyOnly}) => {
    const destination = sameOriginPath(path);
    if (historyOnly) history.replaceState(null, '', destination);
    else setTimeout(() => location.assign(destination), 0);
    return true;
  },
  'browser.asterStream': ({binding, dispatchLabel}) => observeAsterStream(binding, dispatchLabel),
  'browser.assuranceRefresh': refreshAssurance,
  'browser.request': async ({path, method = 'GET', bearer, form, fragment, query, rows}) => {
    const destination = localUrl(sameOriginPath(path));
    const policy = interactionWasm();
    const requestMethod = typeof method === 'string' ? method : '';
    const routeFor = path => policy.requestRoute(...interactionText(policy, requestMethod, path));
    const initialRoute = routeFor(destination.pathname);
    if (initialRoute === 1) throw new Error('Unsupported browser request method');
    const normalizedPath = localUrl(decodeURIComponent(destination.pathname)).pathname;
    const route = normalizedPath === destination.pathname ? initialRoute : routeFor(normalizedPath);
    if (route === 2) cancelWorkspaceSession();
    if (route === 3) throw new Error('Ask Aster events require the scoped stream port');
    const headers = requestHeaders(bearer);
    let body;
    if (form) {
      const element = target(form);
      if (!(element instanceof HTMLFormElement)) throw new Error('Expected a browser form');
      const fields = new URLSearchParams(new FormData(element));
      const encoded = fields.toString();
      const mobileOffer = /^\/workspace\/mobile\/pair\/[A-Za-z0-9_-]{16}\/offer$/.test(destination.pathname);
      if (!policy.requestForm(...interactionText(policy, destination.pathname), mobileOffer, encoded.length)) {
        throw new Error('Browser form exceeds the request limit');
      }
      if (method === 'GET') destination.search = encoded;
      else {
        body = fields;
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
      }
    }
    if (query) {
      const fields = Object.entries(query);
      if (!policy.requestQuery(fields.length) || fields.some(([key, value]) => {
        const text = typeof value === 'string';
        return !policy.queryField(...interactionText(policy, key), text, text ? value.length : 0);
      })) throw new Error('Invalid browser query fields');
      for (const [key, value] of fields) destination.searchParams.set(key, value);
    }
    const timing = active?.timing;
    const response = await fetch(destination, {method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(requestDeadline)});
    recordResponse(timing, response.status);
    const text = await boundedResponse(response);
    const action = policy.requestResponse(...interactionText(policy, destination.pathname),
      destination.searchParams.get('view') === 'aster', response.ok, Boolean(asterSubscription), Boolean(fragment));
    const content = action >= 2 ? asterFragment(text, fragment, action === 3)
      : action === 1 ? new DOMParser().parseFromString(text, 'text/html').querySelector(fragment)?.outerHTML ?? null : text;
    const result = {status: response.status, body: content};
    if (rows && method === 'GET' && response.ok && content) result.rows = markupRows(content, rows);
    return result;
  },
  'browser.frontGateStatus': async ({countdown}) => {
    const ports = document.querySelector('meta[name="appdev-ssh-ports-v1"]')?.content;
    const match = /^(\d{4,5}),\d{4,5}$/.exec(ports ?? '');
    const port = Number(match?.[1]);
    const integer = Number.isInteger(port);
    if (!interactionWasm().frontGatePort(integer, String(port) === match?.[1], integer ? port : 0)) {
      throw new Error('The published Front Gate SSH port is unavailable');
    }
    const timing = active?.timing;
    const finish = countdowns.get(countdown)?.begin();
    try {
      const response = await fetch(`http://localhost:${port}/front-gate/status-data`, {
        method: 'GET',
        mode: 'cors',
        credentials: 'omit',
        redirect: 'error',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
        targetAddressSpace: 'loopback',
        signal: AbortSignal.timeout(requestDeadline),
      });
      recordResponse(timing, response.status);
      return {status: response.status, body: response.ok ? await boundedResponse(response) : null};
    } finally {
      finish?.();
    }
  },
  'browser.requestOnExit': ({path, bearer}) => {
    exitRequest = path === null ? undefined : {path: sameOriginPath(path), headers: requestHeaders(bearer)};
    return true;
  },
  'browser.delay': ({milliseconds}) => {
    const integer = Number.isSafeInteger(milliseconds);
    if (!interactionWasm().delayAllowed(integer, integer ? milliseconds : 0)) {
      throw new Error('Browser delay outside the supported interval');
    }
    return new Promise(resolve => setTimeout(() => resolve(true), milliseconds));
  },
  'browser.fileText': ({ref, maxBytes}) => {
    const input = target(ref);
    const fileInput = input instanceof HTMLInputElement && input.type === 'file';
    const file = fileInput ? input.files[0] : undefined;
    const integer = Number.isSafeInteger(maxBytes);
    const action = interactionWasm().fileReadAction(fileInput, integer, integer ? maxBytes : 0, Boolean(file), file?.size ?? 0);
    if (action === 1) throw new Error('Expected a file input and a bounded read');
    if (action === 2) throw new Error('Choose a file within the local import limit');
    return file.text();
  },
  'download.text': ({name, text}) => {
    const url = URL.createObjectURL(new Blob([text], {type: 'text/plain;charset=utf-8'}));
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    return true;
  },
};

window.addEventListener('pagehide', () => {
  leaving = true;
  resumeAfterClose = false;
  clearTimeout(retryTimer);
  clearTimeout(timeoutTimer);
  clearInterval(countdownTimer);
  socket?.close();
  if (!exitRequest) return;
  const {path, headers} = exitRequest;
  exitRequest = undefined;
  fetch(path, {method: 'POST', headers, keepalive: true, redirect: 'manual'}).catch(() => {});
});

window.addEventListener('pageshow', event => {
  const policy = loadInteractionPolicy();
  if (!policy) return;
  const [resume, waitForClose] = policy.historyResume(event.persisted, leaving, Boolean(socket));
  if (!resume) return;
  leaving = false;
  resumeAfterClose = Boolean(waitForClose);
  if (!waitForClose) connect();
});

async function receive(event) {
  const connection = event.currentTarget;
  if (connection !== socket) return;
  const message = JSON.parse(event.data);
  if (message.done) {
    const policy = interactionWasm();
    const [close, ready, status] = policy.bootCompletion(booting, Boolean(reconnectEnabled), Boolean(message.error));
    if (close) {
      const [prefix, showNotice] = policy.startupFailureNotice(Boolean(connectionPanel));
      connectionReason = interactionResultText(policy, prefix) + message.error;
      if (showNotice) report(message.error);
      connection.close();
      return;
    }
    if (active?.resolve) {
      if (message.error) active.reject(new Error(message.error));
      else active.resolve(message.agentResult);
    } else report(message.error);
    recordBlocker(active);
    recordTiming(active?.timing, message.error ? 'Dispatch failed' : null, message.timing);
    active = undefined;
    if (message.agentEnabled) {
      window.encounter = Object.freeze({invoke: agent => new Promise((resolve, reject) => {
        if (!interactionWasm().agentInvocationAllowed(connection === socket, connection.readyState === WebSocket.OPEN, queue.length)) {
          reject(new Error('Browser invocation unavailable'));
          return;
        }
        queue.push({label: 'Browser agent', message: {agent}, resolve, reject});
        flush();
      })});
    }
    if (ready) {
      booting = false;
      retryDelay = firstRetryDelay;
      clearTimeout(timeoutTimer);
      connectionReason = '';
      const readyState = interactionResultText(policy, status);
      connectionStatus(readyState);
      document.documentElement.dataset.encounter = readyState;
    }
    busy = false;
    flush();
    return;
  }
  let reply;
  const timing = active?.timing;
  const previousReveal = timing?.revealed;
  if (timing) timing.activationWrites = null;
  const started = timing ? performance.now() : undefined;
  const policy = interactionWasm();
  const effectName = typeof message.effect === 'string' ? message.effect : '';
  const request = timing && policy.timingEffectRequest(...interactionText(policy, effectName));
  if (request) {
    timing.requests++;
    timing.requestStarted = started;
  }
  try {
    if (!Object.hasOwn(effects, message.effect)) throw new Error('Unsupported browser effect');
    reply = {reply: true, value: await effects[message.effect](message.args)};
    markReveal(timing, message.effect, message.args);
  } catch (error) {
    if (timing) timing.outcome = interactionResultText(policy, policy.timingFailure(Boolean(request)));
    reply = {reply: true, error: String(error.message ?? error)};
  }
  if (timing) {
    const [elapsed, offset, keep, revealed] = policy.timingEffectSample(timing.started, started, performance.now(),
      timing.effects.length, previousReveal !== undefined, timing.revealed !== undefined);
    timing.browserMs += elapsed;
    if (request) timing.requestMs += elapsed;
    if (keep) {
      timing.effects.push({port: message.effect, atMs: Math.round(offset),
        browserMs: Math.round(elapsed), activationWrites: timing.activationWrites,
        revealed: Boolean(revealed), ok: !reply.error,
        status: request && Number.isInteger(reply.value?.status) ? reply.value.status : null});
    } else {
      timing.omittedEffects++;
    }
  }
  if (policy.socketReplyAllowed(connection === socket, connection.readyState === WebSocket.OPEN)) {
    connection.send(JSON.stringify(reply));
  }
}

function disconnected(event) {
  if (event.currentTarget !== socket) return;
  socket = undefined;
  cancelWorkspaceSession();
  for (const cleanup of cleanups.splice(0)) cleanup();
  const fault = new Error('Browser session disconnected');
  active?.reject?.(fault);
  recordBlocker(active);
  recordTiming(active?.timing, 'Disconnected');
  active = undefined;
  for (const pending of queue.splice(0)) {
    pending.reject?.(fault);
    recordTiming(pending.timing, 'Disconnected');
  }
  observations.clear();
  nodeHandles = new WeakMap();
  nextHandle = 0;
  busy = true;
  booting = true;
  clearTimeout(timeoutTimer);
  if (resumeAfterClose) {
    resumeAfterClose = false;
    connect();
    return;
  }
  const policy = interactionWasm();
  const [publish, preserveReason, includeCode, includeSocketReason, prefix, suffix, notice, logNotice] =
    policy.disconnectPlan(leaving, Boolean(connectionReason), Boolean(event.reason), event.code,
      Boolean(connectionPanel), Boolean(reconnectEnabled));
  if (!publish) return;
  const reason = preserveReason ? connectionReason : interactionResultText(policy, prefix) +
    (includeCode ? String(event.code) : '') + interactionResultText(policy, suffix) +
    (includeSocketReason ? event.reason : '');
  const message = interactionResultText(policy, notice);
  if (message) report(message, Boolean(logNotice));
  scheduleRetry(reason);
}

function connect() {
  const policy = interactionWasm();
  const [open, status] = policy.connectionOpen(leaving, Boolean(socket));
  if (!open) return;
  clearTimeout(retryTimer);
  clearInterval(countdownTimer);
  nextRetryAt = 0;
  lastAttemptAt = Date.now();
  connectionReason = '';
  const connecting = interactionResultText(policy, status);
  connectionStatus(connecting);
  document.documentElement.dataset.encounter = connecting;
  try {
    socket = new WebSocket(endpoint);
    const connection = socket;
    connection.addEventListener('message', receive);
    connection.addEventListener('close', disconnected);
    if (connectionTimeout) timeoutTimer = setTimeout(() => {
      const policy = interactionWasm();
      const [close, reason] = policy.startupTimedOut(connection === socket, booting);
      if (!close) return;
      connectionReason = interactionResultText(policy, reason);
      connection.close();
    }, connectionTimeout);
  } catch (error) {
    socket = undefined;
    scheduleRetry(String(error.message ?? error));
  }
}

bindClockDisplay();

if (reconnectEnabled) {
  // A form must stay in the current page while its session listeners are absent.
  document.addEventListener('submit', event => {
    if (interactionWasm().holdStartupSubmit(Boolean(reconnectEnabled), booting)) event.preventDefault();
  }, true);
}
if (loadInteractionPolicy()) {
  connectionPanel?.querySelector('[data-encounter-retry]').addEventListener('click', () => {
    if (retryAllowed(Boolean(socket))) connect();
  });
  connect();
} else {
  const name = connectionPanel?.dataset.connectionName || 'this workspace';
  const reason = 'This release requires WebAssembly to start ' + name + '.';
  if (connectionPanel) {
    document.documentElement.dataset.encounter = 'unavailable';
    connectionPanel.dataset.state = 'disconnected';
    const label = connectionPanel.querySelector('[data-connection-state]')
      ?? connectionPanel.querySelector('[data-connection-label]');
    label.textContent = reason;
    const retry = connectionPanel.querySelector('[data-encounter-retry]');
    retry.hidden = retry.disabled = true;
  }
  report(reason);
}
