const policy = loadBrowserWasm(encounterAsterFrameWasm);
if (!policy) return;

const decode = result => browserWasmTextResult(policy.memory, result);
const [protocol, requestType, snapshotType, changedType] = policy.messageTypes().map(decode);
const script = document.currentScript;
const allowedParent = script.dataset.sourceryAsterParent;
const role = policy.bridgeRole(window.parent !== window, Boolean(allowedParent),
  script.hasAttribute('data-sourcery-aster-host'));
if (role === 0) return;
const pack = (...values) => browserWasmText(policy.memory, ...values);
const validAdapter = adapter => policy.adapterAllowed(...pack(adapter));
const validNonce = nonce => policy.nonceAllowed(...pack(nonce));
const markerSelector = '[data-sourcery-frame-adapter]';
const text = value => typeof value === 'string' ? value : '';
const messageFields = data => pack(text(data?.protocol), text(data?.type));

function read(adapter, scope = document) {
  let summary = '';
  for (const marker of scope.querySelectorAll(markerSelector)) {
    const matches = marker.dataset.sourceryFrameAdapter === adapter;
    const label = marker.dataset.sourceryFrameContextField ?? '';
    const value = marker.textContent.replace(/\s+/g, ' ').trim();
    const provided = marker.dataset.sourceryFrameContext?.trim() ?? '';
    const [labelText, valueText] = pack(label, value);
    const [next, labelled, divider, ending, separator] =
      policy.markerPlan(matches, summary.length, labelText, label.length, valueText, value.length, provided.length);
    if (next) {
      const part = labelled ? label + decode(divider) + value + decode(ending) : provided;
      summary += decode(separator) + part;
    }
  }
  return summary;
}

if (role === 1) {
  let requestedAdapter = '';
  let observedSummary = '';
  window.addEventListener('message', ({source, origin, data}) => {
    const adapter = validAdapter(text(data?.adapter));
    const nonce = validNonce(text(data?.nonce));
    if (!policy.childRequest(source === window.parent, origin === allowedParent, ...messageFields(data), adapter, nonce)) return;
    requestedAdapter = data.adapter;
    const summary = read(requestedAdapter);
    if (!summary) return;
    observedSummary = summary;
    source.postMessage({protocol, type: snapshotType, nonce: data.nonce, adapter: requestedAdapter, summary}, origin);
  });
  new MutationObserver(() => {
    if (!requestedAdapter) return;
    const current = read(requestedAdapter);
    const matches = !browserWasmTextChanged(policy.memory, policy.summaryChanged, current, observedSummary);
    if (!policy.childChanged(Boolean(requestedAdapter), matches)) return;
    observedSummary = current;
    window.parent.postMessage({protocol, type: changedType, adapter: requestedAdapter}, allowedParent);
  }).observe(document.body, {
    childList: true, characterData: true, subtree: true, attributes: true,
    attributeFilter: ['data-sourcery-frame-context', 'data-sourcery-frame-adapter', 'data-sourcery-frame-context-field'],
  });
  return;
}

for (const marker of document.querySelectorAll(markerSelector)) {
  const adapter = marker.dataset.sourceryFrameAdapter;
  if (validAdapter(adapter)) {
    Object.defineProperty(marker, 'sourceryAsterContext', {get: () => read(adapter)});
  }
}
if (role !== 3) return;

const selector = 'iframe[data-sourcery-aster-adapter]';
const frames = new Map();

function bindingCurrent(frame, binding) {
  return frame.src === binding.source && frame.dataset.sourceryAsterAdapter === binding.adapter;
}

function frameSummary(frame, binding) {
  const preferLocal = frame.hasAttribute('data-sourcery-aster-same-origin');
  const target = preferLocal ? new URL(frame.src, location.href) : null;
  const child = preferLocal ? frame.contentDocument : null;
  const current = child ? new URL(child.URL) : null;
  const source = policy.summarySource(preferLocal, Boolean(child), target?.origin === location.origin,
    target?.pathname.endsWith('/') ?? false, current?.origin === target?.origin,
    current?.pathname.startsWith(target.pathname) ?? false, bindingCurrent(frame, binding));
  if (source === 1) return binding.summary;
  if (source === 2) return read(frame.dataset.sourceryAsterAdapter, child);
  return '';
}

function request(frame) {
  const binding = frames.get(frame);
  binding.summary = '';
  binding.nonce = '';
  binding.source = null;
  const adapter = text(frame.dataset.sourceryAsterAdapter);
  const source = frame.src;
  const destination = new URL(source, location.href);
  const child = frame.contentWindow;
  if (!policy.requestChild(validAdapter(adapter), destination.origin === location.origin,
    ...pack(destination.protocol), Boolean(child))) return;
  const nonce = [...crypto.getRandomValues(new Uint8Array(16))]
    .map(byte => byte.toString(16).padStart(2, '0')).join('');
  Object.assign(binding, {source, adapter, origin: destination.origin, nonce});
  child.postMessage({protocol, type: requestType, adapter, nonce}, destination.origin);
}

function updateFrames() {
  for (const [frame, binding] of frames) {
    if (policy.frameAction(frame.isConnected, frame.matches(selector), true) !== 2) continue;
    frame.removeEventListener('load', binding.onLoad);
    delete frame.sourceryAsterContext;
    frames.delete(frame);
  }
  for (const frame of document.querySelectorAll(selector)) {
    if (policy.frameAction(frame.isConnected, true, frames.has(frame)) !== 3) continue;
    const onLoad = () => request(frame);
    const binding = {onLoad, summary: ''};
    frames.set(frame, binding);
    Object.defineProperty(frame, 'sourceryAsterContext', {
      configurable: true,
      get: () => frameSummary(frame, binding),
    });
    frame.addEventListener('load', onLoad);
    request(frame);
  }
}

window.addEventListener('message', ({source, origin, data}) => {
  const fields = messageFields(data);
  for (const [frame, binding] of frames) {
    const action = policy.hostMessage(frame.isConnected, source === frame.contentWindow, origin === binding.origin,
      data?.adapter === binding.adapter, ...fields, Boolean(binding.nonce && data?.nonce === binding.nonce),
      typeof data?.summary === 'string', text(data?.summary).length, bindingCurrent(frame, binding));
    if (action === 1) request(frame);
    if (action === 2) {
      binding.nonce = '';
      binding.summary = data.summary;
    }
    if (action) return;
  }
});
new MutationObserver(records => {
  for (const {type, target} of records) {
    if (type === 'attributes' && policy.frameAction(target.isConnected, target.matches(selector), frames.has(target)) === 1) {
      request(target);
    }
  }
  updateFrames();
}).observe(document.body, {
  childList: true, subtree: true, attributes: true,
  attributeFilter: ['src', 'data-sourcery-aster-adapter'],
});
updateFrames();
