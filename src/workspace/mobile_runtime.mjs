const mobileWasm = loadBrowserWasm(encounterMobileWasm);
const mobileText = (...values) => browserWasmText(mobileWasm.memory, ...values);
const observedText = value => typeof value === 'string' ? value : '';
const mobilePolicy = selectBrowserPolicy(mobileWasm ? {
  ...mobileWasm,
  pairRequest(action) {
    return mobileWasm.pairRequest(...mobileText(action));
  },
  invitationAdmission(id, bearer, pair) {
    return mobileWasm.invitationAdmission(...mobileText(id, bearer), pair);
  },
  claimAction(phone, code, previous, next, hasPrevious) {
    return mobileWasm.claimAction(...mobileText(phone, code, previous, next), hasPrevious);
  },
  draftBasis(task, pin, id, base) {
    return mobileWasm.draftBasis(...mobileText(task, pin, id, base));
  },
  snapshotDigest(actual, claimed) {
    return mobileWasm.snapshotDigest(...browserWasmText(mobileWasm.memory, actual, claimed));
  },
  snapshotIntegrity(actual, claimed) {
    return mobileWasm.snapshotIntegrity(...mobileText(actual, claimed));
  },
  referenceId(id) {
    const offset = mobileWasm.referenceOffset(...mobileText(id.slice(0, 10)), id.length);
    return offset > 0 && browserWasmTextEvery(mobileWasm.memory, mobileWasm.referenceDigits, id, offset);
  },
  itemAdmission(id, ...observations) {
    return mobileWasm.itemAdmission(...browserWasmText(mobileWasm.memory, id), ...observations);
  },
  tripItemView(id, count) {
    return mobileWasm.tripItemView(...mobileText(id.slice(0, 128)), count);
  },
  draftRecordAdmission(basis, text, sameKey, state) {
    return mobileWasm.draftRecordAdmission(basis, text, sameKey, ...browserWasmText(mobileWasm.memory, state));
  },
  draftView(state, hasCurrent, active) {
    return mobileWasm.draftView(...browserWasmText(mobileWasm.memory, state), hasCurrent, active);
  },
  draftSaveState(state) {
    return mobileWasm.draftSaveState(...mobileText(state));
  },
  draftTextChanged(current, saved) {
    return browserWasmTextChanged(mobileWasm.memory, mobileWasm.draftTextChanged, current, saved);
  },
  draftPending(state) {
    return mobileWasm.draftPending(...browserWasmText(mobileWasm.memory, state));
  },
  draftAction(currentBase, submittedBase, state, reply, sameText, replyBase) {
    const [current, submitted, stateText, replyText, baseText] =
      mobileText(currentBase, submittedBase, state, reply, replyBase);
    return mobileWasm.draftAction(current, submitted, stateText, replyText, sameText, baseText);
  },
  pilotSubmit(status, hasCsrf) {
    return mobileWasm.pilotSubmit(...browserWasmText(mobileWasm.memory, status), hasCsrf);
  },
  receiptAction(hasReceipt, ...fields) {
    return mobileWasm.receiptAction(hasReceipt, ...browserWasmText(mobileWasm.memory, ...fields));
  },
  roomAction(status, hasTrip) {
    return mobileWasm.roomAction(...browserWasmText(mobileWasm.memory, status), hasTrip);
  },
} : null);
const pendingDrafts = document.querySelector('#mobile-phone-drafts');
let activeDraft;
let displayed;
let syncingDrafts = false;
let draftWrites = Promise.resolve();
const status = document.querySelector('#mobile-phone-status');
if (!mobilePolicy) {
  history.replaceState(null, '', location.pathname);
  status.textContent = 'This release requires WebAssembly to open a Mobile trip.';
  throw new Error(status.textContent);
}
const [root, workerPath, cacheName, sessionKey, packageKey, receiptKey, draftCacheName, draftPrefix] =
  mobilePolicy.tripStorage().map(tripMessage);
const retry = document.querySelector('#mobile-phone-retry');
const clear = document.querySelector('#mobile-phone-clear');
let session;
let running = false;
let stopped = false;
let removing = false;
let removingLocally = false;
let booted = false;

function report(message) { status.textContent = message; }
function tripMessage(message) {
  return mobileWasm ? browserWasmTextResult(mobileWasm.memory, message) : message;
}
async function read(key) {
  const response = await (await caches.open(cacheName)).match(key);
  return response ? response.json() : null;
}
async function write(key, value) {
  await (await caches.open(cacheName)).put(key, new Response(JSON.stringify(value), {headers:{'Content-Type':'application/json'}}));
}
async function request(action, device = session, receipt) {
  const [prefix, suffix, method, authorization, digest, challenge] = mobilePolicy.pairRequest(action).map(tripMessage);
  if (!prefix) throw new Error('Unknown Mobile pairing action.');
  const body = method === 'GET' ? undefined : new URLSearchParams();
  if (digest) body.set(digest, receipt.digest);
  if (challenge) body.set(challenge, receipt.challenge);
  const response = await fetch(prefix + device.id + suffix, {
    method,
    headers: {Authorization: authorization + device.bearer},
    body,
    cache:'no-store',
    signal:AbortSignal.timeout(5000)
  });
  const [reply, messageHandle] = mobilePolicy.pairReply(response.status, response.ok);
  const message = tripMessage(messageHandle);
  if (message) {
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return reply === 1 ? null : response.json();
}
async function validate(trip) {
  const [hash, inputMessage] = mobilePolicy.snapshotInput(typeof trip?.snapshot === 'string');
  if (!hash) throw new Error(tripMessage(inputMessage));
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(trip.snapshot));
  const digest = [...new Uint8Array(bytes)].map(value => value.toString(16).padStart(2, '0')).join('');
  const [parse, integrityMessage] = mobilePolicy.snapshotIntegrity(digest, observedText(trip.digest));
  if (!parse) throw new Error(tripMessage(integrityMessage));
  const snapshot = JSON.parse(trip.snapshot);
  const items = Array.isArray(snapshot?.items) ? snapshot.items : [];
  const expected = Number.isSafeInteger(trip.count) ? trip.count : -1;
  const hasExpiry = Number.isFinite(snapshot?.expires);
  const sameRevision = snapshot?.revision === trip.revision;
  const unique = items.length === expected && new Set(items.map(item => item?.id)).size === items.length;
  const [admit, admissionMessage] = mobilePolicy.snapshotAdmission(hasExpiry, hasExpiry ? snapshot.expires : 0, Date.now(),
    items.length, expected, sameRevision, unique, unique && items.every(validItem));
  if (!admit) throw new Error(tripMessage(admissionMessage));
  return snapshot;
}
function validDraftBasis(draft) {
  return mobilePolicy.draftBasis(...[draft?.task, draft?.pin, draft?.id, draft?.base].map(observedText));
}
function validItem(item) {
  const id = typeof item?.id === 'string' ? item.id : '';
  const draft = item?.draft;
  return mobilePolicy.itemAdmission(id, typeof item?.text === 'string', Boolean(item?.text),
    mobilePolicy.referenceId(id), typeof item?.title === 'string' && Boolean(item.title), Boolean(draft), validDraftBasis(draft));
}
function pilotRequest(task, syncing) {
  const [path, work, view, travel, sync] = mobilePolicy.pilotRoute(syncing).map(tripMessage);
  const query = new URLSearchParams({task});
  for (const [field, value] of Object.entries({work, view, travel, sync})) {
    if (value) query.set(field, value);
  }
  return {path, url: path + '?' + query, travel};
}
function reviewLink(task, label = 'Open Pilot review') {
  const link = document.createElement('a');
  link.href = pilotRequest(task, false).url;
  link.textContent = label;
  link.target = '_blank';
  link.rel = 'noopener';
  return link;
}
function draftKey(draft) {
  return draftPrefix + [draft.task, draft.pin, draft.id].join('/');
}
async function draftRecord(cache, key) {
  const response = await cache.match(key);
  if (!response) return null;
  let record;
  try { record = await response.json(); } catch { return null; }
  const basis = validDraftBasis(record?.draft);
  const url = key instanceof Request ? key.url : new URL(key, location.origin).href;
  const sameKey = basis && new URL(draftKey(record.draft), location.origin).href === url;
  const state = typeof record?.state === 'string' ? record.state : '';
  return mobilePolicy.draftRecordAdmission(basis, typeof record?.text === 'string', sameKey, state) ? record : null;
}

function draftPending(state) {
  return mobilePolicy.draftPending(typeof state === 'string' ? state : '');
}

function draftAction(current, draft, text, reply) {
  const sameText = typeof current.text === 'string' && typeof text === 'string'
    ? !mobilePolicy.draftTextChanged(current.text, text) : current.text === text;
  const state = typeof current.state === 'string' ? current.state : '';
  const status = typeof reply?.status === 'string' ? reply.status : '';
  const base = typeof reply?.base === 'string' ? reply.base : '';
  return mobilePolicy.draftAction(current.draft.base, draft.base, state, status, sameText, base);
}
function storeDraft(cache, key, record) {
  return cache.put(key, new Response(JSON.stringify(record)));
}
function updateDraft(key, operation) {
  const lock = key instanceof Request ? key.url : new URL(key, location.origin).href;
  if (navigator.locks) return navigator.locks.request(lock, operation);
  const result = draftWrites.then(operation);
  draftWrites = result.catch(() => {});
  return result;
}
function draftView(record, active = false) {
  const state = typeof record.state === 'string' ? record.state : '';
  return mobilePolicy.draftView(state, typeof record.current === 'string', active);
}

function describeDraft(record, view = draftView(record)) {
  const [message, , , appendCurrent] = view;
  return tripMessage(message) + (appendCurrent ? record.current : '');
}
async function showPendingDrafts() {
  if (!pendingDrafts) return;
  const cache = await caches.open(draftCacheName);
  const rows = [];
  for (const key of await cache.keys()) {
    const record = await draftRecord(cache, key);
    if (!record) continue;
    const active = key.url === new URL(activeDraft?.key ?? root, location.origin).href;
    const view = draftView(record, active);
    if (!view[1]) continue;
    const panel = document.createElement('details');
    panel.className = 'panel';
    const title = document.createElement('summary');
    title.textContent = 'Phone draft · ' + record.draft.task;
    const text = document.createElement('p');
    text.className = 'mobile-copy';
    text.textContent = record.text;
    const state = document.createElement('p');
    state.textContent = describeDraft(record, view);
    panel.append(title, state, text, reviewLink(record.draft.task));
    rows.push(panel);
  }
  pendingDrafts.replaceChildren(...rows);
}
async function attachDraft(section, item) {
  const key = draftKey(item.draft);
  const cache = await caches.open(draftCacheName);
  const saved = await draftRecord(cache, key);
  const form = document.createElement('form');
  form.className = 'onboarding-form phone-controls';
  const label = document.createElement('label');
  label.htmlFor = 'mobile-pilot-draft';
  label.textContent = 'Draft comment';
  const input = document.createElement('textarea');
  input.id = label.htmlFor;
  input.required = true;
  input.maxLength = 300;
  input.value = saved?.text ?? item.text;
  const save = document.createElement('button');
  save.type = 'submit';
  save.textContent = 'Save draft on phone';
  const message = document.createElement('p');
  message.setAttribute('role', 'status');
  message.textContent = saved ? describeDraft(saved) : 'You can edit this comment offline. It will sync as a staged comment.';
  const editor = { key, dirty:false, message };
  activeDraft = editor;
  input.addEventListener('input', () => { editor.dirty = true; });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const text = input.value;
    if (!mobilePolicy.draftSaveAdmission(Boolean(text.trim()))) return;
    save.disabled = true;
    try {
      const record = await updateDraft(key, async () => {
        const current = await draftRecord(cache, key);
        const currentState = typeof current?.state === 'string' ? current.state : '';
        const state = tripMessage(mobilePolicy.draftSaveState(currentState));
        const next = {draft:current?.draft ?? item.draft, text, state, current:current?.current};
        await storeDraft(cache, key, next);
        return next;
      });
      editor.dirty = Boolean(mobilePolicy.draftTextChanged(input.value, text));
      message.textContent = describeDraft(record);
      await showPendingDrafts();
      await syncDrafts();
    } catch { message.textContent = 'Could not save this draft on the phone. Keep this page open and try again.'; }
    finally { save.disabled = false; }
  });
  form.append(label, input, save, message, reviewLink(item.draft.task, 'Sign in or open Pilot review'));
  section.append(form);
}
async function syncDrafts() {
  if (!mobilePolicy.canSyncDrafts(syncingDrafts, navigator.onLine, Boolean(pendingDrafts))) return;
  syncingDrafts = true;
  try {
    const cache = await caches.open(draftCacheName);
    for (const key of await cache.keys()) {
      const record = await draftRecord(cache, key);
      if (!record || !draftPending(record.state)) continue;
      const {draft, text} = record;
      const request = pilotRequest(draft.task, true);
      const options = {redirect:'manual', cache:'no-store', signal:AbortSignal.timeout(5000)};
      let reply;
      try {
        const response = await fetch(request.url, options);
        const redirected = response.type === 'opaqueredirect';
        const [readBody, readStatus] = mobilePolicy.pilotRead(redirected, response.status, response.ok);
        const fallback = tripMessage(readStatus);
        if (fallback) reply = {status:fallback};
        if (readBody) {
          const session = await response.json();
          reply = session;
          const [submit, ...fieldHandles] = mobilePolicy.pilotSubmit(observedText(session?.status),
            typeof session?.csrf === 'string' && session.csrf.length > 0);
          if (submit) {
            const [task, travel, comment, base, pin, note, csrf] = fieldHandles.map(tripMessage);
            const body = new URLSearchParams({
              [task]: draft.task, [travel]: request.travel, [comment]: draft.id, [base]: draft.base,
              [pin]: draft.pin, [note]: text, [csrf]: session.csrf,
            });
            const sent = await fetch(request.path, {...options, method:'POST', body,
              headers:{'Content-Type':'application/x-www-form-urlencoded'}});
            const [readResult, submitStatus] = mobilePolicy.pilotResult(sent.ok, sent.status);
            reply = readResult ? await sent.json() : {status:tripMessage(submitStatus)};
          }
        }
      } catch { continue; }
      const latest = await updateDraft(key, async () => {
        const current = await draftRecord(cache, key);
        if (!current) return null;
        const [state, updateBase, updateCurrent] = draftAction(current, draft, text, reply);
        const nextState = tripMessage(state);
        if (!nextState) return null;
        current.state = nextState;
        if (updateBase) current.draft.base = reply.base;
        if (updateCurrent) current.current = reply.current;
        await storeDraft(cache, key, current);
        return current;
      });
      if (!latest) continue;
      if (activeDraft?.key === draftKey(draft)) activeDraft.message.textContent = describeDraft(latest);
      await showPendingDrafts();
    }
  } finally { syncingDrafts = false; }
}
async function display(snapshot, digest) {
  if (mobilePolicy.snapshotDigest(observedText(displayed), digest)) return;
  const sections = [];
  activeDraft = null;
  const container = document.querySelector('#mobile-phone-items');
  for (const item of snapshot.items) {
    const section = document.createElement('section');
    section.className = 'panel';
    const [fallbackTitle, element, draft, position] = mobilePolicy.tripItemView(item.id, sections.length);
    const title = document.createElement('h2');
    title.textContent = item.title ?? tripMessage(fallbackTitle);
    const text = document.createElement(tripMessage(element));
    text.className = 'mobile-copy';
    text.textContent = item.text;
    section.append(title);
    if (draft) {
      await attachDraft(section, item);
    } else {
      section.append(text);
    }
    sections.splice(position, 0, section);
  }
  container.replaceChildren(...sections);
  displayed = digest;
  await showPendingDrafts();
}

function receiptAction(receipt, trip) {
  const fields = [receipt?.digest, trip.digest, receipt?.challenge, trip.challenge]
    .map(value => typeof value === 'string' ? value : '');
  return mobilePolicy.receiptAction(Boolean(receipt), ...fields);
}

function removalFinished(error) {
  const code = Number.isFinite(error.status) ? error.status : 0;
  return mobilePolicy.removalFinished(code);
}

async function finishRemoval() {
  if (!mobilePolicy.canFinishRemoval(Boolean(session?.pendingRemoval), navigator.onLine, removing, removingLocally)) return;
  removing = true;
  try {
    await request('disconnect');
    await caches.delete(cacheName);
    session = null;
    const [message] = mobilePolicy.removalMessages();
    report(tripMessage(message));
  } catch (error) {
    if (removalFinished(error)) {
      await caches.delete(cacheName);
      session = null;
    }
  } finally {
    removing = false;
  }
}
async function synchronise() {
  const paired = Boolean(session);
  const online = navigator.onLine;
  const canSynchronise = mobilePolicy.canSynchronise(running, stopped, booted, paired, online);
  if (!canSynchronise) return;
  running = true;
  try {
    const room = await request('read');
    const roomStatus = typeof room.status === 'string' ? room.status : '';
    const hasTrip = Boolean(room.trip);
    const [next, roomMessage] = mobilePolicy.roomAction(roomStatus, hasTrip);
    if (next === 0) {
      report('Code: ' + session.code + '. Match this code and approve the phone on your desktop.');
      return;
    }
    if (next === 1) {
      report(tripMessage(roomMessage));
      return;
    }
    const snapshot = await validate(room.trip);
    const receipt = await read(receiptKey);
    const replay = receiptAction(receipt, room.trip);
    let clearReceipt = replay === 1;
    let receiptMessage = '';
    if (replay === 2) {
      let accepted = false;
      let failure;
      try {
        await request('receipt', session, receipt);
        accepted = true;
      } catch (error) {
        failure = error;
      }
      const code = Number.isFinite(failure?.status) ? failure.status : 0;
      const [retry, confirm, clear, message] = mobilePolicy.receiptReply(accepted, code);
      if (retry) throw failure;
      if (confirm) room.trip.confirmed = true;
      clearReceipt = Boolean(clear);
      receiptMessage = tripMessage(message);
    }
    if (clearReceipt) {
      await (await caches.open(cacheName)).delete(receiptKey);
    }
    if (receiptMessage) {
      report(receiptMessage);
      return;
    }
    let installed = false;
    try {
      const cached = await read(packageKey);
      if (mobilePolicy.snapshotDigest(observedText(cached?.digest), room.trip.digest)) {
        await validate(cached);
        installed = true;
      }
    } catch { /* Restore a missing or corrupt local copy from the verified server snapshot. */ }
    const dirty = Boolean(activeDraft?.dirty);
    const confirmed = Boolean(room.trip.confirmed);
    const [action, message] = mobilePolicy.tripAction(installed, dirty, confirmed);
    if (action === 1) {
      report(tripMessage(message));
      return;
    }
    if (action !== 0) {
      if (action === 3) await request('invalidate');
      await write(packageKey, room.trip);
      const reopened = await read(packageKey);
      await validate(reopened);
    }
    await display(snapshot, room.trip.digest);
    report(tripMessage(message));
    clear.hidden = false;
  } catch (error) { report(error.message); }
  finally { running = false; }
}
async function boot() {
  try {
    const coordinates = location.hash.slice(1).split('.', 3);
    const [id = '', bearer = ''] = coordinates;
    const invitation = mobilePolicy.invitationAdmission(id, bearer, coordinates.length === 2);
    history.replaceState(null, '', location.pathname);
    if (!('serviceWorker' in navigator) || !('caches' in window)) throw new Error('This browser cannot keep an offline trip. Use a browser with service worker support.');
    const registration = await navigator.serviceWorker.getRegistration(root);
    const [register, refresh] = mobilePolicy.workerStartup(Boolean(registration?.active), navigator.onLine);
    if (register) await navigator.serviceWorker.register(workerPath, {scope:root});
    if (refresh) registration.update().catch(() => {});
    await navigator.serviceWorker.ready;
    await showPendingDrafts();
    if (invitation) {
      let previous = null;
      try { previous = await read(sessionKey); } catch {}
      const claim = await request('claim', {id, bearer});
      const phone = observedText(claim?.phone);
      const code = observedText(claim?.code);
      const [action, message] = mobilePolicy.claimAction(phone, code, observedText(previous?.id), id, Boolean(previous));
      if (action === 0) throw new Error(tripMessage(message));
      const nextSession = {id, bearer:phone, code};
      if (action === 2) {
        try { await request('disconnect', previous); }
        catch (error) { if (!removalFinished(error)) throw error; }
      }
      await caches.delete(cacheName);
      await write(sessionKey, nextSession);
      session = nextSession;
    } else session = await read(sessionKey);
    const [action, message] = mobilePolicy.resumePairing(Boolean(session), Boolean(session?.pendingRemoval));
    if (action === 0) throw new Error(tripMessage(message));
    if (action === 1) {
      stopped = true;
      report(tripMessage(message));
      await finishRemoval();
      return;
    }
    booted = true;
    retry.hidden = false;
    retry.disabled = !navigator.onLine;
    const trip = await read(packageKey);
    if (trip) {
      const snapshot = await validate(trip);
      await display(snapshot, trip.digest);
      clear.hidden = false;
      const [, marker] = mobilePolicy.offlineMarkers();
      const offline = document.body.hasAttribute(tripMessage(marker));
      if (mobilePolicy.offlineReceipt(offline, false, 0)[0] === 1) {
        await write(receiptKey, {digest:trip.digest, challenge:trip.challenge});
        const receipt = await read(receiptKey);
        const [action, message, detail] = mobilePolicy.offlineReceipt(offline, true, receiptAction(receipt, trip));
        if (action === 3) throw new Error(tripMessage(message));
        report(tripMessage(message) + snapshot.items.length + tripMessage(detail));
      }
    }
    await synchronise();

  } catch (error) { report(error.message); }
}
retry.addEventListener('click', synchronise);
window.addEventListener('online', () => { retry.disabled = false; finishRemoval(); synchronise(); syncDrafts().catch(() => {}); });
window.addEventListener('offline', () => { retry.disabled = true; });
clear.addEventListener('click', async () => {
  const [action, message] = mobilePolicy.localRemoval(running, stopped, Boolean(activeDraft?.dirty));
  if (action === 0) return;
  if (action === 1) {
    report(tripMessage(message));
    return;
  }
  stopped = true;
  removingLocally = true;
  const original = session;
  try {
    const removal = {...session, pendingRemoval:true};
    // Retain only the revocation capability until it reaches the server.
    await write(sessionKey, removal);
    session = removal;
    const cache = await caches.open(cacheName);
    await cache.delete(packageKey);
    await cache.delete(receiptKey);
    if (activeDraft) {
      const key = activeDraft.key;
      const draftCache = await caches.open(draftCacheName);
      await updateDraft(key, async () => {
        const local = await draftRecord(draftCache, key);
        const [, , removeWithTrip] = local ? draftView(local) : [];
        if (removeWithTrip) await draftCache.delete(key);
      });
      activeDraft = null;
      await showPendingDrafts();
    }
    document.querySelector('#mobile-phone-items').replaceChildren();
    retry.hidden = true;
    clear.hidden = true;
    report(tripMessage(message));
    removingLocally = false;
    await finishRemoval();
  } catch {
    session = original;
    stopped = false;
    const [, failure] = mobilePolicy.removalMessages();
    report(tripMessage(failure));
  } finally {
    removingLocally = false;
  }
});

boot();
const [tripInterval, draftInterval] = mobilePolicy.refreshIntervals();
setInterval(synchronise, tripInterval);
setInterval(() => syncDrafts().catch(() => {}), draftInterval);
