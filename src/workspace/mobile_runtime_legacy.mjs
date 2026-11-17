const encounterLegacyMobile = {
  tripStorage() {
    return ['/workspace/mobile/', '/workspace/mobile/worker.mjs', 'sourcery-mobile-trip-1',
      '/workspace/mobile/local-session', '/workspace/mobile/local-package', '/workspace/mobile/local-receipt',
      'sourcery-mobile-pilot-drafts-1', '/workspace/mobile/pilot-draft/'];
  },
  pairRequest(action) {
    const writes = ['claim', 'disconnect', 'invalidate', 'receipt'];
    const allowed = action === 'read' || writes.includes(action);
    const receipt = action === 'receipt';
    return [allowed ? '/workspace/mobile/pair/' : '', writes.includes(action) ? '/' + action : '',
      action === 'read' ? 'GET' : 'POST', 'Bearer ', receipt ? 'digest' : '', receipt ? 'challenge' : ''];
  },
  pairReply(status, ok) {
    if (ok) return [status === 204 ? 1 : 2, ''];
    if (status === 404) return [3, 'Pairing expired. Pair the phone again from Mobile.'];
    return [0, 'The trip changed or confirmation was refused. Reconnect and check for the latest trip.'];
  },
  claimAction(phone, code, previous, next, hasPrevious) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(phone) || !/^[0-9]{6}$/.test(code)) {
      return [0, 'Mobile received an invalid pairing response. Pair the phone again from Mobile.'];
    }
    return [hasPrevious && previous !== next ? 2 : 1, ''];
  },
  invitationAdmission(id, bearer, pair) {
    return pair && /^[A-Za-z0-9_-]{16}$/.test(id) && /^[A-Za-z0-9_-]{43}$/.test(bearer);
  },
  draftBasis(task, pin, id, base) {
    return /^[A-Za-z0-9_-]{1,80}$/.test(task) && /^[a-f0-9]{64}$/.test(pin) &&
      /^[A-Za-z0-9_-]{1,80}$/.test(id) && /^(new|[a-f0-9]{64})$/.test(base);
  },
  snapshotInput(hasText) {
    return [hasText, hasText ? '' : 'The trip copy is missing. Reconnect and send it again.'];
  },
  snapshotDigest(actual, claimed) {
    return Boolean(claimed) && actual === claimed;
  },
  snapshotIntegrity(actual, claimed) {
    const parse = this.snapshotDigest(actual, claimed);
    return [parse, parse ? '' : 'The trip copy failed its integrity check. Reconnect and send it again.'];
  },
  refreshIntervals() {
    return [3000, 4000];
  },
  snapshotAdmission(hasExpiry, expires, now, count, expected, sameRevision, unique, validItems) {
    if (hasExpiry && expires <= now) return [false, 'This trip copy expired. Reconnect and prepare it again.'];
    const admit = hasExpiry && count > 0 && count === expected && sameRevision && unique && validItems;
    return [admit, admit ? '' : 'The trip item list is incomplete. Reconnect and send it again.'];
  },
  referenceId(id) {
    return /^pilot-ref-[0-9]+$/.test(id);
  },
  itemAdmission(id, text, nonempty, reference, title, hasDraft, validDraft) {
    if (!text) return false;
    if (id === 'note' || id === 'project') return nonempty;
    if (!title) return false;
    if (id === 'pilot-draft') return validDraft;
    return (reference || ['pilot-review', 'pilot-plan', 'pilot-checks', 'pilot-diff'].includes(id)) && !hasDraft;
  },
  tripItemView(id, count) {
    const draft = id === 'pilot-draft';
    return [id === 'note' ? 'My first note' : 'Field visit task',
      id.startsWith('pilot-ref-') || id === 'pilot-diff' ? 'pre' : 'p', draft, draft ? 1 : count];
  },
  offlineMarkers() {
    return ['data-mobile-online', 'data-mobile-offline'];
  },
  offlineReceipt(offline, reopened, receipt) {
    if (!offline) return [0, '', ''];
    if (!reopened) return [1, '', ''];
    if (receipt !== 2) return [3, 'The offline receipt could not be saved. Reconnect and retry.', ''];
    return [2, 'Offline check passed · all ', ' selected items reopened. Reconnect to confirm Ready on your desktop.'];
  },
  draftRecordAdmission(basis, text, sameKey, state) {
    return basis && text && sameKey && ['pending', 'sign-in', 'saved', 'conflict'].includes(state);
  },
  draftView(state, hasCurrent, active) {
    const saved = state === 'saved';
    const status = saved ? 1 : state === 'conflict' ? (hasCurrent ? 3 : 2) : state === 'sign-in' ? 4 : 0;
    const messages = [
      'Saved on this phone. It will sync when Pilot is reachable.',
      'Synced to Pilot staged comments.',
      'The Pilot review or draft changed. Your phone copy is still here.',
      'The desktop draft changed. Your phone copy is still here. Current Pilot draft: ',
      'Sign in to Pilot to sync this draft.',
    ];
    return [messages[status], !saved && !active, saved, status === 3];
  },
  draftSaveAdmission(hasText) {
    return hasText;
  },
  draftSaveState(state) {
    return state === 'conflict' ? 'conflict' : 'pending';
  },
  draftTextChanged(current, saved) {
    return current !== saved;
  },
  canSyncDrafts(syncing, online, hasList) {
    return !syncing && online && hasList;
  },
  draftPending(state) {
    return ['pending', 'sign-in'].includes(state);
  },
  draftAction(currentBase, submittedBase, state, reply, sameText, replyBase) {
    if (currentBase !== submittedBase || !this.draftPending(state)) return ['', false, false];
    if (reply === 'saved' && /^[a-f0-9]{64}$/.test(replyBase)) return [sameText ? 'saved' : 'pending', true, false];
    if (['conflict', 'unavailable'].includes(reply)) return ['conflict', false, true];
    return [reply === 'sign-in' && state !== 'sign-in' ? 'sign-in' : '', false, false];
  },
  pilotRoute(syncing) {
    return ['/encounter-pilot/task', '1', syncing ? '' : 'comments', syncing ? '1' : '', syncing ? '1' : ''];
  },
  pilotRead(redirected, status, ok) {
    return redirected || [401, 403].includes(status) ? [false, 'sign-in'] : [ok, ''];
  },
  pilotSubmit(status, hasCsrf) {
    return [status === 'open' && hasCsrf, 'task', 'travel', 'comment', 'draft-base', 'pin', 'review-note', '_csrf'];
  },
  pilotResult(ok, status) {
    return ok ? [true, ''] : [false, status === 401 || status === 403 ? 'sign-in' : 'retry'];
  },
  receiptAction(hasReceipt, digest, tripDigest, challenge, tripChallenge) {
    if (!hasReceipt) return 0;
    return digest && digest.length <= 128 && digest === tripDigest &&
      challenge && challenge.length <= 128 && challenge === tripChallenge ? 2 : 1;
  },
  removalFinished(status) {
    return status === 404;
  },
  removalMessages() {
    return ['Trip and pairing removed from this phone. Pair again to prepare another trip.',
      'Could not remove the trip. Keep this page open and try again.'];
  },
  workerStartup(active, online) {
    return [!active, active && online];
  },
  resumePairing(paired, pendingRemoval) {
    if (!paired) return [0, 'Pair this phone from Mobile on your desktop to prepare a trip.'];
    if (pendingRemoval) return [1, 'Trip removed on this phone. Reconnect to end pairing on the desktop.'];
    return [2, ''];
  },
  canSynchronise(running, stopped, booted, paired, online) {
    return !running && !stopped && booted && paired && online;
  },
  roomAction(status, hasTrip) {
    const action = status === 'connected' ? (hasTrip ? 2 : 1) : 0;
    return [action, action === 1 ? 'Phone paired. Choose what to take on your desktop, then send the trip.' : ''];
  },
  receiptReply(accepted, status) {
    const superseded = !accepted && status === 409;
    const clear = accepted || superseded;
    return [!clear, accepted, clear, superseded ? 'The desktop selection changed. Checking for the latest trip…' : ''];
  },
  localRemoval(running, stopped, dirty) {
    if (running || stopped) return [0, ''];
    if (dirty) return [1, 'Save your open draft before removing this trip.'];
    return [2, this.resumePairing(true, true)[1]];
  },
  canFinishRemoval(pending, online, removing, removingLocally) {
    return pending && online && !removing && !removingLocally;
  },
  tripAction(installed, dirty, confirmed) {
    if (installed) {
      const message = confirmed ? 'Ready · this trip version reopened offline. Saved copies expire after 24 hours.'
        : 'Trip saved. Turn on airplane mode, then reload this page to run the offline reopen check.';
      return [0, message];
    }
    if (dirty) return [1, 'Save your open draft before switching to the new trip.'];
    return [confirmed ? 3 : 2, 'Trip saved. Turn on airplane mode, then reload this page to check that every item reopens offline.'];
  },
};
