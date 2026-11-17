const encounterLegacyLiveEvents = {
  sameCoordinate(currentLength, savedLength, current, saved) {
    return currentLength === savedLength && current === saved;
  },
  draftChanged(_currentLength, _savedLength, current, saved) {
    return current !== saved;
  },
  editorActive(editable, canvasControl) {
    return editable && !canvasControl;
  },
  updatePlan(surfacePresent, updating, force) {
    return !surfacePresent ? 0 : !updating ? 1 : force ? 2 : 0;
  },
  applyQueued(force, queued, sameRoute) {
    const consume = queued && sameRoute;
    return [force || consume, consume];
  },
  queuedApplied(replaced, consume) {
    return replaced && consume;
  },
  inspectQueuedRoute(queued, applied) {
    return queued && !applied;
  },
  finishQueued(queued, sameRoute, applied) {
    return [queued, queued && sameRoute && !applied];
  },
  cueCandidate(_validTimes, start, now, previous, hasCue) {
    return start <= now && (!hasCue || start > previous);
  },
  replace(dirty, force, media, partCount, matchedParts, moved, surfacesPresent, markerInside, incomingMarkerInside) {
    if (dirty && !force) return [0, false, false, false, false];
    const incompleteParts = media && (partCount === 0 || partCount !== matchedParts);
    if (!surfacesPresent || markerInside !== incomingMarkerInside || incompleteParts) return [3, false, false, false, false];
    return media ? [1, dirty, moved, force, true] : [2, dirty, false, force, !markerInside];
  },
  pendingNotice(show, moved, hasConnection) {
    const message = !show ? '' : moved
      ? 'Playback moved to another segment. Show the update to change the feedback target. Your draft will be kept.'
      : hasConnection ? 'New activity is ready. Your draft is still here.'
      : 'New activity is ready. Your answer draft is still here.';
    return [message, !show, show];
  },
  mediaClockReady(hasCurrentData, seeking) {
    return hasCurrentData && !seeking;
  },
  seekCue(hasCue, hasCurrentData, primaryButton, modified) {
    return hasCue && hasCurrentData && primaryButton && !modified;
  },
  replaceToken(hasToken, sameStream) {
    return hasToken && sameStream;
  },
  refresh(moved, _validRendered, rendered, wanted, force, dirty, editing, media) {
    if (!moved && rendered >= wanted) return [false, media ? 1 : 0];
    if (!force && dirty) return [false, 2];
    return [force || moved || !editing, 0];
  },
  refreshReply(ok, current) {
    return ok && current;
  },
  replaceReply(current, sameStream, moved, _validSequences, shown, incoming) {
    return current && sameStream && (moved || incoming > shown);
  },
  socketSchedule(event, delay, hasConnection) {
    const backoff = event === 'failed' || (event === 'close' && hasConnection);
    const starting = event === 'start';
    const next = starting || event === 'open' ? 500 : backoff ? Math.min(delay * 2, 5000) : delay;
    const wait = event === 'close' ? delay : event === 'failed' ? next : event === 'sign-in' ? 5000 : event === 'poll' ? 750 : 0;
    const notices = {
      start: 'Connecting live…', open: 'Live updates connected', close: 'Reconnecting live updates…',
      'sign-in': 'Sign in again to reconnect.',
    };
    return [next, wait, Object.hasOwn(notices, event) ? notices[event] : '', !starting];
  },
  reconnectRequest(hasConnection) {
    return [hasConnection, 'no-store', 'manual'];
  },
  reconnectAction(status, redirected, ok) {
    if (redirected || [401, 403].includes(status)) return [false, 'sign-in'];
    return ok ? [true, ''] : [false, 'failed'];
  },
  resumeCursor(safeInteger, saved) {
    return safeInteger && saved >= 0 ? saved : 0;
  },
  socketCoordinates(secure) {
    return [secure ? 'wss:' : 'ws:', 'after', 'encounter-events:'];
  },
  socketDelivery(opening, validSequence, after, wanted, sequence) {
    const accept = !opening && validSequence && !(sequence <= after);
    if (accept) after = sequence;
    return [accept, after, opening || accept ? Math.max(wanted, after) : wanted];
  },
  holdSubmit(hasDraft, seeking, moved) {
    return hasDraft && (seeking || moved);
  },
};
