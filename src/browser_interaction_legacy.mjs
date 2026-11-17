const encounterLegacyInteraction = {
  activate(sameMember, hasPrevious) {
    return sameMember ? 0 : hasPrevious ? 2 : 1;
  },
  activeGroupAdmission(text, duplicate, used, array, count) {
    return text && !duplicate && used < 16 && array && count >= 1 && count <= 64;
  },
  activeMemberId(id) {
    return /^#[a-z][a-z0-9-]{0,100}$/.test(id);
  },
  activeMemberAdmission(html, directChild, duplicate) {
    return html && directChild && !duplicate;
  },
  activeMemberInitial(active, hasPrevious) {
    return active ? (hasPrevious ? 2 : 1) : 0;
  },
  observationHandle(known, count) {
    return [!known, !known && count >= 2048];
  },
  descriptionCards(count) {
    return count <= 128;
  },
  descriptionBinding(summary, button, panelMatches) {
    return summary && button && panelMatches;
  },
  timingIntervals(started, enqueued, ended, hasDispatch, dispatched, revealed) {
    return [enqueued - started, ended - dispatched, ended - started,
      (hasDispatch ? dispatched : ended) - started, revealed - started];
  },
  timingAge(now, recordedAt) {
    return Math.max(0, Math.floor((now - recordedAt) / 1000));
  },
  timingHost(host, exchange) {
    return Math.max(0, host - exchange);
  },
  timingBlocker(enqueued, dispatched, ended, started, count) {
    const start = Math.max(enqueued, dispatched);
    return [ended - start, start - started, count < 12];
  },
  timingEffectRequest(port) {
    return port === 'browser.request' || port === 'browser.frontGateStatus';
  },
  timingEffectSample(started, effectStarted, ended, count, previousReveal, hasReveal) {
    return [ended - effectStarted, effectStarted - started, count < 48, !previousReveal && hasReveal];
  },
  timingResponse(ended, requestStarted, status) {
    return [ended - requestStarted, status >= 500];
  },
  timingFailure(request) {
    return request ? 'Request failed' : 'Browser action failed';
  },
  timingEvict(count) {
    return count > 30;
  },
  retryAt(enabled, now, delay) {
    return enabled ? now + delay : 0;
  },
  backoff(delay, hasPanel) {
    return Math.min(delay * 2, hasPanel ? 60_000 : 5000);
  },
  retryPlan(enabled, now, delay, hasPanel) {
    const at = this.retryAt(enabled, now, delay);
    return [at, Boolean(at), at ? this.backoff(delay, hasPanel) : delay,
      enabled ? 'reconnecting' : 'disconnected', hasPanel ? 1000 : 0, 'disconnected', at ? delay : 0];
  },
  retryAllowed(now, lastAttempt, hasAttempt, hasSocket) {
    return !hasSocket && (!hasAttempt || now - lastAttempt >= 10_000);
  },
  startupReceiver(receiver, arrays, paths, hashes, encoded, seen, used) {
    if (!/^[a-z][a-z0-9-]{0,31}$/.test(receiver) || !arrays || paths > 8 || hashes > 8 || encoded > 8) return 0;
    return seen ? 1 : used >= 16 ? 2 : 3;
  },
  startupRoute(pathAllowed, hashAllowed, hasSearch, hasHash) {
    return [hasSearch || hasHash, pathAllowed && hashAllowed];
  },
  startupField(key, encoded) {
    return !/^[a-z][a-z0-9-]{0,31}$/.test(key) ? 0 : encoded ? 2 : 1;
  },
  startupFields(length, count, unique) {
    return length <= 4096 && count <= 16 && unique;
  },
  startupCleanup(consume, samePath, hasSearch, sameLaunchHash) {
    return consume && samePath ? (sameLaunchHash ? 2 : hasSearch ? 1 : 0) : 0;
  },
  sessionRequestAllowed(inFlight, pending) {
    return !inFlight && !pending;
  },
  sessionRetry(received, status, aborted) {
    return !aborted && (!received || [502, 503, 504].includes(status));
  },
  sessionFields(identityText, usernameText, xAvailable) {
    return [identityText ? 1024 : 0, usernameText ? 1024 : 0, xAvailable];
  },
  queueHasRoom(queued) {
    return queued < 64;
  },
  canDispatch(busy, hasQueued, socketOpen) {
    return !busy && hasQueued && socketOpen;
  },
  canDeliverObservation(aborted, sameSocket, socketOpen, queued) {
    return !aborted && sameSocket && socketOpen && this.queueHasRoom(queued);
  },
  observationReply(status) {
    return status === 200;
  },
  bootCompletion(booting, reconnect, failed) {
    const close = booting && reconnect && failed;
    const ready = booting && !close;
    return [close, ready, ready ? 'ready' : ''];
  },
  startupTimedOut(sameSocket, booting) {
    const close = sameSocket && booting;
    return [close, close ? 'The workspace did not finish connecting within 15 seconds.' : ''];
  },
  asterAttempt(attempt, aborted) {
    return attempt < 3 && !aborted;
  },
  asterRetryDelay(attempt, aborted) {
    return aborted ? 0 : 350 * (attempt + 1);
  },
  asterResponse(ok, mediaType, hasBody) {
    return ok && mediaType === 'text/event-stream' && hasBody;
  },
  asterField(field, hasColon, space, eventPresent) {
    return [field === 'event' && !eventPresent ? 1 : field === 'data' ? 2 : 0, hasColon ? (space ? 2 : 1) : 0];
  },
  asterFrameKind(name) {
    return name === 'update' ? 1 : name === 'done' ? 2 : 0;
  },
  asterThreadMatches(expected, observed) {
    return Boolean(expected) && expected === observed;
  },
  asterWatchAction(sameMarker, hasWatch, expected, observed) {
    return sameMarker ? 0 : hasWatch && this.asterThreadMatches(expected, observed) ? 2 : 1;
  },
  transportLimits() {
    return [5000, 300_000, 5000, 3_000_000];
  },
  delayAllowed(integer, milliseconds) {
    return integer && milliseconds >= 0 && milliseconds <= this.transportLimits()[2];
  },
  fileReadAction(fileInput, integer, maxBytes, hasFile, size) {
    if (!fileInput || !integer || maxBytes < 1 || maxBytes > this.transportLimits()[3]) return 1;
    return hasFile && size <= maxBytes ? 0 : 2;
  },
  overlayPlacement(anchored, x, pointY, anchorTop, anchorBottom, width, height, viewportWidth, viewportHeight) {
    const gutter = 8;
    const y = anchored ? (anchorBottom + height > viewportHeight - gutter ? anchorTop - height : anchorBottom) : pointY;
    const fit = (value, size, available) => Math.max(gutter, Math.min(value, available - size - gutter));
    return [fit(x, width, viewportWidth), fit(y, height, viewportHeight)];
  },
  eventAdmission(excluded, delegated, withinScope, unmodified, primary, modified, alreadyPrevented,
    preventDefault, preventKey, waitingForBoot) {
    const admitted = !excluded && (!delegated || withinScope) && (!unmodified || (primary && !modified && !alreadyPrevented));
    return [admitted && (preventDefault || preventKey), admitted && !waitingForBoot];
  },
  canPoll(busy, queued, socketOpen) {
    return !busy && !queued && socketOpen;
  },
  intervalSelector(ref, nullRef) {
    return !nullRef && ref !== 'window' && ref !== 'document';
  },
  intervalDispatch(scoped, visible) {
    return !scoped || visible;
  },
  intervalAllowed(whole, milliseconds) {
    return whole && milliseconds >= 500 && milliseconds <= 60_000;
  },
  workspaceObservationTrigger(ref, event, booting, backgroundSession) {
    if (event === 'workspace-access') return ref === 'window' && booting ? 1 : 3;
    if (!backgroundSession) return 0;
    return ref === 'window' && ['focus', 'pageshow'].includes(event) ? 2 : 4;
  },
  sessionObservation(initial, booting, leaving, socketOpen) {
    return !leaving && (initial ? booting : !booting && socketOpen);
  },
  bootBatchAllowed(booting, array, count) {
    return booting && this.batchLength(array, count);
  },
  preflightPlain(hasSearch, hasHash, sameLocation) {
    return !hasSearch && !hasHash && sameLocation;
  },
  preflightRead(port, plain) {
    if (port === 'browser.startup') return plain ? 2 : 1;
    if (port === 'browser.location') return plain ? 3 : 1;
    return ['dom.exists', 'browser.property', 'storage.read', 'state.get'].includes(port) ? 4 : 0;
  },
  deferredBootEffect(port) {
    if (port === 'browser.startup') return 1;
    return ['browser.asterStream', 'browser.countdown', 'browser.on', 'browser.onMany',
      'browser.activeGroup', 'browser.appDescriptions', 'browser.copyText', 'browser.guard',
      'browser.write', 'browser.attribute', 'browser.content', 'state.set'].includes(port) ? 2 : 0;
  },
  bootStartupMatches(sameFirst, samePath, hadInput, hasHash, hasFields) {
    return sameFirst && samePath && !hadInput && !hasHash && !hasFields;
  },
  followupBootEffect(port, present, known) {
    if (!present) return 0;
    return known && port !== 'browser.bootEffects' && port !== 'browser.preflight' ? 2 : 1;
  },
  domWriteProperty(name) {
    return ['value', 'checked', 'disabled', 'hidden', 'readOnly', 'tabIndex', 'textContent', 'className',
      'open', 'max', 'min', 'title'].includes(name);
  },
  domAttribute(name, anchor, image, page, nullValue, boolean, valueTrue) {
    if (name === 'aria-current' && anchor && (page || nullValue)) return nullValue ? 1 : 2;
    if (name === 'aria-pressed' && boolean) return 3;
    if (/^data-[a-z][a-z0-9-]{0,63}$/.test(name) && boolean) return valueTrue ? 4 : 1;
    if (name !== 'src' || !image) return 0;
    return nullValue ? 1 : 5;
  },
  pngPayloadOffset(head, length) {
    const prefix = 'data:image/png;base64,';
    return head.startsWith(prefix) && length > prefix.length && length <= 131_072 ? prefix.length : 0;
  },
  pngPayloadChunk(chunk) {
    return /^[A-Za-z0-9+/=]+$/.test(chunk);
  },
  clipboardControl(id) {
    return this.activeMemberId(id);
  },
  timingLabelAllowed(click, text, length) {
    return click && text && length >= 1 && length <= 80;
  },
  timingTarget(id) {
    return /^#[a-z0-9-]{1,100}$/.test(id);
  },
  launchId(id) {
    return /^[0-9]{1,16}$/.test(id);
  },
  clipboardTrigger(trusted, matches) {
    return trusted && matches;
  },
  clipboardSelection(readOnly, feedback, length) {
    return readOnly && feedback && length > 0 && length <= 96_000;
  },
  clipboardNotice(copied) {
    return copied ? 'Copied to clipboard.' : 'Use your device’s Copy command to copy the selected text.';
  },
  storageInTab(scope) {
    return scope === 'tab';
  },
  storageReadAllowed(present, length, limit) {
    return !present || !(length > limit);
  },
  documentStateKey(text, length) {
    return text && length <= 512;
  },
  documentStateAdmission(used, previousSize, keyLength, valueLength, remove, count, existing) {
    const size = remove ? 0 : keyLength + valueLength;
    const total = used - previousSize + size;
    return [total, total <= 4_000_000 && (!size || existing || count < 64), size];
  },
  formField(name, nameLength, text, valueLength, repeated, count, used) {
    const valid = /^[A-Za-z0-9_-]{1,80}$/.test(name) && text && !repeated && count < 64;
    const size = used + nameLength + valueLength;
    return [valid ? (size <= 16384 ? 0 : 2) : 1, size];
  },
  fileSizeBatch(array, count) {
    return array && count <= 8192;
  },
  fileSize(safeInteger, bytes) {
    const valid = safeInteger && bytes >= 0;
    let scaled = bytes;
    let unit = 0;
    while (valid && unit < 5 && scaled >= 1000) {
      scaled /= 1000;
      unit += 1;
    }
    if (unit > 0 && unit < 5 && scaled >= 999.95) {
      scaled /= 1000;
      unit += 1;
    }
    return [valid, scaled, unit];
  },
  connectionView(state, now, retryAt, manualRetry) {
    const label = state === 'ready' ? 'Connected' : state === 'connecting' ? 'Connecting…' : 'Offline';
    const title = manualRetry ? 'Connect to ' : 'Wait at least 10 seconds between connection attempts.';
    return [label, retryAt ? 'Retry in ' : '', Math.max(0, Math.ceil((retryAt - now) / 1000)), retryAt ? 's' : '',
      state === 'disconnected', title];
  },
  disconnectPlan(leaving, storedReason, socketReason, code, hasPanel, reconnect) {
    const lost = !socketReason && code === 1006;
    const prefix = socketReason ? 'Connection closed (' : lost
      ? 'Connection lost without a close reason (code 1006).' : 'Connection closed (code ';
    const suffix = socketReason ? '). ' : lost ? '' : ').';
    const showNotice = !hasPanel && !leaving;
    const notice = !showNotice ? '' : reconnect ? 'Browser session disconnected. Reconnecting…'
      : 'Browser session disconnected. Reload to reconnect.';
    return [!leaving, storedReason, !lost, socketReason, prefix, suffix, notice, showNotice && !reconnect];
  },
  startupFailureNotice(hasPanel) {
    return ['Workspace startup failed. ', !hasPanel];
  },
  holdStartupSubmit(reconnect, booting) {
    return reconnect && booting;
  },
  connectionOpen(leaving, hasSocket) {
    const open = !leaving && !hasSocket;
    return [open, open ? 'connecting' : ''];
  },
  historyResume(persisted, leaving, hasSocket) {
    const resume = persisted && leaving;
    return [resume, resume && hasSocket];
  },
  connectionProfile(hasPanel, homeAster, requestedReconnect) {
    const reconnect = hasPanel || homeAster || requestedReconnect;
    return [reconnect, hasPanel ? 10_000 : 250, reconnect ? 15_000 : 0];
  },
  socketReplyAllowed(sameSocket, socketOpen) {
    return sameSocket && socketOpen;
  },
  agentInvocationAllowed(sameSocket, socketOpen, queued) {
    return sameSocket && socketOpen && this.queueHasRoom(queued);
  },
  batchLength(array, count) {
    return array && count >= 1 && count <= 64;
  },
  batchPort(port) {
    return ['dom.exists', 'browser.property', 'browser.write', 'browser.attribute',
      'browser.focus', 'browser.activate'].indexOf(port) + 1;
  },
  batchStep(port, record, conditional, guardPort, save, key, duplicate) {
    if (!port || !record || (conditional && guardPort !== 1)) return 1;
    return save && (!/^[a-z][a-zA-Z0-9]{0,39}$/.test(key) || duplicate || conditional) ? 2 : 0;
  },
  batchExecute(conditional, observed) {
    return !conditional || !observed;
  },
  markReveal(port, matchingTarget, open, unhide) {
    return matchingTarget && (port === 'browser.dialog' && open || port === 'browser.write' && unhide);
  },
  asterCredential(capture, thread, bearer) {
    if (!capture) return 0;
    const valid = /^[a-f0-9]{32}$/.test(thread) && (/^[A-Za-z0-9_-]{43}$/.test(bearer) || /^[a-f0-9]{64}$/.test(bearer));
    return valid ? 2 : 1;
  },
  asterChunkBoundary(previousCR, leadingLF, trailingCR) {
    return [previousCR && leadingLF ? 1 : 0, trailingCR];
  },
  asterBuffer(boundary, pending) {
    const complete = boundary !== -1;
    const size = complete ? boundary : pending;
    return size <= 131_072 ? (complete ? 1 : 0) : 2;
  },
  asterDispatchFrame(action, expected, observed) {
    return this.asterThreadMatches(expected, observed) ? action : 0;
  },
  asterQueueAction(pending, room) {
    return pending ? 1 : room ? 2 : 0;
  },
  descriptionTransition(event, preview, mouse, open, hidden) {
    if (event === 'enter' && mouse && !open) return [1, 180, preview];
    if (event === 'leave' && preview) return [2, 180, preview];
    if (event === 'show' && !hidden && !open) return [1, 0, true];
    if (event === 'hide') return [2, 0, preview];
    if (event === 'closed') return [0, 0, false];
    if (event === 'click' && preview) return [3, 0, false];
    return [0, 0, preview];
  },
  descriptionLayout(height, scrollHeight, open) {
    return !height ? 0 : scrollHeight > height + 1 ? 2 : open ? 3 : 1;
  },
  requestRoute(method, path) {
    if (method !== 'GET' && method !== 'POST') return 1;
    if (path === '/workspace/session' || path === '/workspace/sign-out') return 2;
    return path === '/workspace/aster/events' ? 3 : 0;
  },
  requestForm(path, mobileOffer, length) {
    return length <= (mobileOffer ? 65536 : path === '/workspace/formation/records' ? 32768 : 16384);
  },
  requestQuery(count) {
    return count <= 8;
  },
  queryField(key, text, length) {
    return /^[A-Za-z0-9_-]{1,64}$/.test(key) && text && length <= 1024;
  },
  requestResponse(path, asterView, ok, subscription, fragment) {
    if (path === '/identity-management/aster/') return ok && subscription ? 3 : 2;
    if (path === '/identity-management/' && asterView) return 2;
    return fragment ? 1 : 0;
  },
  requestBearer(present, bearer) {
    return !present ? 0 : /^[A-Za-z0-9_-]{1,128}$/.test(bearer) ? 1 : 2;
  },
  frontGatePort(integer, canonical, port) {
    return integer && canonical && port >= 1024 && port <= 65535;
  },
};
