const encounterLegacyTemple = {
  savedTempleAdmission(validIdentity, canonicalOrigin) {
    return validIdentity && canonicalOrigin;
  },
  savedOriginMatch(current, saved) {
    return current === saved;
  },
  retainSavedTemple(count, sameOrigin) {
    return count < this.catalogueLimit() && !sameOrigin;
  },
  catalogueLimit() {
    return 20;
  },
  savedCatalogue(version, hasList) {
    return version === 1 && hasList;
  },
  greetingWorkspaceCount(hasList, count) {
    return hasList && count <= 4;
  },
  greetingPlan(subscriptionVersion, reconnecting, selected, path) {
    const canonicalPath = this.workspacePath(selected);
    return [subscriptionVersion === 1, reconnecting && canonicalPath !== '' && path === canonicalPath];
  },
  connectionTimedOut(active, greeted) {
    return active && !greeted;
  },
  messageBody(text, length) {
    return text && length <= 4096;
  },
  subscriptionRequest(previous) {
    return ['workspace.subscribe', previous + 1];
  },
  subscriptionReply(pendingId, observedId, pendingWorkspace, observedWorkspace) {
    return pendingId !== 0 && pendingId === observedId && pendingWorkspace === observedWorkspace;
  },
  subscriptionTimedOut(pendingId, observedId, pendingWorkspace, observedWorkspace) {
    const expire = this.subscriptionReply(pendingId, observedId, pendingWorkspace, observedWorkspace);
    return [expire, expire ? this.workspaceNotice('subscription-timeout')[1] : ''];
  },
  retryConnection(greeted, reconnecting, delay) {
    if (greeted || reconnecting) return [true, delay, this.nextRetry(delay), 'Reconnecting to Temple…'];
    return [false, 0, delay, 'Could not connect to that Temple. Check its address and setup, then try again.'];
  },
  platformAppCount(array, count, distinct) {
    return array && count <= 2 && distinct === count;
  },
  platformApp(view, titleText, titleLength, detailText, detailLength) {
    return Boolean(this.platformViewCode(view)) && titleText && titleLength <= 80 && detailText && detailLength <= 160;
  },
  originInput(text, length) {
    return text && length <= 240;
  },
  connectionCoordinates(secure) {
    return ['/workspace/temple/connection', secure ? 'wss:' : 'ws:'];
  },
  originAllowed(protocol, loopbackHost, explicitPort, rootPath, credentials, decorated) {
    const transport = protocol === 'https:' || (protocol === 'http:' && loopbackHost && explicitPort);
    return transport && rootPath && !credentials && !decorated;
  },
  platformViewCode(view) {
    return view === 'platform-inbox' ? 1 : view === 'work-items' ? 2 : 0;
  },
  workspaceLocation(path, view, uniqueView) {
    if (uniqueView && (path === '/' || path === '/workspace/home') && (view === 'platform' || this.platformViewCode(view))) {
      return 'platform';
    }
    const locations = {'/workspace/home': 'home', '/workspace/work': 'work', '/workspace/platform': 'platform', '/workspace/mobile': 'mobile'};
    return Object.hasOwn(locations, path) ? locations[path] : '';
  },
  workspacePath(workspace) {
    return this.workspaceName(workspace) ? '/workspace/' + workspace : '';
  },
  historyRestore(path, view, uniqueView) {
    const workspace = this.workspaceLocation(path, view, uniqueView);
    return [workspace, workspace ? 'none' : ''];
  },
  workspaceName(workspace) {
    const names = {home: 'Home', work: 'Work', platform: 'Platform', mobile: 'Mobile'};
    return Object.hasOwn(names, workspace) ? names[workspace] : '';
  },
  navigationItem(workspace, selected) {
    const label = this.workspaceName(workspace);
    return [label, label && workspace === selected ? 'page' : ''];
  },
  workspaceNotice(phase) {
    const notices = {
      opening: ['Opening ', '…'],
      'subscription-timeout': ['', ' did not respond. Select it again to retry.'],
      unavailable: ['', ' is unavailable for this Temple session.'],
      slow: ['', ' is taking longer to open.'],
      empty: ['', 'This Temple has no available workspaces.'],
    };
    return Object.hasOwn(notices, phase) ? notices[phase] : ['', ''];
  },
  launchFields(workspace, local) {
    if (local) return ['open', 'view', 'item', 'setup', 'play', 'pilot', 'comment', 'sign-in'];
    return ['', workspace === 'platform' ? 'view' : '', '', '', '', '', '', ''];
  },
  launchValueAllowed(workspace, name, value, count, local) {
    return count === 1 && (local || (workspace === 'platform' && name === 'view' && Boolean(this.platformViewCode(value))));
  },
  platformTarget(workspace, view, item) {
    if (workspace !== 'platform') return [false, '', false];
    const validItem = /^[a-f0-9]{32}$/.test(item);
    let code = this.platformViewCode(view);
    if (!code && (!view || view === 'platform') && validItem) code = 2;
    return [true, ['', 'platform-inbox', 'work-items'][code], Boolean(code && validItem)];
  },
  identityAdmission(id) {
    return /^[A-Za-z0-9._-]{1,80}$/.test(id);
  },
  selection(selected, available, preferred, preferredAvailable, first) {
    if (selected) return [available ? 2 : 1, selected];
    const workspace = preferredAvailable ? preferred : first;
    return [workspace ? 2 : 0, workspace];
  },
  subscription(resubscribe, mounted, pending, subscriptions) {
    return !resubscribe && (mounted || pending) ? 0 : subscriptions ? 2 : 1;
  },
  timing() {
    return [1000, 8000, 12000, 30000];
  },
  workspaceReply(type, workspace, kind, hasView, validApps, entryMatches) {
    const launcher = workspace === 'platform' && !hasView;
    return type !== 'workspace.ready' ? 0 : launcher
      ? (kind === 'platform-launcher' && validApps ? 2 : 0) : kind === 'frame' && entryMatches ? 1 : 0;
  },
  greetingAccepted(protocol, savedTemple, observedTemple, knownTemple, validTemple, validWorkspaces) {
    return protocol === 'sourcery/temple-connection/1' && validTemple && validWorkspaces &&
      (!knownTemple || savedTemple === observedTemple);
  },
  frameLoadAction(active, targetDocument, local, workspace, connected) {
    if (!active) return 0;
    if (targetDocument) return 1;
    return local && workspace === 'work' && connected ? 2 : 3;
  },
  frameMount(workspace, local) {
    return [local ? '' : 'allow-scripts allow-forms allow-same-origin allow-popups',
      workspace === 'home' ? '[data-home-connection]' : '',
      local ? 'form.workspace-preference[action="/workspace/default"]' : '', 'no-referrer'];
  },
  frameObservation(hasHomeConnection) {
    return [hasHomeConnection ? 'data-state' : 'data-encounter', 'script[src*="_encounter/browser"]'];
  },
  frameSignIn() {
    return ['/workspace/temple/work-sign-in', 'Work requires sign-in. ', 'Sign in to Work'];
  },
  frameReady(hasHomeConnection, homeReady, bridgeReady, waitForBridge) {
    return !waitForBridge || (hasHomeConnection ? homeReady : bridgeReady);
  },
  showFrame(connected, pending, ready) {
    return connected && !pending && ready;
  },
  frameTimedOut(active, connected) {
    return active && connected;
  },
  nextRetry(delay) {
    return Math.min(30000, delay * 2);
  },
  followWorkspaceLink(hasLink, primary, prevented, modified, target) {
    return hasLink && primary && !prevented && !modified && (!target || target === '_self');
  },
  workspaceDestination(sameOrigin, available) {
    return sameOrigin && available;
  },
  workspaceOpen(connected, available) {
    return connected && available;
  },
  workspaceHistory(mode, samePath, sameQuery) {
    if (samePath && sameQuery) return '';
    return mode === 'replace' ? 'replaceState' : mode === 'push' ? 'pushState' : '';
  },
  surfacePlan(mounted, hasFrame, frameReady, launcher) {
    return [mounted ? 0 : launcher ? 2 : 1, mounted ? (!hasFrame || frameReady) : launcher, !frameReady];
  },
  preferenceReply(ok, current, connected, available) {
    if (!ok) return [2, 'Could not save the default environment. Try again.'];
    return current && connected && available ? [1, 'Default environment saved.'] : [0, ''];
  },
  connectionNotice(reconnecting) {
    return reconnecting ? 'Reconnecting to Temple…' : 'Connecting to Temple…';
  },
};
